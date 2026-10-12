# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""events.py — security / ops events and request statistics.

* Catalog of events; each can be switched off or re-graded in the UI (config.yaml → events.overrides).
* HTTP middleware classifies admin changes, sensitive reads, logins, OAuth and refused agent requests —
  one place instead of a call in every route. Floods (blocked commands, bad keys) are aggregated per window.
* Durable outbox (data/events.db) → notify-gate JSON source API (POST {NOTIFY_GATE_URL}/in/{source}) with retry;
  Telegram / SMTP from the Notifications page as fallback or in parallel.
* Hourly request counters (survive audit trimming) for the dashboard and Prometheus /metrics.
Secrets never enter an event: only ids, paths, IPs and counters."""
import asyncio, html, ipaddress, json, logging, os, re, sqlite3, time
from collections import Counter
from contextlib import contextmanager

import httpx
from starlette.responses import Response

import storage

log = logging.getLogger("mcp-gate.events")
DB = storage.DATA_DIR / "events.db"
NG_URL = os.environ.get("NOTIFY_GATE_URL", "").rstrip("/")
NG_SOURCE = os.environ.get("NOTIFY_GATE_SOURCE", "mcp-gate")
NG_TOKEN = os.environ.get("NOTIFY_GATE_TOKEN", "")


def _nets(v):
    return [n.strip() for n in v.split(",") if n.strip()]


TRUSTED = _nets(os.environ.get("TRUSTED_PROXIES", ""))
METRICS_CIDRS = _nets(os.environ.get("METRICS_CIDRS", "127.0.0.1/32"))
SEVERITIES = ("info", "warning", "critical")
# event: (severity, on by default, EN title, RU title)
CATALOG = {
    "login_ok": ("info", False, "Admin login", "Вход администратора"),
    "login_fail": ("warning", True, "Failed admin login", "Неудачный вход администратора"),
    "password": ("warning", True, "Admin password changed", "Пароль администратора изменён"),
    "agent": ("info", True, "Agent changed", "Изменение агента"),
    "agent_key": ("warning", True, "Agent key issued", "Выпущен ключ агента"),
    "key_reveal": ("critical", True, "Agent key revealed", "Ключ агента показан в UI"),
    "host": ("info", True, "Host changed", "Изменение хоста"),
    "command_set": ("info", True, "Command set changed", "Изменение набора команд"),
    "secret": ("warning", True, "Secret changed", "Изменение секрета"),
    "ssh": ("warning", True, "SSH key / deploy", "SSH-ключ или деплой"),
    "notify_cfg": ("warning", True, "Notification settings changed", "Изменены настройки уведомлений"),
    "config": ("info", True, "Settings / backup / audit changed", "Изменены настройки, бэкап или аудит"),
    "sensitive_read": ("warning", True, "Sensitive export", "Выгрузка чувствительных данных"),
    "console": ("warning", True, "Admin console command", "Команда из консоли администратора"),
    "approval": ("warning", True, "Approval required", "Команда ждёт подтверждения"),
    "approval_result": ("info", False, "Approval decided", "Решение по подтверждению"),
    "grant": ("info", True, "Timed agent access", "Временный доступ агента"),
    "blocked": ("warning", True, "Command blocked", "Команда заблокирована"),
    "agent_denied": ("warning", True, "Request with invalid or inactive key", "Запрос с неверным или неактивным ключом"),
    "oauth": ("warning", True, "OAuth client", "OAuth-клиент"),
    "system": ("info", True, "mcp-gate started", "mcp-gate запущен"),
}
DEFAULTS = {"enabled": True, "legacy": "fallback", "window_min": 10, "max_tries": 8, "retention_days": 30, "overrides": {}}
# (method or "*" = any non-GET, path regex, event) — first match wins
RULES = [
    ("POST", r"/api/admin/exec", "console"),
    ("GET", r"/api/admin/agents/[^/]+/reveal-key", "key_reveal"),
    ("POST", r"/api/admin/agents/[^/]+/generate-key", "agent_key"),
    ("*", r"/api/admin/agents(/.*)?", "agent"),
    ("*", r"/api/admin/hosts/[^/]+/(deploy-key|verify-sudoers)", "ssh"),
    ("*", r"/api/admin/hosts(/.*)?", "host"),
    ("*", r"/api/admin/command-sets(/.*)?", "command_set"),
    ("GET", r"/api/admin/(secrets/export|backup|audit/export|mcp-connection)", "sensitive_read"),
    ("*", r"/api/admin/secrets(/.*)?", "secret"),
    ("*", r"/api/admin/(ssh/.*|bootstrap)", "ssh"),
    ("*", r"/api/admin/(telegram|smtp|notification-templates|events/settings)", "notify_cfg"),
    ("*", r"/api/admin/(approve|reject)/.*", "approval_result"),
    ("*", r"/api/admin/(instance|audit.*|restore|mcp-connection.*|appearance|themes.*|upload)", "config"),
]
SKIP = re.compile(r".*/(test|test-all|test-paths|sandbox/files|generate-htpasswd)$")
CREATE = re.compile(r"/api/admin/(agents|hosts|command-sets|secrets)")
MCP_PATHS = ("/mcp", "/sse", "/messages", "/api/exec")

_agg: dict = {}
COUNTS: Counter = Counter()          # Prometheus counters (since start)
_state = {"last_ok": 0.0, "last_error": "", "last_error_ts": 0.0}


# ── storage ──
@contextmanager
def _db():
    c = sqlite3.connect(str(DB), timeout=5, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with _db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, ts REAL, event TEXT, severity TEXT,
                     title TEXT, body TEXT, state TEXT, tries INT DEFAULT 0, next_at REAL, done_at REAL,
                     channel TEXT DEFAULT '', error TEXT DEFAULT '')""")
        c.execute("CREATE INDEX IF NOT EXISTS ix_outbox_state ON outbox(state, next_at)")
        c.execute("""CREATE TABLE IF NOT EXISTS hits(hour INT, kind TEXT, who TEXT, host TEXT, status TEXT, n INT,
                     PRIMARY KEY(hour, kind, who, host, status))""")
    storage.AUDIT_HOOKS.append(on_audit)


def settings() -> dict:
    s = {**DEFAULTS, **(storage.load_config().get("events") or {})}
    s["overrides"] = dict(s.get("overrides") or {})
    return s


def validate(d: dict) -> dict:
    s = settings()
    if d.get("legacy", s["legacy"]) not in ("fallback", "parallel", "off"):
        raise ValueError("legacy: fallback | parallel | off")
    out = {"enabled": bool(d.get("enabled", s["enabled"])), "legacy": d.get("legacy", s["legacy"])}
    for k, lo, hi in (("window_min", 1, 1440), ("max_tries", 1, 50), ("retention_days", 1, 365)):
        v = int(d.get(k, s[k]))
        if not lo <= v <= hi:
            raise ValueError(f"{k}: {lo}…{hi}")
        out[k] = v
    ov = {}
    for ev, o in (d.get("overrides") or {}).items():
        if ev not in CATALOG or (o.get("severity") and o["severity"] not in SEVERITIES):
            raise ValueError(f"override {ev}")
        ov[ev] = {"on": bool(o.get("on", CATALOG[ev][1])), **({"severity": o["severity"]} if o.get("severity") else {})}
    out["overrides"] = ov
    return out


def _ru() -> bool:
    return (storage.load_config().get("instance") or {}).get("language", "ru") == "ru"


def title(ev: str) -> str:
    return CATALOG[ev][3 if _ru() else 2]


# ── emit ──
def emit(ev: str, head: str = "", body: str = "", severity: str = "", agg: str | None = None):
    """Queue an event. head = object (agent id, path…); agg = flood key (one message + summary per window)."""
    s = settings()
    o = s["overrides"].get(ev, {})
    if not o.get("on", CATALOG[ev][1]):
        return
    sev = o.get("severity") or severity or CATALOG[ev][0]
    COUNTS[f"event:{ev}"] += 1
    t = title(ev) + (f": {head}" if head else "")
    if agg is not None:
        k, now = (ev, agg), time.time()
        a = _agg.get(k)
        if a and now - a["t0"] < s["window_min"] * 60:
            a["n"] += 1
            return
        _agg[k] = {"t0": now, "n": 0, "title": t, "sev": sev}
    _enqueue(ev, sev, t, body)


def _enqueue(ev, sev, t, body):
    with _db() as c:
        c.execute("INSERT INTO outbox(ts,event,severity,title,body,state,next_at) VALUES(?,?,?,?,?,'pending',?)",
                  (time.time(), ev, sev, t[:300], body[:3000], time.time()))


def _flush_agg():
    win = settings()["window_min"] * 60
    for k, a in list(_agg.items()):
        if time.time() - a["t0"] >= win:
            if a["n"]:
                more = (f"ещё {a['n']} за {win // 60} мин" if _ru() else f"{a['n']} more in {win // 60} min")
                _enqueue(k[0], a["sev"], f"{a['title']} ({more})", "")
            del _agg[k]


# ── request classification (middleware) ──
def client_ip(req) -> str:
    def inside(ip, nets):
        try:
            a = ipaddress.ip_address(ip)
            return any(a in ipaddress.ip_network(n, strict=False) for n in nets)
        except ValueError:
            return False
    peer = req.client.host if req.client else ""
    if not inside(peer, TRUSTED):
        return peer
    for h in reversed([x.strip() for x in req.headers.get("x-forwarded-for", "").split(",") if x.strip()]):
        if not inside(h, TRUSTED):
            return h
    return peer


def classify(method: str, path: str) -> str | None:
    if SKIP.fullmatch(path):
        return None
    for m, rx, ev in RULES:
        if (m == method or (m == "*" and method not in ("GET", "HEAD", "OPTIONS"))) and re.fullmatch(rx, path):
            return ev
    return None


async def middleware(request, call_next):
    ip = client_ip(request)
    tok = storage.client_ip_var.set(ip)
    try:
        resp = await call_next(request)
    finally:
        storage.client_ip_var.reset(tok)
    try:
        resp = await _observe(request, resp, ip)
    except Exception as x:  # never break a request because of an event
        log.warning(f"event: {x}")
    return resp


async def _observe(req, resp, ip):
    p, m, st = req.url.path, req.method, resp.status_code
    who = f"IP {ip}"
    if (p in MCP_PATHS or (p == "/" and m == "POST")) and st in (401, 403):
        _hit("auth", ip, "mcp", str(st))
        emit("agent_denied", ip, f"{st} {m} {p}", agg=ip)
    elif p == "/api/auth/login" and m == "POST" and st in (200, 401):
        _hit("login", ip, "-", "ok" if st == 200 else "fail")
        emit("login_ok" if st == 200 else "login_fail", ip, who, agg=None if st == 200 else ip)
    elif p == "/api/auth/change-password" and m == "POST" and st == 200:
        emit("password", ip, who)
    elif p == "/oauth/approve" and m == "POST":
        ok = st in (302, 303)
        _hit("oauth", ip, "-", "ok" if ok else str(st))
        emit("oauth", ("authorized" if ok else f"refused {st}") + f", {ip}", who, severity="" if ok else "critical",
             agg=None if ok else ip)
    elif 200 <= st < 300 and (ev := classify(m, p)):
        obj = p.split("/api/admin/", 1)[-1]
        if m == "POST" and CREATE.fullmatch(p):
            raw = b"".join([c async for c in resp.body_iterator])
            hdr = {k: v for k, v in resp.headers.items() if k.lower() != "content-length"}
            resp = Response(raw, status_code=st, headers=hdr, media_type=resp.media_type)
            try:
                obj += f"/{json.loads(raw).get('id', '')}"
            except Exception:
                pass
        emit(ev, f"{m} {obj}", who)
    return resp


# ── stats ──
def _hit(kind, who, host, status):
    COUNTS[f"{kind}|{who if kind == 'cmd' else '-'}|{host}|{status}"] += 1
    with _db() as c:
        c.execute("INSERT INTO hits VALUES(?,?,?,?,?,1) ON CONFLICT(hour,kind,who,host,status) DO UPDATE SET n=n+1",
                  (int(time.time() // 3600), kind, who or "-", host or "-", status or "?"))


def on_audit(e: dict):
    h = e.get("host_id") or ""
    if e.get("source") == "admin" or h in ("", "-"):
        return
    _hit("cmd", e.get("agent_id") or "-", h, e.get("status") or "?")


def stats(hours: int) -> dict:
    hours = max(1, min(int(hours), 24 * 90))
    now_h = int(time.time() // 3600)
    with _db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM hits WHERE hour>?", (now_h - hours,))]
        ob = {r["state"]: r["n"] for r in c.execute(
            "SELECT state, COUNT(*) n FROM outbox WHERE ts>? GROUP BY state", (time.time() - hours * 3600,))}
    step = 1 if hours <= 48 else 24
    series = {}
    for b in range((now_h - hours) // step + 1, now_h // step + 1):
        series[b] = {"t": b * step * 3600, "ok": 0, "blocked": 0, "error": 0, "pending": 0, "other": 0}
    agents, hosts, auth = {}, {}, Counter()
    for r in rows:
        if r["kind"] != "cmd":
            auth[f"{r['kind']}_{r['status']}"] += r["n"]
            continue
        st = r["status"] if r["status"] in ("ok", "blocked", "error", "pending") else "other"
        if (b := r["hour"] // step) in series:
            series[b][st] += r["n"]
        for d, k in ((agents, r["who"]), (hosts, r["host"])):
            x = d.setdefault(k, {"id": k, "ok": 0, "blocked": 0, "error": 0, "pending": 0, "other": 0, "total": 0})
            x[st] += r["n"]
            x["total"] += r["n"]
    since = time.time() - hours * 3600
    with storage._audit_db() as a:
        reasons = [dict(r) for r in a.execute(
            "SELECT COALESCE(json_extract(data,'$.reason'),'?') reason, COUNT(*) n FROM audit "
            "WHERE status='blocked' AND ts>? GROUP BY reason ORDER BY n DESC LIMIT 8", (since,))]
        cmds = [dict(r) for r in a.execute(
            "SELECT command, host_id, COUNT(*) n FROM audit WHERE status='blocked' AND source!='admin' AND ts>? "
            "GROUP BY command, host_id ORDER BY n DESC LIMIT 8", (since,))]
    top = lambda d: sorted(d.values(), key=lambda x: -x["total"])[:12]
    return {"hours": hours, "step_h": step, "series": list(series.values()), "agents": top(agents), "hosts": top(hosts),
            "auth": dict(auth), "reasons": reasons, "blocked_cmds": cmds, "outbox": ob}


def outbox(limit=50) -> list[dict]:
    with _db() as c:
        return [dict(r) for r in c.execute("SELECT id,ts,event,severity,title,state,tries,channel,error,done_at "
                                            "FROM outbox ORDER BY id DESC LIMIT ?", (min(int(limit), 500),))]


def status() -> dict:
    with _db() as c:
        pend = c.execute("SELECT COUNT(*) FROM outbox WHERE state='pending'").fetchone()[0]
    return {"url": NG_URL, "source": NG_SOURCE, "token_set": bool(NG_TOKEN), "configured": bool(NG_URL and NG_TOKEN),
            "pending": pend, **_state}


def metrics_text() -> str:
    def lbl(**kv):
        return "{" + ",".join(f'{k}="{str(v).replace(chr(34), "")}"' for k, v in kv.items()) + "}"
    from constants import VERSION
    out = ["# TYPE mcpgate_build_info gauge", f"mcpgate_build_info{lbl(version=VERSION)} 1",
           "# TYPE mcpgate_requests_total counter", "# TYPE mcpgate_auth_total counter", "# TYPE mcpgate_events_total counter"]
    for k, n in sorted(COUNTS.items()):
        if k.startswith("event:"):
            out.append(f"mcpgate_events_total{lbl(event=k[6:])} {n}")
            continue
        kind, who, host, st = k.split("|")
        out.append(f"mcpgate_requests_total{lbl(agent=who, host=host, status=st)} {n}" if kind == "cmd"
                   else f"mcpgate_auth_total{lbl(kind=kind, status=st)} {n}")
    agents = storage.load_agents()
    out += ["# TYPE mcpgate_agents_active gauge", f"mcpgate_agents_active {sum(storage.agent_active(a) for a in agents)}",
            "# TYPE mcpgate_approvals_pending gauge", f"mcpgate_approvals_pending {len(storage.get_pending_approvals())}",
            "# TYPE mcpgate_outbox_pending gauge", f"mcpgate_outbox_pending {status()['pending']}",
            "# TYPE mcpgate_notify_last_ok_timestamp gauge", f"mcpgate_notify_last_ok_timestamp {_state['last_ok']}"]
    return "\n".join(out) + "\n"


def metrics_allowed(req) -> bool:
    try:
        a = ipaddress.ip_address(client_ip(req))
        return any(a in ipaddress.ip_network(n, strict=False) for n in METRICS_CIDRS)
    except ValueError:
        return False


# ── delivery ──
async def _to_ng(r) -> tuple[bool, str, bool]:
    """(ok, error, retryable)"""
    try:
        async with httpx.AsyncClient(timeout=10) as cl:
            x = await cl.post(f"{NG_URL}/in/{NG_SOURCE}", headers={"Authorization": f"Bearer {NG_TOKEN}"},
                              json={"title": r["title"], "body": r["body"], "severity": r["severity"]})
        if 200 <= x.status_code < 300:
            return True, "", False
        return False, f"HTTP {x.status_code}: {x.text[:200]}", x.status_code in (408, 425, 429) or x.status_code >= 500
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"[:300], True


async def _to_legacy(r) -> bool:
    import notifications
    cfg, ok = storage.load_config(), False
    flag = {"blocked": "notify_blocked", "approval": "notify_approvals"}.get(r["event"])
    tg, sm = cfg.get("telegram") or {}, cfg.get("smtp") or {}
    if tg.get("enabled") and (not flag or tg.get(flag, True)):
        res = await notifications.send_telegram(f"<b>{html.escape(r['title'])}</b>\n{html.escape(r['body'] or '')}")
        ok |= bool(res.get("ok"))
    if sm.get("enabled") and (not flag or sm.get(flag, True)):
        ok |= bool((await notifications.send_smtp(f"MCP Gate: {r['title']}", r["body"] or r["title"])).get("ok"))
    return ok


def _mark(i, **kv):
    with _db() as c:
        c.execute(f"UPDATE outbox SET {','.join(k + '=?' for k in kv)} WHERE id=?", (*kv.values(), i))


async def _deliver():
    s = settings()
    with _db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM outbox WHERE state='pending' AND next_at<=? ORDER BY id LIMIT 20", (time.time(),))]
    ng = s["enabled"] and NG_URL and NG_TOKEN
    for r in rows:
        now = time.time()
        if not ng:
            ok = s["legacy"] != "off" and await _to_legacy(r)
            _mark(r["id"], state="sent" if ok else "skipped", channel="legacy" if ok else "", done_at=now)
            continue
        ok, err, retry = await _to_ng(r)
        if ok:
            _state["last_ok"] = now
            if s["legacy"] == "parallel":
                await _to_legacy(r)
            _mark(r["id"], state="sent", channel="notify-gate", done_at=now, error="")
            continue
        _state.update(last_error=err, last_error_ts=now)
        COUNTS["event:_delivery_error"] += 1
        if retry and r["tries"] + 1 < s["max_tries"]:
            _mark(r["id"], tries=r["tries"] + 1, next_at=now + min(600, 5 * 2 ** r["tries"]), error=err)
        else:
            fb = s["legacy"] != "off" and await _to_legacy(r)
            _mark(r["id"], state="fallback" if fb else "failed", tries=r["tries"] + 1, channel="legacy" if fb else "",
                  error=err, done_at=now)


async def loop():
    from constants import full_version
    await asyncio.sleep(3)
    emit("system", f"v{full_version()}", "")
    gc = 0.0
    while True:
        try:
            await _deliver()
            _flush_agg()
            if time.time() - gc > 3600:
                gc = time.time()
                with _db() as c:
                    c.execute("DELETE FROM outbox WHERE ts<?", (gc - settings()["retention_days"] * 86400,))
                    c.execute("DELETE FROM hits WHERE hour<?", (int(gc // 3600) - 24 * 90,))
        except Exception as x:
            log.error(f"events loop: {x}")
        await asyncio.sleep(2)
