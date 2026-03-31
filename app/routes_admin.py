# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""routes_admin.py — Admin CRUD routes for MCP Gate.
Hosts, Agents, Command Sets, Secrets, Settings, Audit, Backup, Appearance, i18n, Bootstrap.
"""
import csv
import re
import hashlib
import io
import json as J
import secrets as S
import shlex
import subprocess
import time

import bcrypt
from fastapi import APIRouter, Request, HTTPException, File, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse

import storage
import ssh_client
import notifications
import app_state
from models import (HostM, ModeChg, AgentM, CmdSetM, SecretM,
                    TgCfg, SmtpCfg, PwReq, AuditS, BootReq)

router = APIRouter(tags=["admin"])

# ═══ Host CRUD ═══

@router.get("/api/admin/hosts")
async def admin_hosts():
    return storage.load_hosts()


@router.post("/api/admin/hosts")
async def cr_host(host: HostM):
    app_state.validate_id(host.id, "host")
    if storage.get_host(host.id):
        raise HTTPException(409)
    storage.upsert_host(host.model_dump())
    storage.append_audit({"command": f"create host: {host.id}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "created", "id": host.id}


@router.put("/api/admin/hosts/{hid}")
async def up_host(hid: str, host: HostM):
    if host.id != hid:
        raise HTTPException(400)
    storage.upsert_host(host.model_dump())
    storage.append_audit({"command": f"update host: {hid}", "source": "admin", "status": "ok", "host_id": hid})
    return {"status": "updated", "id": hid}


@router.delete("/api/admin/hosts/{hid}")
async def del_host(hid: str):
    if not storage.delete_host(hid):
        raise HTTPException(404)
    storage.append_audit({"command": f"delete host: {hid}", "source": "admin", "status": "ok", "host_id": hid})
    return {"status": "deleted"}


@router.post("/api/admin/hosts/{hid}/test")
async def test_host(hid: str):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    return ssh_client.test_connection(h)


@router.post("/api/admin/hosts/{hid}/toggle")
async def toggle_host(hid: str):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    h["enabled"] = not h.get("enabled", True)
    storage.upsert_host(h)
    storage.append_audit({"command": f"toggle host: {hid}", "source": "admin", "status": "ok", "host_id": hid})
    return {"status": "toggled", "enabled": h["enabled"]}


@router.put("/api/admin/hosts/{hid}/mode")
async def chg_mode(hid: str, b: ModeChg):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    if b.mode not in ("auto", "pessimistic", "optimistic", "strict"):
        raise HTTPException(400)
    h["approval_mode"] = b.mode
    storage.upsert_host(h)
    return {"status": "updated", "mode": b.mode}


@router.get("/api/admin/hosts/{hid}/effective-whitelist")
async def eff_wl(hid: str):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    return storage.get_effective_whitelist(h)


@router.get("/api/admin/hosts/{hid}/effective-deny")
async def eff_deny(hid: str):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    return list(storage.get_effective_deny(h))


@router.get("/api/admin/hosts/status")
async def hosts_status():
    return app_state.host_status


@router.post("/api/admin/hosts/{hid}/duplicate")
async def dup_host(hid: str):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    new = dict(h)
    new["id"] = f"{hid}-copy-{S.token_hex(3)}"
    new["name"] = f"{h.get('name', hid)} (copy)"
    new["enabled"] = False
    storage.upsert_host(new)
    return {"status": "created", "id": new["id"]}


# ═══ Sandbox ═══


@router.get("/api/admin/hosts/export")
async def exp_hosts():
    hosts = storage.load_hosts()
    return [{k: v for k, v in h.items() if k not in ("created_at", "updated_at")} for h in hosts]


@router.post("/api/admin/hosts/import")
async def imp_hosts(req: Request):
    body = await req.json()
    items = body if isinstance(body, list) else [body]
    imported = []
    for it in items:
        if "id" not in it or "hostname" not in it:
            continue
        it.setdefault("name", it["id"])
        it.setdefault("user", "mcp-reader")
        it.setdefault("port", 22)
        it.setdefault("enabled", True)
        it.setdefault("approval_mode", "pessimistic")
        it["created_at"] = it["updated_at"] = time.time()
        storage.upsert_host(it)
        imported.append(it["id"])
    if imported:
        storage.append_audit({"command": f"import hosts: {imported}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "imported", "count": len(imported), "ids": imported}


@router.get("/api/admin/hosts/{hid}/sandbox")
async def sandbox_info(hid: str):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    sp = h.get("sandbox_path", "")
    if not sp:
        return {"configured": False}
    cmd = f'test -d {shlex.quote(sp)} && test -w {shlex.quote(sp)} && echo "OK" && du -sb {shlex.quote(sp)} | cut -f1 && find {shlex.quote(sp)} -maxdepth 1 -not -path {shlex.quote(sp)} | wc -l || echo "FAIL"'
    try:
        r = ssh_client.execute(h, cmd)
        out = (r.get("output", "") or "").strip().split("\n")
        if out and out[0] == "OK":
            sz = int(out[1]) if len(out) > 1 and out[1].strip().isdigit() else 0
            cnt = int(out[2]) if len(out) > 2 and out[2].strip().isdigit() else 0
            return {"configured": True, "path": sp, "exists": True, "writable": True,
                    "size_bytes": sz, "file_count": cnt}
        return {"configured": True, "path": sp, "exists": False, "writable": False}
    except Exception as e:
        return {"configured": True, "path": sp, "exists": False, "error": str(e)}


@router.get("/api/admin/hosts/{hid}/sandbox/files")
async def sandbox_files(hid: str, subdir: str = ""):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    sp = h.get("sandbox_path", "")
    if not sp:
        raise HTTPException(400, "No sandbox_path")
    target = sp
    if subdir:
        if ".." in subdir or subdir.startswith("/"):
            raise HTTPException(400, "Invalid subdir")
        target = f"{sp}/{subdir}"
    cmd = f'ls -la {shlex.quote(target)} 2>/dev/null || echo "NOT_FOUND"'
    try:
        r = ssh_client.execute(h, cmd)
        out = (r.get("output", "") or "").strip()
        if out == "NOT_FOUND":
            return {"files": [], "error": "Not found"}
        files = []
        for line in out.split("\n")[1:]:
            parts = line.split(None, 8)
            if len(parts) >= 9:
                name = parts[8]
                if name in (".", ".."):
                    continue
                files.append({"name": name, "size": parts[4], "date": f"{parts[5]} {parts[6]} {parts[7]}",
                              "perms": parts[0], "is_dir": parts[0].startswith("d")})
        return {"path": target, "files": files}
    except Exception as e:
        return {"files": [], "error": str(e)}


@router.post("/api/admin/hosts/{hid}/sandbox/clear")
async def sandbox_clear(hid: str):
    h = storage.get_host(hid)
    if not h:
        raise HTTPException(404)
    sp = h.get("sandbox_path", "")
    if not sp:
        raise HTTPException(400, "No sandbox_path")
    cmd = f'find {shlex.quote(sp)} -mindepth 1 -delete 2>&1 && echo "CLEARED" || echo "FAIL"'
    try:
        r = ssh_client.execute(h, cmd)
        out = (r.get("output", "") or "").strip()
        ok = "CLEARED" in out
        storage.append_audit({"host_id": hid, "command": f"sandbox:clear {sp}", "source": "admin",
                              "status": "ok" if ok else "error"})
        return {"status": "ok" if ok else "error", "output": out}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ═══ Agents CRUD ═══

@router.get("/api/admin/agents")
async def admin_agents():
    return storage.load_agents()


@router.post("/api/admin/agents")
async def cr_agent(a: AgentM):
    app_state.validate_id(a.id, "agent")
    if storage.get_agent(a.id):
        raise HTTPException(409)
    d = a.model_dump()
    raw_key = d.pop("api_key", "")
    d["created_at"] = d["updated_at"] = time.time()
    if raw_key:
        d["encrypted_api_key"] = storage.encrypt_agent_key(raw_key)
    storage.upsert_agent(d)
    storage.invalidate_agent_key_cache()
    return {"status": "created", "id": a.id}


@router.put("/api/admin/agents/{aid}")
async def up_agent(aid: str, a: AgentM):
    if a.id != aid:
        raise HTTPException(400)
    old = storage.get_agent(aid)
    d = a.model_dump()
    raw_key = d.pop("api_key", "")
    d["created_at"] = old.get("created_at", time.time()) if old else time.time()
    d["updated_at"] = time.time()
    if raw_key and raw_key != "***":
        d["encrypted_api_key"] = storage.encrypt_agent_key(raw_key)
    elif old and old.get("encrypted_api_key"):
        d["encrypted_api_key"] = old["encrypted_api_key"]
    storage.upsert_agent(d)
    storage.append_audit({"command": f"update agent: {aid}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "updated", "id": aid}


@router.delete("/api/admin/agents/{aid}")
async def del_agent(aid: str):
    storage.invalidate_agent_key_cache()
    if not storage.delete_agent(aid):
        raise HTTPException(404)
    storage.append_audit({"command": f"delete agent: {aid}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "deleted"}


@router.post("/api/admin/agents/{aid}/toggle")
async def toggle_agent(aid: str):
    storage.invalidate_agent_key_cache()
    a = storage.get_agent(aid)
    if not a:
        raise HTTPException(404)
    a["enabled"] = not a.get("enabled", True)
    storage.upsert_agent(a)
    return {"status": "toggled", "enabled": a["enabled"]}


@router.post("/api/admin/agents/{aid}/duplicate")
async def dup_agent(aid: str):
    a = storage.get_agent(aid)
    if not a:
        raise HTTPException(404)
    new = dict(a)
    new["id"] = f"{aid}-copy-{S.token_hex(3)}"
    new["name"] = f"{a.get('name', aid)} (copy)"
    new["enabled"] = False
    new.pop("encrypted_api_key", None)
    new["created_at"] = new["updated_at"] = time.time()
    storage.upsert_agent(new)
    return {"status": "created", "id": new["id"]}


@router.post("/api/admin/agents/{aid}/generate-key")
async def gen_agent_key(aid: str):
    a = storage.get_agent(aid)
    if not a:
        raise HTTPException(404)
    raw = S.token_urlsafe(32)
    a["encrypted_api_key"] = storage.encrypt_agent_key(raw)
    a["updated_at"] = time.time()
    storage.upsert_agent(a)
    return {"status": "ok", "api_key": raw, "warning": "Save this key now."}


@router.get("/api/admin/agents/{aid}/reveal-key")
async def reveal_agent_key(aid: str):
    """Reveal current API key (Fernet-decrypted)."""
    key = storage.decrypt_agent_key(aid)
    if key is None:
        return {"ok": False, "message": "No key set or decrypt failed"}
    return {"ok": True, "api_key": key}


@router.get("/api/admin/agents/export")
async def exp_agents():
    return [
        {k: v for k, v in a.items() if k != "encrypted_api_key"}
        | {"has_key": bool(a.get("encrypted_api_key"))}
        for a in storage.load_agents()
    ]


@router.post("/api/admin/agents/import")
async def imp_agents(req: Request):
    body = await req.json()
    items = body if isinstance(body, list) else [body]
    imported = []
    for it in items:
        if "id" not in it:
            continue
        it.setdefault("name", it["id"])
        it.setdefault("agent_type", "custom")
        it["created_at"] = it["updated_at"] = time.time()
        it.pop("encrypted_api_key", None)
        storage.upsert_agent(it)
        imported.append(it["id"])
    if imported:
        storage.append_audit({"command": f"import agents: {imported}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "imported", "count": len(imported), "ids": imported}


# ═══ Command Sets CRUD ═══

@router.get("/api/admin/command-sets")
async def list_sets():
    return storage.load_command_sets()


@router.post("/api/admin/command-sets")
async def cr_set(cs: CmdSetM):
    app_state.validate_id(cs.id, "command_set")
    if storage.get_command_set(cs.id):
        raise HTTPException(409)
    d = cs.model_dump()
    # Force deny sets to dark red
    if d["type"] == "deny":
        d["color"] = "#7f1d1d"
    d["created_at"] = d["updated_at"] = time.time()
    storage.upsert_command_set(d)
    return {"status": "created", "id": cs.id}


@router.put("/api/admin/command-sets/{sid}")
async def up_set(sid: str, cs: CmdSetM):
    if cs.id != sid:
        raise HTTPException(400)
    d = cs.model_dump()
    old = storage.get_command_set(sid)
    if d["type"] == "deny":
        d["color"] = "#7f1d1d"
    d["created_at"] = old.get("created_at", time.time()) if old else time.time()
    d["updated_at"] = time.time()
    storage.upsert_command_set(d)
    storage.append_audit({"command": f"update command_set: {sid}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "updated", "id": sid}


@router.delete("/api/admin/command-sets/{sid}")
async def del_set(sid: str):
    if not storage.delete_command_set(sid):
        raise HTTPException(404)
    # Remove from hosts
    hosts = storage.load_hosts()
    ch = False
    for h in hosts:
        if sid in h.get("command_sets", []):
            h["command_sets"].remove(sid)
            ch = True
    if ch:
        storage.save_hosts(hosts)
    # Remove from agents
    agents = storage.load_agents()
    ca = False
    for a in agents:
        if sid in a.get("command_sets", []):
            a["command_sets"].remove(sid)
            ca = True
    if ca:
        storage.save_agents(agents)
    storage.append_audit({"command": f"delete command_set: {sid}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "deleted"}


@router.post("/api/admin/command-sets/{sid}/toggle")
async def toggle_set(sid: str):
    cs = storage.get_command_set(sid)
    if not cs:
        raise HTTPException(404)
    cs["enabled"] = not cs.get("enabled", True)
    storage.upsert_command_set(cs)
    return {"status": "toggled", "enabled": cs["enabled"]}


@router.get("/api/admin/command-sets/{sid}/export")
async def exp_set(sid: str):
    cs = storage.get_command_set(sid)
    if not cs:
        raise HTTPException(404)
    return {k: v for k, v in cs.items() if k not in ("created_at", "updated_at")}


@router.post("/api/admin/command-sets/import")
async def imp_set(req: Request):
    body = await req.json()
    items = body if isinstance(body, list) else [body]
    imported = []
    for it in items:
        if "id" not in it or "commands" not in it:
            continue
        it.setdefault("name", it["id"])
        it.setdefault("type", "allow")
        it.setdefault("enabled", True)
        if it["type"] == "deny":
            it["color"] = "#7f1d1d"
        it["created_at"] = it["updated_at"] = time.time()
        storage.upsert_command_set(it)
        imported.append(it["id"])
    if imported:
        storage.append_audit({"command": f"import command_sets: {imported}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "imported", "count": len(imported), "ids": imported}


# ═══ Secrets ═══

@router.get("/api/admin/secrets")
async def list_secrets():
    return storage.export_secrets_meta()


@router.post("/api/admin/secrets")
async def cr_secret(s: SecretM):
    app_state.validate_id(s.id, "secret")
    if storage.get_secret(s.id):
        raise HTTPException(409)
    d = {"id": s.id, "name": s.name or s.id, "service": s.service, "description": s.description,
         "hosts": s.hosts, "created_at": time.time(), "updated_at": time.time()}
    if s.value:
        d["encrypted_value"] = storage._encrypt_value(s.value)
    storage.upsert_secret(d)
    return {"status": "created", "id": s.id}

@router.put("/api/admin/secrets/{sid}")
async def up_secret(sid: str, s: SecretM):
    if s.id != sid:
        raise HTTPException(400)
    old = storage.get_secret(sid)
    d = {"id": s.id, "name": s.name or s.id, "service": s.service, "description": s.description,
         "hosts": s.hosts, "created_at": old.get("created_at", time.time()) if old else time.time(),
         "updated_at": time.time()}
    if s.value and s.value != "***":
        d["encrypted_value"] = storage._encrypt_value(s.value)
    elif old and old.get("encrypted_value"):
        d["encrypted_value"] = old["encrypted_value"]
    storage.upsert_secret(d)
    return {"status": "updated", "id": sid}

@router.delete("/api/admin/secrets/{sid}")
async def del_secret(sid: str):
    if not storage.delete_secret(sid):
        raise HTTPException(404)
    return {"status": "deleted"}

@router.get("/api/admin/secrets/{sid}/verify")
async def verify_secret(sid: str):
    v = storage.decrypt_secret_value(sid)
    return {"ok": True, "length": len(v)} if v else {"ok": False, "message": "Cannot decrypt"}

@router.get("/api/admin/secrets/export")
async def exp_secrets():
    return storage.export_secrets_meta()

@router.post("/api/admin/secrets/import")
async def imp_secrets(req: Request):
    body = await req.json()
    items = body if isinstance(body, list) else [body]
    imp = []
    for it in items:
        if "id" not in it:
            continue
        d = {"id": it["id"], "name": it.get("name", it["id"]), "service": it.get("service", ""),
             "description": it.get("description", ""), "hosts": it.get("hosts", []),
             "created_at": time.time(), "updated_at": time.time()}
        if it.get("value"):
            d["encrypted_value"] = storage._encrypt_value(it["value"])
        storage.upsert_secret(d)
        imp.append(it["id"])
    if imp:
        storage.append_audit({"command": f"import secrets: {imp}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "imported", "count": len(imp), "ids": imp}


# ═══ Notifications ═══


@router.get("/api/admin/telegram")
async def get_tg():
    tg = storage.load_config().get("telegram", {})
    if tg.get("bot_token"):
        t = tg["bot_token"]
        tg["bot_token"] = t[:8] + "..." + t[-4:] if len(t) > 12 else "***"
    return tg

@router.put("/api/admin/telegram")
async def put_tg(tg: TgCfg):
    c = storage.load_config()
    old = c.get("telegram", {})
    d = tg.model_dump()
    if "..." in d.get("bot_token", "") or d.get("bot_token") == "***":
        d["bot_token"] = old.get("bot_token", "")
    c["telegram"] = d
    storage.save_config(c)
    return {"status": "updated"}

@router.post("/api/admin/telegram/test")
async def test_tg(token: str = "", chat_id: str = ""):
    return await notifications.send_telegram("MCP Gate: test", token=token or None, chat_id=chat_id or None)

@router.get("/api/admin/smtp")
async def get_smtp():
    s = storage.load_config().get("smtp", {})
    if s.get("password"):
        s["password"] = "***"
    return s

@router.put("/api/admin/smtp")
async def put_smtp(smtp: SmtpCfg):
    c = storage.load_config()
    old = c.get("smtp", {})
    d = smtp.model_dump()
    if d.get("password") == "***":
        d["password"] = old.get("password", "")
    c["smtp"] = d
    storage.save_config(c)
    return {"status": "updated"}

@router.post("/api/admin/smtp/test")
async def test_smtp():
    return await notifications.send_smtp("MCP Gate: test", "Test notification.")

@router.get("/api/admin/notification-templates")
async def get_nt():
    return storage.load_config().get("notification_templates", storage._default_templates())

@router.put("/api/admin/notification-templates")
async def put_nt(req: Request):
    c = storage.load_config()
    c["notification_templates"] = await req.json()
    storage.save_config(c)
    return {"status": "updated"}


# ═══ Settings ═══


@router.post("/api/admin/generate-htpasswd")
async def gen_ht(req: PwReq):
    import subprocess
    try:
        r = subprocess.run(["openssl", "passwd", "-apr1", req.password],
                           capture_output=True, text=True, timeout=5)
        return {"hash": f"admin:{r.stdout.strip()}"} if r.returncode == 0 else {"error": r.stderr.strip()}
    except Exception as x:
        return {"error": str(x)}

@router.post("/api/admin/test-paths")
async def test_paths(req: Request):
    body = await req.json()
    paths = body.get("paths", {})
    results = {}
    for key, path in paths.items():
        if not path:
            results[key] = None
            continue
        if path.startswith("/data"):
            results[key] = os.path.exists(path)
        elif path.startswith("/"):
            results[key] = bool(re.match(r"^/[\w./_-]+$", path))
        else:
            results[key] = False
    return {"results": results}


# ═══ Audit ═══

@router.get("/api/admin/audit-settings")
async def get_as():
    c = storage.load_config()
    sz = storage.AUDIT_FILE.stat().st_size if storage.AUDIT_FILE.exists() else 0
    cnt = sum(1 for l in storage.AUDIT_FILE.read_text().strip().split("\n")
              if l.strip()) if storage.AUDIT_FILE.exists() else 0
    return {"retention_days": c.get("audit_retention_days", 90), "file_size": sz, "entry_count": cnt}


@router.put("/api/admin/audit-settings")
async def put_as(b: AuditS):
    c = storage.load_config()
    c["audit_retention_days"] = max(1, b.retention_days)
    storage.save_config(c)
    return {"status": "updated"}

@router.post("/api/admin/audit/clear")
async def clr_audit():
    return {"status": "cleared", "deleted": storage.clear_audit()}

@router.post("/api/admin/audit/apply-retention")
async def apply_ret():
    c = storage.load_config()
    return {"status": "applied", "removed": storage.apply_retention(c.get("audit_retention_days", 90))}

@router.get("/api/admin/metrics")
async def metrics():
    now = time.time()
    d1, d7 = now - 86400, now - 604800
    m = {"24h": {"ok": 0, "blocked": 0, "error": 0, "pending": 0, "total": 0},
         "7d": {"ok": 0, "blocked": 0, "error": 0, "pending": 0, "total": 0}}
    for e in storage.load_audit(limit=5000):
        t, s = e.get("ts", 0), e.get("status", "")
        if t >= d7:
            m["7d"]["total"] += 1
            m["7d"][s] = m["7d"].get(s, 0) + 1
        if t >= d1:
            m["24h"]["total"] += 1
            m["24h"][s] = m["24h"].get(s, 0) + 1
    return m

@router.get("/api/admin/audit")
async def admin_audit(limit: int = 200, host_id: str = "", status: str = "",
                      source: str = "", group: str = "", ts_from: float = 0, ts_to: float = 0):
    return storage.load_audit(limit=limit, host_id=host_id, status=status,
                              source=source, group=group, ts_from=ts_from, ts_to=ts_to)

@router.get("/api/admin/audit/export")
async def audit_exp(fmt: str = "json"):
    entries = storage.load_audit_all()
    if fmt == "csv":
        o = io.StringIO()
        if entries:
            w = csv.DictWriter(o, fieldnames=["ts", "host_id", "command", "source", "status",
                                               "reason", "error", "duration_ms", "agent_id"],
                               extrasaction="ignore")
            w.writeheader()
            for e in entries:
                w.writerow(e)
        return StreamingResponse(iter([o.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=mcp_audit.csv"})
    return StreamingResponse(iter([J.dumps(entries, ensure_ascii=False, indent=2)]),
                             media_type="application/json",
                             headers={"Content-Disposition": "attachment; filename=mcp_audit.json"})


# ═══ Backup ═══

@router.get("/api/admin/backup")
async def backup():
    return StreamingResponse(
        iter([J.dumps(storage.export_backup(), ensure_ascii=False, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=mcp_gate_backup.json"})

@router.post("/api/admin/restore")
async def restore(req: Request):
    return {"status": "restored", **storage.import_backup(await req.json())}




# ═══ Themes ═══

@router.get("/api/admin/themes")
async def get_themes():
    return storage.load_themes()

@router.post("/api/admin/themes")
async def create_theme(req: Request):
    body = await req.json()
    tid = body.get("id", "").strip().lower().replace(" ", "-")
    if not tid or not re.match(r"^[a-z0-9][a-z0-9_-]{0,63}$", tid):
        raise HTTPException(400, "Invalid theme ID")
    if tid.startswith("sys-"):
        raise HTTPException(400, "Cannot use sys- prefix for user themes")
    if storage.get_theme(tid):
        raise HTTPException(409, "Theme ID already exists")
    theme = {"id": tid, "name": body.get("name", tid), "system": False}
    for k in storage._THEME_FIELDS:
        if k in body:
            theme[k] = body[k]
    storage.upsert_theme(theme)
    storage.append_audit({"command": f"create theme: {tid}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "created", "id": tid}

@router.put("/api/admin/themes/{tid}")
async def update_theme(tid: str, req: Request):
    theme = storage.get_theme(tid)
    if not theme:
        raise HTTPException(404)
    body = await req.json()
    if "name" in body and not theme.get("system"):
        theme["name"] = body["name"]
    for k in storage._THEME_FIELDS:
        if k in body:
            theme[k] = body[k]
    storage.upsert_theme(theme)
    return {"status": "updated"}

@router.delete("/api/admin/themes/{tid}")
async def del_theme(tid: str):
    theme = storage.get_theme(tid)
    if not theme:
        raise HTTPException(404)
    if theme.get("system"):
        raise HTTPException(403, "Cannot delete system theme")
    storage.delete_theme(tid)
    storage.append_audit({"command": f"delete theme: {tid}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "deleted"}

@router.post("/api/admin/themes/{tid}/duplicate")
async def dup_theme(tid: str, req: Request):
    src = storage.get_theme(tid)
    if not src:
        raise HTTPException(404)
    body = await req.json() if req.headers.get("content-type","").startswith("application/json") else {}
    base_id = tid.replace("sys-", "") + "-copy"
    new_id = base_id
    n = 1
    while storage.get_theme(new_id):
        n += 1
        new_id = f"{base_id}-{n}"
    dup = dict(src)
    dup["id"] = new_id
    dup["name"] = body.get("name", src["name"].replace("[Sys] ", "") + " (copy)")
    dup["system"] = False
    storage.upsert_theme(dup)
    storage.append_audit({"command": f"duplicate theme: {tid} → {new_id}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "created", "id": new_id, "theme": dup}

@router.post("/api/admin/themes/reset-system")
async def reset_sys_themes():
    count = storage.reset_system_themes()
    return {"status": "reset", "count": count}

@router.get("/api/admin/themes/export")
async def export_themes(ids: str = ""):
    id_list = [x.strip() for x in ids.split(",") if x.strip()] if ids else None
    data = storage.export_themes(id_list)
    return StreamingResponse(
        iter([J.dumps(data, ensure_ascii=False, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=mcp_gate_themes.json"})

@router.post("/api/admin/themes/import")
async def import_themes(req: Request):
    body = await req.json()
    items = body if isinstance(body, list) else [body]
    imported = storage.import_themes(items)
    if imported:
        storage.append_audit({"command": f"import themes: {imported}", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "imported", "count": len(imported), "ids": imported}


# ═══ Appearance ═══

@router.get("/api/admin/appearance")
async def get_appear():
    return storage.load_config().get("appearance", storage._default_appearance())

@router.put("/api/admin/appearance")
async def put_appear(req: Request):
    c = storage.load_config()
    c["appearance"] = await req.json()
    storage.save_config(c)
    return {"status": "updated"}

@router.post("/api/admin/upload")
async def upload(file: UploadFile = File(...)):
    ct = await file.read()
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else "bin"
    if ext not in {"png", "jpg", "jpeg", "gif", "webp", "svg", "ico"}:
        raise HTTPException(400)
    if len(ct) > 5 * 1024 * 1024:
        raise HTTPException(400, "Max 5MB")
    fn = f"{hashlib.md5(ct).hexdigest()[:10]}.{ext}"
    (storage.ASSETS_DIR / fn).write_bytes(ct)
    return {"url": f"/assets/{fn}", "filename": fn}

@router.get("/assets/{fn}")
async def asset(fn: str):
    fp = storage.ASSETS_DIR / fn
    if not fp.exists():
        raise HTTPException(404)
    mt = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif",
          "webp": "image/webp", "svg": "image/svg+xml", "ico": "image/x-icon"}
    return FileResponse(fp, media_type=mt.get(fn.rsplit(".", 1)[-1], "application/octet-stream"),
                        headers={"Cache-Control": "public, max-age=86400"})


# ═══ i18n + Instance ═══

@router.get("/api/i18n/{lang}")
async def get_i18n(lang: str):
    return storage.load_i18n(lang)

@router.get("/api/i18n")
async def list_i18n():
    return {"languages": storage.list_languages(),
            "current": storage.load_config().get("instance", {}).get("language", "ru")}

@router.get("/api/admin/instance")
async def get_instance():
    return storage.load_config().get("instance", storage._default_instance())

@router.put("/api/admin/instance")
async def put_instance(req: Request):
    c = storage.load_config()
    c["instance"] = await req.json()
    storage.save_config(c)
    return {"status": "updated"}


# ═══ Bootstrap + SSH ═══

@router.post("/api/admin/ssh/generate")
async def gen_key():
    _, pub = ssh_client.generate_keypair()
    return {"public_key": pub}

@router.get("/api/admin/ssh/pubkey")
async def get_pubkey():
    pub = ssh_client.get_public_key()
    if not pub:
        raise HTTPException(404)
    return {"public_key": pub}


@router.post("/api/admin/bootstrap")
async def bootstrap(req: BootReq):
    c = storage.load_config()
    if c.get("bootstrap_done"):
        raise HTTPException(409)
    r = {}
    if req.generate_key:
        _, pub = ssh_client.generate_keypair()
        r["public_key"] = pub
    raw = S.token_urlsafe(32)
    c["mcp_api_key_hash"] = bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()
    c["bootstrap_done"] = True
    storage.save_config(c)
    r.update(api_key=raw, status="done", warning="Save the API key now.")
    return r

