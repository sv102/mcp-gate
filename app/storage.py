# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""
storage.py — Data layer for MCP Gate v0.1.0
Handles hosts, command sets (allow/deny), secrets, agents, audit, config.
"""

import json, os, re, time, uuid, hashlib
import contextvars, copy
from pathlib import Path
from typing import Optional

import yaml

# ═══ Paths ═══
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
HOSTS_FILE = DATA_DIR / "hosts.yaml"
CONFIG_FILE = DATA_DIR / "config.yaml"
AUDIT_FILE = DATA_DIR / "audit.jsonl"
AUDIT_ARCHIVE = DATA_DIR / "audit_archive.jsonl"
QUEUE_FILE = DATA_DIR / "approval_queue.json"
COMMAND_SETS_FILE = DATA_DIR / "command_sets.yaml"
SECRETS_FILE = DATA_DIR / "secrets.yaml"
AGENTS_FILE = DATA_DIR / "agents.yaml"
SSH_KEYS_DIR = DATA_DIR / "ssh_keys"
SECRETS_KEY_FILE = SSH_KEYS_DIR / "secrets.key"
ASSETS_DIR = DATA_DIR / "assets"
I18N_DIR = Path(os.environ.get("I18N_DIR", "/app/i18n"))
MAX_AUDIT_ENTRIES = 10_000
AUDIT_HOOKS: list = []  # SV_MCPGATE_020: callables(entry) after each audit write
client_ip_var = contextvars.ContextVar("client_ip", default="")  # set per request by events.middleware

# Agent key cache: {encrypted_key: agent_id} — avoids O(n) Fernet per request
_agent_key_cache: dict[str, str] = {}

# Command set cache: {set_id: (command_set_dict, expires_ts)}
# Reduces YAML reads on the hot path (check_command_authorized).
_cs_cache: dict[str, tuple] = {}
_CS_CACHE_TTL = 5.0  # seconds

# ═══ Agent type registry ═══
AGENT_TYPES = {
    "claude": {"name": "Claude (Anthropic)", "icon": "🟠", "color": "#d97706",
               "connect_hint": "Claude.ai → Settings → Integrations → Add MCP Server → URL: {gate_url}/sse"},
    "chatgpt": {"name": "ChatGPT (OpenAI)", "icon": "🟢", "color": "#10a37f",
                "connect_hint": "Custom GPT → Configure → Actions → Import URL: {gate_url}/openapi.json"},
    "gemini": {"name": "Gemini (Google)", "icon": "🔵", "color": "#4285f4",
               "connect_hint": "Gemini Extensions → MCP → Server URL: {gate_url}/sse"},
    "cursor": {"name": "Cursor", "icon": "⚡", "color": "#7c3aed",
               "connect_hint": ".cursor/mcp.json → {\"mcpServers\":{\"gate\":{\"url\":\"{gate_url}/sse\"}}}"},
    "windsurf": {"name": "Windsurf (Codeium)", "icon": "🏄", "color": "#06b6d4",
                 "connect_hint": "Settings → MCP → Add Server → URL: {gate_url}/sse"},
    "continue": {"name": "Continue.dev", "icon": "▶️", "color": "#f59e0b",
                 "connect_hint": "config.json → mcpServers → url: {gate_url}/sse"},
    "cline": {"name": "Cline (VS Code)", "icon": "🔧", "color": "#8b5cf6",
              "connect_hint": "Cline Settings → MCP Servers → Add → URL: {gate_url}/sse"},
    "openwebui": {"name": "Open WebUI", "icon": "🌐", "color": "#3b82f6",
                  "connect_hint": "Admin → Functions → MCP Bridge → API: {gate_url}/api/exec"},
    "custom": {"name": "Custom Agent", "icon": "🤖", "color": "#6366f1",
               "connect_hint": "POST {gate_url}/api/exec with header X-API-Key"},
}


def ensure_dirs():
    for d in (DATA_DIR, SSH_KEYS_DIR, ASSETS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(SSH_KEYS_DIR, 0o700)
    _ensure_audit_schema()
    n = migrate_agent_keys()  # SV_MCPGATE_020
    if n:
        print(f"mcp-gate: {n} agent key(s) migrated to HMAC", flush=True)


# mtime-keyed cache for config/registry YAML. Reads compare st_mtime; writes go
# through _atomic_write which pops the entry, so the cache is correct even when two
# writes land within one mtime tick. Cuts repeated YAML parsing on hot paths
# (auth middleware, /health, per-request agent-key + command authorization).
_yaml_cache: dict[str, tuple] = {}


def _load_yaml_file(path: "Path"):
    """Parse a YAML file through the mtime cache. Returns parsed object or None."""
    key = str(path)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        _yaml_cache.pop(key, None)
        return None
    cached = _yaml_cache.get(key)
    if cached and cached[0] == mtime:
        return cached[1]
    data = yaml.safe_load(path.read_text())
    _yaml_cache[key] = (mtime, data)
    return data


def _atomic_write(path: Path, content: str):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    _yaml_cache.pop(str(path), None)  # invalidate cache on write


def _yaml_dump(data):
    return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ═══ Fernet (shared) ═══

_fernet_cache: tuple = (0.0, None)  # (mtime, Fernet) — avoids re-reading key file


def _get_fernet():
    global _fernet_cache
    from cryptography.fernet import Fernet
    env = os.environ.get("MCPGATE_MASTER_KEY", "").strip()  # SV_MCPGATE_020: master key outside the data volume
    if env:
        if _fernet_cache[0] != -1.0:
            _fernet_cache = (-1.0, Fernet(env.encode()))
        return _fernet_cache[1]
    if not SECRETS_KEY_FILE.exists():
        SECRETS_KEY_FILE.write_bytes(Fernet.generate_key())
        os.chmod(SECRETS_KEY_FILE, 0o600)
    mtime = SECRETS_KEY_FILE.stat().st_mtime
    if _fernet_cache[1] is not None and _fernet_cache[0] == mtime:
        return _fernet_cache[1]
    fernet = Fernet(SECRETS_KEY_FILE.read_bytes().strip())
    _fernet_cache = (mtime, fernet)
    return fernet


def _encrypt_value(v: str) -> str:
    return _get_fernet().encrypt(v.encode()).decode()


def _decrypt_value(e: str) -> str:
    return _get_fernet().decrypt(e.encode()).decode()


# ═══ Config ═══

def _default_appearance():
    return {"accent_color": "#6366f1", "bg_color": "#0f1117", "card_bg": "#1a1d27",
            "nav_bg": "#1a1d27", "text_color": "#e0e0e0", "glass_blur": 0, "panel_opacity": 1.0,
            "bg_image": "/static/background/bg-default.jpg", "btn_primary": "#4f52b8", "btn_success": "#1a8a47",
            "btn_danger": "#b83a3a", "btn_info": "#0891a2", "btn_warning": "#b47a10"}


def _default_instance():
    return {"app_url": "", "language": "ru", "ping_interval": 60, "audit_max_entries": 10000,
            "traefik_config_path": "", "ssh_key_path": "/data/ssh_keys/mcp_ed25519",
            "compose_path": "", "data_volume_path": "", "auth_type": "basic"}


def _default_templates():
    return {"blocked": "🚫 Blocked: {command} on {host}", "approved": "✅ Approved: {command}",
            "error": "❌ Error: {command} on {host}", "pending": "⏳ Pending: {command}"}


# ═══ Themes ═══

def _default_system_themes():
    """Factory system themes — cannot be deleted, can be reset."""
    return [
        {"id": "sys-standard", "name": "[Sys] Standard", "system": True,
         "accent_color": "#6366f1", "bg_color": "#0f1117", "card_bg": "#1a1d27",
         "nav_bg": "#1a1d27", "text_color": "#e0e0e0", "glass_blur": 0, "panel_opacity": 1.0,
         "bg_image": "", "btn_primary": "#4f52b8", "btn_success": "#1a8a47",
         "btn_danger": "#b83a3a", "btn_info": "#0891a2", "btn_warning": "#b47a10"},
        {"id": "sys-sv-projekt", "name": "[Sys] SV-Projekt", "system": True,
         "accent_color": "#0e3e5c", "bg_color": "#0a1929", "card_bg": "#0f2233",
         "nav_bg": "#0c1e30", "text_color": "#c8d6e0", "glass_blur": 0, "panel_opacity": 1.0,
         "bg_image": "", "btn_primary": "#0e3e5c", "btn_success": "#1a6a3a",
         "btn_danger": "#8b3030", "btn_info": "#0e5e6c", "btn_warning": "#8a6a10"},
        {"id": "sys-glass", "name": "[Sys] Glass", "system": True,
         "accent_color": "#818cf8", "bg_color": "#0f1117", "card_bg": "rgba(26,29,39,0.7)",
         "nav_bg": "rgba(26,29,39,0.6)", "text_color": "#e0e0e0", "glass_blur": 12, "panel_opacity": 0.85,
         "bg_image": "/static/background/bg-default.jpg", "btn_primary": "#5558c0", "btn_success": "#1a7a42",
         "btn_danger": "#a03838", "btn_info": "#0880a0", "btn_warning": "#9a7010"},
        {"id": "sys-emerald", "name": "[Sys] Emerald", "system": True,
         "accent_color": "#22c55e", "bg_color": "#0f1a0f", "card_bg": "#1a2d1a",
         "nav_bg": "#1a2d1a", "text_color": "#d0e8d0", "glass_blur": 0, "panel_opacity": 1.0,
         "bg_image": "", "btn_primary": "#1a8a47", "btn_success": "#1a8a47",
         "btn_danger": "#8b3030", "btn_info": "#0e6e5c", "btn_warning": "#7a7a10"},
        {"id": "sys-cyberpunk", "name": "[Sys] Cyberpunk", "system": True,
         "accent_color": "#ec4899", "bg_color": "#0f0618", "card_bg": "#1a0d28",
         "nav_bg": "#1a0d28", "text_color": "#e0d0f0", "glass_blur": 0, "panel_opacity": 1.0,
         "bg_image": "", "btn_primary": "#b03878", "btn_success": "#1a7a47",
         "btn_danger": "#a02040", "btn_info": "#6030b0", "btn_warning": "#a06020"},
    ]

_THEME_FIELDS = ["accent_color", "bg_color", "card_bg", "nav_bg", "text_color",
                  "glass_blur", "panel_opacity", "bg_image",
                  "btn_primary", "btn_success", "btn_danger", "btn_info", "btn_warning"]


def load_themes():
    cfg = load_config()
    themes = cfg.get("themes")
    if not themes:
        themes = _default_system_themes()
        cfg["themes"] = themes
        save_config(cfg)
    return themes


def save_themes(themes):
    cfg = load_config()
    cfg["themes"] = themes
    save_config(cfg)


def get_theme(theme_id):
    for t in load_themes():
        if t["id"] == theme_id:
            return t
    return None


def upsert_theme(theme):
    themes = load_themes()
    for i, t in enumerate(themes):
        if t["id"] == theme["id"]:
            themes[i] = theme
            save_themes(themes)
            return "updated"
    themes.append(theme)
    save_themes(themes)
    return "created"


def delete_theme(theme_id):
    themes = load_themes()
    t = next((x for x in themes if x["id"] == theme_id), None)
    if not t:
        return False
    if t.get("system"):
        return False
    themes = [x for x in themes if x["id"] != theme_id]
    save_themes(themes)
    return True


def reset_system_themes():
    """Reset all system themes to factory defaults."""
    themes = load_themes()
    factory = {t["id"]: t for t in _default_system_themes()}
    for i, t in enumerate(themes):
        if t.get("system") and t["id"] in factory:
            themes[i] = factory[t["id"]]
    save_themes(themes)
    return len(factory)


def export_themes(ids=None):
    """Export themes with optional base64-encoded custom backgrounds."""
    import base64 as b64
    themes = load_themes()
    if ids:
        themes = [t for t in themes if t["id"] in ids]
    result = []
    for t in themes:
        te = dict(t)
        bg = te.get("bg_image", "")
        if bg.startswith("/assets/"):
            fn = bg.rsplit("/", 1)[-1]
            fp = ASSETS_DIR / fn
            if fp.exists():
                te["bg_image_data"] = b64.b64encode(fp.read_bytes()).decode()
                te["bg_image_ext"] = fn.rsplit(".", 1)[-1] if "." in fn else "jpg"
        result.append(te)
    return result


def import_themes(data):
    """Import themes, decode embedded bg images."""
    import base64 as b64
    themes = load_themes()
    existing_ids = {t["id"] for t in themes}
    imported = []
    for te in data:
        if not te.get("id") or not te.get("name"):
            continue
        # Decode embedded background
        if te.get("bg_image_data"):
            try:
                raw = b64.b64decode(te["bg_image_data"])
                ext = te.get("bg_image_ext", "jpg")
                fn = f"{hashlib.md5(raw).hexdigest()[:10]}.{ext}"
                (ASSETS_DIR / fn).write_bytes(raw)
                te["bg_image"] = f"/assets/{fn}"
            except Exception:
                pass
            te.pop("bg_image_data", None)
            te.pop("bg_image_ext", None)
        # Prevent overwriting system themes
        if te["id"] in existing_ids:
            existing = next(t for t in themes if t["id"] == te["id"])
            if existing.get("system"):
                continue
            for k, v in te.items():
                existing[k] = v
        else:
            te["system"] = False
            themes.append(te)
        imported.append(te["id"])
    save_themes(themes)
    return imported



def load_config() -> dict:
    if not CONFIG_FILE.exists():
        cfg = {"appearance": _default_appearance(), "instance": _default_instance(),
               "notification_templates": _default_templates()}
        save_config(cfg)
        return cfg
    cfg = _load_yaml_file(CONFIG_FILE) or {}
    cfg = copy.deepcopy(cfg)  # SV_MCPGATE_020: nested too (masking the Telegram token in GET used to corrupt the cache)
    cfg.setdefault("appearance", _default_appearance())
    cfg.setdefault("instance", _default_instance())
    return cfg


def save_config(cfg: dict):
    _atomic_write(CONFIG_FILE, _yaml_dump(cfg))


def load_i18n(lang: str) -> dict:
    f = I18N_DIR / f"{lang}.json"
    if not f.exists():
        f = I18N_DIR / "en.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except:
        return {}


def list_languages() -> list[str]:
    if not I18N_DIR.exists():
        return ["en"]
    return sorted(f.stem for f in I18N_DIR.glob("*.json"))


# ═══ Hosts ═══

def load_hosts() -> list[dict]:
    d = _load_yaml_file(HOSTS_FILE)
    if isinstance(d, list):
        return list(d)
    return list(d.get("hosts", [])) if isinstance(d, dict) else []


def save_hosts(h: list[dict]):
    _atomic_write(HOSTS_FILE, _yaml_dump({"hosts": h}))


def get_host(hid: str) -> Optional[dict]:
    return next((h for h in load_hosts() if h.get("id") == hid), None)


def upsert_host(host: dict):
    hosts = load_hosts()
    for i, h in enumerate(hosts):
        if h["id"] == host["id"]:
            hosts[i] = host
            save_hosts(hosts)
            return
    hosts.append(host)
    save_hosts(hosts)


def delete_host(hid: str) -> bool:
    hosts = load_hosts()
    n = [h for h in hosts if h.get("id") != hid]
    if len(n) == len(hosts):
        return False
    save_hosts(n)
    return True


# ═══ Agents ═══

def load_agents() -> list[dict]:
    d = _load_yaml_file(AGENTS_FILE)
    if isinstance(d, list):
        return list(d)
    return list(d.get("agents", [])) if isinstance(d, dict) else []


def save_agents(a: list[dict]):
    _atomic_write(AGENTS_FILE, _yaml_dump({"agents": a}))


def get_agent(aid: str) -> Optional[dict]:
    return next((a for a in load_agents() if a.get("id") == aid), None)


def agent_active(a: Optional[dict]) -> bool:  # SV_MCPGATE_OPS
    """Enabled and, for timed agents, inside a live grant. Fail closed."""
    if not a or not a.get("enabled", True):
        return False
    if int(a.get("auto_off_min") or 0) <= 0:  # permanent agent: grant fields ignored
        return True
    u = a.get("enabled_until") or 0
    return bool(u) and time.time() <= u


def upsert_agent(agent: dict):
    agents = load_agents()
    for i, a in enumerate(agents):
        if a["id"] == agent["id"]:
            agents[i] = agent
            save_agents(agents)
            return
    agents.append(agent)
    save_agents(agents)


def delete_agent(aid: str) -> bool:
    agents = load_agents()
    n = [a for a in agents if a.get("id") != aid]
    if len(n) == len(agents):
        return False
    save_agents(n)
    return True


# ═══ Agent keys (SV_MCPGATE_020) ═══
# Stored as HMAC-SHA256(pepper, key): constant-time lookup, nothing reversible on disk; a key is shown once,
# when issued. Pepper: MCPGATE_KEY_PEPPER (.env) or data/key_pepper (generated, 0600). Static keys may be bound
# to source IPs (allow_ip) and expire (key_ttl_days); last use is kept outside agents.yaml.
import hmac as _hmac, ipaddress as _ipa, secrets as _secrets

_KEY_FIELDS = ("encrypted_api_key", "key_hash", "key_hint", "key_created_at", "key_expires_at")
PEPPER_FILE = DATA_DIR / "key_pepper"
_last_use: dict[str, tuple] = {}


def _pepper() -> bytes:
    v = os.environ.get("MCPGATE_KEY_PEPPER", "").strip()
    if v:
        return v.encode()
    if not PEPPER_FILE.exists():
        PEPPER_FILE.write_text(_secrets.token_urlsafe(48))
        os.chmod(PEPPER_FILE, 0o600)
    return PEPPER_FILE.read_text().strip().encode()


def key_hash(raw: str) -> str:
    return _hmac.new(_pepper(), raw.encode(), hashlib.sha256).hexdigest()


def new_agent_key() -> str:
    return "mg_" + _secrets.token_urlsafe(32)


def set_agent_key(a: dict, raw: str) -> dict:
    a.pop("encrypted_api_key", None)
    ttl = int(a.get("key_ttl_days") or 0)
    a.update(key_hash=key_hash(raw), key_hint=raw[-4:], key_created_at=time.time(),
             key_expires_at=time.time() + ttl * 86400 if ttl > 0 else 0)
    return a


def _key_owner(provided: str) -> Optional[dict]:
    if not provided:
        return None
    h, found = key_hash(provided), None
    for a in load_agents():                      # no early exit: time does not depend on position
        if a.get("key_hash") and _hmac.compare_digest(a["key_hash"], h):
            found = a
    return found


def agent_refusal(a: Optional[dict]) -> str:
    """Why a static key of this agent is refused now ('' = accepted)."""
    if not agent_active(a):
        return "disabled or grant expired"
    if a.get("key_expires_at") and time.time() > a["key_expires_at"]:
        return "key expired"
    nets, ip = a.get("allow_ip") or [], client_ip_var.get()
    if nets:
        try:
            if not any(_ipa.ip_address(ip) in _ipa.ip_network(n, strict=False) for n in nets):
                return f"IP {ip} not allowed"
        except ValueError:
            return f"IP {ip or '?'} not allowed"
    return ""


def verify_agent_key(provided_key: str) -> Optional[str]:
    a = _key_owner(provided_key)
    if a and not agent_refusal(a):
        note_key_use(a["id"])
        return a["id"]
    return None


def agent_id_for_key(provided_key: str) -> Optional[str]:
    """Agent id for a key regardless of state (to explain a refusal)."""
    a = _key_owner(provided_key)
    return a["id"] if a else None


def invalidate_agent_key_cache():
    """No key cache any more (HMAC lookup is cheap); kept for callers."""
    return None


def note_key_use(aid: str):
    now, ip = time.time(), client_ip_var.get()
    p = _last_use.get(aid)
    if p and now - p[0] < 60 and p[1] == ip:
        return
    _last_use[aid] = (now, ip)
    with _audit_db() as db:
        db.execute("CREATE TABLE IF NOT EXISTS key_use(agent TEXT PRIMARY KEY, ts REAL, ip TEXT)")
        db.execute("INSERT INTO key_use VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET ts=excluded.ts, ip=excluded.ip",
                   (aid, now, ip))
        db.commit()


def key_uses() -> dict:
    try:
        with _audit_db() as db:
            return {r[0]: {"ts": r[1], "ip": r[2]} for r in db.execute("SELECT agent, ts, ip FROM key_use")}
    except sqlite3.OperationalError:
        return {}


def migrate_agent_keys() -> int:
    """One-time: Fernet-encrypted keys -> HMAC. Existing clients keep working."""
    agents, n = load_agents(), 0
    for a in agents:
        if a.get("encrypted_api_key") and not a.get("key_hash"):
            try:
                raw = _decrypt_value(a["encrypted_api_key"])
            except Exception:
                continue
            set_agent_key(a, raw)
            a.update(key_created_at=a.get("updated_at") or time.time(), key_expires_at=0)
            n += 1
    if n:
        save_agents(agents)
    return n


def public_agent(a: dict) -> dict:  # key material (even its hash) never leaves the server
    d = {k: v for k, v in a.items() if k not in ("encrypted_api_key", "key_hash")}
    d["has_key"] = bool(a.get("key_hash") or a.get("encrypted_api_key"))
    return d

def get_agent_types() -> dict:
    return AGENT_TYPES


# ═══ Command Sets ═══

def load_command_sets() -> list[dict]:
    d = _load_yaml_file(COMMAND_SETS_FILE)
    if isinstance(d, list):
        return list(d)
    return list(d.get("sets", [])) if isinstance(d, dict) else []


def save_command_sets(s: list[dict]):
    _atomic_write(COMMAND_SETS_FILE, _yaml_dump({"sets": s}))


def get_command_set(sid: str) -> Optional[dict]:
    now = time.time()
    cached = _cs_cache.get(sid)
    if cached and cached[1] > now:
        return cached[0]
    found = next((s for s in load_command_sets() if s.get("id") == sid), None)
    _cs_cache[sid] = (found, now + _CS_CACHE_TTL)
    return found


def upsert_command_set(cs: dict):
    sets = load_command_sets()
    for i, s in enumerate(sets):
        if s["id"] == cs["id"]:
            sets[i] = cs
            save_command_sets(sets)
            _cs_cache.pop(cs["id"], None)
            return
    sets.append(cs)
    save_command_sets(sets)
    _cs_cache.pop(cs["id"], None)


def delete_command_set(sid: str) -> bool:
    sets = load_command_sets()
    n = [s for s in sets if s.get("id") != sid]
    if len(n) == len(sets):
        return False
    save_command_sets(n)
    _cs_cache.pop(sid, None)
    return True


def _collect_commands_from_sets(set_ids: list[str], set_type: str) -> set:
    """Collect command strings from sets of given type (allow/deny), only enabled."""
    cmds = set()
    for sid in set_ids:
        cs = get_command_set(sid)
        if not cs:
            continue
        if not cs.get("enabled", True):
            continue
        if cs.get("type", "allow") != set_type:
            continue
        for cmd in cs.get("commands", []):
            cmds.add(cmd["cmd"])
    return cmds


def get_effective_whitelist(host: dict) -> list[dict]:
    """Get merged whitelist for host (own + from allow sets). Used for display."""
    result = list(host.get("whitelist", []))
    seen = {w["cmd"] for w in result}
    for sid in host.get("command_sets", []):
        cs = get_command_set(sid)
        if not cs or not cs.get("enabled", True):
            continue
        if cs.get("type", "allow") != "allow":
            continue
        for cmd in cs.get("commands", []):
            if cmd["cmd"] not in seen:
                e = dict(cmd)
                e["_from_set"] = sid
                result.append(e)
                seen.add(cmd["cmd"])
    return result


def get_effective_deny(host: dict) -> set:
    """Get merged deny commands for host."""
    return _collect_commands_from_sets(host.get("command_sets", []), "deny")


def check_command_authorized(host: dict, agent: Optional[dict], cmd: str) -> tuple[bool, str]:
    """
    Check if command is authorized given host + agent context.
    Returns (allowed: bool, reason: str).

    Logic:
    1. host_allow = own whitelist + allow-sets of host
    2. host_deny  = deny-sets of host
    3. If agent has allow-sets: agent_allow = allow-sets of agent → intersect with host_allow
    4. agent_deny = deny-sets of agent
    5. final = effective_allow - all_deny
    """
    # Host allow: own whitelist + allow command sets
    host_allow_cmds = {w["cmd"] for w in host.get("whitelist", [])}
    host_allow_cmds |= _collect_commands_from_sets(host.get("command_sets", []), "allow")

    if cmd not in host_allow_cmds:
        return False, "not in host whitelist"

    # Host deny
    host_deny_cmds = _collect_commands_from_sets(host.get("command_sets", []), "deny")
    if cmd in host_deny_cmds:
        return False, "blocked by host deny list"

    # Agent restrictions
    if agent:
        # Agent deny (highest priority)
        agent_deny = _collect_commands_from_sets(agent.get("command_sets", []), "deny")
        if cmd in agent_deny:
            return False, "blocked by agent deny list"

        # Agent allow (intersection)
        agent_allow_sets = [sid for sid in agent.get("command_sets", [])
                           if (cs := get_command_set(sid)) and cs.get("enabled", True)
                           and cs.get("type", "allow") == "allow"]
        if agent_allow_sets:
            agent_allow_cmds = _collect_commands_from_sets(agent.get("command_sets", []), "allow")
            if cmd not in agent_allow_cmds:
                return False, "not in agent allow list (intersection)"

    return True, "ok"


def find_whitelist_entry(host: dict, cmd: str) -> Optional[dict]:
    """Find the whitelist entry for exact command match (for params, approval mode etc)."""
    for w in get_effective_whitelist(host):
        if w["cmd"] == cmd:
            return w
    return None


# ═══ Secrets Vault ═══

def load_secrets() -> list[dict]:
    d = _load_yaml_file(SECRETS_FILE)
    if isinstance(d, list):
        return list(d)
    return list(d.get("secrets", [])) if isinstance(d, dict) else []


def save_secrets(s: list[dict]):
    _atomic_write(SECRETS_FILE, _yaml_dump({"secrets": s}))


def get_secret(sid: str) -> Optional[dict]:
    return next((s for s in load_secrets() if s.get("id") == sid), None)


def upsert_secret(s: dict):
    secrets = load_secrets()
    for i, x in enumerate(secrets):
        if x["id"] == s["id"]:
            secrets[i] = s
            save_secrets(secrets)
            return
    secrets.append(s)
    save_secrets(secrets)


def delete_secret(sid: str) -> bool:
    secrets = load_secrets()
    n = [s for s in secrets if s.get("id") != sid]
    if len(n) == len(secrets):
        return False
    save_secrets(n)
    return True


def decrypt_secret_value(sid: str) -> Optional[str]:
    s = get_secret(sid)
    if not s or not s.get("encrypted_value"):
        return None
    try:
        return _decrypt_value(s["encrypted_value"])
    except:
        return None


def substitute_secrets(cmd: str, hid: str) -> tuple[str, list[str]]:
    scrub = []
    def repl(m):
        sid = m.group(1)
        sec = get_secret(sid)
        if not sec:
            raise ValueError(f"Secret '{sid}' not found")
        if hid not in sec.get("hosts", []):
            raise ValueError(f"Secret '{sid}' not linked to '{hid}'")
        v = decrypt_secret_value(sid)
        if v is None:
            raise ValueError(f"Cannot decrypt '{sid}'")
        scrub.append(v)
        return v
    return re.sub(r'\$SECRET\{([^}]+)\}', repl, cmd), scrub


def scrub_output(text: str, vals: list[str]) -> str:
    for v in vals:
        if v and v in text:
            text = text.replace(v, "[REDACTED]")
    return text


def export_secrets_meta() -> list[dict]:
    return [
        {k: v for k, v in s.items() if k != "encrypted_value"}
        | {"has_value": bool(s.get("encrypted_value"))}
        for s in load_secrets()
    ]


# ═══ Audit (SQLite) ═══
import sqlite3
from contextlib import contextmanager

AUDIT_DB = DATA_DIR / "audit.db"


@contextmanager
def _audit_db():
    conn = sqlite3.connect(str(AUDIT_DB), timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
    finally:
        conn.close()


def _ensure_audit_schema():
    with _audit_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS audit (
            id TEXT PRIMARY KEY, ts REAL NOT NULL,
            host_id TEXT DEFAULT '', status TEXT DEFAULT '',
            source TEXT DEFAULT '', agent_id TEXT DEFAULT '',
            command TEXT DEFAULT '', data TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_host ON audit(host_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_status ON audit(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_source ON audit(source)")
        db.commit()
    _migrate_jsonl_to_sqlite()


def _migrate_jsonl_to_sqlite():
    if not AUDIT_FILE.exists():
        return
    with _audit_db() as db:
        if db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] > 0:
            AUDIT_FILE.rename(AUDIT_FILE.with_suffix(".jsonl.bak"))
            return
    text = AUDIT_FILE.read_text(encoding="utf-8").strip()
    if not text:
        AUDIT_FILE.rename(AUDIT_FILE.with_suffix(".jsonl.bak"))
        return
    with _audit_db() as db:
        for line in text.split("\n"):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
                db.execute(
                    "INSERT OR IGNORE INTO audit (id,ts,host_id,status,source,agent_id,command,data) VALUES (?,?,?,?,?,?,?,?)",
                    (e.get("id", str(uuid.uuid4())[:8]), e.get("ts", time.time()),
                     e.get("host_id",""), e.get("status",""), e.get("source",""),
                     e.get("agent_id",""), e.get("command",""),
                     json.dumps(e, ensure_ascii=False))
                )
            except Exception:
                pass
        db.commit()
    AUDIT_FILE.rename(AUDIT_FILE.with_suffix(".jsonl.bak"))


def append_audit(e: dict):
    e.setdefault("id", str(uuid.uuid4())[:8])
    e.setdefault("ts", time.time())
    if client_ip_var.get():  # SV_MCPGATE_020
        e.setdefault("ip", client_ip_var.get())
    with _audit_db() as db:
        db.execute(
            "INSERT OR REPLACE INTO audit (id,ts,host_id,status,source,agent_id,command,data) VALUES (?,?,?,?,?,?,?,?)",
            (e["id"], e["ts"], e.get("host_id",""), e.get("status",""),
             e.get("source",""), e.get("agent_id",""), e.get("command",""),
             json.dumps(e, ensure_ascii=False))
        )
        db.commit()
    for h in AUDIT_HOOKS:  # SV_MCPGATE_020
        try:
            h(e)
        except Exception:
            pass


def load_audit(limit=100, host_id="", status="", source="", group="",
               ts_from=0.0, ts_to=0.0) -> list[dict]:
    conditions, sql_params = [], []
    if group:
        hg_ids = [h["id"] for h in load_hosts() if h.get("group","") == group]
        if not hg_ids:
            return []
        conditions.append(f"host_id IN ({','.join('?'*len(hg_ids))})")
        sql_params.extend(hg_ids)
    elif host_id:
        conditions.append("host_id = ?")
        sql_params.append(host_id)
    if status:
        conditions.append("status = ?"); sql_params.append(status)
    if source:
        conditions.append("source = ?"); sql_params.append(source)
    if ts_from:
        conditions.append("ts >= ?"); sql_params.append(ts_from)
    if ts_to:
        conditions.append("ts <= ?"); sql_params.append(ts_to)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql_params.append(limit)
    with _audit_db() as db:
        rows = db.execute(f"SELECT data FROM audit {where} ORDER BY ts DESC LIMIT ?", sql_params).fetchall()
    return [json.loads(r[0]) for r in rows if r[0]]


def load_audit_all() -> list[dict]:
    with _audit_db() as db:
        rows = db.execute("SELECT data FROM audit ORDER BY ts DESC").fetchall()
    return [json.loads(r[0]) for r in rows if r[0]]


def clear_audit() -> int:
    with _audit_db() as db:
        count = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        db.execute("DELETE FROM audit")
        db.commit()
    return count


def apply_retention(days: int) -> int:
    if days <= 0:
        return 0
    cut = time.time() - days * 86400
    with _audit_db() as db:
        count = db.execute("SELECT COUNT(*) FROM audit WHERE ts < ?", (cut,)).fetchone()[0]
        if count:
            db.execute("DELETE FROM audit WHERE ts < ?", (cut,))
            db.commit()
    return count


def trim_audit() -> int:
    with _audit_db() as db:
        total = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        if total <= MAX_AUDIT_ENTRIES:
            return 0
        row = db.execute("SELECT ts FROM audit ORDER BY ts DESC LIMIT 1 OFFSET ?", (MAX_AUDIT_ENTRIES,)).fetchone()
        if not row:
            return 0
        cutoff_ts = row[0]
        trimmed = db.execute("SELECT data FROM audit WHERE ts <= ?", (cutoff_ts,)).fetchall()
        if trimmed:
            with open(AUDIT_ARCHIVE, "a", encoding="utf-8") as f:
                for r in trimmed:
                    f.write(r[0] + "\n")
            db.execute("DELETE FROM audit WHERE ts <= ?", (cutoff_ts,))
            db.commit()
        return len(trimmed)


# ═══ Approval Queue ═══

def load_queue() -> list[dict]:
    if not QUEUE_FILE.exists():
        return []
    try:
        return json.loads(QUEUE_FILE.read_text()) or []
    except:
        return []


def save_queue(q: list[dict]):
    _atomic_write(QUEUE_FILE, json.dumps(q, ensure_ascii=False, indent=2))


def add_to_queue(item: dict) -> str:
    item.update(approval_id=str(uuid.uuid4())[:8], created_at=time.time(), status="pending")
    q = load_queue()
    q.append(item)
    save_queue(q)
    return item["approval_id"]


def resolve_approval(aid: str, decision: str) -> Optional[dict]:
    q = load_queue()
    for i in q:
        if i["approval_id"] == aid and i["status"] == "pending":
            i.update(status=decision, resolved_at=time.time())
            save_queue(q)
            return i
    return None


def get_pending_approvals() -> list[dict]:
    return [i for i in load_queue() if i["status"] == "pending"]


def set_queue_result(aid: str, result: dict) -> bool:
    """SV_MCPGATE_V015: store the single execution result for the MCP waiter; drop the payload."""
    keep = ("status", "exit_code", "output", "stderr", "error", "duration_ms", "truncated")
    q = load_queue()
    for i in q:
        if i.get("approval_id") == aid:
            i["result"] = {k: result[k] for k in keep if k in result}
            i.pop("payload", None)
            save_queue(q)
            return True
    return False


def get_queue_item(aid: str) -> Optional[dict]:
    """Get approval queue item by approval_id. Returns None if not found."""
    return next((i for i in load_queue() if i.get("approval_id") == aid), None)


def update_queue_status(aid: str, status: str) -> bool:
    """Update status of an approval queue item. Returns True if found."""
    q = load_queue()
    for i in q:
        if i.get("approval_id") == aid:
            i["status"] = status
            i["resolved_at"] = time.time()
            save_queue(q)
            return True
    return False


def cleanup_expired(default_timeout=300) -> list[dict]:
    q, now, expired = load_queue(), time.time(), []
    for i in q:
        if i["status"] != "pending":
            continue
        if i.get("approval_mode") == "strict":
            continue
        if now - i["created_at"] > i.get("timeout", default_timeout):
            auto = "timeout_approve" if i.get("approval_mode") == "optimistic" else "timeout_reject"
            i.update(status="approved" if auto == "timeout_approve" else "rejected",
                     resolved_at=now, auto_resolved=auto)
            expired.append(i)
    if expired:
        save_queue(q)
    return expired


# ═══ Backup ═══

def export_backup() -> dict:
    from constants import VERSION
    cfg = load_config()
    safe = {k: v for k, v in cfg.items() if k != "mcp_api_key_hash"}
    if safe.get("telegram", {}).get("bot_token"):
        t = safe["telegram"]["bot_token"]
        safe["telegram"]["bot_token"] = t[:8] + "..." + t[-4:] if len(t) > 12 else "***"
    if safe.get("smtp", {}).get("password"):
        safe["smtp"]["password"] = "***"
    # Strip encrypted keys from agents
    agents_safe = []
    for a in load_agents():
        a_copy = public_agent(a)  # SV_MCPGATE_020
        agents_safe.append(a_copy)
    return {
        "version": VERSION, "exported_at": time.time(),
        "hosts": [{k: v for k, v in h.items() if k != "key_path"} for h in load_hosts()],  # strip key_path
        "command_sets": load_command_sets(),
        "agents": agents_safe, "secrets_meta": export_secrets_meta(), "config": safe,
    }


def import_backup(data: dict) -> dict:
    r = {"hosts": 0, "command_sets": 0, "agents": 0, "config": False}
    if "hosts" in data:
        # Normalize key_path: set default if missing or invalid
        for h in data["hosts"]:
            kp = h.get("key_path", "")
            if not kp or ".." in kp or not kp.startswith("/data/ssh_keys/"):
                h["key_path"] = "/data/ssh_keys/mcp_ed25519"
        save_hosts(data["hosts"])
        r["hosts"] = len(data["hosts"])
    if "command_sets" in data:
        save_command_sets(data["command_sets"])
        r["command_sets"] = len(data["command_sets"])
    if "agents" in data:
        # Strip any leaked keys on import
        clean = [{k: v for k, v in a.items() if k not in _KEY_FIELDS} for a in data["agents"]]  # SV_MCPGATE_020
        save_agents(clean)
        r["agents"] = len(clean)
    if "config" in data and isinstance(data["config"], dict):
        cfg = load_config()
        for k, v in data["config"].items():
            if k in ("mcp_api_key_hash", "bootstrap_done"):
                continue
            cfg[k] = v
        save_config(cfg)
        r["config"] = True
    return r
