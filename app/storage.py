"""
storage.py — Data layer for MCP Gate v0.1.0
Handles hosts, command sets (allow/deny), secrets, agents, audit, config.
"""

import json, os, re, time, uuid, hashlib
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

# Agent key cache: {encrypted_key: agent_id} — avoids O(n) Fernet per request
_agent_key_cache: dict[str, str] = {}

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


def _atomic_write(path: Path, content: str):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def _yaml_dump(data):
    return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ═══ Fernet (shared) ═══

def _get_fernet():
    from cryptography.fernet import Fernet
    if not SECRETS_KEY_FILE.exists():
        SECRETS_KEY_FILE.write_bytes(Fernet.generate_key())
        os.chmod(SECRETS_KEY_FILE, 0o600)
    return Fernet(SECRETS_KEY_FILE.read_bytes().strip())


def _encrypt_value(v: str) -> str:
    return _get_fernet().encrypt(v.encode()).decode()


def _decrypt_value(e: str) -> str:
    return _get_fernet().decrypt(e.encode()).decode()


# ═══ Config ═══

def _default_appearance():
    return {"accent_color": "#6366f1", "bg_color": "#0f1117", "card_bg": "#1a1d27",
            "nav_bg": "#1a1d27", "text_color": "#e0e0e0", "glass_blur": 0, "panel_opacity": 1.0,
            "bg_image": "", "btn_primary": "#4f52b8", "btn_success": "#1a8a47",
            "btn_danger": "#b83a3a", "btn_info": "#0891a2", "btn_warning": "#b47a10"}


def _default_instance():
    return {"app_url": "", "language": "ru", "ping_interval": 60, "audit_max_entries": 10000,
            "traefik_config_path": "", "ssh_key_path": "/data/ssh_keys/mcp_ed25519",
            "compose_path": "", "data_volume_path": "", "auth_type": "basic"}


def _default_templates():
    return {"blocked": "🚫 Blocked: {command} on {host}", "approved": "✅ Approved: {command}",
            "error": "❌ Error: {command} on {host}", "pending": "⏳ Pending: {command}"}


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        cfg = {"appearance": _default_appearance(), "instance": _default_instance(),
               "notification_templates": _default_templates()}
        save_config(cfg)
        return cfg
    cfg = yaml.safe_load(CONFIG_FILE.read_text()) or {}
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
    if not HOSTS_FILE.exists():
        return []
    d = yaml.safe_load(HOSTS_FILE.read_text())
    if isinstance(d, list):
        return d
    return d.get("hosts", []) if isinstance(d, dict) else []


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
    if not AGENTS_FILE.exists():
        return []
    d = yaml.safe_load(AGENTS_FILE.read_text())
    if isinstance(d, list):
        return d
    return d.get("agents", []) if isinstance(d, dict) else []


def save_agents(a: list[dict]):
    _atomic_write(AGENTS_FILE, _yaml_dump({"agents": a}))


def get_agent(aid: str) -> Optional[dict]:
    return next((a for a in load_agents() if a.get("id") == aid), None)


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


def encrypt_agent_key(raw: str) -> str:
    """Encrypt agent API key with Fernet (reversible)."""
    return _encrypt_value(raw)


def decrypt_agent_key(aid: str) -> Optional[str]:
    """Decrypt agent API key. Returns None if not set or decrypt fails."""
    a = get_agent(aid)
    if not a or not a.get("encrypted_api_key"):
        return None
    try:
        return _decrypt_value(a["encrypted_api_key"])
    except:
        return None


def verify_agent_key(provided_key: str) -> Optional[str]:
    """Check provided API key against all enabled agents. Returns agent_id or None.
    Uses cache to avoid O(n) Fernet decryptions on every request."""
    # Check cache first
    for enc_key, aid in list(_agent_key_cache.items()):
        try:
            if _decrypt_value(enc_key) == provided_key:
                a = get_agent(aid)
                if a and a.get("enabled", True):
                    return aid
                else:
                    _agent_key_cache.pop(enc_key, None)
        except:
            _agent_key_cache.pop(enc_key, None)
    # Cache miss: full scan
    for a in load_agents():
        if not a.get("enabled", True):
            continue
        enc = a.get("encrypted_api_key")
        if not enc:
            continue
        try:
            stored = _decrypt_value(enc)
            if stored == provided_key:
                _agent_key_cache[enc] = a["id"]
                return a["id"]
        except:
            continue
    return None


def invalidate_agent_key_cache():
    """Clear agent key cache. Call after agent CRUD operations."""
    _agent_key_cache.clear()

def get_agent_types() -> dict:
    return AGENT_TYPES


# ═══ Command Sets ═══

def load_command_sets() -> list[dict]:
    if not COMMAND_SETS_FILE.exists():
        return []
    d = yaml.safe_load(COMMAND_SETS_FILE.read_text())
    if isinstance(d, list):
        return d
    return d.get("sets", []) if isinstance(d, dict) else []


def save_command_sets(s: list[dict]):
    _atomic_write(COMMAND_SETS_FILE, _yaml_dump({"sets": s}))


def get_command_set(sid: str) -> Optional[dict]:
    return next((s for s in load_command_sets() if s.get("id") == sid), None)


def upsert_command_set(cs: dict):
    sets = load_command_sets()
    for i, s in enumerate(sets):
        if s["id"] == cs["id"]:
            sets[i] = cs
            save_command_sets(sets)
            return
    sets.append(cs)
    save_command_sets(sets)


def delete_command_set(sid: str) -> bool:
    sets = load_command_sets()
    n = [s for s in sets if s.get("id") != sid]
    if len(n) == len(sets):
        return False
    save_command_sets(n)
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
    if not SECRETS_FILE.exists():
        return []
    d = yaml.safe_load(SECRETS_FILE.read_text())
    if isinstance(d, list):
        return d
    return d.get("secrets", []) if isinstance(d, dict) else []


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


# ═══ Audit ═══

def append_audit(e: dict):
    e.setdefault("id", str(uuid.uuid4())[:8])
    e.setdefault("ts", time.time())
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")


def load_audit(limit=100, host_id="", status="", source="", group="",
               ts_from=0.0, ts_to=0.0) -> list[dict]:
    if not AUDIT_FILE.exists():
        return []
    hg = {h["id"]: h.get("group", "") for h in load_hosts()} if group else {}
    entries = []
    for line in reversed(AUDIT_FILE.read_text().strip().split("\n")):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except:
            continue
        if host_id and e.get("host_id") != host_id:
            continue
        if status and e.get("status") != status:
            continue
        if source and e.get("source") != source:
            continue
        if group and hg.get(e.get("host_id", "")) != group:
            continue
        if ts_from and e.get("ts", 0) < ts_from:
            continue
        if ts_to and e.get("ts", 0) > ts_to:
            continue
        entries.append(e)
        if len(entries) >= limit:
            break
    return entries


def load_audit_all() -> list[dict]:
    if not AUDIT_FILE.exists():
        return []
    r = []
    for l in reversed(AUDIT_FILE.read_text().strip().split("\n")):
        if l.strip():
            try:
                r.append(json.loads(l))
            except:
                pass
    return r


def clear_audit() -> int:
    if not AUDIT_FILE.exists():
        return 0
    c = sum(1 for l in AUDIT_FILE.read_text().strip().split("\n") if l.strip())
    _atomic_write(AUDIT_FILE, "")
    return c


def apply_retention(days: int) -> int:
    if not AUDIT_FILE.exists() or days <= 0:
        return 0
    cut = time.time() - days * 86400
    kept, rm = [], 0
    for l in AUDIT_FILE.read_text().strip().split("\n"):
        if not l.strip():
            continue
        try:
            if json.loads(l).get("ts", 0) >= cut:
                kept.append(l)
            else:
                rm += 1
        except:
            kept.append(l)
    if rm:
        _atomic_write(AUDIT_FILE, "\n".join(kept) + "\n" if kept else "")
    return rm


def trim_audit() -> int:
    if not AUDIT_FILE.exists():
        return 0
    lines = AUDIT_FILE.read_text().strip().split("\n")
    if len(lines) <= MAX_AUDIT_ENTRIES:
        return 0
    trimmed, kept = lines[:-MAX_AUDIT_ENTRIES], lines[-MAX_AUDIT_ENTRIES:]
    with open(AUDIT_ARCHIVE, "a") as f:
        for l in trimmed:
            f.write(l + "\n")
    _atomic_write(AUDIT_FILE, "\n".join(kept) + "\n")
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


def cleanup_expired(default_timeout=300) -> list[dict]:
    q, now, expired = load_queue(), time.time(), []
    for i in q:
        if i["status"] != "pending":
            continue
        if i.get("approval_mode") == "strict":
            continue
        if now - i["created_at"] > i.get("timeout", default_timeout):
            auto = "timeout_approve" if i.get("approval_mode") == "optimistic" else "timeout_reject"
            i.update(status="approve" if "approve" in auto else "reject",
                     resolved_at=now, auto_resolved=auto)
            expired.append(i)
    if expired:
        save_queue(q)
    return expired


# ═══ Backup ═══

def export_backup() -> dict:
    from main import VERSION
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
        a_copy = {k: v for k, v in a.items() if k != "encrypted_api_key"}
        a_copy["has_key"] = bool(a.get("encrypted_api_key"))
        agents_safe.append(a_copy)
    return {
        "version": VERSION, "exported_at": time.time(),
        "hosts": load_hosts(), "command_sets": load_command_sets(),
        "agents": agents_safe, "secrets_meta": export_secrets_meta(), "config": safe,
    }


def import_backup(data: dict) -> dict:
    r = {"hosts": 0, "command_sets": 0, "agents": 0, "config": False}
    if "hosts" in data:
        save_hosts(data["hosts"])
        r["hosts"] = len(data["hosts"])
    if "command_sets" in data:
        save_command_sets(data["command_sets"])
        r["command_sets"] = len(data["command_sets"])
    if "agents" in data:
        # Strip any leaked keys on import
        clean = [{k: v for k, v in a.items() if k != "encrypted_api_key"} for a in data["agents"]]
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
