# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""mcp_transport.py — MCP Protocol Transport for mcp-gate.
SSE + JSON-RPC 2.0 + OAuth 2.0. OAuth token bound to agent_id.
Tools: exec_command, list_hosts, list_capabilities, write_sandbox_file, server_health
"""
import asyncio, base64, hashlib, hmac, json, os, secrets, time, logging, difflib
from html import escape as _esc
from urllib.parse import urlencode, urlparse
from typing import AsyncGenerator, Optional
from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse, JSONResponse
import storage, ssh_client, params
import executor
import notifications
import app_state

_bcast_fn = None
def set_bcast(fn):
    global _bcast_fn
    _bcast_fn = fn

log = logging.getLogger("mcp-gate.mcp")

MCP_TOKEN = os.getenv("MCP_TOKEN", "")
BASE_URL = os.getenv("MCP_BASE_URL", "")
TOKENS_FILE = os.path.join(os.getenv("DATA_DIR", "/data"), "mcp_oauth_tokens.json")
from constants import VERSION, full_version

# NOTE: auth_codes are in-memory (5 min TTL); oauth_clients persist to CLIENTS_FILE (v0.1.5).
# access_tokens are persisted to TOKENS_FILE and survive restarts. First-party clients
# (e.g. OpenWebUI) should authenticate with an agent api_key as a static Bearer token
# (see _require_mcp_auth) — this has no OAuth handshake state and is restart-proof.
# The OAuth DCR flow below remains for third-party MCP clients.
oauth_clients: dict = {}
auth_codes: dict = {}

def _load_tokens() -> dict:
    try:
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _save_tokens(tokens: dict):
    try:
        os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
        with open(TOKENS_FILE, "w") as f:
            json.dump(tokens, f)
    except Exception:
        log.warning("Failed to save MCP OAuth tokens")

CLIENTS_FILE = os.path.join(os.getenv("DATA_DIR", "/data"), "mcp_oauth_clients.json")


def _th(tok: str) -> str:
    """SV_MCPGATE_V015: tokens are stored only as SHA-256 (hex[:16] == UI token_hash)."""
    return hashlib.sha256(tok.encode()).hexdigest()


def _migrate_tokens(tokens: dict) -> dict:
    out = {(k if v.get("hashed") else _th(k)): (v if v.get("hashed") else {**v, "hashed": True, "prefix": k[:8]})
           for k, v in tokens.items()}
    if any(not v.get("hashed") for v in tokens.values()):
        _save_tokens(out)
    return out


def _load_clients() -> dict:
    try:
        with open(CLIENTS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_clients():
    try:
        with open(CLIENTS_FILE, "w") as f:
            json.dump(oauth_clients, f)
    except Exception:
        log.warning("Failed to save MCP OAuth clients")


access_tokens = _migrate_tokens(_load_tokens())
oauth_clients.update(_load_clients())

def _get_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None  # SV_MCPGATE_V015: ?token= removed (leaks via access logs / Referer)

def _require_mcp_auth(request: Request) -> dict:
    token = _get_bearer(request)
    if not token:
        raise HTTPException(401, "Missing bearer token")
    # Static API-key path: an agent's api_key used directly as the Bearer token.
    # First-party clients (e.g. OpenWebUI) configure this fixed token once — no
    # OAuth handshake, so there is no per-restart DCR state to lose. Third-party
    # clients keep using the OAuth 2.0 DCR flow below.
    aid = storage.verify_agent_key(token)
    if aid:
        return {"agent_id": aid, "client_id": "static", "expires": time.time() + 3600}
    off = storage.agent_id_for_key(token)  # SV_MCPGATE_OPS p4
    if off:
        log.warning(f"MCP request blocked: agent '{off}' is disabled or its grant expired")
        raise HTTPException(403, f"Agent '{off}': {storage.agent_refusal(storage.get_agent(off)) or 'refused'}")
    entry = access_tokens.get(_th(token))
    if not entry or entry.get("expires", 0) < time.time():
        access_tokens.pop(_th(token), None)
        raise HTTPException(401, "Invalid or expired token")
    # ── Check agent is still enabled (toggle OFF = instant block) ──
    agent_id = entry.get("agent_id", "")
    if agent_id:
        agent = storage.get_agent(agent_id)
        if not storage.agent_active(agent):  # SV_MCPGATE_OPS
            log.warning(f"MCP request blocked: agent '{agent_id}' is disabled")
            raise HTTPException(403, f"Agent '{agent_id}' is disabled")
    return entry


# ═══════════════════════════════════════════════════════════════════
#  Dynamic tool descriptions — per-agent
# ═══════════════════════════════════════════════════════════════════

def _build_capabilities_summary(agent_id: str) -> str:
    """Build a compact summary of allowed hosts + command sets for this agent.
    Used in exec_command tool description so the LLM knows what's available upfront."""
    agent = storage.get_agent(agent_id) if agent_id else None
    allowed_hosts = agent.get("allowed_hosts", []) if agent else []
    agent_cs = set(agent.get("command_sets", [])) if agent else set()

    lines = []
    for h in storage.load_hosts():
        if not h.get("enabled", True):
            continue
        if allowed_hosts and h["id"] not in allowed_hosts:
            continue

        host_cs_ids = h.get("command_sets", [])
        # Effective sets = intersection of host sets with agent sets (if agent has sets)
        if agent_cs:
            effective_cs_ids = [sid for sid in host_cs_ids if sid in agent_cs]
        else:
            effective_cs_ids = host_cs_ids

        # Filter to allow-type only
        cs_summaries = []
        for sid in effective_cs_ids:
            cs = storage.get_command_set(sid)
            if not cs or not cs.get("enabled", True):
                continue
            if cs.get("type", "allow") != "allow":
                continue
            cs_summaries.append(sid)  # SV_MCPGATE_V015: ids only — details via list_capabilities

        if cs_summaries:
            lines.append(f"{h['id']}: {', '.join(cs_summaries)}")

    return "\n".join(lines) if lines else "No hosts available."


def _build_tools(agent_id: str) -> list:
    """Generate MCP tool list with agent-specific descriptions."""
    caps = _build_capabilities_summary(agent_id)

    return [
        {
            "name": "exec_command",
            "description": (
                "Execute a command on a managed SSH host. "
                "Commands must EXACTLY match the whitelist — any deviation is blocked.\n"
                "For parameterized commands, pass parameters in the 'args' field.\n\n"
                "AVAILABLE COMMANDS FOR THIS AGENT:\n"
                f"{caps}\n\n"
                "Use list_capabilities for full command list with parameters and examples."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {"type": "string", "description": "Host identifier"},
                    "command": {"type": "string", "description": "Shell command to execute (must match whitelist exactly)"},
                    "args": {"type": "object", "description": "Parameters for parameterized commands (e.g. {\"path\": \"/opt/app\", \"lines\": \"50\"})"},
                },
                "required": ["host_id", "command"],
            },
        },
        {
            "name": "list_hosts",
            "description": "List SSH hosts available to the current agent, with status and command sets.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "list_capabilities",
            "description": (
                "Show ALL allowed commands for this agent, grouped by host and command set. "
                "Includes parameter schemas, examples, approval mode, and risk level. "
                "Use this to discover exactly what you can execute before calling exec_command."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {"type": "string", "description": "Filter by specific host (optional)"},
                    "command_set": {"type": "string", "description": "Filter by specific command set (optional)"},
                },
            },
        },
        {
            "name": "server_health",
            "description": "Get mcp-gate server health: version, host count, agent count.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "write_sandbox_file",
            "description": (
                "Write a file to the sandbox directory on a managed host via SFTP. "
                "Use this to deploy scripts before executing them with exec_command. "
                "Sandbox path is per-host config (default: /tmp/mcp-sandbox). "
                "Filenames: alphanumeric + ._- only, max 100 chars. "
                "Content limit: 100KB. Scripts (.sh, .py) are auto-chmod +x. "
                "May require operator approval — the operator sees the full content."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {"type": "string", "description": "Target host identifier"},
                    "filename": {"type": "string", "description": "Filename (e.g. script.py, config.json). No paths — just the name."},
                    "content": {"type": "string", "description": "File content to write"},
                },
                "required": ["host_id", "filename", "content"],
            },
        },
    ]


# ═══════════════════════════════════════════════════════════════════
#  Fuzzy matching for blocked command suggestions
# ═══════════════════════════════════════════════════════════════════

def _find_similar_commands(cmd: str, whitelist: list, top: int = 5) -> list[str]:
    """Find similar allowed commands using difflib sequence matching."""
    wl_cmds = [w["cmd"] for w in whitelist]
    if not wl_cmds:
        return []

    # Try difflib first
    matches = difflib.get_close_matches(cmd, wl_cmds, n=top, cutoff=0.4)
    if matches:
        return matches

    # Fallback: match by first word (command name)
    first_word = cmd.split()[0] if cmd.strip() else ""
    if first_word:
        return [c for c in wl_cmds if c.split()[0] == first_word][:top]

    return []


# ═══════════════════════════════════════════════════════════════════
#  Tool execution
# ═══════════════════════════════════════════════════════════════════

_start_time = time.time()


# ═══ Token management API (used by routes_admin for revocation UI) ═══

def list_tokens_safe() -> list[dict]:
    """Return token list with sensitive values masked. Safe for API responses."""
    now = time.time()
    result = [{
        "token_prefix": e.get("prefix", "????????") + "...",
        "token_hash": th[:16],
        "agent_id": e.get("agent_id", ""),
        "expires": e.get("expires", 0),
        "expires_in_days": max(0, int((e.get("expires", 0) - now) / 86400)),
        "active": e.get("expires", 0) > now,
    } for th, e in access_tokens.items()]
    return sorted(result, key=lambda x: x["expires"], reverse=True)


def revoke_token_by_hash(token_hash: str) -> bool:
    """Revoke token by its SHA-256 prefix (first 16 hex chars). Returns True if found."""
    for th in list(access_tokens):
        if th[:16] == token_hash:
            del access_tokens[th]
            _save_tokens(access_tokens)
            log.info(f"Token revoked: hash={token_hash}")
            return True
    return False


def _fmt_result(r: dict, suffix: str = "") -> str:
    if "exit_code" not in r:
        return f"Error: {r.get('error', 'execution failed (no exit_code)')}" + suffix
    text = f"exit_code={r['exit_code']}" + suffix
    out = (r.get("output") or "").strip()
    err = (r.get("stderr") or "").strip()
    if out:
        text += f"\n{out}"
    if err:
        text += f"\nSTDERR:\n{err}"
    if r.get("error"):
        text += f"\nERROR: {r['error']}"
    return text


async def _wait_result(aid: str, mode: str, expires_at) -> str:
    """SV_MCPGATE_V015: wait for operator/timeout and READ the stored result.
    Never executes — main.api_approve / tasks.approval_loop run the item exactly once."""
    poll_max = min(120, int(expires_at - time.time())) if expires_at else 120
    ev = app_state.create_approval_event(aid)
    item = storage.get_queue_item(aid)
    if item and item.get("status") == "pending":
        try:
            await asyncio.wait_for(ev.wait(), timeout=float(max(1, poll_max)))
        except asyncio.TimeoutError:
            pass
    app_state.approval_events.pop(aid, None)
    item = storage.get_queue_item(aid) or {}
    st = item.get("status", "unknown")
    if st == "approved":
        if "result" in item:
            auto = " (auto-approved, optimistic)" if item.get("auto_resolved") == "timeout_approve" else ""
            return _fmt_result(item["result"], auto)
        return f"Approved, still executing (approval_id={aid}) — result will be in audit."
    if st == "rejected":
        why = "expired without approval" if item.get("auto_resolved") == "timeout_reject" else "rejected by operator"
        return f"Rejected: {why} (mode={mode}, approval_id={aid})"
    if st == "pending":
        return f"Pending approval (mode={mode}, approval_id={aid}). Approve via WebUI."
    return f"Approval status: {st} (approval_id={aid})"


async def _exec_tool(name: str, args: dict, agent_id: str) -> str:
    agent = storage.get_agent(agent_id) if agent_id else None
    # ── Reject if agent is disabled ──
    if agent and not storage.agent_active(agent):  # SV_MCPGATE_OPS
        return f"Error: agent '{agent_id}' is disabled or its grant expired."
    allowed_hosts = agent.get("allowed_hosts", []) if agent else []

    if name == "list_hosts":
        hosts = storage.load_hosts()
        if not hosts:
            return "No hosts configured."
        lines = []
        for h in hosts:
            if not h.get("enabled", True):
                continue
            if allowed_hosts and h["id"] not in allowed_hosts:
                continue
            all_cs_ids = h.get("command_sets", [])
            sets_allow_ids = [sid for sid in all_cs_ids
                              if (cs := storage.get_command_set(sid)) and cs.get("type", "allow") == "allow"]
            sets_deny_ids = [sid for sid in all_cs_ids
                             if (cs := storage.get_command_set(sid)) and cs.get("type") == "deny"]
            sets_allow = ", ".join(sets_allow_ids)
            sets_deny = ", ".join(sets_deny_ids)
            mode = h.get("approval_mode", "pessimistic")
            line = f"* {h['id']} -- {h.get('name', '')} mode={mode}"
            if sets_allow:
                line += f" allow=[{sets_allow}]"
            if sets_deny:
                line += f" deny=[{sets_deny}]"
            wl = storage.get_effective_whitelist(h)
            if wl:
                cmds = [w["cmd"] for w in wl[:10]]
                line += f"\n  commands: {', '.join(cmds)}"
                if len(wl) > 10:
                    line += f" ... (+{len(wl)-10} more)"
            lines.append(line)
        return "\n".join(lines) if lines else "No hosts available for this agent."

    elif name == "list_capabilities":
        return _handle_list_capabilities(args, agent_id, agent, allowed_hosts)

    elif name == "exec_command":
        host_id = args.get("host_id", "")
        command = args.get("command", "")
        if not host_id or not command:
            return "Error: host_id and command are required."
        h = storage.get_host(host_id)
        if not h:
            return f"Error: host '{host_id}' not found."
        if not h.get("enabled", True):
            return f"Error: host '{host_id}' is disabled."
        if allowed_hosts and host_id not in allowed_hosts:
            return f"Error: agent '{agent_id}' not allowed on host '{host_id}'."

        result = await executor.execute_command(
            host=h, command=command, agent=agent, agent_id=agent_id,
            source=agent_id or "mcp-transport",
            args=args.get("args"), bcast_fn=_bcast_fn,
        )
        action = result["action"]
        if action == "blocked":
            return _format_blocked_response(result, h, command, agent)
        elif action == "dry_run":
            return f"Dry run: would execute '{result['would_execute']}' (mode: {result['mode']})"
        elif action == "pending":
            # SV_MCPGATE_V015: the resolver executes once and stores the result; we only read it
            return await _wait_result(result["approval_id"], result["approval_mode"], result.get("expires_at"))
        elif action == "executed":
            r = result["result"]
            if "exit_code" not in r:
                return f"Error: {r.get('error', 'execution failed (no exit_code)')}"
            text = f"exit_code={r['exit_code']}"
            out = r.get("output", "").strip()
            err = r.get("stderr", "").strip()
            if out:
                text += f"\n{out}"
            if err:
                text += f"\nSTDERR:\n{err}"
            return text
        else:
            return f"Error: unexpected executor action '{action}'"

    elif name == "write_sandbox_file":
        # SV_MCPGATE_V015: single branch; write is a whitelisted, approvable action
        # (cmd 'write_sandbox_file') — the operator sees the full content before it lands.
        host_id = args.get("host_id", "")
        filename = args.get("filename", "")
        content = args.get("content", "")
        if not host_id or not filename:
            return "Error: host_id and filename are required."
        if not content:
            return "Error: content is required (empty file not allowed)."
        h = storage.get_host(host_id)
        if not h:
            return f"Error: host '{host_id}' not found."
        if not h.get("enabled", True):
            return f"Error: host '{host_id}' is disabled."
        if allowed_hosts and host_id not in allowed_hosts:
            return f"Error: agent '{agent_id}' not allowed on host '{host_id}'."
        src = agent_id or "mcp-transport"
        ok, reason = storage.check_command_authorized(h, agent, "write_sandbox_file")
        if not ok:
            storage.append_audit({"host_id": host_id, "command": f"write_sandbox_file: {filename}",
                                  "source": src, "agent_id": agent_id, "status": "blocked", "reason": reason})
            return f"Error: write_sandbox_file not allowed on '{host_id}': {reason}"
        sha = hashlib.sha256(content.encode()).hexdigest()
        item = {"kind": "write_sandbox", "host_id": host_id, "command": "write_sandbox_file",
                "resolved": f"write_sandbox_file {filename} ({len(content.encode())} B, sha256={sha[:16]})",
                "filename": filename, "payload": content, "sha256": sha, "source": src, "agent_id": agent_id,
                "sandbox_dir": h.get("sandbox_path", "").strip() or "/tmp/mcp-sandbox"}
        if h.get("dry_run"):
            return f"Dry run: would {item['resolved']}"
        mode = executor.get_approval_mode(h, storage.find_whitelist_entry(h, "write_sandbox_file") or {})
        if mode == "auto":
            r = await asyncio.to_thread(executor.run_queued, item)
            entry = {"host_id": host_id, "command": item["resolved"], "source": src,
                     "agent_id": agent_id, "sha256": sha, **r}
            storage.append_audit(entry)
            if _bcast_fn:
                try:
                    await _bcast_fn(entry)
                except Exception:
                    pass
            return _fmt_result(r)
        timeout = h.get("approval_timeout", 300)
        item.update(approval_mode=mode, timeout=timeout if mode != "strict" else 0)
        aid = storage.add_to_queue(item)
        if _bcast_fn:
            try:
                await _bcast_fn({"host_id": host_id, "command": item["resolved"], "source": src,
                                 "agent_id": agent_id, "status": "pending", "approval_id": aid,
                                 "approval_mode": mode, "created_at": time.time()})
            except Exception:
                pass
        await notifications.notify("approval", f"Pending\n{host_id}: <code>{_esc(item['resolved'])}</code>\n"
                                               f"Mode: {mode}\n<pre>{_esc(content[:2500])}</pre>")
        return await _wait_result(aid, mode, time.time() + timeout if mode != "strict" else None)

    elif name == "server_health":
        hosts = storage.load_hosts()
        agents = storage.load_agents()
        return json.dumps({
            "status": "ok", "version": full_version(),
            "hosts_total": len(hosts),
            "hosts_enabled": sum(1 for h in hosts if h.get("enabled", True)),
            "agents": len(agents),
            "command_sets": len(storage.load_command_sets()),
            "uptime_seconds": int(time.time() - _start_time),
            "current_agent": agent_id,
        }, indent=2)

    return f"Unknown tool: {name}"


# ═══════════════════════════════════════════════════════════════════
#  list_capabilities handler
# ═══════════════════════════════════════════════════════════════════

def _handle_list_capabilities(args: dict, agent_id: str, agent: Optional[dict], allowed_hosts: list) -> str:
    """Return detailed capabilities for the current agent."""
    filter_host = args.get("host_id", "")
    filter_cs = args.get("command_set", "")
    agent_cs = set(agent.get("command_sets", [])) if agent else set()

    sections = []
    for h in storage.load_hosts():
        if not h.get("enabled", True):
            continue
        if allowed_hosts and h["id"] not in allowed_hosts:
            continue
        if filter_host and h["id"] != filter_host:
            continue

        host_cs_ids = h.get("command_sets", [])
        if agent_cs:
            effective_cs_ids = [sid for sid in host_cs_ids if sid in agent_cs]
        else:
            effective_cs_ids = host_cs_ids

        mode = h.get("approval_mode", "pessimistic")
        host_section = [f"═══ Host: {h['id']} ({h.get('name', '')}) | mode={mode} ═══"]

        for sid in effective_cs_ids:
            cs = storage.get_command_set(sid)
            if not cs or not cs.get("enabled", True):
                continue
            cs_type = cs.get("type", "allow")
            if filter_cs and cs["id"] != filter_cs:
                continue

            desc = cs.get("description", "")
            header = f"\n  [{cs_type.upper()}] {sid}"
            if desc:
                header += f" — {desc}"
            host_section.append(header)

            for cmd_entry in cs.get("commands", []):
                cmd = cmd_entry["cmd"]
                cmd_desc = cmd_entry.get("description", "")
                line = f"    • {cmd}"
                if cmd_desc:
                    line += f"  — {cmd_desc}"
                # Show params if present
                if cmd_entry.get("params"):
                    param_parts = []
                    for p in cmd_entry["params"]:
                        pinfo = p["name"]
                        if p.get("default"):
                            pinfo += f"={p['default']}"
                        if p.get("regex"):
                            pinfo += f" /{p['regex']}/"
                        param_parts.append(pinfo)
                    line += f"\n      params: {', '.join(param_parts)}"
                # Show approval override if present
                if cmd_entry.get("approval"):
                    line += f"\n      approval: {cmd_entry['approval']}"
                host_section.append(line)

        if len(host_section) > 1:
            sections.append("\n".join(host_section))

    if not sections:
        return "No capabilities found for the given filters."
    return "\n\n".join(sections)


# ═══════════════════════════════════════════════════════════════════
#  Structured blocked response
# ═══════════════════════════════════════════════════════════════════

def _format_blocked_response(result: dict, host: dict, command: str, agent: Optional[dict]) -> str:
    """Format a helpful blocked response with reason, suggestions, and hints."""
    reason = result.get("reason", "unknown")
    parts = [f"BLOCKED: {reason}"]
    parts.append(f"Host: {host['id']}, Command: {command}")

    # Find similar commands
    wl = storage.get_effective_whitelist(host)

    # If agent has command sets, intersect
    if agent:
        agent_allow_cmds = set()
        for sid in agent.get("command_sets", []):
            cs = storage.get_command_set(sid)
            if cs and cs.get("enabled", True) and cs.get("type", "allow") == "allow":
                for c in cs.get("commands", []):
                    agent_allow_cmds.add(c["cmd"])
        if agent_allow_cmds:
            wl = [w for w in wl if w["cmd"] in agent_allow_cmds]

    similar = _find_similar_commands(command, wl)
    if similar:
        parts.append("Similar allowed commands:")
        for s in similar:
            parts.append(f"  • {s}")

    # Identify which command set the command _would_ belong to
    first_word = command.split()[0] if command.strip() else ""
    matching_sets = []
    for cs in storage.load_command_sets():
        if cs.get("type") == "deny" or not cs.get("enabled", True):
            continue
        for c in cs.get("commands", []):
            if c["cmd"].split()[0] == first_word:
                if cs["id"] not in matching_sets:
                    matching_sets.append(cs["id"])
                break
    if matching_sets:
        host_cs = set(host.get("command_sets", []))
        agent_cs = set(agent.get("command_sets", [])) if agent else set()
        for ms in matching_sets:
            if ms not in host_cs:
                parts.append(f"Hint: command set '{ms}' has '{first_word}' commands but is not assigned to host '{host['id']}'")
            elif agent_cs and ms not in agent_cs:
                parts.append(f"Hint: command set '{ms}' is on host but not assigned to agent '{agent.get('id', '?')}'")

    parts.append("Use list_capabilities to see all allowed commands.")
    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════
#  JSON-RPC handler
# ═══════════════════════════════════════════════════════════════════

async def _handle_rpc(req: dict, agent_id: str) -> dict:
    method = req.get("method", "")
    rid = req.get("id")
    p = req.get("params", {})

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "mcp-gate", "version": full_version()},
        }}
    elif method == "tools/list":
        tools = _build_tools(agent_id)
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}}
    elif method == "tools/call":
        tname = p.get("name", "")
        targs = p.get("arguments", {})
        try:
            result = await _exec_tool(tname, targs, agent_id)
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": str(result)}],
            }}
        except Exception as e:
            log.exception(f"Tool error: {tname}")
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"Error: {e}"}], "isError": True,
            }}
    elif method in ("notifications/initialized", "notifications/cancelled"):
        return {}
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"Method not found: {method}"}}

router = APIRouter(tags=["mcp-transport"])

@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/{path:path}")
async def oauth_protected_resource(path: str = ""):
    return JSONResponse({
        "resource": BASE_URL, "authorization_servers": [BASE_URL],
        "scopes_supported": ["mcp"], "bearer_methods_supported": ["header"],
    })

@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return JSONResponse({
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "registration_endpoint": f"{BASE_URL}/oauth/register",
        "scopes_supported": ["mcp"], "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    })

@router.post("/oauth/register")
async def oauth_register(request: Request):
    body = await request.json()
    cid = secrets.token_urlsafe(16)
    cs = secrets.token_urlsafe(32)
    uris = [u for u in body.get("redirect_uris", []) if isinstance(u, str)]
    bad = [u for u in uris if not (urlparse(u).scheme == "https"
                                   or urlparse(u).hostname in ("localhost", "127.0.0.1"))]
    if not uris or bad:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    oauth_clients[cid] = {"secret": cs, "redirect_uris": uris}  # SV_MCPGATE_V015: persisted
    _save_clients()
    return JSONResponse({"client_id": cid, "client_secret": cs,
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": ["authorization_code"], "response_types": ["code"]}, status_code=201)

@router.get("/oauth/authorize")
async def oauth_authorize(
    client_id: str, redirect_uri: str, response_type: str = "code",
    state: str = "", code_challenge: str = "", code_challenge_method: str = "S256",
    scope: str = "mcp",
):
    cfg = storage.load_config()
    appear = cfg.get("appearance", {})
    accent = appear.get("accent_color", "#818cf8")
    bg = appear.get("bg_color", "#0f1117")
    text_c = appear.get("text_color", "#e0e0e0")
    card = appear.get("card_bg", "rgba(26,29,39,0.7)")

    # Escape reflected query params before embedding in HTML form fields.
    # This page also collects the MCP_TOKEN, so HTML injection here is high-risk.
    import html as _html
    client_id = _html.escape(client_id, quote=True)
    redirect_uri = _html.escape(redirect_uri, quote=True)
    state = _html.escape(state, quote=True)
    code_challenge = _html.escape(code_challenge, quote=True)

    agents = storage.load_agents()
    mcp_agents = [a for a in agents if a.get("enabled", True)]
    opts = ""
    for a in mcp_agents:
        icon = a.get("icon", "\U0001f916")
        name = a.get("name", a["id"])
        opts += f'<option value="{a["id"]}">{icon} {name}</option>\n'
    if not opts:
        opts = '<option value="" disabled>No agents \u2014 create one in WebUI first</option>'

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MCP-Gate \u2014 Authorize</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="/static/logo/mcp-gate_favicon.png">
<style>
  body{{font-family:system-ui,sans-serif;max-width:460px;margin:60px auto;padding:20px;background:{bg};color:{text_c}}}
  .card{{background:{card};border-radius:12px;padding:32px;box-shadow:0 4px 24px rgba(0,0,0,.4);backdrop-filter:blur(12px)}}
  .logo{{width:90%;max-width:380px;display:block;margin:0 auto 20px}}
  label{{font-size:13px;font-weight:600;display:block;margin-bottom:4px}}
  input,select{{width:100%;padding:10px;margin:0 0 16px;border:1px solid #444;border-radius:6px;font-size:14px;box-sizing:border-box;background:#1a1d27;color:{text_c}}}
  select{{cursor:pointer}}
  button{{width:100%;padding:12px;background:{accent};color:#fff;border:none;border-radius:6px;font-size:16px;cursor:pointer;font-weight:600}}
  button:hover{{opacity:0.9}}
  .info{{font-size:13px;color:#999;margin-bottom:20px}}
  .note{{font-size:11px;color:#777;margin-top:-8px;margin-bottom:16px}}
</style></head><body><div class="card">
  <img src="/static/logo/mcp-gate_logonameW.png" alt="MCP-Gate" class="logo">
  <p class="info">An MCP client requests access to execute commands on your managed SSH hosts.</p>
  <form method="post" action="/oauth/approve">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <label>Agent</label>
    <select name="agent_id" required>
      <option value="" disabled selected>Select agent...</option>
      {opts}
    </select>
    <p class="note">The MCP client will operate with this agent's permissions (allowed hosts, command sets).</p>
    <label>MCP Token</label>
    <input type="password" name="token" placeholder="Enter MCP_TOKEN from .env" required autofocus>
    <button type="submit">\u2705 Authorize Access</button>
  </form>
</div></body></html>"""
    return HTMLResponse(html)

@router.post("/oauth/approve")
async def oauth_approve(
    client_id: str = Form(...), redirect_uri: str = Form(...),
    state: str = Form(""), code_challenge: str = Form(""),
    token: str = Form(...), agent_id: str = Form(...),
):
    if not MCP_TOKEN or not hmac.compare_digest(token.encode(), MCP_TOKEN.encode()):
        return HTMLResponse(
            '<div style="font-family:system-ui;color:#ef4444;padding:40px;text-align:center">'
            '<h2>\u274c Invalid MCP token</h2><p><a href="javascript:history.back()" style="color:#818cf8">Try again</a></p></div>',
            status_code=401)
    if not agent_id:
        return HTMLResponse(
            '<div style="font-family:system-ui;color:#ef4444;padding:40px;text-align:center">'
            '<h2>\u274c No agent selected</h2><p><a href="javascript:history.back()" style="color:#818cf8">Try again</a></p></div>',
            status_code=400)
    agent = storage.get_agent(agent_id)
    if not agent:
        return HTMLResponse(f'<h2 style="color:#ef4444;font-family:system-ui">\u274c Agent not found</h2>', status_code=404)

    # SV_MCPGATE_V015: redirect_uri must be registered by this client (blocks code theft)
    cl = oauth_clients.get(client_id)
    if not cl or redirect_uri not in cl.get("redirect_uris", []):
        return HTMLResponse('<h2 style="color:#ef4444;font-family:system-ui">Unknown client or '
                            'unregistered redirect_uri: remove and re-add the connector</h2>', status_code=400)
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": client_id, "redirect_uri": redirect_uri,
        "code_challenge": code_challenge, "agent_id": agent_id,
        "expires": time.time() + 300,
    }
    sep = "&" if "?" in redirect_uri else "?"
    url = f"{redirect_uri}{sep}" + urlencode({"code": code, **({"state": state} if state else {})})
    log.info(f"MCP OAuth approved for agent '{agent_id}' client '{client_id}'")
    return RedirectResponse(url, status_code=302)

@router.post("/oauth/token")
async def oauth_token(request: Request):
    ct = request.headers.get("content-type", "")
    body = await request.json() if "json" in ct else dict(await request.form())
    if body.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    entry = auth_codes.pop(body.get("code", ""), None)
    if not entry or entry["expires"] < time.time():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    # SV_MCPGATE_V015: bind code to client_id + redirect_uri, enforce PKCE S256
    if (body.get("client_id") or entry["client_id"]) != entry["client_id"] or \
            (body.get("redirect_uri") or entry["redirect_uri"]) != entry["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    verifier = body.get("code_verifier", "")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if not verifier or not entry.get("code_challenge") or \
            not hmac.compare_digest(challenge, entry["code_challenge"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE check failed"}, status_code=400)
    tok = secrets.token_urlsafe(48)
    access_tokens[_th(tok)] = {"hashed": True, "prefix": tok[:8],
        "client_id": entry["client_id"],
        "agent_id": entry["agent_id"],
        "expires": time.time() + 86400 * 90,
    }
    _save_tokens(access_tokens)
    log.info(f"MCP OAuth token issued for agent '{entry['agent_id']}'")
    return JSONResponse({
        "access_token": tok, "token_type": "bearer",
        "expires_in": 86400 * 90, "scope": "mcp",
    })



@router.get("/favicon.ico")
async def favicon():
    import os
    from fastapi.responses import FileResponse
    ico = os.path.join("/app", "static", "logo", "mcp-gate_favicon.png")
    if os.path.exists(ico):
        return FileResponse(ico, media_type="image/png")
    raise HTTPException(404)

# ── MCP Connection info (for admin WebUI) ──
def get_active_sessions() -> list:
    """Return list of active MCP OAuth sessions."""
    now = time.time()
    sessions = []
    for tok, entry in access_tokens.items():
        if entry.get("expires", 0) > now:
            sessions.append({
                "agent_id": entry.get("agent_id", ""),
                "client_id": entry.get("client_id", "")[:8] + "...",
                "expires_in_days": int((entry["expires"] - now) / 86400),
            })
    return sessions

@router.get("/sse")
async def sse_endpoint(request: Request):
    _require_mcp_auth(request)
    async def stream() -> AsyncGenerator[str, None]:
        yield f"event: endpoint\ndata: {BASE_URL}/messages\n\n"
        while True:
            if await request.is_disconnected():
                break
            yield ": ping\n\n"
            await asyncio.sleep(15)
    return StreamingResponse(stream(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@router.post("/messages")
@router.post("/mcp")
@router.post("/")
async def messages_endpoint(request: Request):
    entry = _require_mcp_auth(request)
    agent_id = entry.get("agent_id", "")
    body = await request.json()
    if isinstance(body, list):
        results = []
        for x in body:
            r = await _handle_rpc(x, agent_id)
            if r:
                results.append(r)
        return results
    return await _handle_rpc(body, agent_id) or {}
