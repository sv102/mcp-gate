# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""mcp_transport.py — MCP Protocol Transport for mcp-gate.
SSE + JSON-RPC 2.0 + OAuth 2.0. OAuth token bound to agent_id.
Tools: exec_command, list_hosts, list_capabilities, server_health
"""
import asyncio, json, os, secrets, time, logging, difflib
from typing import AsyncGenerator, Optional
from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse, JSONResponse
import storage, ssh_client, params
import executor

_bcast_fn = None
def set_bcast(fn):
    global _bcast_fn
    _bcast_fn = fn

log = logging.getLogger("mcp-gate.mcp")

MCP_TOKEN = os.getenv("MCP_TOKEN", "")
BASE_URL = os.getenv("MCP_BASE_URL", "")
TOKENS_FILE = os.path.join(os.getenv("DATA_DIR", "/data"), "mcp_oauth_tokens.json")
from constants import VERSION, full_version

# NOTE: oauth_clients and auth_codes are in-memory only — lost on container restart.
# This is acceptable: OAuth DCR clients re-register automatically on reconnect.
# access_tokens are persisted to TOKENS_FILE (mcp_oauth_tokens.json) and survive restarts.
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

access_tokens = _load_tokens()

def _get_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.query_params.get("token")

def _require_mcp_auth(request: Request) -> dict:
    token = _get_bearer(request)
    if not token:
        raise HTTPException(401, "Missing bearer token")
    entry = access_tokens.get(token)
    if not entry or entry.get("expires", 0) < time.time():
        access_tokens.pop(token, None)
        raise HTTPException(401, "Invalid or expired token")
    # ── Check agent is still enabled (toggle OFF = instant block) ──
    agent_id = entry.get("agent_id", "")
    if agent_id:
        agent = storage.get_agent(agent_id)
        if not agent or not agent.get("enabled", True):
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
            cmds = cs.get("commands", [])
            # Show first 3 commands as examples
            examples = [c["cmd"] for c in cmds[:3]]
            suffix = f" (+{len(cmds)-3} more)" if len(cmds) > 3 else ""
            cs_summaries.append(f"  {sid}: {', '.join(examples)}{suffix}")

        if cs_summaries:
            mode = h.get("approval_mode", "pessimistic")
            lines.append(f"Host '{h['id']}' (mode={mode}):")
            lines.extend(cs_summaries)

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

async def _exec_tool(name: str, args: dict, agent_id: str) -> str:
    agent = storage.get_agent(agent_id) if agent_id else None
    # ── Reject if agent is disabled ──
    if agent and not agent.get("enabled", True):
        return f"Error: agent '{agent_id}' is disabled."
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
            aid = result["approval_id"]
            mode = result["approval_mode"]
            # For MCP transport: poll until resolved (max 120s)
            # Optimistic auto-approves on timeout; pessimistic auto-rejects
            poll_max = min(120, int(result.get("expires_at", time.time() + 120) - time.time())) if result.get("expires_at") else 120
            poll_interval = 2
            elapsed = 0
            while elapsed < poll_max:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval
                # Check queue for resolution
                item = storage.get_queue_item(aid)
                if not item:
                    break
                st = item.get("status", "pending")
                if st == "approved":
                    try:
                        r = await asyncio.to_thread(executor.execute_with_secrets, h, item.get("resolved", command))
                    except ValueError as ve:
                        return f"Error during execution: {ve}"
                    entry = {"host_id": host_id, "command": command,
                             "resolved": item.get("resolved", command),
                             "source": agent_id or "mcp-transport",
                             "agent_id": agent_id, **r}
                    storage.append_audit(entry)
                    text = f"exit_code={r['exit_code']}"
                    out = r.get("output", "").strip()
                    err = r.get("stderr", "").strip()
                    if out:
                        text += f"\n{out}"
                    if err:
                        text += f"\nSTDERR:\n{err}"
                    return text
                elif st == "rejected":
                    return f"Rejected by operator (approval_id={aid})"
                elif st == "expired":
                    if mode == "optimistic":
                        try:
                            r = await asyncio.to_thread(executor.execute_with_secrets, h, item.get("resolved", command))
                        except ValueError as ve:
                            return f"Error during execution: {ve}"
                        entry = {"host_id": host_id, "command": command,
                                 "resolved": item.get("resolved", command),
                                 "source": agent_id or "mcp-transport",
                                 "agent_id": agent_id, "auto_approved": True, **r}
                        storage.append_audit(entry)
                        text = f"exit_code={r['exit_code']} (auto-approved, optimistic mode)"
                        out = r.get("output", "").strip()
                        err = r.get("stderr", "").strip()
                        if out:
                            text += f"\n{out}"
                        if err:
                            text += f"\nSTDERR:\n{err}"
                        return text
                    else:
                        return f"Expired without approval (mode={mode}, approval_id={aid})"
            # Timeout
            item = storage.get_queue_item(aid)
            if item and item.get("status") == "pending":
                if mode == "optimistic":
                    try:
                        r = await asyncio.to_thread(executor.execute_with_secrets, h, item.get("resolved", command))
                    except ValueError as ve:
                        return f"Error during execution: {ve}"
                    storage.update_queue_status(aid, "approved")
                    entry = {"host_id": host_id, "command": command,
                             "resolved": item.get("resolved", command),
                             "source": agent_id or "mcp-transport",
                             "agent_id": agent_id, "auto_approved": True, **r}
                    storage.append_audit(entry)
                    text = f"exit_code={r['exit_code']} (auto-approved, optimistic timeout)"
                    out = r.get("output", "").strip()
                    err = r.get("stderr", "").strip()
                    if out:
                        text += f"\n{out}"
                    if err:
                        text += f"\nSTDERR:\n{err}"
                    return text
                else:
                    return f"Pending approval (mode={mode}, approval_id={aid}). Approve via WebUI."
            return f"Approval status unknown (approval_id={aid})"
        elif action == "executed":
            r = result["result"]
            text = f"exit_code={r['exit_code']}"
            out = r.get("output", "").strip()
            err = r.get("stderr", "").strip()
            if out:
                text += f"\n{out}"
            if err:
                text += f"\nSTDERR:\n{err}"
            return text
        else:
            return f"Error: {r.get('error', 'unknown')}"

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
    oauth_clients[cid] = {"secret": cs, "redirect_uris": body.get("redirect_uris", [])}
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
    if not MCP_TOKEN or token != MCP_TOKEN:
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
        return HTMLResponse(f'<h2 style="color:#ef4444;font-family:system-ui">\u274c Agent not found: {agent_id}</h2>', status_code=404)

    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": client_id, "redirect_uri": redirect_uri,
        "code_challenge": code_challenge, "agent_id": agent_id,
        "expires": time.time() + 300,
    }
    sep = "&" if "?" in redirect_uri else "?"
    url = f"{redirect_uri}{sep}code={code}" + (f"&state={state}" if state else "")
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
    tok = secrets.token_urlsafe(48)
    access_tokens[tok] = {
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
