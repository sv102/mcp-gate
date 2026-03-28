"""
executor.py — Unified command execution logic for MCP Gate.
Single source of truth: auth check → params → approval → secrets → SSH → audit → broadcast.

Called from:
  - main.py api_exec()      (API key auth, rate limit done by caller)
  - main.py admin_exec()    (skip_approval=True, check_whitelist_only=True)
  - mcp_transport.py        (OAuth auth, host/agent filtering done by caller)
"""

import asyncio
import time
import logging
from typing import Optional, Callable

import storage
import ssh_client
import params
import notifications

log = logging.getLogger("mcp-gate.executor")


def get_approval_mode(host: dict, wl_entry: dict) -> str:
    """Get effective approval mode from whitelist entry or host default."""
    return wl_entry.get("approval", host.get("approval_mode", "pessimistic"))


def get_exec_delay(host: dict, wl_entry: dict) -> float:
    """Get effective execution delay from whitelist entry or host default."""
    return wl_entry.get("exec_delay", host.get("exec_delay", 0))


def execute_with_secrets(host: dict, cmd: str) -> dict:
    """Execute command via SSH with secret substitution and output scrubbing.

    Used by:
      - execute_command() for immediate execution
      - approval_loop / api_approve in main.py for deferred execution
    """
    resolved, scrub = storage.substitute_secrets(cmd, host["id"])
    result = ssh_client.execute(host, resolved)
    if scrub:
        for k in ("output", "stderr"):
            if result.get(k):
                result[k] = storage.scrub_output(result[k], scrub)
    return result


async def execute_command(
    host: dict,
    command: str,
    agent: Optional[dict],
    agent_id: str,
    source: str,
    args: Optional[dict] = None,
    skip_approval: bool = False,
    check_whitelist_only: bool = False,
    bcast_fn: Optional[Callable] = None,
) -> dict:
    """
    Unified command execution pipeline.

    Returns dict with "action" key:
      blocked  — command denied (whitelist/deny/params/secrets)
      dry_run  — host in dry_run mode
      executed — command ran, "result" has SSH output
      pending  — queued for approval

    Args:
        host:                 Host dict from storage
        command:              Raw command string
        agent:                Agent dict (None = global key or admin)
        agent_id:             Agent identifier for audit
        source:               Source label for audit
        args:                 Optional param args for parameterized commands
        skip_approval:        True for admin console (skip approval, still check whitelist)
        check_whitelist_only: True for admin (host whitelist only, no agent intersection/deny)
        bcast_fn:             Async WebSocket broadcast function
    """

    async def _bcast(entry):
        if bcast_fn:
            try:
                await bcast_fn(entry)
            except Exception:
                pass

    # ── 1. Authorization + find whitelist entry ──
    wl = storage.find_whitelist_entry(host, command)

    if check_whitelist_only:
        # Admin path: only check if command exists in effective whitelist
        if not wl:
            entry = {"host_id": host["id"], "command": command, "source": source,
                     "status": "blocked", "reason": "not in whitelist"}
            storage.append_audit(entry)
            await _bcast(entry)
            return {"action": "blocked", "reason": "not in whitelist", "entry": entry}
    else:
        # Full auth: INTERSECTION + DENY
        allowed, reason = storage.check_command_authorized(host, agent, command)
        if not allowed:
            entry = {"host_id": host["id"], "command": command, "source": source,
                     "agent_id": agent_id, "status": "blocked", "reason": reason}
            storage.append_audit(entry)
            await _bcast(entry)
            await notifications.notify("blocked",
                                       f"Blocked\n{host['id']}: {command}\n{reason}")
            return {"action": "blocked", "reason": reason, "entry": entry}

    if not wl:
        wl = {"cmd": command, "category": "read"}

    # ── 2. Parameterized command resolution ──
    resolved_cmd = command
    if params.entry_has_params(wl):
        try:
            resolved_cmd = params.validate_and_substitute(wl, args)
        except ValueError as ve:
            entry = {"host_id": host["id"], "command": command, "source": source,
                     "agent_id": agent_id, "status": "blocked",
                     "reason": f"param: {ve}"}
            storage.append_audit(entry)
            await _bcast(entry)
            return {"action": "blocked", "reason": str(ve), "entry": entry}

    # ── 3. Approval mode routing ──
    mode = get_approval_mode(host, wl)
    delay = get_exec_delay(host, wl)

    # Dry run
    if host.get("dry_run") and not skip_approval:
        entry = {"host_id": host["id"], "command": command,
                 "resolved": resolved_cmd, "source": source,
                 "agent_id": agent_id, "status": "dry_run", "mode": mode}
        storage.append_audit(entry)
        await _bcast(entry)
        return {"action": "dry_run", "would_execute": resolved_cmd, "mode": mode}

    # Execute immediately if: admin (skip_approval) OR auto mode
    if skip_approval or mode == "auto":
        if delay > 0:
            await asyncio.sleep(delay)
        try:
            result = execute_with_secrets(host, resolved_cmd)
        except ValueError as ve:
            entry = {"host_id": host["id"], "command": command, "source": source,
                     "agent_id": agent_id, "status": "blocked", "reason": str(ve)}
            storage.append_audit(entry)
            await _bcast(entry)
            return {"action": "blocked", "reason": str(ve), "entry": entry}

        entry = {"host_id": host["id"], "command": command,
                 "resolved": resolved_cmd, "source": source,
                 "agent_id": agent_id, **result}
        storage.append_audit(entry)
        await _bcast(entry)
        return {"action": "executed", "result": result, "entry": entry}

    # ── 4. Queue for approval (pessimistic / optimistic / strict) ──
    timeout = host.get("approval_timeout", 300)
    aid = storage.add_to_queue({
        "host_id": host["id"], "command": command, "resolved": resolved_cmd,
        "source": source, "agent_id": agent_id, "approval_mode": mode,
        "timeout": timeout if mode != "strict" else 0,
    })
    await notifications.notify("approval",
                               f"Pending\n{host['id']}: {command}\nMode: {mode}")
    return {
        "action": "pending",
        "approval_id": aid,
        "approval_mode": mode,
        "expires_at": time.time() + timeout if mode != "strict" else None,
    }
