# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""executor.py — Unified command execution logic for MCP Gate.
Single source of truth: auth check → rate limit → params → approval → secrets → SSH → audit → broadcast.

Changes vs previous:
  - Rate limiting enforced: host.rate_limit and agent.rate_limit are now checked here.
    Previously the fields existed in models but were never evaluated.
"""

import asyncio
import functools
import time
import logging
from typing import Optional, Callable

import storage
import ssh_client
import params
import notifications
import app_state

log = logging.getLogger("mcp-gate.executor")


def get_approval_mode(host: dict, wl_entry: dict) -> str:
    return wl_entry.get("approval", host.get("approval_mode", "pessimistic"))


def get_exec_delay(host: dict, wl_entry: dict) -> float:
    return wl_entry.get("exec_delay", host.get("exec_delay", 0))


def execute_with_secrets(host: dict, cmd: str) -> dict:
    """Execute command via SSH with secret substitution and output scrubbing.
    Synchronous — must be called via asyncio.to_thread() from async contexts.
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
      blocked  — command denied (whitelist/deny/params/secrets/rate-limit)
      dry_run  — host in dry_run mode
      executed — command ran, "result" has SSH output
      pending  — queued for approval
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
        if not wl:
            entry = {"host_id": host["id"], "command": command, "source": source,
                     "status": "blocked", "reason": "not in whitelist"}
            storage.append_audit(entry)
            await _bcast(entry)
            return {"action": "blocked", "reason": "not in whitelist", "entry": entry}
    else:
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

    # ── 2. Rate limiting ──
    # Checked after auth so rate limit violations are still auditable.
    if not check_whitelist_only:
        host_limit = host.get("rate_limit", 0)
        if not app_state.check_rate_limit(f"host:{host['id']}", host_limit):
            entry = {"host_id": host["id"], "command": command, "source": source,
                     "agent_id": agent_id, "status": "blocked",
                     "reason": f"rate limit exceeded (host: {host_limit}/min)"}
            storage.append_audit(entry)
            await _bcast(entry)
            return {"action": "blocked",
                    "reason": f"rate limit exceeded (host: {host_limit}/min)", "entry": entry}

        if agent:
            agent_limit = agent.get("rate_limit", 0)
            if not app_state.check_rate_limit(f"agent:{agent_id}", agent_limit):
                entry = {"host_id": host["id"], "command": command, "source": source,
                         "agent_id": agent_id, "status": "blocked",
                         "reason": f"rate limit exceeded (agent: {agent_limit}/min)"}
                storage.append_audit(entry)
                await _bcast(entry)
                return {"action": "blocked",
                        "reason": f"rate limit exceeded (agent: {agent_limit}/min)", "entry": entry}

    # ── 3. Parameterized command resolution ──
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

    # ── 4. Approval mode routing ──
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
            result = await asyncio.to_thread(execute_with_secrets, host, resolved_cmd)
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

    # ── 5. Queue for approval (pessimistic / optimistic / strict) ──
    timeout = host.get("approval_timeout", 300)
    item = {
        "host_id": host["id"], "command": command, "resolved": resolved_cmd,
        "source": source, "agent_id": agent_id, "approval_mode": mode,
        "timeout": timeout if mode != "strict" else 0,
    }
    aid = storage.add_to_queue(item)
    pending_event = {
        "host_id": host["id"], "command": command, "source": source,
        "agent_id": agent_id, "status": "pending", "approval_id": aid,
        "approval_mode": mode, "timeout": timeout if mode != "strict" else 0,
        "created_at": time.time(),
    }
    await _bcast(pending_event)
    await notifications.notify("approval",
                               f"Pending\n{host['id']}: {command}\nMode: {mode}")
    return {
        "action": "pending",
        "approval_id": aid,
        "approval_mode": mode,
        "expires_at": time.time() + timeout if mode != "strict" else None,
    }
