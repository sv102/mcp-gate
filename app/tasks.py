# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""tasks.py — Background tasks for MCP Gate: approval loop, audit trim, host ping.

Changes vs previous:
  - approval_loop: calls app_state.signal_approval(aid) after resolving expired items
    so mcp_transport handlers waiting on asyncio.Event are woken immediately.
  - cleanup_expired now sets status "approved"/"rejected" (was "approve"/"reject") —
    consistency fix for mcp_transport status checks.
"""
import asyncio
import logging
import time

import storage
import ssh_client
import executor
import app_state

log = logging.getLogger("mcp-gate.tasks")


async def approval_loop():
    """Process expired approval queue items and signal waiting MCP handlers."""
    await asyncio.sleep(5)
    while True:
        try:
            for it in storage.cleanup_expired():
                aid = it["approval_id"]
                auto = it.get("auto_resolved", "")

                if auto == "timeout_approve":
                    h = storage.get_host(it["host_id"])
                    if h:
                        # Re-check authorization (whitelist may have changed since queuing)
                        _agent = storage.get_agent(it.get("agent_id")) if it.get("agent_id") else None
                        _ok, _reason = storage.check_command_authorized(h, _agent, it["command"])
                        if not _ok:
                            e = {"host_id": it["host_id"], "command": it["command"],
                                 "source": "auto_approve_denied", "approval_id": aid,
                                 "status": "blocked", "reason": f"recheck: {_reason}"}
                            storage.update_queue_status(aid, "rejected")
                            storage.append_audit(e)
                            await app_state.ws_broadcast(e)
                            app_state.signal_approval(aid)
                            continue

                        d = h.get("exec_delay", 0)
                        if d > 0:
                            await asyncio.sleep(d)
                        r = await asyncio.to_thread(
                            executor.execute_with_secrets, h, it.get("resolved", it["command"])
                        )
                        e = {"host_id": it["host_id"], "command": it["command"],
                             "source": "auto_approve", "approval_id": aid, **r}
                        storage.update_queue_status(aid, "approved")
                        storage.append_audit(e)
                        await app_state.ws_broadcast(e)

                elif auto == "timeout_reject":
                    e = {"host_id": it["host_id"], "command": it["command"],
                         "source": "auto_reject", "approval_id": aid,
                         "status": "rejected", "reason": "Timeout"}
                    storage.update_queue_status(aid, "rejected")
                    storage.append_audit(e)
                    await app_state.ws_broadcast(e)

                # Wake up any mcp_transport handler waiting on this approval
                app_state.signal_approval(aid)

        except Exception as x:
            log.error(f"approval: {x}")
        await asyncio.sleep(5)


async def trim_loop():
    """Periodic audit trim and retention cleanup."""
    while True:
        await asyncio.sleep(3600)
        try:
            t = storage.trim_audit()
            if t:
                log.info(f"Trimmed {t}")
            cfg = storage.load_config()
            d = cfg.get("audit_retention_days", 90)
            if d > 0:
                r = storage.apply_retention(d)
                if r:
                    log.info(f"Retention removed {r} ({d}d)")
        except Exception as x:
            log.error(f"trim: {x}")


async def ping_loop():
    """Periodic SSH connectivity check for all hosts."""
    await asyncio.sleep(10)
    while True:
        try:
            intv = storage.load_config().get("instance", {}).get("ping_interval", 60)
            for h in storage.load_hosts():
                hid = h["id"]
                if not h.get("enabled", True):
                    app_state.host_status[hid] = {"ok": False, "msg": "disabled",
                                                   "ms": 0, "ts": time.time()}
                    continue
                try:
                    t0 = time.time()
                    r = await asyncio.to_thread(ssh_client.test_connection, h)
                    ms = int((time.time() - t0) * 1000)
                    app_state.host_status[hid] = {"ok": r.get("ok", False),
                                                   "msg": r.get("message", ""),
                                                   "ms": ms, "ts": time.time()}
                except Exception as x:
                    app_state.host_status[hid] = {"ok": False, "msg": str(x),
                                                   "ms": 0, "ts": time.time()}
            await asyncio.sleep(max(10, intv))
        except Exception as x:
            log.error(f"ping: {x}")
            await asyncio.sleep(60)
