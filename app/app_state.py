# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""app_state.py — Shared mutable state and helpers for MCP Gate.
Avoids circular imports: modules import from here, not from main.

Changes vs previous:
  - approval_events: dict[str, asyncio.Event] — event-based approval signalling
    (replaces 2s polling loop in mcp_transport; max wait now uses asyncio.wait_for)
  - create_approval_event / signal_approval helpers
  - ws_broadcast: asyncio.wait_for(timeout=2.0) — dead client protection
  - check_rate_limit: key is now arbitrary string (host:X / agent:X), limit=0 → unlimited
"""
import asyncio
import json as J
import re
import time
from typing import Optional
from fastapi import WebSocket, HTTPException
import bcrypt
import storage

# ═══ Mutable state ═══
ws_clients: set[WebSocket] = set()
host_status: dict[str, dict] = {}
rate_limit_cache: dict[str, list[float]] = {}

# approval_events: aid → asyncio.Event
# Lifecycle: created by mcp_transport before add_to_queue;
#            signalled by tasks.approval_loop (timeout) or routes_admin (manual).
approval_events: dict[str, asyncio.Event] = {}

_VALID_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


# ═══ Validation ═══

def validate_id(entity_id: str, entity_type: str):
    """Validate entity ID: lowercase alphanumeric, hyphens, underscores, 1-64 chars."""
    if not _VALID_ID.match(entity_id):
        raise HTTPException(400, f"Invalid {entity_type} ID: must match [a-z0-9][a-z0-9_-]{{0,63}}")


# ═══ Rate limiting ═══

def check_rate_limit(key: str, limit: int) -> bool:
    """Sliding-window rate limiter. Returns True if under limit, False if exceeded.
    key  : arbitrary cache key, e.g. 'host:pve1' or 'agent:claude-main'
    limit: max requests per 60s window. 0 = unlimited.
    """
    if limit <= 0:
        return True
    now = time.time()
    window = rate_limit_cache.setdefault(key, [])
    rate_limit_cache[key] = [t for t in window if now - t < 60]
    if len(rate_limit_cache[key]) >= limit:
        return False
    rate_limit_cache[key].append(now)
    return True


# ═══ Approval event helpers ═══

def create_approval_event(aid: str) -> asyncio.Event:
    """Register asyncio.Event for approval_id.
    Must be called BEFORE add_to_queue so the event exists when tasks signals it."""
    ev = asyncio.Event()
    approval_events[aid] = ev
    return ev


def signal_approval(aid: str):
    """Signal that approval_id has been resolved (any status).
    Wakes up mcp_transport handler waiting on the event.
    Called from: tasks.approval_loop, routes_admin manual approve/reject.
    """
    ev = approval_events.pop(aid, None)
    if ev:
        ev.set()


# ═══ WebSocket broadcast ═══

async def ws_broadcast(entry: dict):
    """Broadcast audit entry to all connected WebSocket clients.
    Uses asyncio.wait_for(timeout=2s) to protect against slow/dead clients.
    Dead connections are removed automatically.
    """
    if not ws_clients:
        return
    msg = J.dumps(entry, ensure_ascii=False)
    dead = set()
    for ws in list(ws_clients):
        try:
            await asyncio.wait_for(ws.send_text(msg), timeout=2.0)
        except (asyncio.TimeoutError, Exception):
            dead.add(ws)
    ws_clients.difference_update(dead)


# ═══ API key validation ═══

def validate_api_key(key: str) -> Optional[str]:
    """Validate API key. Returns agent_id or None.
    Checks global key (bcrypt) then per-agent keys (Fernet)."""
    if not key:
        return None
    h = storage.load_config().get("mcp_api_key_hash", "")
    if h and bcrypt.checkpw(key.encode(), h.encode()):
        return "__global__"
    return storage.verify_agent_key(key)
