"""app_state.py — Shared mutable state and helpers for MCP Gate.
Avoids circular imports: modules import from here, not from main.
"""
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

_VALID_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


# ═══ Helpers ═══

def validate_id(entity_id: str, entity_type: str):
    """Validate entity ID: lowercase alphanumeric, hyphens, underscores, 1-64 chars."""
    if not _VALID_ID.match(entity_id):
        raise HTTPException(400, f"Invalid {entity_type} ID: must match [a-z0-9][a-z0-9_-]{{0,63}}")


def check_rate_limit(host_id: str, limit: int) -> bool:
    """Return True if under rate limit, False if exceeded."""
    now = time.time()
    window = rate_limit_cache.setdefault(host_id, [])
    rate_limit_cache[host_id] = [t for t in window if now - t < 60]
    if len(rate_limit_cache[host_id]) >= limit:
        return False
    rate_limit_cache[host_id].append(now)
    return True


async def ws_broadcast(entry: dict):
    """Broadcast audit entry to all connected WebSocket clients."""
    msg = J.dumps(entry, ensure_ascii=False)
    dead = set()
    for ws in ws_clients:
        try:
            await ws.send_text(msg)
        except:
            dead.add(ws)
    ws_clients.difference_update(dead)


def validate_api_key(key: str) -> Optional[str]:
    """Validate API key. Returns agent_id or None.
    Checks global key (bcrypt) then per-agent keys (Fernet)."""
    if not key:
        return None
    # Global key (bcrypt) — used by custom agents without OAuth
    h = storage.load_config().get("mcp_api_key_hash", "")
    if h and bcrypt.checkpw(key.encode(), h.encode()):
        return "__global__"
    # Per-agent keys (Fernet — reversible, cached)
    agent_id = storage.verify_agent_key(key)
    return agent_id
