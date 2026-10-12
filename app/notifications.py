# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""
notifications.py — Telegram + SMTP alerts for mcp-gate.

Changes vs previous:
  - Per-channel cooldown: Telegram and SMTP each have independent cooldown tracking.
    Previously only Telegram had cooldown; SMTP could flood on blocked-command storms.
  - _last_sent now keyed by "{channel}:{event_type}" instead of "{event_type}".
"""

import time
import email.message
from typing import Optional

import httpx
import aiosmtplib

from storage import load_config

# Cooldown cache: "{channel}:{event_type}" → last_sent_ts
_last_sent: dict[str, float] = {}

_TYPE_MAP = {
    "blocked": "notify_blocked",
    "error": "notify_errors",
    "approval": "notify_approvals",
}


def _check_cooldown(channel: str, event_type: str, cooldown_seconds: int) -> bool:
    """Returns True if OK to send (not in cooldown). Updates last_sent on True."""
    if event_type in ("approval", "ops"):  # SV_MCPGATE_OPS
        # Approvals are always sent (no cooldown — operator needs to act)
        return True
    key = f"{channel}:{event_type}"
    last = _last_sent.get(key, 0)
    if time.time() - last < cooldown_seconds:
        return False
    _last_sent[key] = time.time()
    return True


async def send_telegram(text, token=None, chat_id=None):
    cfg = load_config().get("telegram", {})
    token = token or cfg.get("bot_token", "")
    chat_id = chat_id or cfg.get("chat_id", "")
    if not token or not chat_id:
        return {"ok": False, "error": "Telegram not configured"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={
                "chat_id": chat_id, "text": text,
                "parse_mode": "HTML", "disable_web_page_preview": True,
            })
            return resp.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def send_smtp(subject, body, **overrides):
    cfg = load_config().get("smtp", {})
    host = overrides.get("smtp_host") or cfg.get("host", "")
    port = overrides.get("smtp_port") or cfg.get("port", 587)
    user = overrides.get("smtp_user") or cfg.get("user", "")
    password = overrides.get("smtp_password") or cfg.get("password", "")
    from_addr = overrides.get("smtp_from") or cfg.get("from_addr", "") or user
    to_addr = overrides.get("smtp_to") or cfg.get("to_addr", "")
    tls = cfg.get("use_tls", True)
    if not host or not to_addr:
        return {"ok": False, "error": "SMTP not configured"}
    msg = email.message.EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        kwargs = {"hostname": host, "port": port, "timeout": 15}
        if tls:
            kwargs["use_tls"] = (port == 465)
            kwargs["start_tls"] = (port != 465)
        await aiosmtplib.send(msg, **kwargs,
                              username=user if user else None,
                              password=password if password else None)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def notify(event_type: str, text: str) -> dict:
    """Legacy entry point (approval / ops / blocked): routed through events —
    outbox → notify-gate, Telegram/SMTP as fallback or in parallel (Notifications page)."""  # SV_MCPGATE_020
    import html as _html, re as _re
    import events
    lines = _html.unescape(_re.sub(r"<[^>]+>", "", text)).strip().split("\n")
    if len(lines) > 1 and lines[0] in ("Blocked", "Pending"):
        lines = lines[1:]
    ev = {"approval": "approval", "ops": "grant", "blocked": "blocked", "error": "blocked"}.get(event_type, "system")
    events.emit(ev, lines[0][:160], "\n".join(lines[1:]), agg=lines[0] if ev == "blocked" else None)
    return {"queued": ev}
