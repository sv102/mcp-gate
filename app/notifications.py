# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""
notifications.py — Telegram + SMTP alerts for mcp-gate.
"""

import time
import email.message
from typing import Optional

import httpx
import aiosmtplib

from storage import load_config

_last_sent: dict[str, float] = {}


async def send_telegram(text, token=None, chat_id=None):
    cfg = load_config().get("telegram", {})
    token = token or cfg.get("bot_token", "")
    chat_id = chat_id or cfg.get("chat_id", "")
    if not token or not chat_id:
        return {"ok": False, "error": "Telegram не настроен"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True})
            return resp.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def send_smtp(subject, body, **overrides):
    cfg = load_config().get("smtp", {})
    host = overrides.get("smtp_host") or cfg.get("host", "")
    port = overrides.get("smtp_port") or cfg.get("port", 587)
    user = overrides.get("smtp_user") or cfg.get("user", "")
    password = overrides.get("smtp_pass") or cfg.get("password", "")
    from_addr = overrides.get("smtp_from") or cfg.get("from_addr", "") or user
    to_addr = overrides.get("smtp_to") or cfg.get("to_addr", "")
    tls = cfg.get("use_tls", True)
    if not host or not to_addr:
        return {"ok": False, "error": "SMTP не настроен"}
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
        await aiosmtplib.send(msg, **kwargs, username=user if user else None, password=password if password else None)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def notify(event_type, text):
    results = {}
    cfg = load_config()
    type_map = {"blocked": "notify_blocked", "error": "notify_errors", "approval": "notify_approvals"}
    setting = type_map.get(event_type, "")
    if event_type != "approval":
        tg_cfg = cfg.get("telegram", {})
        cooldown = tg_cfg.get("cooldown_seconds", 300)
        last = _last_sent.get(event_type, 0)
        if time.time() - last < cooldown:
            return {"skipped": "cooldown"}
    _last_sent[event_type] = time.time()
    tg_cfg = cfg.get("telegram", {})
    if tg_cfg.get("enabled", False):
        if not setting or tg_cfg.get(setting, True):
            results["telegram"] = await send_telegram(text)
    smtp_cfg = cfg.get("smtp", {})
    if smtp_cfg.get("enabled", False):
        if not setting or smtp_cfg.get(setting, True):
            subject = f"MCP Gate: {event_type}"
            plain = text.replace("<b>", "").replace("</b>", "").replace("<code>", "").replace("</code>", "")
            results["smtp"] = await send_smtp(subject, plain)
    return results
