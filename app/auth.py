#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""
MCP Gate — App-level authentication module.

auth_type modes (config.yaml → instance.auth_type):
  "none"  — no auth, all requests pass (homelab behind VPN)
  "basic" — built-in login with bcrypt password + signed session cookie
  "proxy" — trust reverse proxy header (X-Forwarded-User / X-Forwarded-Email)
  any other value (e.g. "authentik") — treated as "proxy"

Session: HMAC-SHA256 signed cookie, configurable expiry.
Password: bcrypt hash in config.yaml → instance.admin_password_hash.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional

import bcrypt
from fastapi import Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse

import storage

# ── Constants ──
SESSION_COOKIE = "mcp_session"
SESSION_MAX_AGE = 86400 * 7  # 7 days

def _get_secret() -> bytes:
    """Derive session signing key from Fernet secrets key (stable, unique per instance)."""
    key_file = storage.SECRETS_KEY_FILE
    if key_file.exists():
        material = key_file.read_bytes()
    else:
        material = os.environ.get("MCP_TOKEN", "mcp-gate-default").encode()
    return hashlib.sha256(b"mcp-gate-session:" + material).digest()


def _sign_session(data: dict) -> str:
    """Create signed session token."""
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    sig = hmac.new(_get_secret(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}.{sig}"


def _verify_session(token: str) -> Optional[dict]:
    """Verify and decode session token. Returns None if invalid."""
    try:
        payload, sig = token.rsplit(".", 1)
        expected = hmac.new(_get_secret(), payload.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


def get_auth_type() -> str:
    """Get current auth mode from config."""
    cfg = storage.load_config()
    return cfg.get("instance", {}).get("auth_type", "basic")


def get_password_hash() -> str:
    """Get stored admin password hash."""
    cfg = storage.load_config()
    return cfg.get("instance", {}).get("admin_password_hash", "")


def set_password(password: str) -> str:
    """Hash and store admin password. Returns hash."""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cfg = storage.load_config()
    inst = cfg.get("instance", {})
    inst["admin_password_hash"] = hashed
    cfg["instance"] = inst
    storage.save_config(cfg)
    return hashed


def verify_password(password: str) -> bool:
    """Verify password against stored hash."""
    stored = get_password_hash()
    if not stored:
        return False
    try:
        return bcrypt.checkpw(password.encode(), stored.encode())
    except Exception:
        return False


def create_session_cookie(response, username: str = "admin"):
    """Set signed session cookie on response."""
    token = _sign_session({
        "user": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_MAX_AGE,
    })
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,  # Allow HTTP for LAN access; Traefik handles HTTPS
    )
    return response


def clear_session_cookie(response):
    """Remove session cookie."""
    response.delete_cookie(SESSION_COOKIE)
    return response


def check_request(request: Request) -> Optional[str]:
    """
    Check if request is authenticated. Returns username or None.
    
    Logic by auth_type:
      "none"  → always returns "admin"
      "basic" → checks session cookie → returns username or None
      "proxy" → checks X-Forwarded-User header → returns username or None
    """
    auth_type = get_auth_type()
    
    if auth_type == "none":
        return "admin"
    
    if auth_type == "basic":
        token = request.cookies.get(SESSION_COOKIE, "")
        if token:
            data = _verify_session(token)
            if data:
                return data.get("user", "admin")
        return None
    
    # "proxy", "authentik", or any other — trust proxy headers
    user = (request.headers.get("X-Forwarded-User") or
            request.headers.get("X-Forwarded-Email") or
            request.headers.get("Remote-User"))
    return user or None


def needs_setup() -> bool:
    """Check if initial password setup is needed (auth_type=basic but no hash)."""
    return get_auth_type() == "basic" and not get_password_hash()
