# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""routes_auth.py — login with 2FA, enrollment, step-up, recovery codes, session revocation, security settings."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import auth
import events
import storage

router = APIRouter(tags=["auth"])


def _ip(req: Request) -> str:
    return storage.client_ip_var.get() or (req.client.host if req.client else "")


def _audit(cmd: str, status: str = "ok"):
    storage.append_audit({"command": cmd, "source": "admin", "status": status, "host_id": "-"})


def _origin(req: Request):
    if not auth.origin_ok(req):
        raise HTTPException(403, "Origin check failed")


def _full(req: Request) -> dict:
    s = auth.session(req) if auth.get_auth_type() == "basic" else {"u": "admin"}
    if not s or s.get("en"):
        raise HTTPException(401, "Login required")
    return s


def _stepped(req: Request):
    need = auth.stepup_needed(req)
    if need:
        raise HTTPException(*need)


@router.post("/api/auth/login")
async def login(req: Request):
    _origin(req)
    b, ip = await req.json(), _ip(req)
    pw, code = str(b.get("password", "")), str(b.get("code", "")).strip()
    if auth.get_auth_type() != "basic":
        raise HTTPException(400, "Login is handled by the reverse proxy")
    if auth.needs_setup():
        if len(pw) < 8:
            return JSONResponse({"error": "Password must be at least 8 characters"}, 400)
        auth.set_password(pw)
        _audit("admin password set (initial setup)")
        enroll = auth.setting("totp_required")
        return auth.set_session_cookie(JSONResponse({"status": "enroll" if enroll else "ok", "setup": True}),
                                       auth.new_session(enroll=enroll))
    if auth.locked(ip):
        return JSONResponse({"error": "Too many attempts, try later"}, 429)
    if not auth.verify_password(pw):
        auth.failed(ip)
        _audit("login failed", "blocked")
        return JSONResponse({"error": "Invalid credentials"}, 401)
    if auth.totp_active():
        trusted = auth.device_ok(req)
        if not code and not trusted:
            return JSONResponse({"status": "totp"}, 202)          # password ok, ask for the code
        if code and not auth.check_second_factor(code):
            auth.failed(ip)
            _audit("login failed: 2FA code", "blocked")
            return JSONResponse({"error": "Invalid 2FA code", "need": "totp"}, 401)
        auth.cleared(ip)
        _audit("login" + (" (remembered device)" if not code else ""))
        r = auth.set_session_cookie(JSONResponse({"status": "ok"}), auth.new_session())
        if code and b.get("remember") and auth.setting("trust_device_days"):
            auth.set_device_cookie(r)
        return r
    auth.cleared(ip)
    enroll = auth.get_auth_type() == "basic" and auth.setting("totp_required")
    _audit("login" + (" (2FA enrollment required)" if enroll else ""))
    return auth.set_session_cookie(JSONResponse({"status": "enroll" if enroll else "ok"}), auth.new_session(enroll=enroll))


@router.post("/api/auth/logout")
async def logout(req: Request):
    return auth.clear_session_cookie(JSONResponse({"status": "ok"}))


@router.get("/api/auth/status")
async def status(req: Request):
    return {"authenticated": auth.check_request(req) is not None, "needs_setup": auth.needs_setup(), **auth.status(req)}


@router.post("/api/auth/stepup")
async def stepup(req: Request):
    _origin(req)
    b, ip = await req.json(), _ip(req)
    if auth.locked(ip):
        raise HTTPException(429, "Too many attempts, try later")
    tok = auth.stepup(req, str(b.get("password", "")), str(b.get("code", "")))
    if not tok:
        auth.failed(ip)
        _audit("step-up failed", "blocked")
        events.emit("login_fail", f"step-up, {ip}", f"IP {ip}", agg=ip)
        raise HTTPException(401, "Invalid password or 2FA code")
    auth.cleared(ip)
    return auth.set_session_cookie(JSONResponse({"status": "ok", "until": auth._unsign(tok, "session")["su"]}), tok)


@router.get("/api/auth/stepup/ensure")
async def stepup_ensure(req: Request):
    _full(req)
    _stepped(req)
    return {"status": "ok"}


@router.post("/api/auth/change-password")
async def change_password(req: Request):
    _origin(req)
    _full(req)
    _stepped(req)
    b = await req.json()
    if not auth.verify_password(str(b.get("current_password", ""))):
        return JSONResponse({"error": "Current password incorrect"}, 403)
    if len(str(b.get("new_password", ""))) < 8:
        return JSONResponse({"error": "Password must be at least 8 characters"}, 400)
    auth.set_password(str(b["new_password"]))               # bumps epoch: every other session ends
    _audit("admin password changed")
    return auth.set_session_cookie(JSONResponse({"status": "ok"}), auth.new_session())


@router.post("/api/auth/totp/begin")
async def totp_begin(req: Request):
    _origin(req)
    s = auth.session(req)
    if not s:
        raise HTTPException(401, "Login required")
    if not s.get("en"):                                       # re-enrollment from Settings
        _stepped(req)
    return auth.totp_begin()


@router.post("/api/auth/totp/confirm")
async def totp_confirm(req: Request):
    _origin(req)
    s = auth.session(req)
    if not s:
        raise HTTPException(401, "Login required")
    codes = auth.totp_confirm(str((await req.json()).get("code", "")))
    if not codes:
        raise HTTPException(400, "Invalid code (or enrollment expired: start again)")
    c = storage.load_config()
    c["security"] = {**(c.get("security") or {}), "totp_required": True}
    storage.save_config(c)
    _audit("2FA enrolled")
    return auth.set_session_cookie(JSONResponse({"status": "ok", "recovery_codes": codes}), auth.new_session(s.get("su", 0)))


@router.post("/api/auth/totp/disable")
async def totp_disable(req: Request):
    _origin(req)
    _full(req)
    _stepped(req)
    auth.totp_disable()
    _audit("2FA disabled")
    return {"status": "ok"}


@router.post("/api/auth/recovery/regenerate")
async def recovery_regenerate(req: Request):
    _origin(req)
    _full(req)
    _stepped(req)
    if not auth.totp_enrolled():
        raise HTTPException(400, "2FA is not enrolled")
    _audit("2FA recovery codes regenerated")
    return {"recovery_codes": auth.recovery_regenerate()}


@router.post("/api/auth/sessions/revoke")
async def sessions_revoke(req: Request):
    _origin(req)
    _full(req)
    auth.bump_epoch()
    _audit("all sessions and remembered devices revoked")
    r = auth.clear_session_cookie(JSONResponse({"status": "ok"}))
    r.delete_cookie(auth.DEVICE_COOKIE, path="/api/auth/login")
    return r


@router.get("/api/admin/security")
async def security_get(req: Request):
    return {"settings": {k: auth.setting(k) for k in auth.SETTINGS}, "defs": auth.settings_defs(), "status": auth.status(req)}


@router.put("/api/admin/security")
async def security_put(req: Request):
    try:
        auth.save_settings(await req.json())
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))
    _audit("update security settings")
    return {"status": "updated"}
