# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""auth.py — admin authentication. instance.auth_type: basic (default) | proxy | none.

basic:
  * password: argon2id (a bcrypt hash from older versions is accepted once and re-hashed);
  * TOTP 2FA (RFC 6238, replay-protected) with one-time recovery codes and "remember this device";
    can be switched off in Settings → Security (step-up required); emergency reset: `python cli.py totp-reset`;
  * lockout per IP after N failures; stateless signed session with idle + absolute timeout; revocation by epoch;
  * step-up: password + TOTP re-check, valid N minutes, for sensitive actions (see main.STEPUP);
  * Origin check for state-changing requests; cookies HttpOnly + SameSite=Strict.
Settings: config.yaml → security; credentials: config.yaml → auth (TOTP secret encrypted with the master key).
Signing keys derive from MCPGATE_SESSION_KEY (.env)."""
import base64, hashlib, hmac, json, os, secrets, time
from typing import Optional
from urllib.parse import urlparse

import bcrypt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

import storage

SESSION_COOKIE, DEVICE_COOKIE = "mcp_session", "mcp_device"
SAFE = ("GET", "HEAD", "OPTIONS")
_SECURE_COOKIE = os.environ.get("SECURE_COOKIE", "0").lower() in ("1", "true", "yes")
_ph = PasswordHasher()
_fails: dict[str, list[float]] = {}
_totp_last = {"step": 0}
_RND = secrets.token_bytes(32)          # last resort: sessions do not survive a restart
# name: (default, min, max, EN label, RU label)
SETTINGS = {
    "totp_required": (True, None, None, "Require 2FA (TOTP) for admin login", "Требовать 2FA (TOTP) при входе"),
    "session_idle_min": (60, 5, 1440, "Session idle timeout, min", "Сессия без активности, мин"),
    "session_absolute_h": (12, 1, 720, "Session max lifetime, h", "Сессия максимум, ч"),
    "trust_device_days": (14, 0, 90, "Remember device for N days (0 = off)", "Запоминать устройство, дней (0 = нет)"),
    "lockout_attempts": (5, 3, 50, "Failed attempts before lockout", "Неудачных попыток до блокировки"),
    "lockout_minutes": (15, 1, 1440, "Lockout duration, min", "Блокировка, мин"),
    "stepup_minutes": (10, 1, 120, "Identity confirmation valid, min", "Подтверждение личности действует, мин"),
    "stepup_https_only": (False, None, None, "Sensitive actions only over HTTPS", "Чувствительные действия только по HTTPS"),
}


# ── keys / settings / stored credentials ──
def _key(purpose: str) -> bytes:
    base = (os.environ.get("MCPGATE_SESSION_KEY") or os.environ.get("MCPGATE_MASTER_KEY") or "").encode()
    if not base and storage.SECRETS_KEY_FILE.exists():
        base = storage.SECRETS_KEY_FILE.read_bytes()
    return hashlib.sha256(b"mcp-gate:" + purpose.encode() + b":" + (base or _RND)).digest()


def setting(name: str):
    d, lo, hi = SETTINGS[name][:3]
    v = (storage.load_config().get("security") or {}).get(name, d)
    try:
        v = (v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")) if isinstance(d, bool) else int(v)
    except (TypeError, ValueError):
        return d
    return v if lo is None or lo <= v <= hi else d


def settings_defs() -> list[dict]:
    ru = (storage.load_config().get("instance") or {}).get("language", "ru") == "ru"
    return [{"name": k, "type": "bool" if isinstance(v[0], bool) else "int", "default": v[0], "min": v[1], "max": v[2],
             "label": v[4] if ru else v[3]} for k, v in SETTINGS.items()]


def save_settings(d: dict) -> dict:
    out = {}
    for k, (dflt, lo, hi) in ((k, v[:3]) for k, v in SETTINGS.items()):
        v = d.get(k, setting(k))
        if isinstance(dflt, bool):
            v = v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
        else:
            v = int(v)
            if not lo <= v <= hi:
                raise ValueError(f"{k}: {lo}…{hi}")
        out[k] = v
    c = storage.load_config()
    c["security"] = out
    storage.save_config(c)
    return out


def _auth() -> dict:
    return storage.load_config().get("auth") or {}


def _save_auth(**kv):
    c = storage.load_config()
    a = c.get("auth") or {}
    a.update(kv)
    c["auth"] = {k: v for k, v in a.items() if v is not None}
    (c.get("instance") or {}).pop("admin_password_hash", None)   # moved to auth
    storage.save_config(c)


def epoch() -> int:
    return int(_auth().get("epoch", 0))


def bump_epoch():
    """Invalidate every session and remembered device."""
    _save_auth(epoch=epoch() + 1)


def get_auth_type() -> str:
    return (storage.load_config().get("instance") or {}).get("auth_type", "basic")


def get_password_hash() -> str:
    return _auth().get("password_hash") or (storage.load_config().get("instance") or {}).get("admin_password_hash", "")


def needs_setup() -> bool:
    return get_auth_type() == "basic" and not get_password_hash()


def set_password(password: str) -> str:
    h = _ph.hash(password)
    _save_auth(password_hash=h, epoch=epoch() + 1)
    return h


def verify_password(password: str) -> bool:
    h = get_password_hash()
    if not h or not password:
        return False
    if h.startswith("$2"):                                   # bcrypt from <=0.1.6: accept once, re-hash
        try:
            ok = bcrypt.checkpw(password.encode(), h.encode())
        except ValueError:
            return False
        if ok:
            _save_auth(password_hash=_ph.hash(password))
        return ok
    try:
        _ph.verify(h, password)
    except (VerificationError, InvalidHashError):
        return False
    if _ph.check_needs_rehash(h):
        _save_auth(password_hash=_ph.hash(password))
    return True


# ── TOTP ──
def totp_enrolled() -> bool:
    return bool(_auth().get("totp_enc"))


def totp_active() -> bool:
    return get_auth_type() == "basic" and setting("totp_required") and totp_enrolled()


def _check_code(secret: str, code: str) -> bool:
    code = (code or "").replace(" ", "")
    if not secret or not code.isdigit():
        return False
    t, now = pyotp.TOTP(secret), time.time()
    for off in (-1, 0, 1):
        ts = now + off * 30
        if hmac.compare_digest(t.at(ts), code):
            step = int(ts // 30)
            if step <= _totp_last["step"]:
                return False                                  # replayed code
            _totp_last["step"] = step
            return True
    return False


def check_second_factor(code: str) -> bool:
    """TOTP code or a one-time recovery code."""
    a = _auth()
    if a.get("totp_enc") and _check_code(storage._decrypt_value(a["totp_enc"]), code):
        return True
    code = (code or "").strip().lower()
    if len(code) >= 12:
        for h in a.get("recovery", []):
            try:
                _ph.verify(h, code)
            except (VerificationError, InvalidHashError):
                continue
            _save_auth(recovery=[x for x in a["recovery"] if x != h])
            return True
    return False


def totp_begin() -> dict:
    import segno
    secret = pyotp.random_base32()
    _save_auth(totp_pending_enc=storage._encrypt_value(secret), totp_pending_at=time.time())
    label = (storage.load_config().get("instance") or {}).get("app_url", "") or "mcp-gate"
    uri = pyotp.TOTP(secret).provisioning_uri(name="admin@" + (urlparse(label).netloc or label), issuer_name="MCP Gate")
    return {"secret": secret, "uri": uri, "svg": segno.make(uri, error="m").svg_inline(scale=5, dark="#000", light="#fff")}


def _new_recovery() -> list[str]:
    codes = ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(10)]
    _save_auth(recovery=[_ph.hash(c) for c in codes])
    return codes


def totp_confirm(code: str) -> Optional[list[str]]:
    a = _auth()
    if not a.get("totp_pending_enc") or time.time() - a.get("totp_pending_at", 0) > 900:
        return None
    secret = storage._decrypt_value(a["totp_pending_enc"])
    if not _check_code(secret, code):
        return None
    _save_auth(totp_enc=a["totp_pending_enc"], totp_pending_enc=None, totp_pending_at=None, totp_enrolled_at=time.time())
    return _new_recovery()


def totp_disable():
    _save_auth(totp_enc=None, recovery=None, totp_enrolled_at=None)
    c = storage.load_config()
    c["security"] = {**(c.get("security") or {}), "totp_required": False}
    storage.save_config(c)


def recovery_regenerate() -> list[str]:
    return _new_recovery()


# ── lockout ──
def locked(ip: str) -> bool:
    win = setting("lockout_minutes") * 60
    _fails[ip] = [t for t in _fails.get(ip, []) if time.time() - t < win]
    return len(_fails[ip]) >= setting("lockout_attempts")


def failed(ip: str):
    _fails.setdefault(ip, []).append(time.time())


def cleared(ip: str):
    _fails.pop(ip, None)


# ── signed tokens / sessions ──
def _sign(d: dict, purpose: str) -> str:
    p = base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode()
    return p + "." + hmac.new(_key(purpose), p.encode(), hashlib.sha256).hexdigest()


def _unsign(tok: str, purpose: str) -> Optional[dict]:
    try:
        p, s = (tok or "").rsplit(".", 1)
        if not hmac.compare_digest(s, hmac.new(_key(purpose), p.encode(), hashlib.sha256).hexdigest()):
            return None
        return json.loads(base64.urlsafe_b64decode(p))
    except (ValueError, TypeError):
        return None


def new_session(su: float = 0, iat: Optional[float] = None, enroll: bool = False) -> str:
    now = time.time()
    d = {"u": "admin", "ep": epoch(), "iat": iat or now, "last": now, "su": su}
    if enroll:
        d["en"] = 1                                           # password ok, 2FA enrollment pending
    return _sign(d, "session")


def _sign_session(data: dict) -> str:
    """Compatibility helper for tests/tools: a full session."""
    return new_session(iat=data.get("iat"))


def session(request) -> Optional[dict]:
    d = _unsign(request.cookies.get(SESSION_COOKIE, ""), "session")
    now = time.time()
    if not d or d.get("ep") != epoch() or now - d.get("iat", 0) > setting("session_absolute_h") * 3600 \
            or now - d.get("last", 0) > setting("session_idle_min") * 60:
        return None
    return d


def check_request(request) -> Optional[str]:
    """Authenticated admin user or None (a 2FA-enrollment session is not authenticated)."""
    t = get_auth_type()
    if t == "none":
        return "admin"
    if t == "basic":
        s = session(request)
        return s["u"] if s and not s.get("en") else None
    return (request.headers.get("X-Forwarded-User") or request.headers.get("X-Forwarded-Email")
            or request.headers.get("Remote-User") or None)


def set_session_cookie(resp, token: str):
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=_SECURE_COOKIE, path="/",
                    max_age=setting("session_absolute_h") * 3600)
    return resp


def create_session_cookie(response, username: str = "admin"):
    return set_session_cookie(response, new_session())


def clear_session_cookie(response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


def refresh(request, response):
    """Sliding idle timeout: page loads and changes extend the session, background polling does not."""
    if get_auth_type() != "basic" or (request.method == "GET" and request.url.path.startswith("/api/")):
        return
    s = session(request)
    if s and not s.get("en") and SESSION_COOKIE not in response.headers.get("set-cookie", ""):
        set_session_cookie(response, new_session(s.get("su", 0), s["iat"]))


def is_https(request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


def origin_ok(request) -> bool:
    if request.method in SAFE:
        return True
    o = request.headers.get("origin") or request.headers.get("referer") or ""
    return bool(o) and urlparse(o).netloc == request.headers.get("host", "")


def stepup_until(request) -> float:
    if get_auth_type() != "basic":
        return float("inf")
    s = session(request)
    return s.get("su", 0) if s else 0


def stepup_needed(request) -> Optional[tuple[int, str]]:
    """None if allowed, else (status, reason)."""
    if get_auth_type() != "basic":
        return None
    if setting("stepup_https_only") and not is_https(request):
        return 403, "This action is allowed only over HTTPS"
    if stepup_until(request) < time.time():
        return 428, "Confirm your identity: password + 2FA code"
    return None


def stepup(request, password: str, code: str) -> Optional[str]:
    """Token of a session with a fresh step-up, or None."""
    s = session(request)
    if not s or s.get("en") or not verify_password(password) or (totp_active() and not check_second_factor(code)):
        return None
    return new_session(time.time() + setting("stepup_minutes") * 60, s["iat"])


# ── remembered device (cookie only on /api/auth/login, own key, revoked by epoch) ──
def device_token() -> str:
    return _sign({"ep": epoch(), "exp": time.time() + setting("trust_device_days") * 86400}, "device")


def device_ok(request) -> bool:
    days = setting("trust_device_days")
    d = _unsign(request.cookies.get(DEVICE_COOKIE, ""), "device")
    now = time.time()
    return bool(days and d and d.get("ep") == epoch() and now < d.get("exp", 0) <= now + days * 86400 + 60)


def set_device_cookie(resp):
    resp.set_cookie(DEVICE_COOKIE, device_token(), httponly=True, samesite="strict", secure=_SECURE_COOKIE,
                    path="/api/auth/login", max_age=setting("trust_device_days") * 86400)


def status(request) -> dict:
    return {"auth_type": get_auth_type(), "totp": totp_enrolled(), "totp_required": setting("totp_required"),
            "recovery_left": len(_auth().get("recovery", [])), "stepup_until": stepup_until(request) if get_auth_type() == "basic" else 0,
            "trusted_device": device_ok(request)}
