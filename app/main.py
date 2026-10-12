# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""main.py — MCP Gate v0.1.0 — SSH access control for LLM agents.
Author: Sergey (@sv_102) | License: AGPLv3 | github.com/sv102/mcp-gate"""
import asyncio, csv, hashlib, io, json as J, logging, os, re, secrets as S, shlex, time
from contextlib import asynccontextmanager
from typing import Optional
import bcrypt
from fastapi import FastAPI, Request, HTTPException, Header, WebSocket, WebSocketDisconnect, File, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
os.umask(0o077)  # SV_MCPGATE_V015: every file written under /data is 0600
import storage, ssh_client, notifications, params
import auth
import mcp_transport
import executor
import app_state
import tasks
import routes_ui
import routes_admin
import routes_onboarding
import events, routes_events, routes_auth  # SV_MCPGATE_020
from models import ExecReq

log = logging.getLogger("mcp-gate")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
from constants import VERSION, full_version, DEV_BUILD


# ═══ App Setup ═══

@asynccontextmanager
async def lifespan(a: FastAPI):
    storage.ensure_dirs()
    events.init()  # SV_MCPGATE_020
    bg = [asyncio.create_task(f()) for f in (tasks.approval_loop, tasks.trim_loop, tasks.ping_loop, tasks.ops_expiry_loop, events.loop)]
    log.info(f"mcp-gate v{VERSION} started")
    yield
    for t in bg:
        t.cancel()


app = FastAPI(title="MCP Gate", version=VERSION, lifespan=lifespan)
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.include_router(mcp_transport.router)
app.include_router(routes_onboarding.router)
# ═══ Auth middleware ═══
_PUBLIC_PREFIXES = (
    "/health", "/static/", "/assets/", "/.well-known/",
    "/oauth/", "/sse", "/messages", "/mcp",
    "/api/exec", "/api/hosts", "/api/agent-types",
    "/api/auth/", "/login", "/favicon",
    "/metrics",  # SV_MCPGATE_020: CIDR-gated in routes_events
)

STEPUP = [  # SV_MCPGATE_020: (method, "*" = any non-GET; path regex) — need a fresh password + 2FA confirmation
    ("POST", r"/api/admin/agents"), ("POST", r"/api/admin/agents/[^/]+/generate-key"),
    ("*", r"/api/admin/secrets(/.*)?"), ("GET", r"/api/admin/(mcp-connection|backup)"), ("POST", r"/api/admin/restore"),
    ("*", r"/api/admin/(ssh/(rotate|generate)|bootstrap|exec)"), ("PUT", r"/api/admin/(security|telegram|smtp)"),
    ("DELETE", r"/api/admin/mcp-connection/sessions"),
]


def _needs_stepup(m: str, p: str) -> bool:
    return any((mm == m or (mm == "*" and m not in auth.SAFE)) and re.fullmatch(rx, p) for mm, rx in STEPUP)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path == "/" and request.method == "POST":                  # MCP transport (Bearer)
        return await call_next(request)
    if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return await call_next(request)
    user = auth.check_request(request)
    if not user:
        if path.startswith("/api/"):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return RedirectResponse(f"/login?next={path}", status_code=302)
    if auth.get_auth_type() == "basic":
        if not auth.origin_ok(request):
            return JSONResponse({"detail": "Origin check failed"}, status_code=403)
        if _needs_stepup(request.method, path) and (need := auth.stepup_needed(request)):
            return JSONResponse({"detail": need[1]}, status_code=need[0])
    request.state.user = user
    resp = await call_next(request)
    auth.refresh(request, resp)
    return resp

app.include_router(routes_events.router)
app.include_router(routes_auth.router)  # SV_MCPGATE_020
app.middleware("http")(events.middleware)  # SV_MCPGATE_020: outermost, sees the final status
app.include_router(routes_admin.router)
app.include_router(routes_ui.router)
mcp_transport.set_bcast(app_state.ws_broadcast)



# ═══ Auth ═══


# auth routes: routes_auth.py  # SV_MCPGATE_020


# ═══ Public API ═══


@app.get("/api/admin/mcp-connection")
async def get_mcp_connection():
    """MCP connection info for admin WebUI."""
    return {
        "mcp_token": os.environ.get("MCP_TOKEN", ""),
        "sse_url": os.environ.get("MCP_BASE_URL", "") + "/sse",
        "base_url": os.environ.get("MCP_BASE_URL", ""),
        "active_sessions": mcp_transport.get_active_sessions(),
    }

@app.delete("/api/admin/mcp-connection/sessions")
async def revoke_mcp_sessions():
    """Revoke all MCP OAuth sessions."""
    count = len(mcp_transport.access_tokens)
    mcp_transport.access_tokens.clear()
    mcp_transport._save_tokens({})
    return {"status": "revoked", "count": count}

@app.get("/health")
async def health():
    c = storage.load_config()
    return {
        "status": "ok", "version": full_version(), "bootstrap": c.get("bootstrap_done", False),
        "hosts": len(storage.load_hosts()), "sets": len(storage.load_command_sets()),
        "agents": len(storage.load_agents()), "secrets": len(storage.load_secrets()),
    }


@app.get("/api/hosts")
async def api_hosts():
    return [
        {"id": h["id"], "name": h.get("name", h["id"]), "group": h.get("group", ""),
         "whitelist": [
             {"cmd": w["cmd"], "category": w.get("category", "read"),
              "description": w.get("description", ""), "params": params.describe_params(w)}
             for w in storage.get_effective_whitelist(h)
         ]}
        for h in storage.load_hosts() if h.get("enabled", True)
    ]


@app.get("/api/agent-types")
async def api_agent_types():
    return storage.get_agent_types()


# ═══ Exec ═══


@app.post("/api/exec")
async def api_exec(req: ExecReq, x_api_key: str = Header("")):
    agent_id = app_state.validate_api_key(x_api_key)
    if not agent_id:
        raise HTTPException(401)
    h = storage.get_host(req.host_id)
    if not h:
        raise HTTPException(404, f"Host {req.host_id} not found")
    if not h.get("enabled", True):
        raise HTTPException(403, "Host disabled")
    if not app_state.check_rate_limit(f"host:{req.host_id}", h.get("rate_limit", 10)):
        e = {"host_id": req.host_id, "command": req.command, "source": req.source,
             "agent_id": agent_id, "status": "blocked", "reason": "rate_limit"}
        storage.append_audit(e)
        await app_state.ws_broadcast(e)
        return JSONResponse({"status": "blocked", "reason": "Rate limit"}, 429)

    agent = storage.get_agent(agent_id) if agent_id != "__global__" else None
    result = await executor.execute_command(
        host=h, command=req.command, agent=agent, agent_id=agent_id,
        source=req.source, args=req.args, bcast_fn=app_state.ws_broadcast,
    )
    action = result["action"]
    if action == "blocked":
        return JSONResponse({"status": "blocked", "reason": result["reason"]}, 403)
    elif action == "dry_run":
        return {"status": "dry_run", "would_execute": result["would_execute"], "mode": result["mode"]}
    elif action == "executed":
        return result["result"]
    elif action == "pending":
        return {"status": "pending", "approval_id": result["approval_id"],
                "approval_mode": result["approval_mode"], "expires_at": result.get("expires_at")}

@app.post("/api/admin/exec")
async def admin_exec(req: ExecReq):
    h = storage.get_host(req.host_id)
    if not h:
        raise HTTPException(404)
    result = await executor.execute_command(
        host=h, command=req.command, agent=None, agent_id="",
        source="admin_console", args=req.args,
        skip_approval=True, check_whitelist_only=True, bcast_fn=app_state.ws_broadcast,
    )
    action = result["action"]
    if action == "blocked":
        return JSONResponse({"status": "blocked", "reason": result["reason"]}, 403)
    elif action == "executed":
        return result["result"]

# ═══ Approvals ═══

@app.post("/api/admin/approve/{aid}")
async def api_approve(aid: str):
    q = storage.get_queue_item(aid) or {}  # SV_MCPGATE_016: never execute for an inactive agent
    qa = q.get("agent_id") or ""
    if q.get("status") == "pending" and qa not in ("", "__global__") and not storage.agent_active(storage.get_agent(qa)):
        it = storage.resolve_approval(aid, "rejected")
        app_state.signal_approval(aid)
        if it:
            e = {"host_id": it["host_id"], "command": it["command"], "source": "manual_approve_denied",
                 "approval_id": aid, "agent_id": qa, "status": "blocked", "reason": "agent inactive"}
            storage.append_audit(e)
            await app_state.ws_broadcast(e)
        raise HTTPException(409, "Agent is disabled or its grant expired: request rejected")
    it = storage.resolve_approval(aid, "approved")
    if not it:
        raise HTTPException(404, "Approval not found or already resolved")
    # SV_MCPGATE_V015: execute ONCE here, store the result, then wake the MCP waiter (no double exec)
    try:
        r = await asyncio.to_thread(executor.run_queued, it)
    except Exception as exc:
        r = {"status": "error", "error": str(exc), "duration_ms": 0}
    storage.set_queue_result(aid, r)
    app_state.signal_approval(aid)
    e = {"host_id": it["host_id"], "command": it["command"], "source": "manual_approve",
         "approval_id": aid, "agent_id": it.get("agent_id", ""), **r}
    storage.append_audit(e)
    await app_state.ws_broadcast(e)
    return {"status": "approved", "result": r}


@app.get("/api/admin/pending")
async def api_get_pending():
    """Return list of pending approval requests for nav badge init."""
    return storage.get_pending_approvals()


@app.post("/api/admin/reject/{aid}")
async def api_reject(aid: str):
    it = storage.resolve_approval(aid, "rejected")
    if not it:
        raise HTTPException(404, "Approval not found or already resolved")
    app_state.signal_approval(aid)  # wake mcp_transport event-wait immediately
    e = {"host_id": it["host_id"], "command": it["command"], "source": "manual_reject",
         "approval_id": aid, "agent_id": it.get("agent_id", ""), "status": "rejected"}
    storage.append_audit(e)
    await app_state.ws_broadcast(e)
    return {"status": "rejected"}


@app.get("/api/approval/{aid}")
async def api_approval_status(aid: str):
    for i in storage.load_queue():
        if i["approval_id"] == aid:
            return {"approval_id": aid, "status": i["status"],
                    "host_id": i.get("host_id"), "command": i.get("command")}
    raise HTTPException(404)




# ═══ WebSocket ═══

@app.websocket("/ws/audit")
async def ws_audit(ws: WebSocket):
    if not auth.check_request(ws):  # SV_MCPGATE_016: HTTP middleware does not cover WebSocket
        await ws.close(code=4401)
        return
    await ws.accept()
    app_state.ws_clients.add(ws)
    try:
        while True:
            await asyncio.sleep(25)
            await ws.send_json({"ping": True})
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        app_state.ws_clients.discard(ws)

