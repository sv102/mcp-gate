"""main.py — MCP Gate v0.0.7 — SSH access control for LLM agents.
Author: Sergey (@sv_102) | License: AGPLv3 | github.com/sv102/mcp-gate"""
import asyncio, base64, csv, hashlib, io, json as J, logging, os, re, secrets as S, shlex, time
from contextlib import asynccontextmanager
from typing import Optional
import bcrypt
from fastapi import FastAPI, Request, HTTPException, Header, WebSocket, WebSocketDisconnect, File, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import storage, ssh_client, notifications, params
import mcp_transport
import executor
import app_state
import tasks
import routes_ui
import routes_admin
from models import ExecReq

log = logging.getLogger("mcp-gate")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
from constants import VERSION


# ═══ App Setup ═══

@asynccontextmanager
async def lifespan(a: FastAPI):
    storage.ensure_dirs()
    bg = [asyncio.create_task(f()) for f in (tasks.approval_loop, tasks.trim_loop, tasks.ping_loop)]
    log.info(f"mcp-gate v{VERSION} started")
    yield
    for t in bg:
        t.cancel()


app = FastAPI(title="MCP Gate", version=VERSION, lifespan=lifespan)
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.include_router(mcp_transport.router)
# ═══ Admin API auth middleware (defense-in-depth) ═══
@app.middleware("http")
async def admin_auth_middleware(request: Request, call_next):
    """App-level auth for /api/admin/* — defense-in-depth behind Traefik."""
    path = request.url.path
    if not path.startswith("/api/admin/"):
        return await call_next(request)
    # Trust Traefik's forwarded user if present
    if request.headers.get("X-Forwarded-User"):
        return await call_next(request)
    # Fallback: verify HTTP Basic Auth at app level
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            user, pwd = decoded.split(":", 1)
            cfg = storage.load_config()
            inst = cfg.get("instance", {})
            stored_hash = inst.get("admin_password_hash", "")
            if stored_hash and bcrypt.checkpw(pwd.encode(), stored_hash.encode()):
                return await call_next(request)
        except Exception:
            pass
    # If auth_type is "none" — allow without auth
    cfg = storage.load_config()
    if cfg.get("instance", {}).get("auth_type") == "none":
        return await call_next(request)
    return JSONResponse({"error": "Unauthorized"}, status_code=401,
                        headers={"WWW-Authenticate": "Basic realm=\"MCP Gate Admin\""})

app.include_router(routes_admin.router)
app.include_router(routes_ui.router)
mcp_transport.set_bcast(app_state.ws_broadcast)


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
        "status": "ok", "version": VERSION, "bootstrap": c.get("bootstrap_done", False),
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
    if not app_state.check_rate_limit(req.host_id, h.get("rate_limit", 10)):
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
    it = storage.resolve_approval(aid, "approve")
    if not it:
        raise HTTPException(404)
    h = storage.get_host(it["host_id"])
    if not h:
        raise HTTPException(404)
    r = executor.execute_with_secrets(h, it.get("resolved", it["command"]))
    e = {"host_id": it["host_id"], "command": it["command"], "source": "manual_approve",
         "approval_id": aid, **r}
    storage.append_audit(e)
    await app_state.ws_broadcast(e)
    return {"status": "approved", "result": r}


@app.post("/api/admin/reject/{aid}")
async def api_reject(aid: str):
    it = storage.resolve_approval(aid, "reject")
    if not it:
        raise HTTPException(404)
    e = {"host_id": it["host_id"], "command": it["command"], "source": "manual_reject",
         "approval_id": aid, "status": "rejected"}
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
    await ws.accept()
    app_state.ws_clients.add(ws)
    try:
        while True:
            await asyncio.sleep(25)
            await ws.send_json({"ping": True})
    except WebSocketDisconnect:
        pass
    finally:
        app_state.ws_clients.discard(ws)

