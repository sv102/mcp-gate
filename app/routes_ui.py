"""routes_ui.py — HTML page routes for MCP Gate WebUI."""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from constants import VERSION
import storage
import ssh_client

router = APIRouter(tags=["ui"])
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def ui_root(r: Request):
    c = storage.load_config()
    return RedirectResponse("/bootstrap" if not c.get("bootstrap_done") else "/dashboard")

@router.get("/bootstrap", response_class=HTMLResponse)
async def ui_boot(r: Request):
    return templates.TemplateResponse("bootstrap.html",
        {"request": r, "done": storage.load_config().get("bootstrap_done", False)})

@router.get("/dashboard", response_class=HTMLResponse)
async def ui_dash(r: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": r, "hosts": storage.load_hosts(), "agents": storage.load_agents(),
        "recent": storage.load_audit(limit=10), "pending": storage.get_pending_approvals(),
        "version": VERSION})

@router.get("/hosts", response_class=HTMLResponse)
async def ui_hosts(r: Request):
    return templates.TemplateResponse("hosts.html", {
        "request": r, "hosts": storage.load_hosts(), "pub_key": ssh_client.get_public_key(),
        "command_sets": storage.load_command_sets()})

@router.get("/agents", response_class=HTMLResponse)
async def ui_agents(r: Request):
    return templates.TemplateResponse("agents.html", {
        "request": r, "agents": storage.load_agents(),
        "agent_types": storage.get_agent_types(), "version": VERSION})

@router.get("/command-sets", response_class=HTMLResponse)
async def ui_sets(r: Request):
    return templates.TemplateResponse("command_sets.html", {
        "request": r, "sets": storage.load_command_sets(), "hosts": storage.load_hosts(),
        "agents": storage.load_agents()})

@router.get("/console", response_class=HTMLResponse)
async def ui_con(r: Request):
    return templates.TemplateResponse("console.html", {"request": r, "hosts": storage.load_hosts()})

@router.get("/audit", response_class=HTMLResponse)
async def ui_audit(r: Request):
    return templates.TemplateResponse("audit.html", {"request": r})

@router.get("/approvals", response_class=HTMLResponse)
async def ui_appr(r: Request):
    return templates.TemplateResponse("approvals.html", {
        "request": r, "pending": storage.get_pending_approvals()})

@router.get("/secrets", response_class=HTMLResponse)
async def ui_sec(r: Request):
    return templates.TemplateResponse("secrets.html", {"request": r})

@router.get("/alerts", response_class=HTMLResponse)
async def ui_alerts(r: Request):
    return templates.TemplateResponse("alerts.html", {"request": r})

@router.get("/settings", response_class=HTMLResponse)
async def ui_set(r: Request):
    return templates.TemplateResponse("settings.html", {"request": r})

@router.get("/appearance", response_class=HTMLResponse)
async def ui_app(r: Request):
    return templates.TemplateResponse("appearance.html", {"request": r})

@router.get("/guide", response_class=HTMLResponse)
async def ui_guide(r: Request):
    return templates.TemplateResponse("guide.html", {"request": r, "version": VERSION})

@router.get("/about", response_class=HTMLResponse)
async def ui_about(r: Request):
    c = storage.load_config()
    sz = storage.AUDIT_FILE.stat().st_size if storage.AUDIT_FILE.exists() else 0
    return templates.TemplateResponse("about.html", {
        "request": r, "version": VERSION,
        "bootstrap_done": c.get("bootstrap_done", False),
        "telegram_enabled": c.get("telegram", {}).get("enabled", False),
        "smtp_enabled": c.get("smtp", {}).get("enabled", False),
        "audit_size": sz, "hosts_count": len(storage.load_hosts()),
        "sets_count": len(storage.load_command_sets()),
        "agents_count": len(storage.load_agents()),
        "secrets_count": len(storage.load_secrets()),
        "data_dir": str(storage.DATA_DIR)})

@router.get("/logout", response_class=HTMLResponse)
async def ui_logout():
    return HTMLResponse(
        '<html><body style="background:#0f1117;color:#e0e0e0;font-family:sans-serif;'
        'display:flex;align-items:center;justify-content:center;height:100vh">'
        '<div style="text-align:center"><h2>Logged out</h2>'
        '<p style="margin-top:16px"><a href="/" style="color:#818cf8">Login</a></p>'
        '</div></body></html>',
        status_code=401, headers={"WWW-Authenticate": 'Basic realm="MCP Gate"'})


@router.get("/login")
async def login_page(request: Request):
    import auth as _auth
    if _auth.check_request(request):
        return RedirectResponse("/", status_code=302)
    lang = storage.load_config().get("instance", {}).get("language", "ru")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "i18n": storage.load_i18n(lang),
        "lang": lang,
        "needs_setup": _auth.needs_setup(),
        "appearance": storage.load_config().get("appearance", storage._default_appearance()),
    })
