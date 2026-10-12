# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
"""routes_events.py — event settings, outbox journal, test send, request statistics, Prometheus /metrics."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

import events
import storage

router = APIRouter(tags=["events"])


@router.get("/api/admin/events/settings")
async def ev_settings():
    s = events.settings()
    cat = [{"id": k, "severity": v[0], "on_default": v[1], "title": events.title(k),
            "on": s["overrides"].get(k, {}).get("on", v[1]), "severity_set": s["overrides"].get(k, {}).get("severity", "")}
           for k, v in events.CATALOG.items()]
    return {"settings": {k: v for k, v in s.items() if k != "overrides"}, "catalog": cat, "status": events.status(),
            "severities": events.SEVERITIES}


@router.put("/api/admin/events/settings")
async def ev_settings_put(req: Request):
    try:
        new = events.validate(await req.json())
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))
    c = storage.load_config()
    c["events"] = new
    storage.save_config(c)
    storage.append_audit({"command": "update event settings", "source": "admin", "status": "ok", "host_id": "-"})
    return {"status": "updated"}


@router.get("/api/admin/events/outbox")
async def ev_outbox(limit: int = 50):
    return events.outbox(limit)


@router.post("/api/admin/events/test")
async def ev_test():
    events._enqueue("system", "info", events.title("system") + ": TEST", "mcp-gate → notify-gate test")
    return {"status": "queued", **events.status()}


@router.get("/api/admin/stats")
async def ev_stats(hours: int = 24):
    return events.stats(hours)


@router.get("/metrics")
async def ev_metrics(req: Request):
    if not events.metrics_allowed(req):
        raise HTTPException(403)
    return PlainTextResponse(events.metrics_text(), media_type="text/plain; version=0.0.4")
