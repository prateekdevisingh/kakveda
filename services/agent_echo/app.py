from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Request

app = FastAPI(title="agent-echo", version="0.1.0")

AGENT_NAME = os.environ.get("AGENT_NAME", "agent-echo")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": AGENT_NAME,
        "status": "healthy",
    }


@app.get("/capabilities")
async def capabilities() -> dict[str, Any]:
    return {
        "name": AGENT_NAME,
        "capabilities": ["echo"],
        "events_in": ["*"],
        "events_out": ["echo"],
    }


@app.post("/invoke")
async def invoke(request: Request) -> dict[str, Any]:
    body = await request.json()
    event_type = str(body.get("event_type") or "unknown")
    payload = body.get("payload")

    out_event = {
        "event_type": "echo",
        "payload": {
            "received_event_type": event_type,
            "received_payload": payload,
            "agent": AGENT_NAME,
        },
    }

    return {"status": "ok", "events": [out_event]}
