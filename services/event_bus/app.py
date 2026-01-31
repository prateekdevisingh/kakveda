from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from fastapi import FastAPI
from pydantic import BaseModel

from services.shared.config import ConfigStore


class SubscribeRequest(BaseModel):
    topic: str
    callback_url: str


class PublishRequest(BaseModel):
    topic: str
    event: Dict[str, Any]


app = FastAPI(title="Event Bus (Demo)")
config = ConfigStore()

_subscribers: Dict[str, List[str]] = {}


@app.post("/subscribe")
def subscribe(req: SubscribeRequest):
    _subscribers.setdefault(req.topic, [])
    if req.callback_url not in _subscribers[req.topic]:
        _subscribers[req.topic].append(req.callback_url)
    return {"ok": True, "topic": req.topic, "subscribers": len(_subscribers[req.topic])}


@app.post("/publish")
async def publish(req: PublishRequest):
    # fan-out delivery; best-effort
    subs = list(_subscribers.get(req.topic, []))
    if not subs:
        return {"ok": True, "delivered": 0}

    import httpx

    async def _post(url: str):
        async with httpx.AsyncClient(timeout=3.0) as client:
            try:
                await client.post(url, json=req.event)
            except Exception:
                # demo: drop on floor
                return

    await asyncio.gather(*[_post(u) for u in subs])
    return {"ok": True, "delivered": len(subs)}


@app.get("/topics")
def topics():
    return {"topics": {k: len(v) for k, v in _subscribers.items()}}
