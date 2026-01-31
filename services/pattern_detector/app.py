from __future__ import annotations

import os

import httpx
from fastapi import FastAPI

from services.shared.config import ConfigStore
from services.shared.fingerprint import signature_text


EVENT_BUS_URL = os.environ.get("EVENT_BUS_URL", "http://localhost:8100")
GFKB_URL = os.environ.get("GFKB_URL", "http://localhost:8101")

app = FastAPI(title="Pattern Detection Service")
config = ConfigStore()


@app.on_event("startup")
async def _subscribe():
    async with httpx.AsyncClient(timeout=3.0) as client:
        await client.post(
            f"{EVENT_BUS_URL}/subscribe",
            json={"topic": "failure.detected", "callback_url": "http://pattern-detector:8104/events/failure"},
        )


@app.post("/events/failure")
async def on_failure(event: dict):
    # Create/Update pattern when same failure spans multiple apps.
    failure_type = event.get("failure_type")
    app_id = event.get("app_id")

    if failure_type != "HALLUCINATION_CITATION":
        return {"ok": True, "ignored": True}

    # Pull failures from GFKB and group by failure_type; if affected_apps >= 2 → create or update named pattern entity
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(f"{GFKB_URL}/failures")
        failures = resp.json().get("failures", [])

        relevant = [f for f in failures if f.get("failure_type") == failure_type]
        affected = sorted(set(sum([f.get("affected_apps", []) for f in relevant], [])))
        failure_ids = sorted(set([f.get("failure_id") for f in relevant if f.get("failure_id")] ))

        if len(affected) < 2:
            return {"ok": True, "pattern": None}

        name = "Citation hallucination without sources"
        await client.post(
            f"{GFKB_URL}/patterns/upsert",
            json={
                "name": name,
                "failure_ids": failure_ids,
                "affected_apps": affected,
                "description": "Same prompt pattern causes hallucinated citations across apps",
            },
        )

    return {"ok": True, "pattern_created_or_updated": True, "name": name, "affected_apps": affected}
