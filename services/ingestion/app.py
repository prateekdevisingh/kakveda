from __future__ import annotations

import os
from fastapi import FastAPI
import httpx

from services.shared.models import IngestRequest


EVENT_BUS_URL = os.environ.get("EVENT_BUS_URL", "http://localhost:8100")

app = FastAPI(title="Trace Ingestion Service")


@app.post("/ingest")
async def ingest(req: IngestRequest):
    # normalize schema already done by Pydantic
    event = req.trace.model_dump(mode="json")
    async with httpx.AsyncClient(timeout=3.0) as client:
        await client.post(f"{EVENT_BUS_URL}/publish", json={"topic": "trace.ingested", "event": event})
    return {"ok": True, "trace_id": req.trace.trace_id}
