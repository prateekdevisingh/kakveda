from __future__ import annotations

import os
from datetime import datetime

import httpx
from fastapi import FastAPI

from services.shared.config import ConfigStore
from services.shared.fingerprint import detect_citation_markers, signature_text
from services.shared.models import FailureSignal, Severity, TracePayload


EVENT_BUS_URL = os.environ.get("EVENT_BUS_URL", "http://localhost:8100")
GFKB_URL = os.environ.get("GFKB_URL", "http://localhost:8101")

app = FastAPI(title="Failure Classification Service")
config = ConfigStore()


@app.on_event("startup")
async def _subscribe():
    async with httpx.AsyncClient(timeout=3.0) as client:
        await client.post(
            f"{EVENT_BUS_URL}/subscribe",
            json={"topic": "trace.ingested", "callback_url": "http://failure-classifier:8103/events/trace"},
        )


@app.post("/events/trace")
async def on_trace(trace: dict):
    t = TracePayload.model_validate(trace)

    # Demo rule classifier: if prompt asks for citations/references but response contains citation markers and user didn't provide sources.
    wants_citations = any(
        k in t.prompt.lower()
        for k in [
            "citation",
            "citations",
            "reference",
            "references",
            "provide references",
            "sources",
            "bibliography",
        ]
    )
    markers = detect_citation_markers(t.response)

    failure = None
    if wants_citations and markers.has_citation_markers:
        failure = FailureSignal(
            trace_id=t.trace_id,
            ts=t.ts,
            app_id=t.app_id,
            failure_type="HALLUCINATION_CITATION",
            severity=Severity.medium,
            root_cause="Model produced citations without provided sources",
            mitigation="Ask model to explicitly say 'no sources available' when none are provided",
            context_signature={
                "prompt_shape": t.prompt[:200],
                "model": t.model,
                "tools": t.tools,
                "env": t.env,
            },
        )

    if failure is None:
        return {"ok": True, "classified": False}

    sig_txt = signature_text(t.prompt, t.tools, t.env)

    # upsert into GFKB (versioned)
    async with httpx.AsyncClient(timeout=4.0) as client:
        await client.post(
            f"{GFKB_URL}/failures/upsert",
            json={
                "failure_type": failure.failure_type,
                "root_cause": failure.root_cause,
                "context_signature": failure.context_signature,
                "impact_severity": failure.severity,
                "resolution": failure.mitigation,
                "signature_text": sig_txt,
                "app_id": t.app_id,
            },
        )
        await client.post(
            f"{EVENT_BUS_URL}/publish",
            json={"topic": "failure.detected", "event": failure.model_dump(mode="json")},
        )

    return {"ok": True, "classified": True, "failure_type": failure.failure_type, "severity": failure.severity}
