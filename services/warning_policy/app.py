from __future__ import annotations

import os

import httpx
from fastapi import FastAPI

from services.shared.config import ConfigStore
from services.shared.fingerprint import signature_text
from services.shared.models import FailureMatchRequest, WarningRequest, WarningResponse


GFKB_URL = os.environ.get("GFKB_URL", "http://localhost:8101")

app = FastAPI(title="Warning & Policy Service")
config = ConfigStore()


@app.post("/warn", response_model=WarningResponse)
async def warn(req: WarningRequest):
    cfg = config.get()
    threshold = float((cfg.get("failure_matching") or {}).get("similarity_threshold", 0.8))

    sig_txt = signature_text(req.prompt, req.tools, req.env)

    async with httpx.AsyncClient(timeout=3.5) as client:
        m = await client.post(f"{GFKB_URL}/failures/match", json=FailureMatchRequest(signature_text=sig_txt).model_dump())
        matches = m.json().get("matches", [])

        best = matches[0] if matches else None
        score = float(best.get("score", 0.0)) if best else 0.0

        action_default = (cfg.get("warning_policy") or {}).get("default_action", "warn")

        # Try to attach a pattern_id if a known pattern includes this failure type.
        pattern_id = None
        try:
            presp = await client.get(f"{GFKB_URL}/patterns")
            patterns = presp.json().get("patterns", [])
            if best:
                bt = best.get("failure_type")
                # heuristic: our demo pattern name is stable
                for p in reversed(patterns):
                    if p.get("name") == "Citation hallucination without sources" and bt == "HALLUCINATION_CITATION":
                        pattern_id = p.get("pattern_id")
                        break
        except Exception:
            pattern_id = None

        # Policy (config driven)
        action = action_default
        if best and score >= threshold:
            msg = (
                f"This execution matches past failure type {best.get('failure_type')} "
                f"(failure_id={best.get('failure_id')}, similarity={score:.2f}). "
                f"Suggested mitigation: {best.get('suggested_mitigation') or 'n/a'}"
            )
            return WarningResponse(
                action=action,
                confidence=score,
                pattern_id=pattern_id,
                references=[best],
                message=msg,
            )

    return WarningResponse(
        action="silent" if action_default == "silent" else "warn",
        confidence=score,
        pattern_id=pattern_id,
        references=[],
        message="No high-similarity match found in GFKB.",
    )
