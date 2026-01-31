from __future__ import annotations

import json
import os
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict

import httpx
from fastapi import FastAPI

from services.shared.config import ConfigStore
from services.shared.models import HealthPoint, Severity


EVENT_BUS_URL = os.environ.get("EVENT_BUS_URL", "http://localhost:8100")
DATA_DIR = Path("/app/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HEALTH_FILE = DATA_DIR / "health.jsonl"

app = FastAPI(title="Health Scoring Service")
config = ConfigStore()

# in-memory rolling window per app (service is stateless-ish in design; demo keeps minimal state)
_fail_window: Dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=50))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _append(point: HealthPoint):
    with HEALTH_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(point.model_dump(mode="json"), ensure_ascii=False) + "\n")


@app.on_event("startup")
async def _subscribe():
    # Best-effort subscribe: in real systems we'd use a real broker.
    # Here we retry a few times so the service doesn't crash if event-bus isn't up yet.
    async def _try_subscribe() -> None:
        for attempt in range(1, 11):
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    await client.post(
                        f"{EVENT_BUS_URL}/subscribe",
                        json={"topic": "failure.detected", "callback_url": "http://health-scoring:8106/events/failure"},
                    )
                return
            except Exception:
                await asyncio.sleep(min(2.0, 0.2 * attempt))

    asyncio.create_task(_try_subscribe())


@app.post("/events/failure")
async def on_failure(event: dict):
    cfg = config.get()
    weights = (cfg.get("health_score") or {}).get("severity_weights", {"low": 1, "medium": 3, "high": 7})
    base = float((cfg.get("health_score") or {}).get("base_score", 100))

    app_id = event.get("app_id", "unknown")
    sev = str(event.get("severity", "low"))
    w = float(weights.get(sev, 1))

    _fail_window[app_id].append({"ts": event.get("ts"), "severity": sev, "weight": w, "failure_type": event.get("failure_type")})

    # compute simple score: base - weighted failures - recurrence penalty
    window = list(_fail_window[app_id])
    n = len(window)
    weighted = sum(x["weight"] for x in window)
    failure_rate = min(1.0, n / 10.0)  # demo assumption: 10 executions per window

    # recurrence penalty: repeated failure_type
    counts: Dict[str, int] = defaultdict(int)
    for x in window:
        counts[str(x.get("failure_type"))] += 1
    recurrent_penalty = sum(max(0, c - 1) for c in counts.values()) * 2.5

    # recovery time is not measured in this demo; keep as placeholder
    avg_recovery = 30.0 + 10.0 * recurrent_penalty

    score = max(0.0, base - (weighted * 5.0) - recurrent_penalty)
    point = HealthPoint(
        ts=_now(),
        app_id=app_id,
        score=score,
        failure_rate=failure_rate,
        recurrent_penalty=recurrent_penalty,
        avg_recovery_time_sec=avg_recovery,
        notes={"window_failures": n, "weighted": weighted, "top_failure": max(counts, key=counts.get) if counts else None},
    )
    _append(point)
    return {"ok": True, "health": point.model_dump()}


@app.get("/health/{app_id}")
def get_health(app_id: str):
    if not HEALTH_FILE.exists():
        return {"app_id": app_id, "points": []}
    pts = []
    for line in HEALTH_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("app_id") == app_id:
            pts.append(obj)
    return {"app_id": app_id, "points": pts[-50:]}
