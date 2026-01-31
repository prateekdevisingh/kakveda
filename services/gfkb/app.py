from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from services.shared.config import ConfigStore
from services.shared.models import (
    CanonicalFailureRecord,
    FailureMatch,
    FailureMatchRequest,
    FailureMatchResponse,
    PatternEntity,
    Severity,
)
from services.shared.similarity import SimilarityEngine


DATA_DIR = Path("/app/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

FAILURES_FILE = DATA_DIR / "failures.jsonl"
PATTERNS_FILE = DATA_DIR / "patterns.jsonl"

app = FastAPI(title="Global Failure Knowledge Base")
config = ConfigStore()
engine = SimilarityEngine()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _read_jsonl(path: Path) -> List[dict]:
    if not path.exists():
        return []
    out: List[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out


def _append_jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _load_failures() -> List[CanonicalFailureRecord]:
    rows = _read_jsonl(FAILURES_FILE)
    return [CanonicalFailureRecord.model_validate(r) for r in rows]


def _load_patterns() -> List[PatternEntity]:
    rows = _read_jsonl(PATTERNS_FILE)
    return [PatternEntity.model_validate(r) for r in rows]


class UpsertFailureRequest(BaseModel):
    failure_type: str
    root_cause: Optional[str] = None
    context_signature: Dict
    impact_severity: Severity
    resolution: Optional[str] = None
    signature_text: str
    app_id: str


@app.get("/failures")
def list_failures():
    return {"failures": [f.model_dump() for f in _load_failures()]}


@app.post("/failures/match", response_model=FailureMatchResponse)
def match(req: FailureMatchRequest):
    failures = _load_failures()
    if not failures:
        return FailureMatchResponse(matches=[])

    corpus = [f.signature_text for f in failures]
    scores = engine.score(req.signature_text, corpus)

    matches: List[FailureMatch] = []
    for f, s in sorted(zip(failures, scores), key=lambda x: x[1], reverse=True)[:5]:
        if req.failure_type and f.failure_type != req.failure_type:
            continue
        matches.append(
            FailureMatch(
                failure_id=f.failure_id,
                version=f.version,
                score=float(s),
                failure_type=f.failure_type,
                suggested_mitigation=f.resolution,
            )
        )

    return FailureMatchResponse(matches=matches)


@app.post("/failures/upsert")
def upsert(req: UpsertFailureRequest):
    failures = _load_failures()

    # "Versioned" by appending a new record when we update.
    existing = None
    for f in reversed(failures):
        if f.failure_type == req.failure_type and f.signature_text == req.signature_text:
            existing = f
            break

    if existing is None:
        failure_id = f"F-{len(failures)+1:04d}"
        rec = CanonicalFailureRecord(
            failure_id=failure_id,
            version=1,
            created_at=_now(),
            updated_at=_now(),
            failure_type=req.failure_type,
            root_cause=req.root_cause,
            context_signature=req.context_signature,
            impact_severity=req.impact_severity,
            resolution=req.resolution,
            occurrences=1,
            affected_apps=[req.app_id],
            signature_text=req.signature_text,
        )
        _append_jsonl(FAILURES_FILE, rec.model_dump(mode="json"))
        return {"ok": True, "created": True, "failure": rec.model_dump()}

    rec = existing.model_copy(deep=True)
    rec.version += 1
    rec.updated_at = _now()
    rec.occurrences += 1
    if req.app_id not in rec.affected_apps:
        rec.affected_apps.append(req.app_id)
    # allow evolving knowledge
    rec.root_cause = req.root_cause or rec.root_cause
    rec.resolution = req.resolution or rec.resolution
    rec.context_signature = req.context_signature or rec.context_signature

    _append_jsonl(FAILURES_FILE, rec.model_dump(mode="json"))
    return {"ok": True, "created": False, "failure": rec.model_dump()}


@app.get("/patterns")
def list_patterns():
    # De-duplicate for presentation: keep the latest record for each pattern_id (or, if missing, name).
    patterns = _load_patterns()
    latest: Dict[str, PatternEntity] = {}
    for p in patterns:
        key = p.pattern_id or p.name
        latest[key] = p
    return {"patterns": [p.model_dump() for p in latest.values()]}


class UpsertPatternRequest(BaseModel):
    name: str
    failure_ids: List[str]
    affected_apps: List[str]
    description: Optional[str] = None


@app.post("/patterns/upsert")
def upsert_pattern(req: UpsertPatternRequest):
    patterns = _load_patterns()

    # Simple heuristic: identity by name
    existing = None
    for p in reversed(patterns):
        if p.name == req.name:
            existing = p
            break

    if existing is None:
        pattern_id = f"FP-{len(patterns)+1:04d}"
        p = PatternEntity(
            pattern_id=pattern_id,
            name=req.name,
            created_at=_now(),
            failure_ids=list(sorted(set(req.failure_ids))),
            affected_apps=list(sorted(set(req.affected_apps))),
            description=req.description,
        )
        _append_jsonl(PATTERNS_FILE, p.model_dump(mode="json"))
        return {"ok": True, "created": True, "pattern": p.model_dump()}

    p = existing.model_copy(deep=True)
    p.failure_ids = list(sorted(set(p.failure_ids + req.failure_ids)))
    p.affected_apps = list(sorted(set(p.affected_apps + req.affected_apps)))
    p.description = req.description or p.description

    _append_jsonl(PATTERNS_FILE, p.model_dump(mode="json"))
    return {"ok": True, "created": False, "pattern": p.model_dump()}
