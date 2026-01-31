from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class TracePayload(BaseModel):
    trace_id: str
    ts: datetime
    app_id: str
    agent_id: str | None = None

    prompt: str
    response: str

    model: str | None = None
    temperature: float | None = None

    tools: List[str] = Field(default_factory=list)
    env: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    trace: TracePayload


class FailureSignal(BaseModel):
    trace_id: str
    ts: datetime
    app_id: str

    failure_type: str
    severity: Severity

    root_cause: Optional[str] = None
    mitigation: Optional[str] = None

    context_signature: Dict[str, Any]


class CanonicalFailureRecord(BaseModel):
    failure_id: str
    version: int
    created_at: datetime
    updated_at: datetime

    failure_type: str
    root_cause: Optional[str] = None
    context_signature: Dict[str, Any]

    impact_severity: Severity
    resolution: Optional[str] = None

    # app-agnostic, but we can keep occurrences for analytics
    occurrences: int = 0
    affected_apps: List[str] = Field(default_factory=list)

    # similarity helpers
    signature_text: str


class FailureMatchRequest(BaseModel):
    signature_text: str
    failure_type: Optional[str] = None


class FailureMatch(BaseModel):
    failure_id: str
    version: int
    score: float
    failure_type: str
    suggested_mitigation: Optional[str] = None


class FailureMatchResponse(BaseModel):
    matches: List[FailureMatch]


class PatternEntity(BaseModel):
    pattern_id: str
    name: str
    created_at: datetime
    failure_ids: List[str]
    affected_apps: List[str]
    description: Optional[str] = None


class WarningRequest(BaseModel):
    app_id: str
    agent_id: Optional[str] = None
    prompt: str
    tools: List[str] = Field(default_factory=list)
    env: Dict[str, Any] = Field(default_factory=dict)


class WarningResponse(BaseModel):
    action: str  # block | warn | silent
    confidence: float
    pattern_id: Optional[str] = None
    references: List[FailureMatch] = Field(default_factory=list)
    message: str


class HealthPoint(BaseModel):
    ts: datetime
    app_id: str
    score: float
    failure_rate: float
    recurrent_penalty: float
    avg_recovery_time_sec: float
    notes: Dict[str, Any] = Field(default_factory=dict)
