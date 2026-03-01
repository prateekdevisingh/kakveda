from __future__ import annotations

import os
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
import json
import yaml
import time
import uuid
import re
import fnmatch
from collections import defaultdict, deque
from urllib.parse import quote
import secrets
import hashlib
import sqlite3
import shutil
from pathlib import Path

import logging

import httpx
from fastapi import Depends, FastAPI, Form, Request, Query, UploadFile, File
import smtplib
from email.message import EmailMessage
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from auth import create_access_token, decode_access_token, hash_password, new_reset_token, verify_password
from db import (
    AuditEvent,
    Dataset,
    DatasetExample,
    Experiment,
    ExperimentRun,
    EvaluationResult,
    EvaluationRun,
    PasswordResetToken,
    PromptLibrary,
    PromptVersion,
    Project,
    ProjectApiKey,
    ProjectBudget,
    InfraDashboardLayout,
    NetraAgentConfig,
    TracePipelineConfig,
    ProjectRetentionPolicy,
    TraceSamplingRule,
    SpanMetricConfig,
    SpanMetricPoint,
    APMErrorGroup,
    APMErrorEvent,
    ProfilerSample,
    DynamicInstrumentationRule,
    DynamicInstrumentationFeedback,
    DBQuerySample,
    RUMEvent,
    RUMMonitor,
    APMMonitor,
    MonitorAlert,
    AgentRegistry,
    ProjectMember,
    Role,
    RunFeedback,
    Scenario,
    ScenarioRun,
    TraceRun,
    TraceSpan,
    User,
    UserRole,
    WarningEvent,
    get_session,
    init_db,
    migrate_db,
    utcnow,
)
from rbac import ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER, require_any
from shared.runtime import ensure_request_id, get_runtime_config, setup_logging
from shared.redis_helpers import RateLimiter, RevocationStore
from shared.otel import instrument_fastapi, setup_otel


# Shared runtime config for production toggles.
_RUNTIME = get_runtime_config(service_name="dashboard")

# --- SMTP config ---
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@localhost")
SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() in ("1", "true", "yes")

def send_email(to: str, subject: str, body: str) -> bool:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        return False
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            if SMTP_TLS:
                s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"SMTP send failed: {e}")
        return False

# Logging / tracing (best-effort, safe defaults).
setup_logging(service_name="dashboard")
logger = logging.getLogger("kakveda.dashboard")
setup_otel(service_name="dashboard")

# Redis-backed revocation (HA-safe). Falls back to in-memory when Redis isn't configured.
_REVOCATION = RevocationStore(redis_url=_RUNTIME.redis_url, prefix=_RUNTIME.session_store_prefix)

# Optional distributed rate limiting.
_REDIS_RL = RateLimiter(redis_url=_RUNTIME.redis_url, prefix=_RUNTIME.rate_limit_prefix)

# --- Security defaults (override via env) ---
COOKIE_SECURE = os.environ.get("DASHBOARD_COOKIE_SECURE", "0") == "1"
COOKIE_SAMESITE = os.environ.get("DASHBOARD_COOKIE_SAMESITE", "lax")
COOKIE_DOMAIN = os.environ.get("DASHBOARD_COOKIE_DOMAIN") or None
COOKIE_PATH = os.environ.get("DASHBOARD_COOKIE_PATH", "/")

SESSION_TTL_MINUTES = int(os.environ.get("DASHBOARD_SESSION_TTL_MINUTES", "120"))

CSRF_COOKIE = os.environ.get("DASHBOARD_CSRF_COOKIE", "aitester_csrf")

SEC_HEADERS_CSP = os.environ.get(
    "DASHBOARD_CSP",
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self' http://localhost:8120 http://localhost:8122 http://127.0.0.1:8120 http://127.0.0.1:8122; base-uri 'self'; frame-ancestors 'none'",
)
SEC_HEADERS_HSTS = os.environ.get("DASHBOARD_HSTS", "max-age=31536000; includeSubDomains")

def parse_tags_csv(tags: str | None) -> list[str]:
    if not tags:
        return []
    parts = [p.strip() for p in str(tags).split(",")]
    return [p for p in parts if p]


def percentile(values: list[int], p: float) -> int:
    """Small helper for p50/p95 without numpy (demo-friendly)."""
    if not values:
        return 0


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _extract_infra_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize infra metrics event payload into {agent_id,timestamp,infra} shape."""
    node_payload = raw.get("node_metrics_payload")
    if isinstance(node_payload, dict) and isinstance(node_payload.get("infra"), dict):
        return node_payload

    infra = raw.get("infra")
    if isinstance(infra, dict):
        return {
            "agent_id": str(raw.get("agent_id") or "unknown"),
            "timestamp": str(raw.get("ts") or datetime.now(timezone.utc).isoformat()),
            "infra": infra,
        }
    return {
        "agent_id": str(raw.get("agent_id") or "unknown"),
        "timestamp": str(raw.get("ts") or datetime.now(timezone.utc).isoformat()),
        "infra": {},
    }


INFRA_UI_MAX_SNAPSHOTS = max(100, _to_int(os.environ.get("KAKVEDA_INFRA_UI_MAX_SNAPSHOTS"), 500))
OBS_UI_MAX_SNAPSHOTS = max(100, _to_int(os.environ.get("KAKVEDA_OBS_UI_MAX_SNAPSHOTS"), 500))
TRACE_ANALYTICS_MAX_RUNS = max(500, _to_int(os.environ.get("KAKVEDA_TRACE_ANALYTICS_MAX_RUNS"), 4000))
INGEST_RETENTION_INTERVAL_SEC = max(60, _to_int(os.environ.get("KAKVEDA_INGEST_RETENTION_INTERVAL_SEC"), 300))
INFRA_RETENTION_DAYS = max(1, _to_int(os.environ.get("KAKVEDA_INFRA_RETENTION_DAYS"), 14))
OBS_RETENTION_DAYS = max(1, _to_int(os.environ.get("KAKVEDA_OBS_RETENTION_DAYS"), 14))
TRACE_RETENTION_DAYS = max(1, _to_int(os.environ.get("KAKVEDA_TRACE_RETENTION_DAYS"), 30))
INFRA_MAX_ROWS = max(1000, _to_int(os.environ.get("KAKVEDA_INFRA_MAX_ROWS"), 120000))
OBS_MAX_ROWS = max(1000, _to_int(os.environ.get("KAKVEDA_OBS_MAX_ROWS"), 120000))
TRACE_MAX_ROWS = max(1000, _to_int(os.environ.get("KAKVEDA_TRACE_MAX_ROWS"), 250000))
_last_ingest_housekeeping_ts = 0.0
METRICS_QUEUE_ENABLED = str(os.environ.get("KAKVEDA_METRICS_QUEUE_ENABLED", "1")).strip().lower() in {"1", "true", "yes", "on"}
METRICS_QUEUE_MAXSIZE = max(1000, _to_int(os.environ.get("KAKVEDA_METRICS_QUEUE_MAXSIZE"), 10000))
METRICS_BATCH_SIZE = max(10, _to_int(os.environ.get("KAKVEDA_METRICS_BATCH_SIZE"), 200))
METRICS_BATCH_FLUSH_MS = max(50, _to_int(os.environ.get("KAKVEDA_METRICS_BATCH_FLUSH_MS"), 200))
_metrics_queue: asyncio.Queue[dict[str, Any]] | None = None
_metrics_worker_task: asyncio.Task[Any] | None = None


def _delete_trace_runs_by_ids(s: Any, run_ids: list[int]) -> int:
    if not run_ids:
        return 0
    s.query(TraceSpan).filter(TraceSpan.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
    s.query(RunFeedback).filter(RunFeedback.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
    s.query(ExperimentRun).filter(ExperimentRun.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
    s.query(EvaluationResult).filter(EvaluationResult.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
    return int(s.query(TraceRun).filter(TraceRun.id.in_(run_ids)).delete(synchronize_session=False) or 0)


def _maybe_run_ingest_housekeeping(s: Any, *, force: bool = False) -> dict[str, int]:
    global _last_ingest_housekeeping_ts
    now_ts = time.time()
    if not force and (now_ts - _last_ingest_housekeeping_ts) < float(INGEST_RETENTION_INTERVAL_SEC):
        return {"deleted": 0}
    _last_ingest_housekeeping_ts = now_ts

    deleted_total = 0
    now = datetime.now(timezone.utc)

    def _retention_delete_filter(name_filter: Any, days: int) -> int:
        cutoff = now - timedelta(days=max(1, days))
        old_ids = [
            int(r[0])
            for r in (
                s.query(TraceRun.id)
                .filter(name_filter, TraceRun.ts < cutoff)
                .order_by(TraceRun.ts.asc())
                .limit(5000)
                .all()
            )
        ]
        return _delete_trace_runs_by_ids(s, old_ids)

    def _cap_delete(name_filter: Any, cap: int) -> int:
        total = int(s.query(TraceRun.id).filter(name_filter).count() or 0)
        extra = total - max(0, cap)
        if extra <= 0:
            return 0
        old_ids = [
            int(r[0])
            for r in (
                s.query(TraceRun.id)
                .filter(name_filter)
                .order_by(TraceRun.ts.asc())
                .limit(min(extra, 5000))
                .all()
            )
        ]
        return _delete_trace_runs_by_ids(s, old_ids)

    # Global defaults for non-project-scoped rows.
    deleted_total += _retention_delete_filter((TraceRun.name == "infra.metrics") & (TraceRun.project_id.is_(None)), INFRA_RETENTION_DAYS)
    deleted_total += _retention_delete_filter((TraceRun.name == "observability.metrics") & (TraceRun.project_id.is_(None)), OBS_RETENTION_DAYS)
    deleted_total += _cap_delete((TraceRun.name == "infra.metrics") & (TraceRun.project_id.is_(None)), INFRA_MAX_ROWS)
    deleted_total += _cap_delete((TraceRun.name == "observability.metrics") & (TraceRun.project_id.is_(None)), OBS_MAX_ROWS)

    trace_filter = (TraceRun.name != "infra.metrics") & (TraceRun.name != "observability.metrics")
    deleted_total += _retention_delete_filter(trace_filter & (TraceRun.project_id.is_(None)), TRACE_RETENTION_DAYS)
    deleted_total += _cap_delete(trace_filter & (TraceRun.project_id.is_(None)), TRACE_MAX_ROWS)

    # Per-project retention/cap overrides.
    policies = (
        s.query(ProjectRetentionPolicy)
        .filter(ProjectRetentionPolicy.enabled == True)  # noqa: E712
        .all()
    )
    for pol in policies:
        pid = _to_int(getattr(pol, "project_id", 0), 0)
        if pid <= 0:
            continue
        pid_filter = TraceRun.project_id == pid
        trace_days = max(1, _to_int(getattr(pol, "trace_retention_days", TRACE_RETENTION_DAYS), TRACE_RETENTION_DAYS))
        trace_cap = max(1000, _to_int(getattr(pol, "trace_max_rows", TRACE_MAX_ROWS), TRACE_MAX_ROWS))
        infra_days = max(1, _to_int(getattr(pol, "infra_retention_days", INFRA_RETENTION_DAYS), INFRA_RETENTION_DAYS))
        infra_cap = max(1000, _to_int(getattr(pol, "infra_max_rows", INFRA_MAX_ROWS), INFRA_MAX_ROWS))
        obs_days = max(1, _to_int(getattr(pol, "observability_retention_days", OBS_RETENTION_DAYS), OBS_RETENTION_DAYS))
        obs_cap = max(1000, _to_int(getattr(pol, "observability_max_rows", OBS_MAX_ROWS), OBS_MAX_ROWS))

        deleted_total += _retention_delete_filter((TraceRun.name == "infra.metrics") & pid_filter, infra_days)
        deleted_total += _retention_delete_filter((TraceRun.name == "observability.metrics") & pid_filter, obs_days)
        deleted_total += _cap_delete((TraceRun.name == "infra.metrics") & pid_filter, infra_cap)
        deleted_total += _cap_delete((TraceRun.name == "observability.metrics") & pid_filter, obs_cap)
        deleted_total += _retention_delete_filter(trace_filter & pid_filter, trace_days)
        deleted_total += _cap_delete(trace_filter & pid_filter, trace_cap)

    if deleted_total > 0:
        s.add(AuditEvent(actor_email=None, action="ingest_housekeeping", details=f"deleted={deleted_total}"))
    return {"deleted": int(deleted_total)}

# Simple (demo-grade) pricing and token heuristics.
# For Ollama we default cost=0 unless overridden by env.
OLLAMA_PRICE_PER_1K_INPUT = float(os.environ.get("OLLAMA_PRICE_PER_1K_INPUT", "0"))
OLLAMA_PRICE_PER_1K_OUTPUT = float(os.environ.get("OLLAMA_PRICE_PER_1K_OUTPUT", "0"))


def _estimate_tokens(text: str) -> int:
    """Rough token estimate good enough for a demo.

    We avoid heavyweight tokenizers; approximate 1 token ~= 4 chars (English-ish).
    """
    t = (text or "").strip()
    if not t:
        return 0
    return max(1, int(len(t) / 4))


def _compute_cost_usd(provider: str, prompt_tokens: int, completion_tokens: int) -> float:
    provider = (provider or "").lower()
    if provider == "ollama":
        return (prompt_tokens / 1000.0) * OLLAMA_PRICE_PER_1K_INPUT + (completion_tokens / 1000.0) * OLLAMA_PRICE_PER_1K_OUTPUT
    # Unknown providers: treat as zero to avoid confusing UX.
    return 0.0


def _usd_to_micro(usd: float) -> int:
    # Store as integer micro-dollars to keep SQLite schema simple.
    try:
        return int(round(float(usd) * 1_000_000))
    except Exception:
        return 0


def _micro_to_usd(micro: int | None) -> float:
    try:
        return float(micro or 0) / 1_000_000.0
    except Exception:
        return 0.0


def _parse_advanced_query(q: str | None) -> tuple[str, dict[str, Any]]:
    """Parse a tiny query language:

    - provider:ollama
    - model:llama3.2:1b
    - tag:prod (matches run_feedback key=tag)
    - label:good (matches run_feedback key=label)
    - thumb:up|down
    - latency_ms>2000, latency_ms<500
    - has:error

    Returns: (free_text, filters)
    """
    if not q:
        return "", {}
    parts = [p for p in (q or "").split() if p.strip()]
    free: list[str] = []
    f: dict[str, Any] = {}
    for p in parts:
        if p.startswith("provider:"):
            f["provider"] = p.split(":", 1)[1]
        elif p.startswith("model:"):
            f["model"] = p.split(":", 1)[1]
        elif p.startswith("project:"):
            f["project"] = p.split(":", 1)[1]
        elif p.startswith("tag:"):
            f.setdefault("tags", []).append(p.split(":", 1)[1])
        elif p.startswith("label:"):
            f.setdefault("labels", []).append(p.split(":", 1)[1])
        elif p.startswith("thumb:"):
            f["thumb"] = p.split(":", 1)[1]
        elif p == "has:error":
            f["has_error"] = True
        elif p.startswith("latency_ms") and (">" in p or "<" in p):
            if ">" in p:
                _, v = p.split(">", 1)
                try:
                    f["latency_gt"] = int(v)
                except Exception:
                    pass
            else:
                _, v = p.split("<", 1)
                try:
                    f["latency_lt"] = int(v)
                except Exception:
                    pass
        else:
            free.append(p)
    return " ".join(free), f


def _get_or_create_default_project(s: Any) -> Project:
    p = s.query(Project).filter(Project.name == "default").first()
    if p:
        return p
    p = Project(name="default", description="Default project")
    s.add(p)
    s.flush()
    return p


def _effective_project_id(request: Request, user: dict[str, Any]) -> int | None:
    # For now, a simple cookie to hold chosen project for UI browsing.
    # If missing, we stay unscoped (show all) for backwards compatibility.
    try:
        v = request.cookies.get("aitester_project_id")
        return int(v) if v else None
    except Exception:
        return None


def _hash_api_key(raw: str) -> str:
    import hashlib

    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def _require_project_api_key(request: Request) -> tuple[int, ProjectApiKey] | None:
    """Return (project_id, api_key_row) if valid, else None."""
    hdr = request.headers.get("x-api-key") or request.headers.get("authorization") or ""
    token = hdr.replace("Bearer ", "").strip() if hdr else ""
    if not token:
        return None
    key_hash = _hash_api_key(token)
    with get_session() as s:
        row = s.query(ProjectApiKey).filter(ProjectApiKey.key_hash == key_hash, ProjectApiKey.is_active == True).first()  # noqa: E712
        if not row:
            return None
        row.last_used_at = utcnow()
        s.commit()
        return int(row.project_id), row


def _to_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    txt = str(value or "").strip()
    if not txt:
        return None
    try:
        return datetime.fromisoformat(txt.replace("Z", "+00:00"))
    except Exception:
        return None


def _pipeline_cfg_dict(cfg: TracePipelineConfig | None) -> dict[str, Any]:
    return {
        "enabled": bool(getattr(cfg, "enabled", True)),
        "retention_days": max(1, _to_int(getattr(cfg, "retention_days", 14), 14)),
        "default_sample_rate": max(0, min(100, _to_int(getattr(cfg, "default_sample_rate", 100), 100))),
        "keep_error_traces": bool(getattr(cfg, "keep_error_traces", True)),
        "drop_healthcheck_traces": bool(getattr(cfg, "drop_healthcheck_traces", True)),
    }


def _trace_seed(trace: dict[str, Any], app_id: str, agent_id: str) -> int:
    raw = str(trace.get("trace_id") or "") + "|" + app_id + "|" + agent_id + "|" + str(trace.get("ts") or "")
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return int(h[:8], 16) % 100


def _pattern_match(value: str, pattern: str | None) -> bool:
    p = (pattern or "").strip()
    if not p:
        return True
    return fnmatch.fnmatch(value or "", p)


def _trace_should_drop_by_sampling(
    trace: dict[str, Any],
    *,
    app_id: str,
    agent_id: str,
    trace_name: str,
    status: str,
    duration_ms: int | None,
    cfg: dict[str, Any],
    rules: list[TraceSamplingRule],
) -> tuple[bool, str, int]:
    if not cfg.get("enabled", True):
        return False, "pipeline_disabled", 100
    if cfg.get("drop_healthcheck_traces", True):
        nm = (trace_name or "").lower()
        if "health" in nm or "heartbeat" in nm:
            return True, "healthcheck_drop", 0

    if cfg.get("keep_error_traces", True) and str(status).lower() == "error":
        return False, "keep_error", 100

    selected_rate = int(cfg.get("default_sample_rate", 100))
    for rule in rules:
        if not bool(rule.enabled):
            continue
        if not _pattern_match(app_id, rule.app_id_pattern):
            continue
        if not _pattern_match(trace_name, rule.name_pattern):
            continue
        if bool(rule.error_only) and str(status).lower() != "error":
            continue
        min_ms = _to_int(rule.min_duration_ms, 0)
        if min_ms > 0 and _to_int(duration_ms, 0) < min_ms:
            continue
        selected_rate = max(0, min(100, _to_int(rule.sample_rate, selected_rate)))
        break

    if selected_rate >= 100:
        return False, "sample_100", selected_rate
    if selected_rate <= 0:
        return True, "sample_0", selected_rate
    seed = _trace_seed(trace, app_id, agent_id)
    keep = seed < selected_rate
    return (not keep), ("sample_drop" if not keep else "sample_keep"), selected_rate


def _parse_trace_spans(trace: dict[str, Any], started: datetime | None, ended: datetime | None, duration_ms: int | None) -> list[dict[str, Any]]:
    raw_spans = trace.get("spans") if isinstance(trace.get("spans"), list) else []
    parsed: list[dict[str, Any]] = []
    for i, sp in enumerate(raw_spans):
        if not isinstance(sp, dict):
            continue
        st = _to_dt(sp.get("start_ts")) or started
        et = _to_dt(sp.get("end_ts")) or ended
        dms = _to_int(sp.get("duration_ms"), 0)
        if dms <= 0 and st and et:
            dms = max(1, int((et - st).total_seconds() * 1000))
        parsed.append(
            {
                "idx": i,
                "parent_idx": _to_int(sp.get("parent_idx"), -1),
                "name": str(sp.get("name") or f"span-{i}"),
                "start_ts": st or started or utcnow(),
                "end_ts": et or ended or started or utcnow(),
                "duration_ms": dms if dms > 0 else _to_int(duration_ms, 1),
                "meta_json": json.dumps(sp.get("meta") if isinstance(sp.get("meta"), dict) else sp, ensure_ascii=False),
            }
        )
    if parsed:
        return parsed
    # Fallback span for traces that don't provide nested spans.
    return [
        {
            "idx": 0,
            "parent_idx": -1,
            "name": str(trace.get("name") or "trace.total"),
            "start_ts": started or utcnow(),
            "end_ts": ended or started or utcnow(),
            "duration_ms": max(1, _to_int(duration_ms, 1)),
            "meta_json": json.dumps({"fallback": True}, ensure_ascii=False),
        }
    ]


def _span_target_service(span_name: str, meta_json: str, default: str = "") -> str:
    try:
        meta = json.loads(meta_json or "{}")
    except Exception:
        meta = {}
    candidates = [
        str(meta.get("target_service") or ""),
        str(meta.get("service") or ""),
        str(meta.get("upstream_service") or ""),
        str(meta.get("downstream_service") or ""),
    ]
    for c in candidates:
        v = c.strip()
        if v:
            return v
    nm = str(span_name or "").strip()
    if "." in nm:
        left = nm.split(".", 1)[0].strip()
        if left and left.lower() not in {"trace", "run", "span", "model", "playground"}:
            return left
    return default


def _generate_span_metric_points(
    s: Any,
    *,
    trace_run_id: int,
    ts: datetime,
    app_id: str,
    spans: list[TraceSpan],
) -> None:
    cfgs = (
        s.query(SpanMetricConfig)
        .filter(SpanMetricConfig.enabled == True)  # noqa: E712
        .order_by(SpanMetricConfig.name.asc())
        .all()
    )
    if not cfgs:
        return
    for cfg in cfgs:
        if cfg.app_id_pattern and not _pattern_match(app_id, cfg.app_id_pattern):
            continue
        matched = [sp for sp in spans if _pattern_match(str(sp.name or ""), cfg.span_name_pattern)]
        if not matched:
            continue
        vals: list[float] = []
        field = (cfg.field_name or "duration_ms").strip().lower()
        for sp in matched:
            if field == "duration_ms":
                vals.append(float(_to_int(sp.duration_ms, 0)))
            else:
                try:
                    m = json.loads(sp.meta_json or "{}")
                except Exception:
                    m = {}
                vals.append(float(_to_float(m.get(field), 0.0)))
        agg = (cfg.aggregation or "count").strip().lower()
        if agg == "count":
            value = float(len(matched))
        elif agg == "avg":
            value = float(sum(vals) / max(1, len(vals)))
        elif agg == "max":
            value = float(max(vals) if vals else 0.0)
        elif agg == "p95":
            v = sorted(vals)
            value = float(v[max(0, int(len(v) * 0.95) - 1)] if v else 0.0)
        else:
            value = float(len(matched))
        s.add(
            SpanMetricPoint(
                ts=ts,
                metric_name=str(cfg.name),
                app_id=app_id,
                trace_run_id=int(trace_run_id),
                value=value,
            )
        )


def _extract_environment_from_trace(trace: dict[str, Any], env: dict[str, Any]) -> str:
    vals = [
        str(trace.get("environment") or ""),
        str(trace.get("env_name") or ""),
        str(env.get("environment") or ""),
        str(env.get("env") or ""),
    ]
    for v in vals:
        vv = v.strip()
        if vv:
            return vv
    return "default"


def _extract_environment_from_run(run: TraceRun) -> str:
    try:
        body = json.loads(run.output_json or "{}")
    except Exception:
        body = {}
    trace = body.get("trace") if isinstance(body.get("trace"), dict) else {}
    env = body.get("env") if isinstance(body.get("env"), dict) else {}
    if not env and isinstance(trace.get("env"), dict):
        env = trace.get("env")
    return _extract_environment_from_trace(trace, env)


def _normalize_error_type(error_text: str, stack_text: str) -> str:
    et = str(error_text or "").strip()
    if ":" in et:
        left = et.split(":", 1)[0].strip()
        if left:
            return left[:128]
    for line in str(stack_text or "").splitlines():
        ln = line.strip()
        if not ln:
            continue
        if ":" in ln:
            left = ln.split(":", 1)[0].strip()
            if left and len(left) <= 128 and " " not in left:
                return left
    return "error"


def _error_signature(app_id: str, environment: str, service_name: str, error_type: str, error_message: str) -> str:
    msg = re.sub(r"\d+", "<num>", str(error_message or "").strip().lower())
    msg = re.sub(r"\s+", " ", msg)[:220]
    raw = f"{app_id}|{environment}|{service_name}|{error_type}|{msg}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _upsert_apm_error(
    s: Any,
    *,
    trace_run_id: int | None,
    ts: datetime,
    app_id: str,
    agent_id: str,
    service_name: str,
    environment: str,
    handled: bool,
    error_message: str,
    stack_trace: str,
    replay_context: dict[str, Any],
) -> int | None:
    msg = str(error_message or "").strip()
    if not msg:
        return None
    etype = _normalize_error_type(msg, stack_trace)
    sig = _error_signature(app_id, environment, service_name, etype, msg)
    grp = s.query(APMErrorGroup).filter(APMErrorGroup.signature == sig).first()
    if not grp:
        grp = APMErrorGroup(
            signature=sig,
            error_type=etype,
            error_message=msg[:5000],
            service_name=service_name or None,
            app_id=app_id,
            environment=environment,
            handled=bool(handled),
            occurrence_count=1,
            workflow_status="open",
            first_seen_ts=ts,
            last_seen_ts=ts,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        s.add(grp)
        s.flush()
    else:
        grp.occurrence_count = int(_to_int(grp.occurrence_count, 0) + 1)
        grp.last_seen_ts = ts
        grp.updated_at = utcnow()
        grp.handled = bool(grp.handled or handled)

    s.add(
        APMErrorEvent(
            ts=ts,
            created_at=utcnow(),
            error_group_id=int(grp.id),
            trace_run_id=(int(trace_run_id) if trace_run_id is not None else None),
            app_id=app_id,
            agent_id=agent_id,
            service_name=service_name or None,
            environment=environment,
            handled=bool(handled),
            error_type=etype,
            error_message=msg[:5000],
            stack_trace=(str(stack_trace or "")[:20000] or None),
            replay_context_json=json.dumps(replay_context or {}, ensure_ascii=False),
        )
    )
    return int(grp.id)


def _trace_version(trace: dict[str, Any], env: dict[str, Any]) -> str:
    for v in [
        str(trace.get("version") or ""),
        str(env.get("version") or ""),
        str((env.get("build") if isinstance(env.get("build"), dict) else {}).get("version") or ""),
    ]:
        vv = v.strip()
        if vv:
            return vv[:64]
    return "unknown"


def _sql_fingerprint(query: str) -> str:
    txt = str(query or "").strip().lower()
    txt = re.sub(r"'[^']*'", "?", txt)
    txt = re.sub(r'"[^"]*"', "?", txt)
    txt = re.sub(r"\b\d+\b", "?", txt)
    txt = re.sub(r"\s+", " ", txt)[:1000]
    return hashlib.sha256(txt.encode("utf-8")).hexdigest()


def _compare_threshold(observed: float, op: str, threshold: float) -> bool:
    o = str(op or ">").strip()
    if o == ">=":
        return observed >= threshold
    if o == "<":
        return observed < threshold
    if o == "<=":
        return observed <= threshold
    return observed > threshold


def _upsert_open_alert(
    s: Any,
    *,
    source_type: str,
    monitor_id: int,
    monitor_name: str,
    app_id: str | None,
    environment: str | None,
    severity: str,
    metric_name: str,
    observed_value: float,
    threshold_value: float,
    context: dict[str, Any],
) -> None:
    existing = (
        s.query(MonitorAlert)
        .filter(
            MonitorAlert.source_type == source_type,
            MonitorAlert.monitor_id == int(monitor_id),
            MonitorAlert.status == "open",
        )
        .order_by(MonitorAlert.ts.desc(), MonitorAlert.id.desc())
        .first()
    )
    if existing:
        existing.ts = utcnow()
        existing.observed_value = float(observed_value)
        existing.threshold_value = float(threshold_value)
        existing.context_json = json.dumps(context or {}, ensure_ascii=False)
        existing.severity = severity
        return
    s.add(
        MonitorAlert(
            ts=utcnow(),
            source_type=source_type,
            monitor_id=int(monitor_id),
            monitor_name=monitor_name,
            app_id=(app_id or None),
            environment=(environment or None),
            severity=severity,
            status="open",
            metric_name=metric_name,
            observed_value=float(observed_value),
            threshold_value=float(threshold_value),
            context_json=json.dumps(context or {}, ensure_ascii=False),
        )
    )


def _resolve_open_alert(s: Any, *, source_type: str, monitor_id: int) -> None:
    rows = (
        s.query(MonitorAlert)
        .filter(
            MonitorAlert.source_type == source_type,
            MonitorAlert.monitor_id == int(monitor_id),
            MonitorAlert.status == "open",
        )
        .all()
    )
    for r in rows:
        r.status = "resolved"


def _ensure_dashboard_schema() -> None:
    try:
        migrate_db()
    except Exception:
        pass


def _ensure_default_apm_monitors(s: Any) -> None:
    defaults = [
        ("auto-error-rate", "metric", "error_rate_percent", 5.0, ">"),
        ("auto-latency-p95", "metric", "latency_p95_ms", 1200.0, ">"),
        ("auto-watchdog-latency", "anomaly", "latency_p95_ms", 2.5, ">"),
    ]
    for name, mtype, metric, thr, op in defaults:
        row = s.query(APMMonitor).filter(APMMonitor.name == name).first()
        if row:
            continue
        s.add(
            APMMonitor(
                name=name,
                app_id=None,
                environment=None,
                monitor_type=mtype,
                metric_name=metric,
                threshold_value=float(thr),
                threshold_op=op,
                window_minutes=15,
                enabled=True,
                auto_generated=True,
                created_by="system",
                created_at=utcnow(),
                updated_at=utcnow(),
            )
        )


def _evaluate_apm_monitor(s: Any, mon: APMMonitor) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(minutes=max(1, _to_int(mon.window_minutes, 15)))
    app_filter = str(mon.app_id or "").strip()
    env_filter = str(mon.environment or "").strip()
    metric = str(mon.metric_name or "error_rate_percent").strip()

    q = s.query(TraceRun).filter(
        TraceRun.ts >= since,
        TraceRun.name != "infra.metrics",
        TraceRun.name != "observability.metrics",
    )
    if app_filter:
        q = q.filter(TraceRun.app_id == app_filter)
    runs = q.order_by(TraceRun.ts.desc()).limit(5000).all()
    if env_filter:
        keep: list[TraceRun] = []
        for r in runs:
            if _extract_environment_from_run(r) == env_filter:
                keep.append(r)
        runs = keep

    observed = 0.0
    if metric == "error_rate_percent":
        err = sum(1 for r in runs if str(r.status or "").lower() == "error")
        observed = (float(err) / max(1.0, float(len(runs)))) * 100.0
    elif metric == "latency_p95_ms":
        ds = sorted([float(_to_int(r.duration_ms, 0)) for r in runs if _to_int(r.duration_ms, 0) > 0])
        observed = float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0)
    elif metric == "trace_count":
        observed = float(len(runs))
    else:
        observed = float(len(runs))

    if str(mon.monitor_type or "") == "anomaly":
        # watchdog anomaly monitor: z-score-ish ratio vs previous window average
        prev_since = since - timedelta(minutes=max(1, _to_int(mon.window_minutes, 15)))
        prev_q = s.query(TraceRun).filter(
            TraceRun.ts >= prev_since,
            TraceRun.ts < since,
            TraceRun.name != "infra.metrics",
            TraceRun.name != "observability.metrics",
        )
        if app_filter:
            prev_q = prev_q.filter(TraceRun.app_id == app_filter)
        prev_runs = prev_q.order_by(TraceRun.ts.desc()).limit(5000).all()
        if env_filter:
            prev_runs = [r for r in prev_runs if _extract_environment_from_run(r) == env_filter]
        prev_ds = [float(_to_int(r.duration_ms, 0)) for r in prev_runs if _to_int(r.duration_ms, 0) > 0]
        prev_avg = (sum(prev_ds) / float(len(prev_ds))) if prev_ds else 0.0
        observed = (observed / prev_avg) if prev_avg > 0 else 0.0

    breached = _compare_threshold(float(observed), str(mon.threshold_op or ">"), float(mon.threshold_value or 0.0))
    sev = "critical" if float(observed) >= float(mon.threshold_value or 0.0) * 2 else "warning"
    return {
        "breached": breached,
        "observed": float(observed),
        "samples": len(runs),
        "severity": sev,
    }

def _persist_profiler_samples(
    s: Any,
    *,
    trace_run_id: int,
    ts: datetime,
    app_id: str,
    agent_id: str,
    environment: str,
    version: str,
    trace_name: str,
    spans: list[TraceSpan],
) -> None:
    # Continuous profiler (lightweight): convert span durations to hotspot samples.
    if not spans:
        return
    for sp in spans:
        method_name = str(sp.name or "unknown")
        cpu_ms = float(_to_int(sp.duration_ms, 0))
        s.add(
            ProfilerSample(
                ts=ts,
                app_id=app_id,
                agent_id=agent_id,
                environment=environment,
                service_name=str(trace_name or app_id or "service"),
                method_name=method_name,
                version=version or "unknown",
                trace_run_id=int(trace_run_id),
                sample_type="cpu",
                cpu_ms=cpu_ms,
                memory_bytes=0,
                sample_count=1,
                details_json=json.dumps({"source": "trace_span", "span_id": int(sp.id)}),
            )
        )

        # Optional memory sample if present in span meta.
        try:
            meta = json.loads(sp.meta_json or "{}")
        except Exception:
            meta = {}
        mem_b = _to_int(meta.get("memory_bytes"), 0)
        if mem_b > 0:
            s.add(
                ProfilerSample(
                    ts=ts,
                    app_id=app_id,
                    agent_id=agent_id,
                    environment=environment,
                    service_name=str(trace_name or app_id or "service"),
                    method_name=method_name,
                    version=version or "unknown",
                    trace_run_id=int(trace_run_id),
                    sample_type="memory",
                    cpu_ms=0.0,
                    memory_bytes=mem_b,
                    sample_count=1,
                    details_json=json.dumps({"source": "trace_span_meta", "span_id": int(sp.id)}),
                )
            )


def _persist_db_query_samples(
    s: Any,
    *,
    trace_run_id: int,
    ts: datetime,
    app_id: str,
    agent_id: str,
    environment: str,
    trace_name: str,
    spans: list[TraceSpan],
) -> None:
    for sp in spans:
        try:
            meta = json.loads(sp.meta_json or "{}")
        except Exception:
            meta = {}
        if not isinstance(meta, dict):
            continue
        db_query = str(meta.get("db_query") or meta.get("query") or "").strip()
        db_system = str(meta.get("db_system") or "").strip().lower()
        if not db_query and db_system not in {"postgres", "mysql", "sqlite", "mongodb", "redis"}:
            continue
        if not db_query:
            db_query = f"-- {sp.name}"
        qtype = db_query.split(" ", 1)[0].strip().upper() if db_query else ""
        qfp = _sql_fingerprint(db_query)
        s.add(
            DBQuerySample(
                ts=ts,
                app_id=app_id,
                agent_id=agent_id,
                environment=environment,
                db_system=(db_system or "unknown"),
                db_instance=str(meta.get("db_instance") or ""),
                service_name=str(meta.get("service_name") or trace_name or app_id),
                query_fingerprint=qfp,
                query_text=db_query[:5000],
                query_type=(qtype[:16] if qtype else None),
                duration_ms=float(_to_int(sp.duration_ms, 0)),
                rows_examined=_to_int(meta.get("rows_examined"), 0),
                rows_returned=_to_int(meta.get("rows_returned"), 0),
                wait_event=(str(meta.get("wait_event") or "")[:128] or None),
                explain_plan_json=(json.dumps(meta.get("explain_plan")) if meta.get("explain_plan") is not None else None),
                meta_json=json.dumps({"trace_run_id": int(trace_run_id), "span_name": str(sp.name or "")}),
            )
        )


def env_url(name: str, default: str) -> str:
    return os.environ.get(name, default)


GFKB_URL = env_url("GFKB_URL", "http://gfkb:8101")
HEALTH_URL = env_url("HEALTH_URL", "http://health-scoring:8106")
EVENT_BUS_URL = env_url("EVENT_BUS_URL", "http://event-bus:8100")
WARN_URL = env_url("WARN_URL", "http://warning-policy:8105")
INGEST_URL = env_url("INGEST_URL", "http://ingestion:8102")
OLLAMA_URL = env_url("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = env_url("OLLAMA_MODEL", "llama3")
EVENT_BUS_URL = env_url("EVENT_BUS_URL", "http://event-bus:8100")


async def list_ollama_models() -> list[str]:
    """Option B: fetch available models from Ollama (fallback to env model).

    Kept as a small helper so teams can later swap in other providers easily.
    """
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            r.raise_for_status()
            data = r.json() or {}
            models = []
            for m in data.get("models", []) or []:
                name = m.get("name")
                if name:
                    models.append(str(name))
            models = sorted(set(models))
            if models:
                return models
    except Exception:
        pass
    return [OLLAMA_MODEL]

COOKIE_NAME = "aitester_token"
IMPERSONATE_COOKIE = "aitester_impersonate_role"

# Demo apps that ship with sample data; hide them from selectors by default.
HIDDEN_APPS = {"app-A", "app-B"}

DATA_DIR = Path("/app/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def _ts_for_backup() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    bak = path.with_name(f"{path.name}.bak-{_ts_for_backup()}")
    shutil.copy2(path, bak)
    return bak


def _purge_jsonl_apps(path: Path, app_ids: set[str]) -> dict[str, int]:
    """Remove JSONL rows for specific app_ids.

    For failures/patterns: remove app_ids from affected_apps, and drop row if empty.
    For health: drop row if obj.app_id in app_ids.
    """
    if not path.exists():
        return {"kept": 0, "removed": 0, "updated": 0}

    removed = 0
    kept = 0
    updated = 0
    out_lines: list[str] = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            # keep invalid lines as-is (shouldn't happen, but be safe)
            out_lines.append(line)
            kept += 1
            continue

        # Health points: direct app_id field.
        if obj.get("app_id") in app_ids and path.name == "health.jsonl":
            removed += 1
            continue

        # Failures/patterns: affected_apps list.
        if "affected_apps" in obj and isinstance(obj.get("affected_apps"), list):
            before = list(obj.get("affected_apps") or [])
            after = [a for a in before if a not in app_ids]
            if after != before:
                obj["affected_apps"] = after
                updated += 1
            if not after and path.name in {"failures.jsonl", "patterns.jsonl"}:
                removed += 1
                continue

        out_lines.append(json.dumps(obj, ensure_ascii=False))
        kept += 1

    path.write_text("\n".join(out_lines) + ("\n" if out_lines else ""), encoding="utf-8")
    return {"kept": kept, "removed": removed, "updated": updated}


def _purge_dashboard_db(db_path: Path, app_ids: set[str]) -> dict[str, int]:
    """Delete demo-app rows from dashboard SQLite, including dependent tables."""
    if not db_path.exists():
        return {"trace_runs": 0, "trace_spans": 0, "run_feedback": 0, "experiment_runs": 0, "evaluation_results": 0, "scenario_runs": 0, "warning_events": 0, "dataset_examples": 0}

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        placeholders = ",".join(["?"] * len(app_ids))
        ids = sorted(app_ids)

        # Identify TraceRun ids to delete.
        cur.execute(f"SELECT id FROM trace_runs WHERE app_id IN ({placeholders})", ids)
        trace_run_ids = [int(r[0]) for r in cur.fetchall()]

        counts: dict[str, int] = {}

        if trace_run_ids:
            tr_ph = ",".join(["?"] * len(trace_run_ids))

            cur.execute(f"DELETE FROM trace_spans WHERE trace_run_id IN ({tr_ph})", trace_run_ids)
            counts["trace_spans"] = cur.rowcount

            cur.execute(f"DELETE FROM run_feedback WHERE trace_run_id IN ({tr_ph})", trace_run_ids)
            counts["run_feedback"] = cur.rowcount

            cur.execute(f"DELETE FROM experiment_runs WHERE trace_run_id IN ({tr_ph})", trace_run_ids)
            counts["experiment_runs"] = cur.rowcount

            cur.execute(f"DELETE FROM evaluation_results WHERE trace_run_id IN ({tr_ph})", trace_run_ids)
            counts["evaluation_results"] = cur.rowcount

            cur.execute(f"DELETE FROM trace_runs WHERE id IN ({tr_ph})", trace_run_ids)
            counts["trace_runs"] = cur.rowcount
        else:
            counts.update({"trace_spans": 0, "run_feedback": 0, "experiment_runs": 0, "evaluation_results": 0, "trace_runs": 0})

        # Direct app_id tables.
        cur.execute(f"DELETE FROM scenario_runs WHERE app_id IN ({placeholders})", ids)
        counts["scenario_runs"] = cur.rowcount

        cur.execute(f"DELETE FROM warning_events WHERE app_id IN ({placeholders})", ids)
        counts["warning_events"] = cur.rowcount

        cur.execute(f"DELETE FROM dataset_examples WHERE app_id IN ({placeholders})", ids)
        counts["dataset_examples"] = cur.rowcount

        conn.commit()
        return counts
    finally:
        conn.close()


def _coerce_float_confidence(x: Any, default: float = 0.0) -> str:
    try:
        v = float(x)
        if v < 0:
            v = 0.0
        if v > 1:
            v = 1.0
        return f"{v:.2f}"
    except Exception:
        return f"{default:.2f}"


def _stable_fingerprint(obj: dict[str, Any]) -> str:
    """Best-effort stable fingerprint for UI.

    GFKB's CanonicalFailureRecord doesn't currently include a fingerprint field,
    so we compute a short hash from signature/context to keep the UI useful.
    """
    base = (
        obj.get("signature_text")
        or json.dumps(obj.get("context_signature") or {}, sort_keys=True, ensure_ascii=False)
        or json.dumps(obj, sort_keys=True, ensure_ascii=False)
    )
    h = hashlib.sha256(str(base).encode("utf-8")).hexdigest()
    return h[:16]


def _dedupe_latest_failures(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for r in rows or []:
        fid = str(r.get("failure_id") or "")
        if not fid:
            continue
        try:
            ver = int(r.get("version") or 0)
        except Exception:
            ver = 0
        prev = latest.get(fid)
        if not prev:
            latest[fid] = r
            continue
        try:
            prev_ver = int(prev.get("version") or 0)
        except Exception:
            prev_ver = 0
        if ver >= prev_ver:
            latest[fid] = r
    # stable sort: newest (highest version) first
    return sorted(latest.values(), key=lambda x: int(x.get("version") or 0), reverse=True)

# --- Simple in-memory rate limiting (per process) ---
# For production, replace with a shared store / edge rate limiter.
_RL: dict[str, deque[float]] = defaultdict(deque)


def _rate_limit(key: str, limit: int, window_s: int) -> bool:
    """Return True if allowed, False if rate-limited."""
    if _RUNTIME.redis_url:
        try:
            return _REDIS_RL.allowed(key, limit=limit, window_s=window_s)
        except Exception:
            # fall back to local limiter
            pass
    now = time.time()
    q = _RL[key]
    cutoff = now - window_s
    while q and q[0] < cutoff:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _validate_email(email: str) -> str | None:
    e = _normalize_email(email)
    if not e or len(e) > 255:
        return "Email is required"
    if not _EMAIL_RE.match(e):
        return "Email format is invalid"
    return None


def _validate_password(pw: str) -> str | None:
    p = pw or ""
    if len(p) < 8:
        return "Password must be at least 8 characters"
    if len(p) > 128:
        return "Password is too long"
    if not re.search(r"[a-z]", p):
        return "Password must include a lowercase letter"
    if not re.search(r"[A-Z]", p):
        return "Password must include an uppercase letter"
    if not re.search(r"[0-9]", p):
        return "Password must include a number"
    return None


def _set_cookie(resp: RedirectResponse | HTMLResponse, name: str, value: str, *, httponly: bool = True) -> None:
    resp.set_cookie(
        name,
        value,
        httponly=httponly,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
        domain=COOKIE_DOMAIN,
        path=COOKIE_PATH,
    )


def _delete_cookie(resp: RedirectResponse | HTMLResponse, name: str) -> None:
    resp.delete_cookie(name, domain=COOKIE_DOMAIN, path=COOKIE_PATH)


def _csrf_get_or_set(request: Request, resp: RedirectResponse | HTMLResponse | None = None) -> str:
    tok = request.cookies.get(CSRF_COOKIE)
    if tok:
        return tok
    tok = secrets.token_urlsafe(32)
    if resp is not None:
        # CSRF cookie must be readable by JS? We submit as hidden input, so it can be httponly.
        _set_cookie(resp, CSRF_COOKIE, tok, httponly=True)
    return tok


def _csrf_validate(request: Request, csrf: str | None) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE)
    if not cookie or not csrf:
        return False
    return secrets.compare_digest(str(cookie), str(csrf))


# --- Token revocation (demo-grade) ---
# Store revoked JTIs in-memory. This is process-local; for HA, store in DB/redis.
def _is_token_revoked(payload: Any) -> bool:
    try:
        jti = getattr(payload, "jti", None)
        if jti and _REVOCATION.is_revoked(str(jti)):
            return True
    except Exception:
        return False
    return False


 

app = FastAPI(title="kakveda", version="0.1.0")

# OTel instrumentation is a no-op unless KAKVEDA_OTEL_ENABLED=1.
instrument_fastapi(app)


@app.middleware("http")
async def _request_id_mw(request: Request, call_next):
    rid = ensure_request_id(request.headers.get(_RUNTIME.request_id_header))
    started = time.perf_counter()
    request.state.request_id = rid
    resp = await call_next(request)
    resp.headers.setdefault("X-Request-Id", rid)
    try:
        duration_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "request",
            extra={
                "request_id": rid,
                "method": request.method,
                "path": request.url.path,
                "status_code": getattr(resp, "status_code", None),
                "duration_ms": duration_ms,
            },
        )
    except Exception:
        pass
    return resp


# --- Security headers ---
@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    # Basic hardening for a dashboard
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    resp.headers.setdefault("Content-Security-Policy", SEC_HEADERS_CSP)
    if COOKIE_SECURE:
        resp.headers.setdefault("Strict-Transport-Security", SEC_HEADERS_HSTS)
    return resp
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


# --- CSRF protection (browser forms) ---
def _is_api_request(request: Request) -> bool:
    # Treat /api/* as non-browser endpoints (API keys / automation / curl); CSRF not expected.
    if request.url.path.startswith("/api/"):
        return True
    # Auth bootstrap endpoints: allow posting without an existing CSRF cookie.
    # The CSRF cookie is created on the GET pages; but in some browsers/proxies, users can end up
    # POSTing before receiving it (or when cookies are blocked). We handle these endpoints with
    # their own validations and keep the UX smooth.
    if request.url.path in {"/auth/login", "/auth/register"}:
        return True
    # Also treat JSON requests as API-style.
    ct = (request.headers.get("content-type") or "").lower()
    if "application/json" in ct:
        return True
    return False


def _is_form_like_post(request: Request) -> bool:
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    ct = (request.headers.get("content-type") or "").lower()
    return ("application/x-www-form-urlencoded" in ct) or ("multipart/form-data" in ct) or (ct == "")


@app.middleware("http")
async def _csrf_middleware(request: Request, call_next):
    # NOTE: CSRF enforcement is temporarily disabled.
    # It was causing browser login/register attempts to fail with 422/redirect loops in some setups.
    # We keep setting the CSRF cookie for future re-enablement.
    resp = await call_next(request)
    if not _is_api_request(request):
        _csrf_get_or_set(request, resp)
    return resp


def _csrf_input(request: Request) -> str:
    # Jinja helper: {{ csrf_input(request) | safe }}
    tok = request.cookies.get(CSRF_COOKIE) or ""
    # Hidden input name is "csrf" which middleware expects.
    return f'<input type="hidden" name="csrf" value="{tok}">'


templates.env.globals["csrf_input"] = _csrf_input

# Shared UI assets (Option A theme, etc.)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")




def get_current_user(request: Request) -> dict[str, Any] | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        if _is_token_revoked(payload):
            return None
        # Important: do not rely exclusively on roles inside the JWT.
        # Admin operations need the live DB truth so role changes take effect immediately.
        roles = list(payload.roles)
        try:
            with get_session() as s:
                db_user = s.query(User).filter(User.email == payload.sub).first()
                if db_user:
                    roles = [ur.role.name for ur in db_user.roles]
        except Exception:
            # If DB is unavailable for any reason, fall back to JWT roles.
            pass
        impersonating_role: str | None = None
        is_admin = ROLE_ADMIN in set(roles)

        # Admin-only "view as" role for previewing RBAC behavior without modifying accounts.
        # Important: when impersonating, we keep `is_admin=True` so admin pages can still be accessed.
        # We expose the *effective* role via `effective_roles`.
        effective_roles = list(roles)
        imp = request.cookies.get(IMPERSONATE_COOKIE)
        if imp and is_admin and imp in {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}:
            impersonating_role = imp
            effective_roles = [imp]

        return {
            "email": payload.sub,
            "roles": roles,
            "effective_roles": effective_roles,
            "is_admin": is_admin,
            "impersonating_role": impersonating_role,
        }
    except Exception:
        return None


def require_login(request: Request) -> dict[str, Any] | RedirectResponse:
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)
    return user


def require_roles(roles: list[str]):
    def _dep(user: dict[str, Any] | RedirectResponse = Depends(require_login)) -> dict[str, Any] | RedirectResponse:
        if isinstance(user, RedirectResponse):
            return user
        # Admin routes should remain accessible even when admin is using "view as" impersonation.
        # For admin checks, prefer the stable `is_admin` flag.
        if ROLE_ADMIN in roles and user.get("is_admin") is True:
            return user
        if not require_any(user.get("effective_roles", user.get("roles", [])), roles):
            return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
        return user

    return _dep


# --- Agent Registry (admin-only) ---
def _parse_json_array(s: str) -> list[str]:
    try:
        v = json.loads(s or "[]")
        if isinstance(v, list):
            return [str(x) for x in v]
    except Exception:
        pass
    return []


def _dump_json_array(v: list[str]) -> str:
    return json.dumps([str(x).strip() for x in v if str(x).strip()], ensure_ascii=False)


def _agent_row(a: AgentRegistry) -> dict[str, Any]:
    return {
        "id": a.id,
        "name": a.name,
        "description": a.description,
        "base_url": a.base_url,
        "enabled": bool(a.enabled),
        "capabilities": _parse_json_array(a.capabilities_json),
        "events_in": _parse_json_array(a.events_in_json),
        "events_out": _parse_json_array(a.events_out_json),
        "auth_type": a.auth_type,
        "auth_header_name": a.auth_header_name,
        "auth_secret_ref": a.auth_secret_ref,
        "created_at": getattr(a, "created_at", None),
        "updated_at": getattr(a, "updated_at", None),
    }


def _get_known_app_choices(s: Any) -> list[str]:
    """Best-effort list of app_ids seen in the system (excluding demo apps)."""
    app_ids: set[str] = set()

    try:
        app_ids.update({str(r[0]) for r in s.query(TraceRun.app_id).distinct().all() if r and r[0]})
    except Exception:
        pass
    try:
        app_ids.update({str(r[0]) for r in s.query(WarningEvent.app_id).distinct().all() if r and r[0]})
    except Exception:
        pass
    try:
        app_ids.update({str(r[0]) for r in s.query(DatasetExample.app_id).distinct().all() if r and r[0]})
    except Exception:
        pass

    app_ids = {a.strip() for a in app_ids if a and str(a).strip()}
    app_ids = {a for a in app_ids if a not in HIDDEN_APPS}

    if not app_ids:
        app_ids = {"kids-app"}

    return sorted(app_ids)


@app.get("/admin")
async def admin_root(user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN]))):
    if isinstance(user, RedirectResponse):
        return user
    return RedirectResponse(url="/admin/users", status_code=302)


@app.get("/admin/purge-demo", response_class=HTMLResponse)
async def admin_purge_demo(
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
):
    if isinstance(user, RedirectResponse):
        return user

    return templates.TemplateResponse(
        "admin_purge_demo.html",
        {
            "request": request,
            "email": user.get("email"),
            "role": (user.get("effective_roles") or user.get("roles") or [""])[0],
            "is_admin": True,
            "apps": sorted(HIDDEN_APPS),
            "message": request.query_params.get("message") or "",
            "error": request.query_params.get("error") or "",
        },
    )


@app.post("/admin/purge-demo/run")
async def admin_purge_demo_run(
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
):
    if isinstance(user, RedirectResponse):
        return user

    app_ids = set(HIDDEN_APPS)
    try:
        db_path = DATA_DIR / "dashboard.db"
        health_path = DATA_DIR / "health.jsonl"
        failures_path = DATA_DIR / "failures.jsonl"
        patterns_path = DATA_DIR / "patterns.jsonl"

        backups: dict[str, str] = {}
        for p in [db_path, health_path, failures_path, patterns_path]:
            bak = _backup_file(p)
            if bak:
                backups[p.name] = bak.name

        db_counts = _purge_dashboard_db(db_path, app_ids)
        health_counts = _purge_jsonl_apps(health_path, app_ids)
        failure_counts = _purge_jsonl_apps(failures_path, app_ids)
        pattern_counts = _purge_jsonl_apps(patterns_path, app_ids)

        msg = (
            f"Purged demo apps {sorted(app_ids)}. "
            f"DB: {db_counts}. health.jsonl: {health_counts}. failures.jsonl: {failure_counts}. patterns.jsonl: {pattern_counts}. "
            f"Backups: {backups or 'none'}"
        )
        return RedirectResponse(url=f"/admin/purge-demo?message={quote(msg)}", status_code=303)
    except Exception as e:
        logger.exception("purge-demo failed")
        return RedirectResponse(url=f"/admin/purge-demo?error={quote(str(e))}", status_code=303)


# ============================================================================
# Public Agents Page (Top-level, accessible to all logged-in users)
# ============================================================================

@app.get("/agents", response_class=HTMLResponse)
async def agents_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    message: str | None = None,
    error: str | None = None,
):
    """Public agents page - shows all registered agents"""
    if isinstance(user, RedirectResponse):
        return user
    
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    
    with get_session() as s:
        rows = s.query(AgentRegistry).filter(AgentRegistry.enabled == True).order_by(AgentRegistry.name).all()
        agents = []
        for a in rows:
            caps = []
            try:
                caps = json.loads(a.capabilities_json or "[]")
            except Exception:
                pass
            agents.append({
                "id": a.id,
                "name": a.name,
                "description": a.description,
                "base_url": a.base_url,
                "enabled": a.enabled,
                "capabilities": caps,
                "updated_at": str(a.updated_at) if a.updated_at else None,
            })
    
    return templates.TemplateResponse(
        "agents.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "agents": agents,
            "message": request.query_params.get("message") or message,
            "error": request.query_params.get("error") or error,
        },
    )


@app.post("/agents/{agent_id}/test")
async def agents_test(
    agent_id: int,
    request: Request,
    user: dict[str, Any] = Depends(require_login),
):
    """Test agent health from public agents page"""
    if isinstance(user, RedirectResponse):
        return user
    
    with get_session() as s:
        a = s.query(AgentRegistry).filter(AgentRegistry.id == agent_id).first()
        if not a:
            return RedirectResponse(url="/agents?error=Agent%20not%20found", status_code=303)
        url = (a.base_url or "").rstrip("/")
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                # Try primary URL first
                r = await client.get(f"{url}/health")
            except Exception as primary_error:
                # If primary fails, try localhost fallback
                import re
                port_match = re.search(r':(\d+)$', url)
                port = port_match.group(1) if port_match else '8120'
                fallback_url = f"http://localhost:{port}/health"
                try:
                    r = await client.get(fallback_url)
                except:
                    # Both failed, raise the original error
                    raise primary_error
            
            code = r.status_code
            if code == 200:
                return RedirectResponse(url=f"/agents?message=Agent%20{a.name}%20is%20healthy%20(HTTP%20{code})", status_code=303)
            else:
                return RedirectResponse(url=f"/agents?error=Agent%20returned%20HTTP%20{code}", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/agents?error=Connection%20failed:%20{str(e)[:50]}", status_code=303)


@app.get("/admin/agents", response_class=HTMLResponse)
async def admin_agents(request: Request, user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN]))):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        rows = s.query(AgentRegistry).order_by(AgentRegistry.id.desc()).all()
        agents = [_agent_row(a) for a in rows]
    return templates.TemplateResponse(
        "admin_agents.html",
        {
            "request": request,
            "email": user.get("email"),
            "role": (user.get("effective_roles") or user.get("roles") or [""])[0],
            "agents": agents,
            "message": (request.query_params.get("message") or ""),
            "error": (request.query_params.get("error") or ""),
        },
    )


@app.post("/admin/agents/register")
async def admin_agents_register(
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
    name: str = Form(...),
    base_url: str = Form(...),
    description: str = Form(""),
    capabilities: str = Form(""),
    events_in: str = Form(""),
    events_out: str = Form(""),
    auth_type: str = Form("none"),
    auth_header_name: str = Form(""),
    auth_secret_ref: str = Form(""),
):
    if isinstance(user, RedirectResponse):
        return user

    nm = (name or "").strip()
    if not nm:
        return RedirectResponse(url="/admin/agents?error=Missing%20name", status_code=303)

    url = (base_url or "").strip().rstrip("/")
    if not (url.startswith("http://") or url.startswith("https://")):
        return RedirectResponse(url="/admin/agents?error=base_url%20must%20start%20with%20http(s)", status_code=303)

    caps = [x.strip() for x in (capabilities or "").split(",") if x.strip()]
    ev_in = [x.strip() for x in (events_in or "").split(",") if x.strip()]
    ev_out = [x.strip() for x in (events_out or "").split(",") if x.strip()]

    a_type = (auth_type or "none").strip().lower()
    if a_type not in {"none", "bearer", "api_key_header"}:
        return RedirectResponse(url="/admin/agents?error=Invalid%20auth_type", status_code=303)

    with get_session() as s:
        existing = s.query(AgentRegistry).filter(AgentRegistry.name == nm).first()
        if existing:
            existing.base_url = url
            existing.description = description.strip() or None
            existing.capabilities_json = _dump_json_array(caps)
            existing.events_in_json = _dump_json_array(ev_in)
            existing.events_out_json = _dump_json_array(ev_out)
            existing.auth_type = a_type
            existing.auth_header_name = auth_header_name.strip() or None
            existing.auth_secret_ref = auth_secret_ref.strip() or None
            existing.updated_at = utcnow()
        else:
            s.add(
                AgentRegistry(
                    name=nm,
                    description=description.strip() or None,
                    base_url=url,
                    enabled=True,
                    capabilities_json=_dump_json_array(caps),
                    events_in_json=_dump_json_array(ev_in),
                    events_out_json=_dump_json_array(ev_out),
                    auth_type=a_type,
                    auth_header_name=auth_header_name.strip() or None,
                    auth_secret_ref=auth_secret_ref.strip() or None,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
            )
        s.commit()

    return RedirectResponse(url="/admin/agents?message=Saved", status_code=303)


@app.post("/admin/agents/{agent_id}/toggle")
async def admin_agents_toggle(
    agent_id: int,
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        a = s.query(AgentRegistry).filter(AgentRegistry.id == agent_id).first()
        if a:
            a.enabled = not bool(a.enabled)
            a.updated_at = utcnow()
            s.commit()
    return RedirectResponse(url="/admin/agents?message=Toggled", status_code=303)


@app.post("/admin/agents/{agent_id}/test")
async def admin_agents_test(
    agent_id: int,
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        a = s.query(AgentRegistry).filter(AgentRegistry.id == agent_id).first()
        if not a:
            return RedirectResponse(url="/admin/agents?error=Agent%20not%20found", status_code=303)
        url = (a.base_url or "").rstrip("/")
        a_type = (a.auth_type or "none").lower()
        hdr_name = a.auth_header_name or ""
        secret_ref = a.auth_secret_ref or ""

    headers: dict[str, str] = {}
    if a_type == "bearer" and secret_ref:
        tok = os.environ.get(secret_ref, "")
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
    elif a_type == "api_key_header" and secret_ref and hdr_name:
        tok = os.environ.get(secret_ref, "")
        if tok:
            headers[hdr_name] = tok

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(f"{url}/health", headers=headers)
            code = r.status_code
    except Exception:
        code = 0

    return RedirectResponse(url=f"/admin/agents?message=health%3D{code}", status_code=303)


@app.get("/api/agents")
async def api_agents_list(request: Request):
    """List registered agents (admin cookie auth).

    This mirrors the demo's style for other admin pages.
    """
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return {"ok": False, "error": "not authorized"}

    with get_session() as s:
        rows = s.query(AgentRegistry).order_by(AgentRegistry.id.desc()).all()
        return {"ok": True, "agents": [_agent_row(a) for a in rows]}


@app.post("/api/agents/register")
async def api_agents_self_register(request: Request):
    """Agent self-registration API.
    
    Agents can call this endpoint to register themselves with Kakveda.
    Body: {name, base_url, description?, capabilities?}
    Header: X-API-Key for authentication
    """
    # Validate API key
    auth = _require_project_api_key(request)
    if not auth:
        return {"ok": False, "error": "missing or invalid api key"}
    
    body = await request.json()
    name = str(body.get("name") or "").strip()
    base_url = str(body.get("base_url") or "").strip().rstrip("/")
    description = str(body.get("description") or "").strip()
    capabilities = body.get("capabilities") or []
    
    if not name:
        return {"ok": False, "error": "name is required"}
    if not base_url or not (base_url.startswith("http://") or base_url.startswith("https://")):
        return {"ok": False, "error": "valid base_url is required"}
    
    if isinstance(capabilities, str):
        capabilities = [c.strip() for c in capabilities.split(",") if c.strip()]
    
    with get_session() as s:
        existing = s.query(AgentRegistry).filter(AgentRegistry.name == name).first()
        if existing:
            # Update existing agent
            existing.base_url = base_url
            existing.description = description or existing.description
            existing.capabilities_json = json.dumps(capabilities)
            existing.updated_at = utcnow()
            agent_id = existing.id
        else:
            # Create new agent
            agent = AgentRegistry(
                name=name,
                description=description or None,
                base_url=base_url,
                enabled=True,
                capabilities_json=json.dumps(capabilities),
                events_in_json="[]",
                events_out_json="[]",
                auth_type="none",
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            s.add(agent)
            s.flush()
            agent_id = agent.id
        s.commit()
    
    return {"ok": True, "agent_id": agent_id, "message": f"Agent '{name}' registered successfully"}


@app.post("/api/agents/{agent_id}/heartbeat")
async def api_agents_heartbeat(agent_id: int, request: Request):
    """Agent heartbeat API.
    
    Agents should call this periodically to confirm they're alive.
    """
    auth = _require_project_api_key(request)
    if not auth:
        return {"ok": False, "error": "missing or invalid api key"}
    
    with get_session() as s:
        agent = s.query(AgentRegistry).filter(AgentRegistry.id == agent_id).first()
        if agent:
            agent.updated_at = utcnow()
            s.commit()
            return {"ok": True, "message": "heartbeat received"}
        return {"ok": False, "error": "agent not found"}


async def ollama_generate(prompt: str) -> str:
    # Same behavior as scripts/demo_client.py: if not reachable, return a stub that includes citations.
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            r.raise_for_status()
            data = r.json()
            return data.get("response") or ""
    except Exception as e:
        logger.warning(f"Ollama generate failed: {e}, using fallback response")
        return (
            "Here is a summary with references.\n\n"
            "References:\n"
            "[1] Smith et al. (2020) A Study on Things.\n"
            "[2] Doe (2021) Another Paper.\n"
        )


async def ollama_generate_with_meta(prompt: str) -> tuple[str, dict[str, Any]]:
    """Generate response and include provider/latency metadata for observability UI."""
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            r.raise_for_status()
            latency_ms = int((time.perf_counter() - started) * 1000)
            data = r.json()
            return (
                data.get("response") or "",
                {"provider": "ollama", "model": OLLAMA_MODEL, "url": OLLAMA_URL, "latency_ms": latency_ms},
            )
    except Exception as e:
        logger.warning(f"Ollama generate_with_meta failed: {e}, using fallback")
        latency_ms = int((time.perf_counter() - started) * 1000)
        return (
            await ollama_generate(prompt),
            {"provider": "stub", "model": OLLAMA_MODEL, "url": OLLAMA_URL, "latency_ms": latency_ms},
        )


async def ollama_generate_with_meta_model(prompt: str, model: str) -> tuple[str, dict[str, Any]]:
    """Same as `ollama_generate_with_meta` but allows selecting the model per request."""
    started = time.perf_counter()
    try:
        # Ollama can take >8s on the first token (cold start / model load), especially on CPU.
        # Use a more forgiving timeout to avoid unnecessary stub fallbacks.
        timeout = httpx.Timeout(60.0, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            r.raise_for_status()
            latency_ms = int((time.perf_counter() - started) * 1000)
            data = r.json()
            return (
                data.get("response") or "",
                {"provider": "ollama", "model": model, "url": OLLAMA_URL, "latency_ms": latency_ms},
            )
    except Exception as e:
        latency_ms = int((time.perf_counter() - started) * 1000)
        # fall back: use existing stub behavior
        return (
            await ollama_generate(prompt),
            {
                "provider": "stub",
                "model": model,
                "url": OLLAMA_URL,
                "latency_ms": latency_ms,
                # Helpful for debugging timeouts/misconfig without exposing sensitive data.
                "error": f"{type(e).__name__}: {e}",
            },
        )


@app.on_event("startup")
def _startup() -> None:
    init_db()
    migrate_db()

    # Prod guardrails: don't allow default secret.
    if _RUNTIME.env in {"prod", "production"}:
        if (_RUNTIME.dashboard_jwt_secret or "") == "dev-secret-change-me":
            raise RuntimeError("DASHBOARD_JWT_SECRET is using the default value; set a strong secret for production")

    # Bootstrap roles + demo accounts for quick end-to-end testing.
    # NOTE: These are created only if missing (idempotent).
    with get_session() as s:
        for r in [ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER]:
            if not s.query(Role).filter(Role.name == r).first():
                s.add(Role(name=r))
        s.commit()

        force_pw = (os.environ.get("DASHBOARD_BOOTSTRAP_FORCE_PASSWORDS", "0") == "1")

        def _ensure_user(email: str, password: str, role: str):
            u = s.query(User).filter(User.email == email).first()
            if not u:
                u = User(email=email, password_hash=hash_password(password), is_active=True, is_verified=True)
                s.add(u)
                s.flush()
                s.add(AuditEvent(actor_email=None, action="bootstrap", details=f"created demo user {email}"))
            else:
                # Repair common "new setup with old DB" problems:
                # - demo user was deleted and later re-added (missing role mapping)
                # - demo user exists but was deactivated/unverified
                # - optional: reset demo password to documented defaults
                changed = False
                if not bool(getattr(u, "is_active", True)):
                    u.is_active = True
                    changed = True
                if not bool(getattr(u, "is_verified", True)):
                    u.is_verified = True
                    changed = True
                if force_pw:
                    u.password_hash = hash_password(password)
                    changed = True
                if changed:
                    s.add(AuditEvent(actor_email=None, action="bootstrap", details=f"repaired demo user {email}"))
            # Ensure role mapping exists.
            db_role = s.query(Role).filter(Role.name == role).one()
            has = False
            for ur in (u.roles or []):
                try:
                    if ur.role and ur.role.name == role:
                        has = True
                except Exception:
                    pass
            if not has:
                s.add(UserRole(user_id=u.id, role_id=db_role.id))

        # Default admin accounts for local/demo use.
        # - `admin@local` is kept for backwards compatibility.
        # - `admin@kakveda.local` is a valid email format for browsers that block `admin@local`.
        _ensure_user(email="admin@local", password="admin123", role=ROLE_ADMIN)
        _ensure_user(email="admin@kakveda.local", password="admin123", role=ROLE_ADMIN)

        # Dummy credentials for QA/testing kakveda end-to-end.
        # Use these to validate RBAC (viewer/operator) and all flows.
        _ensure_user(email="operator@kakveda.local", password="Operator@123", role=ROLE_OPERATOR)
        _ensure_user(email="viewer@kakveda.local", password="Viewer@123", role=ROLE_VIEWER)

        # Persist any bootstrapped users/role mappings.
        s.commit()


@app.on_event("startup")
async def _subscribe_event_bus() -> None:
    """Best-effort subscriptions so external agents show up in the dashboard.

    - `trace.ingested` -> persists TraceRun rows (Runs page)
    - `child_safety_alert` -> persists WarningEvent rows (Warnings page)
    - `infra.metrics` -> persists node-level infra snapshots (Infra page)
    - `observability.metrics` -> persists observability snapshots (Observability page)
    """
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{EVENT_BUS_URL}/subscribe",
                json={"topic": "trace.ingested", "callback_url": "http://dashboard:8110/events/trace"},
            )
            await client.post(
                f"{EVENT_BUS_URL}/subscribe",
                json={"topic": "child_safety_alert", "callback_url": "http://dashboard:8110/events/child-safety"},
            )
            await client.post(
                f"{EVENT_BUS_URL}/subscribe",
                json={"topic": "infra.metrics", "callback_url": "http://dashboard:8110/events/infra"},
            )
            await client.post(
                f"{EVENT_BUS_URL}/subscribe",
                json={"topic": "observability.metrics", "callback_url": "http://dashboard:8110/events/observability"},
            )
        logger.info("event-bus subscriptions registered")
    except Exception as e:
        # don't fail dashboard startup if event-bus isn't ready yet
        logger.warning(f"event-bus subscription failed: {e}")


def _persist_infra_event_row(s: Any, evt: dict[str, Any]) -> None:
    payload = _extract_infra_payload(evt if isinstance(evt, dict) else {})
    infra = payload.get("infra") if isinstance(payload.get("infra"), dict) else {}
    app_id = str(evt.get("app_id") or "host-infra")
    agent_id = str(payload.get("agent_id") or evt.get("agent_id") or "unknown")
    collection_ms = _to_int(infra.get("collection_duration_ms"), 0)
    tr = TraceRun(
        scenario_run_id=None,
        app_id=app_id,
        agent_id=agent_id,
        name="infra.metrics",
        status="completed",
        provider="system-probe",
        model=None,
        input_json=json.dumps(
            {
                "event_name": "infra.metrics",
                "ts": payload.get("timestamp"),
                "trace_id": evt.get("trace_id"),
            }
        ),
        output_json=json.dumps({"infra_payload": payload, "event": evt}),
        error=None,
        duration_ms=collection_ms if collection_ms > 0 else None,
    )
    s.add(tr)


def _persist_observability_event_row(s: Any, evt: dict[str, Any]) -> None:
    obs_payload = evt.get("observability_payload") if isinstance(evt.get("observability_payload"), dict) else {}
    if not obs_payload:
        obs_payload = {
            "agent_id": str(evt.get("agent_id") or "unknown"),
            "timestamp": str(evt.get("ts") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            "observability": evt.get("observability") if isinstance(evt.get("observability"), dict) else {},
        }
    observability = obs_payload.get("observability") if isinstance(obs_payload.get("observability"), dict) else {}
    app_id = str(evt.get("app_id") or "host-infra")
    agent_id = str(obs_payload.get("agent_id") or evt.get("agent_id") or "unknown")
    latency_current = _to_float(
        ((observability.get("golden_signals") or {}).get("latency_ms") or {}).get("current"),
        0.0,
    )
    duration_ms = int(latency_current) if latency_current > 0 else None
    tr = TraceRun(
        scenario_run_id=None,
        app_id=app_id,
        agent_id=agent_id,
        name="observability.metrics",
        status="completed",
        provider="netra-observability",
        model=None,
        input_json=json.dumps(
            {
                "event_name": "observability.metrics",
                "ts": obs_payload.get("timestamp"),
                "trace_id": evt.get("trace_id"),
            }
        ),
        output_json=json.dumps({"observability_payload": obs_payload, "event": evt}),
        error=None,
        duration_ms=duration_ms,
    )
    s.add(tr)


async def _metrics_ingest_worker() -> None:
    global _metrics_queue
    if not _metrics_queue:
        return
    while True:
        try:
            first = await _metrics_queue.get()
            batch = [first]
            t0 = time.perf_counter()
            while len(batch) < METRICS_BATCH_SIZE:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                remaining = max(0.0, (float(METRICS_BATCH_FLUSH_MS) - elapsed_ms) / 1000.0)
                if remaining <= 0:
                    break
                try:
                    nxt = await asyncio.wait_for(_metrics_queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                batch.append(nxt)
            with get_session() as s:
                for item in batch:
                    kind = str(item.get("kind") or "")
                    evt = item.get("evt") if isinstance(item.get("evt"), dict) else {}
                    if kind == "infra":
                        _persist_infra_event_row(s, evt)
                    elif kind == "observability":
                        _persist_observability_event_row(s, evt)
                _maybe_run_ingest_housekeeping(s)
                s.commit()
        except Exception as e:
            logger.warning(f"metrics ingest worker batch failed: {e}")


async def _enqueue_metrics_event(kind: str, evt: dict[str, Any]) -> bool:
    global _metrics_queue
    if not METRICS_QUEUE_ENABLED:
        return False
    if _metrics_queue is None:
        _metrics_queue = asyncio.Queue(maxsize=METRICS_QUEUE_MAXSIZE)
    try:
        _metrics_queue.put_nowait({"kind": str(kind), "evt": dict(evt or {})})
        return True
    except Exception:
        return False


@app.on_event("startup")
async def _start_metrics_worker() -> None:
    global _metrics_queue, _metrics_worker_task
    if not METRICS_QUEUE_ENABLED:
        return
    if _metrics_queue is None:
        _metrics_queue = asyncio.Queue(maxsize=METRICS_QUEUE_MAXSIZE)
    if _metrics_worker_task is None or _metrics_worker_task.done():
        _metrics_worker_task = asyncio.create_task(_metrics_ingest_worker())


@app.on_event("shutdown")
async def _stop_metrics_worker() -> None:
    global _metrics_worker_task
    if _metrics_worker_task and not _metrics_worker_task.done():
        _metrics_worker_task.cancel()
        try:
            await _metrics_worker_task
        except Exception:
            pass
    _metrics_worker_task = None


@app.post("/events/trace")
async def on_trace_ingested(trace: dict[str, Any]):
    """Persist externally-ingested traces as TraceRuns."""
    try:
        app_id = str(trace.get("app_id") or "unknown")
        agent_id = str(trace.get("agent_id") or "unknown")
        prompt = str(trace.get("prompt") or "")
        response = str(trace.get("response") or "")
        model = str(trace.get("model") or "")
        env = trace.get("env") if isinstance(trace.get("env"), dict) else {}
        trace_name = str(env.get("event_name") or trace.get("name") or "trace.ingested")
        started = _to_dt(trace.get("start_ts")) or _to_dt(env.get("start_ts")) or _to_dt(trace.get("ts")) or utcnow()
        ended = _to_dt(trace.get("end_ts")) or _to_dt(env.get("end_ts"))
        environment = _extract_environment_from_trace(trace, env)
        version = _trace_version(trace, env)

        status_raw = str(env.get("status") or "completed").lower()
        status = "error" if status_raw in {"error", "failed", "blocked"} else "completed"
        err = env.get("error")
        stack_trace = str(env.get("stack_trace") or trace.get("stack_trace") or "")
        handled_err = bool(env.get("handled_error") or trace.get("handled_error") or False)
        duration_ms = int(env.get("duration_ms") or 0) if str(env.get("duration_ms") or "").isdigit() else None
        if (duration_ms is None or duration_ms <= 0) and started and ended:
            duration_ms = max(1, int((ended - started).total_seconds() * 1000))

        with get_session() as s:
            cfg_row = s.query(TracePipelineConfig).order_by(TracePipelineConfig.updated_at.desc()).first()
            cfg = _pipeline_cfg_dict(cfg_row)
            sampling_rules = (
                s.query(TraceSamplingRule)
                .filter(TraceSamplingRule.enabled == True)  # noqa: E712
                .order_by(TraceSamplingRule.priority.desc(), TraceSamplingRule.id.asc())
                .all()
            )
            drop, drop_reason, sample_rate = _trace_should_drop_by_sampling(
                trace,
                app_id=app_id,
                agent_id=agent_id,
                trace_name=trace_name,
                status=status,
                duration_ms=duration_ms,
                cfg=cfg,
                rules=sampling_rules,
            )
            if drop:
                s.add(
                    AuditEvent(
                        actor_email=None,
                        action="trace_drop",
                        details=f"app_id={app_id} agent_id={agent_id} reason={drop_reason} sample_rate={sample_rate}",
                    )
                )
                s.commit()
                return {"ok": True, "dropped": True, "reason": drop_reason, "sample_rate": sample_rate}

            tr = TraceRun(
                scenario_run_id=None,
                app_id=app_id,
                agent_id=agent_id,
                name=trace_name,
                status=status,
                provider=str(env.get("provider") or ""),
                model=model or None,
                input_json=json.dumps({"prompt": prompt, "trace_id": trace.get("trace_id"), "ts": trace.get("ts")}),
                output_json=json.dumps({"response": response, "env": env, "trace": trace}),
                error=str(err) if err else None,
                duration_ms=duration_ms,
            )
            s.add(tr)
            s.flush()

            parsed_spans = _parse_trace_spans(trace, started=started, ended=ended, duration_ms=duration_ms)
            db_spans: list[TraceSpan] = []
            idx_to_id: dict[int, int] = {}
            for row in parsed_spans:
                parent_idx = _to_int(row.get("parent_idx"), -1)
                parent_id = idx_to_id.get(parent_idx) if parent_idx >= 0 else None
                sp = TraceSpan(
                    trace_run_id=int(tr.id),
                    parent_id=parent_id,
                    name=str(row.get("name") or "span"),
                    start_ts=_to_dt(row.get("start_ts")) or started or utcnow(),
                    end_ts=_to_dt(row.get("end_ts")) or ended or started or utcnow(),
                    duration_ms=max(1, _to_int(row.get("duration_ms"), 1)),
                    meta_json=str(row.get("meta_json") or "{}"),
                )
                s.add(sp)
                s.flush()
                idx_to_id[_to_int(row.get("idx"), len(idx_to_id))] = int(sp.id)
                db_spans.append(sp)

            _generate_span_metric_points(
                s,
                trace_run_id=int(tr.id),
                ts=started,
                app_id=app_id,
                spans=db_spans,
            )
            _persist_profiler_samples(
                s,
                trace_run_id=int(tr.id),
                ts=started,
                app_id=app_id,
                agent_id=agent_id,
                environment=environment,
                version=version,
                trace_name=trace_name,
                spans=db_spans,
            )
            _persist_db_query_samples(
                s,
                trace_run_id=int(tr.id),
                ts=started,
                app_id=app_id,
                agent_id=agent_id,
                environment=environment,
                trace_name=trace_name,
                spans=db_spans,
            )

            # APM error tracking: automatic grouping + replay context capture.
            if str(status).lower() == "error" or bool(err):
                _upsert_apm_error(
                    s,
                    trace_run_id=int(tr.id),
                    ts=started,
                    app_id=app_id,
                    agent_id=agent_id,
                    service_name=str(trace_name or ""),
                    environment=environment,
                    handled=handled_err,
                    error_message=str(err or trace.get("error") or "error"),
                    stack_trace=stack_trace,
                    replay_context={
                        "trace_id": trace.get("trace_id"),
                        "app_id": app_id,
                        "agent_id": agent_id,
                        "environment": environment,
                        "trace_name": trace_name,
                        "prompt": prompt,
                        "response": response,
                        "input_trace": trace,
                        "env": env,
                        "span_count": len(db_spans),
                    },
                )

            s.add(
                AuditEvent(
                    actor_email=None,
                    action="trace_ingested",
                    details=f"run_id={tr.id} sample_rate={sample_rate}",
                )
            )
            _maybe_run_ingest_housekeeping(s)
            s.commit()
        return {"ok": True, "dropped": False, "sample_rate": sample_rate}
    except Exception as e:
        logger.warning(f"trace ingest persist failed: {e}")
        return {"ok": False, "error": str(e)}


@app.post("/events/child-safety")
async def on_child_safety_alert(evt: dict[str, Any]):
    """Persist child safety alerts as WarningEvents so they show up in /warnings."""
    try:
        alert_type = str(evt.get("alert_type") or "")
        question = str(evt.get("question") or "")
        severity = str(evt.get("severity") or "").lower()
        recommendation = str(evt.get("recommendation") or "")
        detected = evt.get("detected_keywords") or []
        if not isinstance(detected, list):
            detected = []

        # Heuristic mapping severity->confidence
        conf = 0.6
        if severity == "high":
            conf = 0.95
        elif severity == "medium":
            conf = 0.75
        elif severity == "low":
            conf = 0.55

        action = "warn"
        if alert_type == "blocked_content":
            action = "block"

        with get_session() as s:
            we = WarningEvent(
                app_id=str(evt.get("app_id") or "kids-app"),
                agent_id=str(evt.get("agent_id") or "kakveda-kids-agent"),
                action=action,
                confidence=_coerce_float_confidence(conf, default=conf),
                pattern_id=None,
                prompt=question,
                message=recommendation or f"Child safety alert: {alert_type}",
                references_json=json.dumps(detected),
            )
            s.add(we)
            s.commit()
        return {"ok": True}
    except Exception as e:
        logger.warning(f"child safety persist failed: {e}")
        return {"ok": False, "error": str(e)}
        s.commit()


@app.post("/events/infra")
async def on_infra_metrics(evt: dict[str, Any]):
    """Persist infra snapshots as TraceRun rows for infra monitoring UI."""
    try:
        queued = await _enqueue_metrics_event("infra", evt if isinstance(evt, dict) else {})
        if queued:
            return {"ok": True, "queued": True}
        with get_session() as s:
            _persist_infra_event_row(s, evt if isinstance(evt, dict) else {})
            _maybe_run_ingest_housekeeping(s)
            s.commit()
        return {"ok": True, "queued": False}
    except Exception as e:
        logger.warning(f"infra metrics persist failed: {e}")
        return {"ok": False, "error": str(e)}


@app.post("/events/observability")
async def on_observability_metrics(evt: dict[str, Any]):
    """Persist observability snapshots for observability dashboard UI."""
    try:
        queued = await _enqueue_metrics_event("observability", evt if isinstance(evt, dict) else {})
        if queued:
            return {"ok": True, "queued": True}
        with get_session() as s:
            _persist_observability_event_row(s, evt if isinstance(evt, dict) else {})
            _maybe_run_ingest_housekeeping(s)
            s.commit()
        return {"ok": True, "queued": False}
    except Exception as e:
        logger.warning(f"observability metrics persist failed: {e}")
        return {"ok": False, "error": str(e)}

@app.get("/projects", response_class=HTMLResponse)
async def projects_list(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)

    with get_session() as s:
        projects = s.query(Project).order_by(Project.created_at.desc()).all()
    return templates.TemplateResponse("projects.html", {"request": request, "projects": projects})


@app.post("/projects/create")
async def projects_create(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form(...),
    description: str | None = Form(None),
):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)

    with get_session() as s:
        existing = s.query(Project).filter(Project.name == name.strip()).first()
        if existing:
            return RedirectResponse(url="/projects", status_code=302)
        p = Project(name=name.strip(), description=(description.strip() if description else None))
        s.add(p)
        s.commit()
    return RedirectResponse(url="/projects", status_code=302)


@app.post("/projects/{project_id}/select")
async def projects_select(project_id: int, request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    # Cookie UX: scope run browsing / playgound to a project.
    resp = RedirectResponse(url="/runs", status_code=302)
    resp.set_cookie("aitester_project_id", str(project_id), httponly=True, samesite="lax")
    return resp


@app.post("/projects/clear")
async def projects_clear(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    resp = RedirectResponse(url="/runs", status_code=302)
    resp.delete_cookie("aitester_project_id")
    return resp


@app.post("/projects/{project_id}/keys/create")
async def project_api_key_create(
    project_id: int,
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form("default"),
):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)

    # Generate and store hashed.
    raw = uuid.uuid4().hex + uuid.uuid4().hex
    h = _hash_api_key(raw)
    with get_session() as s:
        s.add(ProjectApiKey(project_id=project_id, name=name.strip() or "default", key_hash=h, is_active=True))
        s.commit()

    # Show once via query param.
    return RedirectResponse(url=f"/projects?new_key={raw}", status_code=302)


@app.post("/api/ingest/run")
async def api_ingest_run(request: Request):
    """Ingest a TraceRun via project API key.

    Header: X-API-Key: <token>
    Body: {app_id, agent_id, name?, status?, duration_ms?, provider?, model?, input_json, output_json, error?, tags?}
    """
    auth = _require_project_api_key(request)
    if not auth:
        return {"ok": False, "error": "missing or invalid api key"}
    project_id, _row = auth

    body = await request.json()
    app_id = str(body.get("app_id") or "app-A")
    agent_id = str(body.get("agent_id") or "api")
    name = str(body.get("name") or "api.ingest")
    status = str(body.get("status") or "ok")
    provider = str(body.get("provider") or "")
    model = str(body.get("model") or "")
    duration_ms = int(body.get("duration_ms") or 0) if body.get("duration_ms") is not None else None
    input_json = json.dumps(body.get("input") or body.get("input_json") or {}, ensure_ascii=False)
    output_json = json.dumps(body.get("output") or body.get("output_json") or {}, ensure_ascii=False)
    error = str(body.get("error")) if body.get("error") else None

    # Token/cost if present; else estimate from strings.
    prompt_text = ""
    try:
        inp = json.loads(input_json or "{}")
        prompt_text = str(inp.get("prompt") or "")
    except Exception:
        prompt_text = ""
    out_text = ""
    try:
        outp = json.loads(output_json or "{}")
        out_text = str(outp.get("response") or outp.get("text") or "")
    except Exception:
        out_text = ""

    prompt_tokens = int(body.get("prompt_tokens") or _estimate_tokens(prompt_text))
    completion_tokens = int(body.get("completion_tokens") or _estimate_tokens(out_text))
    total_tokens = int(body.get("total_tokens") or (prompt_tokens + completion_tokens))
    cost_usd = float(body.get("cost_usd") or _compute_cost_usd(provider, prompt_tokens, completion_tokens))

    # Optional budget check (demo): if enabled and would exceed, mark status=error.
    with get_session() as s:
        b = s.query(ProjectBudget).filter(ProjectBudget.project_id == project_id, ProjectBudget.provider == provider, ProjectBudget.enabled == True).first()  # noqa: E712
        if b and int(b.monthly_usd or 0) > 0:
            # NOTE: real month rollup is out of scope; demo checks last 30d.
            since = utcnow() - timedelta(days=30)
            spent_micro = (
                s.query(TraceRun)
                .filter(TraceRun.project_id == project_id, TraceRun.provider == provider, TraceRun.ts >= since)
                .with_entities(TraceRun.cost_usd)
                .all()
            )
            total_spent = sum(int(r[0] or 0) for r in spent_micro)
            if total_spent + _usd_to_micro(cost_usd) > int(b.monthly_usd) * 1_000_000:
                status = "error"
                error = (error or "") + "\nBudget exceeded"

        tr = TraceRun(
            ts=utcnow(),
            project_id=project_id,
            app_id=app_id,
            agent_id=agent_id,
            name=name,
            status=status,
            duration_ms=duration_ms,
            provider=provider or None,
            model=model or None,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=_usd_to_micro(cost_usd),
            input_json=input_json,
            output_json=output_json,
            error=error,
            scenario_run_id=None,
        )
        s.add(tr)
        s.flush()
        run_id = int(tr.id)

        # Optional tags -> run_feedback
        tags = body.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        if isinstance(tags, list):
            for t in tags:
                s.add(RunFeedback(trace_run_id=run_id, key="tag", value=str(t), actor_email="api"))

        s.commit()

    return {"ok": True, "run_id": run_id}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    # Choose which app_id to plot for health trend.
    # Priority: explicit query param -> latest ingested run -> demo default.
    app_id_for_health = request.query_params.get("app_id")

    # Populate app choices from ingested runs (best-effort).
    app_choices: list[str] = []
    with get_session() as s:
        try:
            app_choices = [r[0] for r in s.query(TraceRun.app_id).distinct().order_by(TraceRun.app_id.asc()).all() if r and r[0]]
        except Exception:
            app_choices = []

        # Hide demo apps from selectors.
        app_choices = [a for a in app_choices if a not in HIDDEN_APPS]

        if not app_id_for_health:
            row = s.query(TraceRun.app_id).order_by(TraceRun.ts.desc()).first()
            if row and row[0]:
                cand = str(row[0])
                if cand not in HIDDEN_APPS:
                    app_id_for_health = cand

    if not app_id_for_health:
        app_id_for_health = app_choices[0] if app_choices else "kids-app"

    async with httpx.AsyncClient(timeout=5.0) as client:
        failures = []
        patterns = []
        health_points = []
        latest_health_score: float | None = None
        try:
            failures = (await client.get(f"{GFKB_URL}/failures")).json().get("failures", [])
            failures = _dedupe_latest_failures(failures)[:10]
        except Exception:
            failures = []
        try:
            patterns = (await client.get(f"{GFKB_URL}/patterns")).json().get("patterns", [])
        except Exception:
            patterns = []
        try:
            health_points = (
                (await client.get(f"{HEALTH_URL}/health/{quote(app_id_for_health)}", params={"limit": 40}))
                .json()
                .get("points", [])
            )
        except Exception:
            health_points = []

        if health_points:
            try:
                latest_health_score = float(health_points[-1].get("score"))
            except Exception:
                latest_health_score = None

    # last warnings collected by dashboard
    with get_session() as s:
        warnings = (
            s.query(WarningEvent)
            .order_by(WarningEvent.ts.desc())
            .limit(8)
            .all()
        )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "failures": failures,
            "patterns": patterns,
            "health_points": health_points,
            "health_app_id": app_id_for_health,
            "health_app_choices": app_choices,
            "latest_health_score": latest_health_score,
            "warnings": warnings,
        },
    )


@app.api_route("/health", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def health_view(
    request: Request,
    app_id: str | None = Query(None),
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    is_admin = bool(user.get("is_admin"))

    # Resolve app_id similarly to home.
    app_choices: list[str] = []
    with get_session() as s:
        try:
            app_choices = [r[0] for r in s.query(TraceRun.app_id).distinct().order_by(TraceRun.app_id.asc()).all() if r and r[0]]
        except Exception:
            app_choices = []

        app_choices = [a for a in app_choices if a not in HIDDEN_APPS]

        if not app_id:
            row = s.query(TraceRun.app_id).order_by(TraceRun.ts.desc()).first()
            if row and row[0]:
                cand = str(row[0])
                if cand not in HIDDEN_APPS:
                    app_id = cand
    if not app_id:
        app_id = app_choices[0] if app_choices else "kids-app"

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            health_points = (
                (await client.get(f"{HEALTH_URL}/health/{quote(app_id)}", params={"limit": 200}))
                .json()
                .get("points", [])
            )
        except Exception:
            health_points = []

    latest_health_score: float | None = None
    if health_points:
        try:
            latest_health_score = float(health_points[-1].get("score"))
        except Exception:
            latest_health_score = None

    return templates.TemplateResponse(
        "health.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "is_admin": is_admin,
            "health_points": health_points,
            "health_app_id": app_id,
            "health_app_choices": app_choices,
            "latest_health_score": latest_health_score,
            "message": request.query_params.get("message") or "",
            "error": request.query_params.get("error") or "",
        },
    )


@app.post("/health/test")
async def health_generate_test_event(
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
    app_id: str = Form("app-A"),
    failure_type: str = Form("HALLUCINATION_CITATION"),
    severity: str = Form("high"),
):
    if isinstance(user, RedirectResponse):
        return user

    aid = (app_id or "app-A").strip() or "app-A"
    ftype = (failure_type or "HALLUCINATION_CITATION").strip() or "HALLUCINATION_CITATION"
    sev = (severity or "high").strip().lower() or "high"
    if sev not in {"low", "medium", "high"}:
        sev = "high"

    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "app_id": aid,
        "failure_type": ftype,
        "severity": sev,
        "summary": f"dashboard test event ({ftype})",
        "source": "dashboard",
        "event_id": str(uuid.uuid4()),
    }

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post(
                f"{EVENT_BUS_URL}/publish",
                json={"topic": "failure.detected", "event": payload},
            )
            ok = 200 <= int(r.status_code) < 300
    except Exception as e:
        return RedirectResponse(
            url=f"/health?app_id={quote(aid)}&error={quote('publish failed: ' + str(e)[:80])}",
            status_code=303,
        )

    if not ok:
        detail = ""
        try:
            detail = (r.text or "").strip()
        except Exception:
            detail = ""
        msg = f"publish failed: HTTP {getattr(r, 'status_code', '?')}"
        if detail:
            msg = f"{msg} {detail[:120]}"
        return RedirectResponse(
            url=f"/health?app_id={quote(aid)}&error={quote(msg)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/health?app_id={quote(aid)}&message={quote('test event published')}",
        status_code=303,
    )


@app.get("/infra", response_class=HTMLResponse)
async def infra_monitoring(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    agent_id: str | None = None,
    q: str | None = None,
    custom_metric: str | None = Query("cpu_percent_total"),
    custom_metric_2: str | None = Query("memory_percent"),
    cpu_threshold: str | None = Query(None),
    memory_threshold: str | None = Query(None),
    disk_threshold: str | None = Query(None),
    load_threshold: str | None = Query(None),
    temp_threshold: str | None = Query(None),
    collection_ms_threshold: str | None = Query(None),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_agent = (agent_id or "").strip() or None
    query_text = (q or "").strip().lower()
    selected_project_id = _effective_project_id(request, user)

    filter_keys = {
        "agent_id",
        "q",
        "custom_metric",
        "custom_metric_2",
        "cpu_threshold",
        "memory_threshold",
        "disk_threshold",
        "load_threshold",
        "temp_threshold",
        "collection_ms_threshold",
    }
    has_explicit_filters = any((request.query_params.get(k) or "").strip() != "" for k in filter_keys)
    threshold_keys = {
        "cpu_threshold",
        "memory_threshold",
        "disk_threshold",
        "load_threshold",
        "temp_threshold",
        "collection_ms_threshold",
    }
    has_explicit_thresholds = any((request.query_params.get(k) or "").strip() != "" for k in threshold_keys)

    with get_session() as s:
        ql = s.query(InfraDashboardLayout).filter(InfraDashboardLayout.user_email == email)
        if selected_project_id is None:
            ql = ql.filter(InfraDashboardLayout.project_id.is_(None))
        else:
            ql = ql.filter((InfraDashboardLayout.project_id == selected_project_id) | (InfraDashboardLayout.project_id.is_(None)))
        layout_rows = ql.order_by(InfraDashboardLayout.updated_at.desc()).all()

    auto_threshold_configs: dict[str, dict[str, Any]] = {}
    for r in layout_rows:
        name_txt = str(r.name or "")
        if not name_txt.startswith("__auto_thresholds__::"):
            continue
        cfg = json.loads(r.config_json or "{}") if isinstance(r.config_json, str) else {}
        auto_threshold_configs[name_txt] = cfg if isinstance(cfg, dict) else {}

    saved_layouts = [
        {
            "id": int(r.id),
            "layout_uid": str(getattr(r, "layout_uid", "") or ""),
            "name": str(r.name or ""),
            "project_id": r.project_id,
            "is_default": bool(r.is_default),
            "config": json.loads(r.config_json or "{}") if isinstance(r.config_json, str) else {},
        }
        for r in layout_rows
        if not str(r.name or "").startswith("__auto_thresholds__::")
    ]
    default_layout = next((l for l in saved_layouts if l.get("is_default")), None)
    active_layout_name = ""
    if (not has_explicit_filters) and default_layout and isinstance(default_layout.get("config"), dict):
        c = default_layout["config"]
        selected_agent = str(c.get("agent_id") or selected_agent or "").strip() or None
        query_text = str(c.get("q") or query_text or "").strip().lower()
        custom_metric = str(c.get("custom_metric") or custom_metric or "cpu_percent_total")
        custom_metric_2 = str(c.get("custom_metric_2") or custom_metric_2 or "memory_percent")
        cpu_threshold = str(c.get("cpu_threshold") if c.get("cpu_threshold") is not None else (cpu_threshold or ""))
        memory_threshold = str(c.get("memory_threshold") if c.get("memory_threshold") is not None else (memory_threshold or ""))
        disk_threshold = str(c.get("disk_threshold") if c.get("disk_threshold") is not None else (disk_threshold or ""))
        load_threshold = str(c.get("load_threshold") if c.get("load_threshold") is not None else (load_threshold or ""))
        temp_threshold = str(c.get("temp_threshold") if c.get("temp_threshold") is not None else (temp_threshold or ""))
        collection_ms_threshold = str(
            c.get("collection_ms_threshold") if c.get("collection_ms_threshold") is not None else (collection_ms_threshold or "")
        )
        active_layout_name = str(default_layout.get("name") or "")

    auto_threshold_key = f"__auto_thresholds__::{selected_agent or '__all__'}"
    auto_cfg = auto_threshold_configs.get(auto_threshold_key) if isinstance(auto_threshold_configs.get(auto_threshold_key), dict) else {}
    if (not has_explicit_thresholds) and auto_cfg:
        cpu_threshold = str(auto_cfg.get("cpu_threshold") if auto_cfg.get("cpu_threshold") is not None else (cpu_threshold or ""))
        memory_threshold = str(auto_cfg.get("memory_threshold") if auto_cfg.get("memory_threshold") is not None else (memory_threshold or ""))
        disk_threshold = str(auto_cfg.get("disk_threshold") if auto_cfg.get("disk_threshold") is not None else (disk_threshold or ""))
        load_threshold = str(auto_cfg.get("load_threshold") if auto_cfg.get("load_threshold") is not None else (load_threshold or ""))
        temp_threshold = str(auto_cfg.get("temp_threshold") if auto_cfg.get("temp_threshold") is not None else (temp_threshold or ""))
        collection_ms_threshold = str(
            auto_cfg.get("collection_ms_threshold") if auto_cfg.get("collection_ms_threshold") is not None else (collection_ms_threshold or "")
        )

    def _qfloat(value: str | None, default: float) -> float:
        try:
            raw = str(value).strip() if value is not None else ""
            if raw == "":
                return float(default)
            return float(raw)
        except Exception:
            return float(default)

    def _qint(value: str | None, default: int) -> int:
        try:
            raw = str(value).strip() if value is not None else ""
            if raw == "":
                return int(default)
            return int(float(raw))
        except Exception:
            return int(default)

    cpu_threshold_v = _qfloat(cpu_threshold, 85.0)
    memory_threshold_v = _qfloat(memory_threshold, 85.0)
    disk_threshold_v = _qfloat(disk_threshold, 90.0)
    load_threshold_v = _qfloat(load_threshold, 1.2)
    temp_threshold_v = _qfloat(temp_threshold, 85.0)
    collection_ms_threshold_v = _qint(collection_ms_threshold, 500)
    threshold_message_parts: list[str] = []

    def _clamp_float(name: str, value: float, lo: float, hi: float) -> float:
        if value < lo:
            threshold_message_parts.append(f"{name} clamped to {lo}")
            return float(lo)
        if value > hi:
            threshold_message_parts.append(f"{name} clamped to {hi}")
            return float(hi)
        return float(value)

    def _clamp_int(name: str, value: int, lo: int, hi: int) -> int:
        if value < lo:
            threshold_message_parts.append(f"{name} clamped to {lo}")
            return int(lo)
        if value > hi:
            threshold_message_parts.append(f"{name} clamped to {hi}")
            return int(hi)
        return int(value)

    cpu_threshold_v = _clamp_float("cpu_threshold", cpu_threshold_v, 0.0, 100.0)
    memory_threshold_v = _clamp_float("memory_threshold", memory_threshold_v, 0.0, 100.0)
    disk_threshold_v = _clamp_float("disk_threshold", disk_threshold_v, 0.0, 100.0)
    load_threshold_v = _clamp_float("load_threshold", load_threshold_v, 0.0, 20.0)
    temp_threshold_v = _clamp_float("temp_threshold", temp_threshold_v, 0.0, 150.0)
    collection_ms_threshold_v = _clamp_int("collection_ms_threshold", collection_ms_threshold_v, 1, 60000)
    threshold_message = "; ".join(threshold_message_parts)

    if has_explicit_thresholds:
        auto_cfg_to_save = {
            "agent_id": selected_agent or "",
            "cpu_threshold": cpu_threshold_v,
            "memory_threshold": memory_threshold_v,
            "disk_threshold": disk_threshold_v,
            "load_threshold": load_threshold_v,
            "temp_threshold": temp_threshold_v,
            "collection_ms_threshold": collection_ms_threshold_v,
        }
        with get_session() as s:
            qauto = s.query(InfraDashboardLayout).filter(
                InfraDashboardLayout.user_email == email,
                InfraDashboardLayout.name == auto_threshold_key,
            )
            if selected_project_id is None:
                qauto = qauto.filter(InfraDashboardLayout.project_id.is_(None))
            else:
                qauto = qauto.filter(InfraDashboardLayout.project_id == selected_project_id)
            row = qauto.first()
            if row:
                row.updated_at = utcnow()
                row.config_json = json.dumps(auto_cfg_to_save, ensure_ascii=True)
            else:
                row = InfraDashboardLayout(
                    user_email=email,
                    project_id=selected_project_id,
                    layout_uid=f"infra-layout-{uuid.uuid4().hex[:12]}",
                    name=auto_threshold_key,
                    config_json=json.dumps(auto_cfg_to_save, ensure_ascii=True),
                    is_default=False,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
                s.add(row)
            s.commit()

    def _parse_ts(ts: str | None) -> datetime | None:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            return None

    def _system_health(snapshot: dict[str, Any]) -> float:
        cpu = _to_float(snapshot.get("cpu_percent_total"), 0.0)
        mem = _to_float(snapshot.get("memory_percent"), 0.0)
        load = _to_float(snapshot.get("load_average_1m"), 0.0)
        swap = _to_float(snapshot.get("swap_percent"), 0.0)
        disk_used = _to_float(snapshot.get("disk_used_percent"), 0.0)
        zombie = _to_int(snapshot.get("process_zombie_count"), 0)
        cpu_count = max(1, _to_int(snapshot.get("cpu_count_logical"), 1))
        fd_open = _to_int(snapshot.get("open_file_descriptors"), 0)
        fd_max = _to_int(snapshot.get("max_file_descriptors"), 0)
        fd_ratio = (float(fd_open) / float(fd_max)) if fd_max > 0 else 0.0

        penalty = 0.0
        penalty += max(cpu - 85.0, 0.0) * 0.8
        penalty += max(mem - 85.0, 0.0) * 0.8
        penalty += max(disk_used - 90.0, 0.0) * 0.9
        penalty += max(swap - 60.0, 0.0) * 0.5
        penalty += max((load / float(cpu_count)) - 1.2, 0.0) * 25.0
        penalty += min(float(zombie) * 2.0, 15.0)
        penalty += max(fd_ratio - 0.8, 0.0) * 100.0
        return max(0.0, min(100.0, 100.0 - penalty))

    snapshots: list[dict[str, Any]] = []
    filter_message = ""
    with get_session() as s:
        q = s.query(TraceRun).filter(TraceRun.name == "infra.metrics")
        runs = q.order_by(TraceRun.ts.desc()).limit(INFRA_UI_MAX_SNAPSHOTS).all()

        for run in runs:
            try:
                out = json.loads(run.output_json or "{}")
            except Exception:
                out = {}
            payload = out.get("infra_payload")
            if not isinstance(payload, dict):
                payload = _extract_infra_payload(out.get("event") or {})
            infra = payload.get("infra") if isinstance(payload.get("infra"), dict) else {}
            cpu = infra.get("cpu") if isinstance(infra.get("cpu"), dict) else {}
            memory = infra.get("memory") if isinstance(infra.get("memory"), dict) else {}
            system = infra.get("system") if isinstance(infra.get("system"), dict) else {}
            process = infra.get("process") if isinstance(infra.get("process"), dict) else {}
            disk = infra.get("disk") if isinstance(infra.get("disk"), list) else []
            network = infra.get("network") if isinstance(infra.get("network"), list) else []
            docker = infra.get("docker") if isinstance(infra.get("docker"), list) else []
            docker_error = str(infra.get("docker_error") or "").strip()
            docker_socket_path = str(infra.get("docker_socket_path") or "").strip()
            ts = str(payload.get("timestamp") or (run.ts.isoformat() if run.ts else ""))
            disk_total = sum(_to_int(d.get("disk_total_bytes"), 0) for d in disk)
            disk_used = sum(_to_int(d.get("disk_used_bytes"), 0) for d in disk)
            disk_used_percent = (float(disk_used) / float(disk_total) * 100.0) if disk_total > 0 else 0.0
            net_total_bytes = sum(_to_int(n.get("net_bytes_recv"), 0) + _to_int(n.get("net_bytes_sent"), 0) for n in network)
            collection_ms = _to_int(infra.get("collection_duration_ms"), 0)
            snapshots.append(
                {
                    "run_id": run.id,
                    "agent_id": str(payload.get("agent_id") or run.agent_id or "unknown"),
                    "system_id": str(payload.get("agent_id") or run.agent_id or "unknown"),
                    "hostname": str(system.get("hostname") or ""),
                    "app_id": str(run.app_id or "host-infra"),
                    "ts": ts,
                    "ts_dt": _parse_ts(ts),
                    "cpu_percent_total": _to_float(cpu.get("cpu_percent_total"), 0.0),
                    "cpu_count_logical": _to_int(cpu.get("cpu_count_logical"), 1),
                    "memory_percent": _to_float(memory.get("memory_percent"), 0.0),
                    "memory_used_bytes": _to_int(memory.get("memory_used_bytes"), 0),
                    "memory_total_bytes": _to_int(memory.get("memory_total_bytes"), 0),
                    "load_average_1m": _to_float(system.get("load_average_1m"), 0.0),
                    "load_average_5m": _to_float(system.get("load_average_5m"), 0.0),
                    "load_average_15m": _to_float(system.get("load_average_15m"), 0.0),
                    "swap_percent": _to_float(memory.get("swap_percent"), 0.0),
                    "open_file_descriptors": _to_int(system.get("open_file_descriptors"), 0),
                    "max_file_descriptors": _to_int(system.get("max_file_descriptors"), 0),
                    "uptime_seconds": _to_int(system.get("uptime_seconds"), 0),
                    "cpu_temperature": _to_float(system.get("cpu_temperature"), 0.0),
                    "gpu_temperature": _to_float(system.get("gpu_temperature"), 0.0),
                    "process_total_count": _to_int(process.get("process_total_count"), 0),
                    "process_running_count": _to_int(process.get("process_running_count"), 0),
                    "process_zombie_count": _to_int(process.get("process_zombie_count"), 0),
                    "top_5_cpu_processes": process.get("top_5_cpu_processes") if isinstance(process.get("top_5_cpu_processes"), list) else [],
                    "top_5_memory_processes": process.get("top_5_memory_processes") if isinstance(process.get("top_5_memory_processes"), list) else [],
                    "disk_used_bytes_total": disk_used,
                    "disk_total_bytes_total": disk_total,
                    "disk_used_percent": disk_used_percent,
                    "net_total_bytes": net_total_bytes,
                    "collection_duration_ms": collection_ms,
                    "fd_utilization_percent": (float(_to_int(system.get("open_file_descriptors"), 0)) / float(max(1, _to_int(system.get("max_file_descriptors"), 1)))) * 100.0 if _to_int(system.get("max_file_descriptors"), 0) > 0 else 0.0,
                    "disk": disk,
                    "network": network,
                    "docker": docker,
                    "docker_error": docker_error,
                    "docker_socket_path": docker_socket_path,
                    "docker_count": len(docker),
                    "docker_count_effective": len(docker),
                    "raw": payload,
                }
            )

        agents = [r[0] for r in s.query(TraceRun.agent_id).filter(TraceRun.name == "infra.metrics").distinct().order_by(TraceRun.agent_id.asc()).all() if r and r[0]]

    base_snapshots = list(snapshots)
    if selected_agent:
        filtered_by_agent = [s for s in snapshots if str(s.get("agent_id") or "") == selected_agent]
        if filtered_by_agent:
            snapshots = filtered_by_agent
        else:
            filter_message = f"agent '{selected_agent}' had no data; showing all snapshots"
            snapshots = base_snapshots

    if query_text:
        def _match(snap: dict[str, Any]) -> bool:
            host = str(((snap.get("raw") or {}).get("infra") or {}).get("system", {}).get("hostname", "")).lower()
            terms = [
                str(snap.get("agent_id") or "").lower(),
                str(snap.get("app_id") or "").lower(),
                str(host),
                str(snap.get("ts") or "").lower(),
            ]
            return any(query_text in t for t in terms)

        filtered_by_query = [s for s in snapshots if _match(s)]
        if filtered_by_query:
            snapshots = filtered_by_query
        else:
            if filter_message:
                filter_message += "; "
            filter_message += f"query '{query_text}' returned no matches; showing current snapshot set"

    # If latest docker poll times out, keep docker_count trend stable with the most recent known-good value.
    for i, snap in enumerate(snapshots):
        live_count = _to_int(snap.get("docker_count"), 0)
        if live_count > 0:
            snap["docker_count_effective"] = live_count
            continue
        sid = str(snap.get("system_id") or "unknown")
        fallback = None
        for prev in snapshots[i + 1 :]:
            if str(prev.get("system_id") or "unknown") != sid:
                continue
            prev_count = _to_int(prev.get("docker_count"), 0)
            if prev_count > 0:
                fallback = prev
                break
        if fallback:
            snap["docker_count_effective"] = _to_int(fallback.get("docker_count"), 0)
            snap["docker_count_source"] = "fallback"
        else:
            snap["docker_count_effective"] = 0
            snap["docker_count_source"] = "live"

    latest = snapshots[0] if snapshots else None
    trend_points = list(reversed(snapshots[:120]))
    for p in snapshots:
        p["system_health_score"] = _system_health(p)
    for p in trend_points:
        p["system_health_score"] = _system_health(p)

    cpu_points = [{"ts": p["ts"], "value": p["cpu_percent_total"]} for p in trend_points]
    mem_points = [{"ts": p["ts"], "value": p["memory_percent"]} for p in trend_points]
    load_points = [{"ts": p["ts"], "value": p["load_average_1m"]} for p in trend_points]
    health_points = [{"ts": p["ts"], "value": p["system_health_score"]} for p in trend_points]
    disk_points = [{"ts": p["ts"], "value": p["disk_used_percent"]} for p in trend_points]
    proc_points = [{"ts": p["ts"], "value": p["process_running_count"]} for p in trend_points]
    collect_points = [{"ts": p["ts"], "value": p["collection_duration_ms"]} for p in trend_points]
    fd_points = [{"ts": p["ts"], "value": p["fd_utilization_percent"]} for p in trend_points]
    temp_points = [{"ts": p["ts"], "value": p["cpu_temperature"]} for p in trend_points]
    swap_points = [{"ts": p["ts"], "value": p["swap_percent"]} for p in trend_points]
    docker_points = [{"ts": p["ts"], "value": _to_int(p.get("docker_count_effective"), _to_int(p.get("docker_count"), 0))} for p in trend_points]

    net_rate_points: list[dict[str, Any]] = []
    prev = None
    for p in trend_points:
        rate = 0.0
        if prev and p.get("ts_dt") and prev.get("ts_dt"):
            dt = (p["ts_dt"] - prev["ts_dt"]).total_seconds()
            if dt > 0:
                delta = float(p.get("net_total_bytes", 0) - prev.get("net_total_bytes", 0))
                rate = max(0.0, delta / dt)
        net_rate_points.append({"ts": p["ts"], "value": rate})
        prev = p

    top_network = []
    top_disk = []
    latest_top_cpu_processes = []
    latest_top_mem_processes = []
    latest_docker = []
    latest_docker_error = ""
    latest_docker_socket_path = ""
    all_containers: list[dict[str, Any]] = []
    data_coverage = {}
    time_data = {"has_time_data": False, "avg_interval_sec": 0.0, "snapshot_count": len(snapshots), "latest_age_sec": 0}
    if latest:
        top_network = sorted(
            latest["network"],
            key=lambda x: _to_int(x.get("net_bytes_recv"), 0) + _to_int(x.get("net_bytes_sent"), 0),
            reverse=True,
        )[:10]
        top_disk = sorted(
            latest["disk"],
            key=lambda x: _to_int(x.get("disk_used_bytes"), 0),
            reverse=True,
        )[:10]
        latest_top_cpu_processes = latest.get("top_5_cpu_processes") or []
        latest_top_mem_processes = latest.get("top_5_memory_processes") or []
        latest_docker = latest.get("docker") or []
        latest_docker_error = str(latest.get("docker_error") or "").strip()
        latest_docker_socket_path = str(latest.get("docker_socket_path") or "").strip()

        # Aggregate docker containers from the latest snapshot of each system.
        latest_by_system: dict[str, dict[str, Any]] = {}
        for s_ in snapshots:
            sid = str(s_.get("system_id") or "unknown")
            if sid not in latest_by_system:
                latest_by_system[sid] = s_
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for sid, snap in latest_by_system.items():
            host = str(snap.get("hostname") or "")
            for c in (snap.get("docker") or []):
                cname = str(c.get("container_name") or "unknown")
                key = (sid, cname)
                if key in seen:
                    continue
                seen.add(key)
                net = c.get("container_net_io") if isinstance(c.get("container_net_io"), dict) else {}
                blk = c.get("container_block_io") if isinstance(c.get("container_block_io"), dict) else {}
                merged.append(
                    {
                        "system_id": sid,
                        "hostname": host,
                        "container_name": cname,
                        "container_status": str(c.get("container_status") or ""),
                        "container_cpu_percent": _to_float(c.get("container_cpu_percent"), 0.0),
                        "container_memory_usage": _to_int(c.get("container_memory_usage"), 0),
                        "container_memory_limit": _to_int(c.get("container_memory_limit"), 0),
                        "container_restart_count": _to_int(c.get("container_restart_count"), 0),
                        "net_rx_bytes": _to_int(net.get("rx_bytes"), 0),
                        "net_tx_bytes": _to_int(net.get("tx_bytes"), 0),
                        "blk_read_bytes": _to_int(blk.get("read_bytes"), 0),
                        "blk_write_bytes": _to_int(blk.get("write_bytes"), 0),
                    }
                )
        all_containers = sorted(
            merged,
            key=lambda x: (x.get("system_id") or "", x.get("container_name") or ""),
        )

        data_coverage = {
            "cpu": bool(latest.get("cpu_percent_total") or latest.get("cpu_percent_total") == 0),
            "memory": bool(latest.get("memory_total_bytes")),
            "disk": bool(latest.get("disk")),
            "network": bool(latest.get("network")),
            "process": bool(latest.get("process_total_count") or latest.get("process_total_count") == 0),
            "docker": "available" if len(latest_docker) > 0 else "none_or_unavailable",
            "docker_error": latest_docker_error,
            "docker_socket_path": latest_docker_socket_path,
            "temperature": bool(latest.get("cpu_temperature") or latest.get("gpu_temperature")),
            "fd": bool(latest.get("max_file_descriptors")),
            "time_data": bool(latest.get("collection_duration_ms")),
            "docker_count_live": _to_int(latest.get("docker_count"), 0),
            "docker_count_effective": _to_int(latest.get("docker_count_effective"), _to_int(latest.get("docker_count"), 0)),
        }

        intervals = []
        for i in range(1, len(trend_points)):
            a = trend_points[i - 1].get("ts_dt")
            b = trend_points[i].get("ts_dt")
            if a and b:
                d = (b - a).total_seconds()
                if d > 0:
                    intervals.append(d)
        now = datetime.now(timezone.utc)
        latest_dt = latest.get("ts_dt")
        time_data = {
            "has_time_data": any(_to_int(s.get("collection_duration_ms"), 0) > 0 for s in snapshots),
            "avg_interval_sec": round(sum(intervals) / len(intervals), 2) if intervals else 0.0,
            "snapshot_count": len(snapshots),
            "latest_age_sec": int((now - latest_dt).total_seconds()) if latest_dt else 0,
        }

    alerts: list[dict[str, Any]] = []
    if latest:
        load_per_cpu = _to_float(latest.get("load_average_1m"), 0.0) / float(max(1, _to_int(latest.get("cpu_count_logical"), 1)))
        checks = [
            ("CPU", _to_float(latest.get("cpu_percent_total"), 0.0), cpu_threshold_v, "%"),
            ("Memory", _to_float(latest.get("memory_percent"), 0.0), memory_threshold_v, "%"),
            ("Disk", _to_float(latest.get("disk_used_percent"), 0.0), disk_threshold_v, "%"),
            ("Load/Core", load_per_cpu, load_threshold_v, ""),
            ("Temp(CPU)", _to_float(latest.get("cpu_temperature"), 0.0), temp_threshold_v, "C"),
            ("Collection", float(_to_int(latest.get("collection_duration_ms"), 0)), float(collection_ms_threshold_v), "ms"),
        ]
        for name, value, thr, unit in checks:
            if value > thr:
                alerts.append(
                    {
                        "metric": name,
                        "value": round(value, 2),
                        "threshold": thr,
                        "unit": unit,
                        "system_id": str(latest.get("system_id") or ""),
                        "hostname": str(latest.get("hostname") or ""),
                    }
                )

    problems_by_system: dict[str, dict[str, Any]] = {}
    for s_ in snapshots[:120]:
        sid = str(s_.get("system_id") or "unknown")
        host = str(s_.get("hostname") or "")
        score = _to_float(s_.get("system_health_score"), 100.0)
        breaches = 0
        if _to_float(s_.get("cpu_percent_total"), 0.0) > cpu_threshold_v:
            breaches += 1
        if _to_float(s_.get("memory_percent"), 0.0) > memory_threshold_v:
            breaches += 1
        if _to_float(s_.get("disk_used_percent"), 0.0) > disk_threshold_v:
            breaches += 1
        load_pc = _to_float(s_.get("load_average_1m"), 0.0) / float(max(1, _to_int(s_.get("cpu_count_logical"), 1)))
        if load_pc > load_threshold_v:
            breaches += 1
        if _to_float(s_.get("cpu_temperature"), 0.0) > temp_threshold_v:
            breaches += 1
        if _to_int(s_.get("collection_duration_ms"), 0) > collection_ms_threshold_v:
            breaches += 1
        if breaches <= 0:
            continue
        row = problems_by_system.get(sid)
        if not row:
            problems_by_system[sid] = {
                "system_id": sid,
                "hostname": host,
                "breach_count": breaches,
                "worst_health": score,
                "latest_ts": s_.get("ts"),
            }
        else:
            row["breach_count"] += breaches
            row["worst_health"] = min(_to_float(row.get("worst_health"), 100.0), score)
            if str(s_.get("ts") or "") > str(row.get("latest_ts") or ""):
                row["latest_ts"] = s_.get("ts")
    problematic_systems = sorted(
        list(problems_by_system.values()),
        key=lambda x: (int(x.get("breach_count") or 0), -_to_float(x.get("worst_health"), 100.0)),
        reverse=True,
    )[:20]

    metric_series = {
        "cpu_percent_total": cpu_points,
        "memory_percent": mem_points,
        "load_average_1m": load_points,
        "disk_used_percent": disk_points,
        "network_bytes_per_sec": net_rate_points,
        "process_running_count": proc_points,
        "collection_duration_ms": collect_points,
        "fd_utilization_percent": fd_points,
        "cpu_temperature": temp_points,
        "swap_percent": swap_points,
        "docker_count": docker_points,
        "system_health_score": health_points,
    }
    metric_units = {
        "cpu_percent_total": "%",
        "memory_percent": "%",
        "load_average_1m": "load",
        "disk_used_percent": "%",
        "network_bytes_per_sec": "B/s",
        "process_running_count": "count",
        "collection_duration_ms": "ms",
        "fd_utilization_percent": "%",
        "cpu_temperature": "C",
        "swap_percent": "%",
        "docker_count": "count",
        "system_health_score": "score",
    }
    m1 = str(custom_metric or "cpu_percent_total")
    m2 = str(custom_metric_2 or "memory_percent")
    if m1 not in metric_series:
        m1 = "cpu_percent_total"
    if m2 not in metric_series:
        m2 = "memory_percent"
    custom_points = metric_series.get(m1, cpu_points)
    custom_points_2 = metric_series.get(m2, mem_points)

    thresholds = {
        "cpu_threshold": cpu_threshold_v,
        "memory_threshold": memory_threshold_v,
        "disk_threshold": disk_threshold_v,
        "load_threshold": load_threshold_v,
        "temp_threshold": temp_threshold_v,
        "collection_ms_threshold": collection_ms_threshold_v,
    }

    return templates.TemplateResponse(
        "infra_monitoring.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "selected_agent": selected_agent or "",
            "q": q or "",
            "agent_choices": agents,
            "thresholds": thresholds,
            "alerts": alerts,
            "problematic_systems": problematic_systems,
            "custom_metric": m1,
            "custom_metric_2": m2,
            "metric_choices": list(metric_series.keys()),
            "metric_units": metric_units,
            "custom_points": custom_points,
            "custom_points_2": custom_points_2,
            "saved_layouts": saved_layouts,
            "active_layout_name": active_layout_name,
            "filter_message": filter_message,
            "threshold_message": threshold_message,
            "snapshot_count_total": len(base_snapshots),
            "snapshot_count_filtered": len(snapshots),
            "latest": latest,
            "latest_docker_count_effective": _to_int((latest or {}).get("docker_count_effective"), _to_int((latest or {}).get("docker_count"), 0)),
            "cpu_points": cpu_points,
            "mem_points": mem_points,
            "load_points": load_points,
            "health_points": health_points,
            "disk_points": disk_points,
            "net_rate_points": net_rate_points,
            "proc_points": proc_points,
            "collect_points": collect_points,
            "fd_points": fd_points,
            "temp_points": temp_points,
            "swap_points": swap_points,
            "docker_points": docker_points,
            "top_network": top_network,
            "top_disk": top_disk,
            "latest_top_cpu_processes": latest_top_cpu_processes,
            "latest_top_mem_processes": latest_top_mem_processes,
            "latest_docker": latest_docker,
            "latest_docker_error": latest_docker_error,
            "latest_docker_socket_path": latest_docker_socket_path,
            "all_containers": all_containers,
            "data_coverage": data_coverage,
            "time_data": time_data,
            "snapshots": snapshots[:80],
        },
    )


@app.get("/infra/detail", response_class=HTMLResponse)
async def infra_detail(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    metric: str | None = Query("docker_count"),
    agent_id: str | None = None,
    q: str | None = None,
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_agent = (agent_id or "").strip() or None
    query_text = (q or "").strip().lower()

    def _parse_ts(ts: str | None) -> datetime | None:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            return None

    snapshots: list[dict[str, Any]] = []
    filter_message = ""
    with get_session() as s:
        runs = (
            s.query(TraceRun)
            .filter(TraceRun.name == "infra.metrics")
            .order_by(TraceRun.ts.desc())
            .limit(INFRA_UI_MAX_SNAPSHOTS)
            .all()
        )
        for run in runs:
            try:
                out = json.loads(run.output_json or "{}")
            except Exception:
                out = {}
            payload = out.get("infra_payload")
            if not isinstance(payload, dict):
                payload = _extract_infra_payload(out.get("event") or {})
            infra = payload.get("infra") if isinstance(payload.get("infra"), dict) else {}
            cpu = infra.get("cpu") if isinstance(infra.get("cpu"), dict) else {}
            memory = infra.get("memory") if isinstance(infra.get("memory"), dict) else {}
            system = infra.get("system") if isinstance(infra.get("system"), dict) else {}
            process = infra.get("process") if isinstance(infra.get("process"), dict) else {}
            disk = infra.get("disk") if isinstance(infra.get("disk"), list) else []
            network = infra.get("network") if isinstance(infra.get("network"), list) else []
            docker = infra.get("docker") if isinstance(infra.get("docker"), list) else []
            ts = str(payload.get("timestamp") or (run.ts.isoformat() if run.ts else ""))
            net_total_bytes = sum(_to_int(n.get("net_bytes_recv"), 0) + _to_int(n.get("net_bytes_sent"), 0) for n in network)
            snapshots.append(
                {
                    "agent_id": str(payload.get("agent_id") or run.agent_id or "unknown"),
                    "system_id": str(payload.get("agent_id") or run.agent_id or "unknown"),
                    "hostname": str(system.get("hostname") or ""),
                    "app_id": str(run.app_id or "host-infra"),
                    "ts": ts,
                    "ts_dt": _parse_ts(ts),
                    "cpu_percent_total": _to_float(cpu.get("cpu_percent_total"), 0.0),
                    "memory_percent": _to_float(memory.get("memory_percent"), 0.0),
                    "load_average_1m": _to_float(system.get("load_average_1m"), 0.0),
                    "disk_used_percent": _to_float(
                        (sum(_to_int(d.get("disk_used_bytes"), 0) for d in disk) / float(max(1, sum(_to_int(d.get("disk_total_bytes"), 0) for d in disk)))) * 100.0
                    ),
                    "process_running_count": _to_int(process.get("process_running_count"), 0),
                    "collection_duration_ms": _to_int(infra.get("collection_duration_ms"), 0),
                    "fd_utilization_percent": (float(_to_int(system.get("open_file_descriptors"), 0)) / float(max(1, _to_int(system.get("max_file_descriptors"), 1)))) * 100.0 if _to_int(system.get("max_file_descriptors"), 0) > 0 else 0.0,
                    "cpu_temperature": _to_float(system.get("cpu_temperature"), 0.0),
                    "swap_percent": _to_float(memory.get("swap_percent"), 0.0),
                    "docker_count": len(docker),
                    "docker_count_effective": len(docker),
                    "net_total_bytes": net_total_bytes,
                    "docker": docker,
                    "raw": payload,
                }
            )
        agent_choices = [r[0] for r in s.query(TraceRun.agent_id).filter(TraceRun.name == "infra.metrics").distinct().order_by(TraceRun.agent_id.asc()).all() if r and r[0]]

    base_snapshots = list(snapshots)
    if selected_agent:
        filtered_by_agent = [s for s in snapshots if str(s.get("agent_id") or "") == selected_agent]
        if filtered_by_agent:
            snapshots = filtered_by_agent
        else:
            filter_message = f"agent '{selected_agent}' had no data; showing all snapshots"
            snapshots = base_snapshots
    if query_text:
        filtered_by_query = [
            s
            for s in snapshots
            if query_text in str(s.get("agent_id") or "").lower()
            or query_text in str(s.get("app_id") or "").lower()
            or query_text in str(s.get("hostname") or "").lower()
            or query_text in str(s.get("ts") or "").lower()
        ]
        if filtered_by_query:
            snapshots = filtered_by_query
        else:
            if filter_message:
                filter_message += "; "
            filter_message += f"query '{query_text}' returned no matches; showing current snapshot set"

    for i, snap in enumerate(snapshots):
        live_count = _to_int(snap.get("docker_count"), 0)
        if live_count > 0:
            snap["docker_count_effective"] = live_count
            continue
        sid = str(snap.get("system_id") or "unknown")
        fallback = None
        for prev in snapshots[i + 1 :]:
            if str(prev.get("system_id") or "unknown") != sid:
                continue
            prev_count = _to_int(prev.get("docker_count"), 0)
            if prev_count > 0:
                fallback = prev
                break
        if fallback:
            snap["docker_count_effective"] = _to_int(fallback.get("docker_count"), 0)
            snap["docker_count_source"] = "fallback"
        else:
            snap["docker_count_effective"] = 0
            snap["docker_count_source"] = "live"

    latest = snapshots[0] if snapshots else None
    trend_points = list(reversed(snapshots[:120]))
    net_rate_points: list[dict[str, Any]] = []
    prev = None
    for p in trend_points:
        rate = 0.0
        if prev and p.get("ts_dt") and prev.get("ts_dt"):
            dt = (p["ts_dt"] - prev["ts_dt"]).total_seconds()
            if dt > 0:
                delta = float(p.get("net_total_bytes", 0) - prev.get("net_total_bytes", 0))
                rate = max(0.0, delta / dt)
        net_rate_points.append({"ts": p["ts"], "value": rate})
        prev = p

    metric_series = {
        "docker_count": [{"ts": p["ts"], "value": _to_int(p.get("docker_count_effective"), _to_int(p.get("docker_count"), 0))} for p in trend_points],
        "cpu_percent_total": [{"ts": p["ts"], "value": p["cpu_percent_total"]} for p in trend_points],
        "memory_percent": [{"ts": p["ts"], "value": p["memory_percent"]} for p in trend_points],
        "load_average_1m": [{"ts": p["ts"], "value": p["load_average_1m"]} for p in trend_points],
        "disk_used_percent": [{"ts": p["ts"], "value": p["disk_used_percent"]} for p in trend_points],
        "network_bytes_per_sec": net_rate_points,
        "process_running_count": [{"ts": p["ts"], "value": p["process_running_count"]} for p in trend_points],
        "collection_duration_ms": [{"ts": p["ts"], "value": p["collection_duration_ms"]} for p in trend_points],
        "fd_utilization_percent": [{"ts": p["ts"], "value": p["fd_utilization_percent"]} for p in trend_points],
        "cpu_temperature": [{"ts": p["ts"], "value": p["cpu_temperature"]} for p in trend_points],
        "swap_percent": [{"ts": p["ts"], "value": p["swap_percent"]} for p in trend_points],
    }
    metric_units = {
        "docker_count": "count",
        "cpu_percent_total": "%",
        "memory_percent": "%",
        "load_average_1m": "load",
        "disk_used_percent": "%",
        "network_bytes_per_sec": "B/s",
        "process_running_count": "count",
        "collection_duration_ms": "ms",
        "fd_utilization_percent": "%",
        "cpu_temperature": "C",
        "swap_percent": "%",
    }
    selected_metric = str(metric or "docker_count")
    if selected_metric not in metric_series:
        selected_metric = "docker_count"
    metric_points = metric_series[selected_metric]

    latest_infra = ((latest or {}).get("raw") or {}).get("infra") or {}
    latest_cpu = latest_infra.get("cpu") if isinstance(latest_infra.get("cpu"), dict) else {}
    latest_memory = latest_infra.get("memory") if isinstance(latest_infra.get("memory"), dict) else {}
    latest_system = latest_infra.get("system") if isinstance(latest_infra.get("system"), dict) else {}
    latest_process = latest_infra.get("process") if isinstance(latest_infra.get("process"), dict) else {}
    latest_disk = latest_infra.get("disk") if isinstance(latest_infra.get("disk"), list) else []
    latest_network = latest_infra.get("network") if isinstance(latest_infra.get("network"), list) else []
    latest_docker = latest_infra.get("docker") if isinstance(latest_infra.get("docker"), list) else []
    docker_error = str(latest_infra.get("docker_error") or "").strip()
    docker_socket_path = str(latest_infra.get("docker_socket_path") or "").strip()
    top_cpu_processes = latest_process.get("top_5_cpu_processes") if isinstance(latest_process.get("top_5_cpu_processes"), list) else []
    top_memory_processes = latest_process.get("top_5_memory_processes") if isinstance(latest_process.get("top_5_memory_processes"), list) else []
    top_disk_partitions = sorted(
        [d for d in latest_disk if isinstance(d, dict)],
        key=lambda d: (_to_float(d.get("disk_percent"), 0.0), _to_int(d.get("disk_used_bytes"), 0)),
        reverse=True,
    )[:10]
    top_network_interfaces = sorted(
        [n for n in latest_network if isinstance(n, dict)],
        key=lambda n: (_to_int(n.get("net_bytes_recv"), 0) + _to_int(n.get("net_bytes_sent"), 0)),
        reverse=True,
    )[:10]

    all_containers: list[dict[str, Any]] = []
    latest_by_system: dict[str, dict[str, Any]] = {}
    for s_ in snapshots:
        sid = str(s_.get("system_id") or "unknown")
        if sid not in latest_by_system:
            latest_by_system[sid] = s_
    for sid, snap in latest_by_system.items():
        host = str(snap.get("hostname") or "")
        for c in (snap.get("docker") or []):
            net = c.get("container_net_io") if isinstance(c.get("container_net_io"), dict) else {}
            blk = c.get("container_block_io") if isinstance(c.get("container_block_io"), dict) else {}
            all_containers.append(
                {
                    "system_id": sid,
                    "hostname": host,
                    "container_name": str(c.get("container_name") or "unknown"),
                    "container_status": str(c.get("container_status") or ""),
                    "container_cpu_percent": _to_float(c.get("container_cpu_percent"), 0.0),
                    "container_memory_usage": _to_int(c.get("container_memory_usage"), 0),
                    "container_memory_limit": _to_int(c.get("container_memory_limit"), 0),
                    "container_restart_count": _to_int(c.get("container_restart_count"), 0),
                    "net_rx_bytes": _to_int(net.get("rx_bytes"), 0),
                    "net_tx_bytes": _to_int(net.get("tx_bytes"), 0),
                    "blk_read_bytes": _to_int(blk.get("read_bytes"), 0),
                    "blk_write_bytes": _to_int(blk.get("write_bytes"), 0),
                }
            )
    all_containers = sorted(all_containers, key=lambda x: (x.get("system_id") or "", x.get("container_name") or ""))

    return templates.TemplateResponse(
        "infra_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "selected_agent": selected_agent or "",
            "q": q or "",
            "agent_choices": agent_choices,
            "selected_metric": selected_metric,
            "metric_choices": list(metric_series.keys()),
            "metric_units": metric_units,
            "selected_metric_unit": str(metric_units.get(selected_metric) or "value"),
            "metric_points": metric_points,
            "latest": latest,
            "latest_cpu": latest_cpu,
            "latest_memory": latest_memory,
            "latest_system": latest_system,
            "latest_process": latest_process,
            "latest_disk": latest_disk,
            "latest_network": latest_network,
            "latest_docker": latest_docker,
            "top_cpu_processes": top_cpu_processes,
            "top_memory_processes": top_memory_processes,
            "top_disk_partitions": top_disk_partitions,
            "top_network_interfaces": top_network_interfaces,
            "all_containers": all_containers,
            "docker_error": docker_error,
            "docker_socket_path": docker_socket_path,
            "snapshot_count": len(snapshots),
            "filter_message": filter_message,
            "latest_infra_json": json.dumps(latest_infra, indent=2, ensure_ascii=True) if latest_infra else "{}",
        },
    )


@app.get("/observability", response_class=HTMLResponse)
async def observability_view(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    agent_id: str | None = None,
    app_id: str | None = None,
    app_group: str | None = Query("all"),
    namespace: str | None = Query(""),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_agent = (agent_id or "").strip() or None
    selected_app = (app_id or "").strip() or None
    selected_app_group = (app_group or "all").strip().lower() or "all"
    selected_namespace = (namespace or "").strip()
    message = str(request.query_params.get("message") or "")
    error = str(request.query_params.get("error") or "")

    def _build_topology(
        rows: list[TraceRun],
        spans_by_run: dict[int, list[TraceSpan]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        nodes: dict[str, dict[str, Any]] = {}
        edge_rollup: dict[tuple[str, str], dict[str, Any]] = {}

        for tr in rows:
            src = str(tr.app_id or "unknown")
            nodes.setdefault(src, {"id": src, "kind": "app"})
            for sp in spans_by_run.get(int(tr.id), []):
                tgt = _span_target_service(str(sp.name or ""), str(sp.meta_json or ""), default="")
                if not tgt or tgt == src:
                    continue
                nodes.setdefault(tgt, {"id": tgt, "kind": "service"})
                key = (src, tgt)
                cur = edge_rollup.get(key)
                dur = float(_to_int(sp.duration_ms, 0))
                if not cur:
                    edge_rollup[key] = {"source": src, "target": tgt, "count": 1, "durations": [dur]}
                else:
                    cur["count"] += 1
                    cur["durations"].append(dur)

        edges: list[dict[str, Any]] = []
        for _, v in edge_rollup.items():
            ds = sorted(v["durations"])
            edges.append(
                {
                    "source": v["source"],
                    "target": v["target"],
                    "count": int(v["count"]),
                    "latency_avg_ms": float(sum(ds) / max(1, len(ds))),
                    "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
                }
            )
        edges.sort(key=lambda x: (x["count"], x["latency_p95_ms"]), reverse=True)
        node_rows = sorted(nodes.values(), key=lambda x: x["id"])
        return node_rows[:200], edges[:500]

    def _parse_ts(ts: str | None) -> datetime | None:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            return None

    obs_snaps: list[dict[str, Any]] = []
    filter_message = ""
    selected_agent_config: dict[str, Any] = {}

    def _ns_from_app_id(aid: str) -> str:
        txt = str(aid or "")
        if txt.startswith("k8s:"):
            parts = txt.split(":")
            if len(parts) >= 3:
                return parts[1]
        return ""

    with get_session() as s:
        q = s.query(TraceRun).filter(TraceRun.name == "observability.metrics")
        runs = q.order_by(TraceRun.ts.desc()).limit(OBS_UI_MAX_SNAPSHOTS).all()
        for run in runs:
            try:
                out = json.loads(run.output_json or "{}")
            except Exception:
                out = {}
            payload = out.get("observability_payload") if isinstance(out.get("observability_payload"), dict) else {}
            obs = payload.get("observability") if isinstance(payload.get("observability"), dict) else {}
            golden = obs.get("golden_signals") if isinstance(obs.get("golden_signals"), dict) else {}
            latency = golden.get("latency_ms") if isinstance(golden.get("latency_ms"), dict) else {}
            traffic = golden.get("traffic") if isinstance(golden.get("traffic"), dict) else {}
            errors = golden.get("errors") if isinstance(golden.get("errors"), dict) else {}
            saturation = golden.get("saturation") if isinstance(golden.get("saturation"), dict) else {}
            apm = obs.get("apm") if isinstance(obs.get("apm"), dict) else {}
            ts = str(payload.get("timestamp") or (run.ts.isoformat() if run.ts else ""))
            obs_snaps.append(
                {
                    "ts": ts,
                    "ts_dt": _parse_ts(ts),
                    "agent_id": str(payload.get("agent_id") or run.agent_id or "unknown"),
                    "app_id": str(run.app_id or "unknown"),
                    "namespace": _ns_from_app_id(str(run.app_id or "")),
                    "latency_current": _to_float(latency.get("current"), 0.0),
                    "latency_p95": _to_float(latency.get("p95"), 0.0),
                    "traffic_rps": _to_float(traffic.get("requests_per_sec"), 0.0),
                    "traffic_bps": _to_float(traffic.get("throughput_bps"), 0.0),
                    "error_rate_percent": _to_float(errors.get("error_rate_percent"), 0.0),
                    "error_count": _to_int(errors.get("error_count"), 0),
                    "cpu_saturation": _to_float(saturation.get("cpu_percent"), 0.0),
                    "memory_saturation": _to_float(saturation.get("memory_percent"), 0.0),
                    "disk_saturation": _to_float(saturation.get("disk_percent"), 0.0),
                    "load_per_core": _to_float(saturation.get("load_per_core"), 0.0),
                    "fd_utilization_percent": _to_float(saturation.get("fd_utilization_percent"), 0.0),
                    "apm": apm,
                    "raw": payload,
                }
            )

        agent_choices = [
            r[0]
            for r in s.query(TraceRun.agent_id)
            .filter(TraceRun.name == "observability.metrics")
            .distinct()
            .order_by(TraceRun.agent_id.asc())
            .all()
            if r and r[0]
        ]
        app_choices = [
            r[0]
            for r in s.query(TraceRun.app_id)
            .filter(TraceRun.name == "observability.metrics")
            .distinct()
            .order_by(TraceRun.app_id.asc())
            .all()
            if r and r[0]
        ]
        registered_agents = [
            {"id": int(a.id), "name": str(a.name or ""), "base_url": str(a.base_url or ""), "enabled": bool(a.enabled)}
            for a in s.query(AgentRegistry).filter(AgentRegistry.enabled == True).order_by(AgentRegistry.name.asc()).all()
        ]
        if selected_agent:
            cfg_row = s.query(NetraAgentConfig).filter(NetraAgentConfig.agent_name == selected_agent).first()
            if cfg_row and isinstance(cfg_row.config_json, str):
                try:
                    selected_agent_config = json.loads(cfg_row.config_json or "{}")
                except Exception:
                    selected_agent_config = {}

    known_agents = sorted(set(agent_choices + [a["name"] for a in registered_agents]))
    selected_agent_meta = next((a for a in registered_agents if a.get("name") == (selected_agent or "")), None)

    base_obs_snaps = list(obs_snaps)
    if selected_agent:
        by_agent = [x for x in obs_snaps if str(x.get("agent_id") or "") == selected_agent]
        if by_agent:
            obs_snaps = by_agent
        else:
            filter_message = f"agent '{selected_agent}' had no observability rows; showing all rows"
            obs_snaps = base_obs_snaps
    if selected_app:
        by_app = [x for x in obs_snaps if str(x.get("app_id") or "") == selected_app]
        if by_app:
            obs_snaps = by_app
        else:
            if filter_message:
                filter_message += "; "
            filter_message += f"app '{selected_app}' had no rows; keeping current set"

    if selected_app_group == "k8s_only":
        by_group = [x for x in obs_snaps if str(x.get("app_id") or "").startswith("k8s:")]
        if by_group:
            obs_snaps = by_group
        else:
            if filter_message:
                filter_message += "; "
            filter_message += "k8s_only filter had no rows; keeping current set"
    elif selected_app_group == "non_k8s":
        by_group = [x for x in obs_snaps if not str(x.get("app_id") or "").startswith("k8s:")]
        if by_group:
            obs_snaps = by_group
        else:
            if filter_message:
                filter_message += "; "
            filter_message += "non_k8s filter had no rows; keeping current set"
    if selected_namespace:
        by_ns = [x for x in obs_snaps if str(x.get("namespace") or "") == selected_namespace]
        if by_ns:
            obs_snaps = by_ns
        else:
            if filter_message:
                filter_message += "; "
            filter_message += f"namespace '{selected_namespace}' had no rows; keeping current set"

    latest = obs_snaps[0] if obs_snaps else None
    trend_points = list(reversed(obs_snaps[:120]))
    latency_points = [{"ts": p["ts"], "value": p["latency_current"]} for p in trend_points]
    traffic_points = [{"ts": p["ts"], "value": p["traffic_rps"]} for p in trend_points]
    errors_points = [{"ts": p["ts"], "value": p["error_rate_percent"]} for p in trend_points]
    sat_cpu_points = [{"ts": p["ts"], "value": p["cpu_saturation"]} for p in trend_points]
    sat_mem_points = [{"ts": p["ts"], "value": p["memory_saturation"]} for p in trend_points]
    sat_disk_points = [{"ts": p["ts"], "value": p["disk_saturation"]} for p in trend_points]

    top_recent = obs_snaps[:100]
    namespace_map: dict[str, dict[str, Any]] = {}
    for p in top_recent:
        ns = str(p.get("namespace") or "")
        if not ns:
            continue
        row = namespace_map.get(ns)
        if not row:
            namespace_map[ns] = {
                "namespace": ns,
                "samples": 1,
                "latency_sum": _to_float(p.get("latency_current"), 0.0),
                "rps_sum": _to_float(p.get("traffic_rps"), 0.0),
                "err_sum": _to_float(p.get("error_rate_percent"), 0.0),
            }
        else:
            row["samples"] += 1
            row["latency_sum"] += _to_float(p.get("latency_current"), 0.0)
            row["rps_sum"] += _to_float(p.get("traffic_rps"), 0.0)
            row["err_sum"] += _to_float(p.get("error_rate_percent"), 0.0)
    namespace_rows = sorted(
        [
            {
                "namespace": ns,
                "samples": int(v["samples"]),
                "latency_avg": float(v["latency_sum"]) / float(max(1, int(v["samples"]))),
                "rps_avg": float(v["rps_sum"]) / float(max(1, int(v["samples"]))),
                "error_avg": float(v["err_sum"]) / float(max(1, int(v["samples"]))),
            }
            for ns, v in namespace_map.items()
        ],
        key=lambda x: x["samples"],
        reverse=True,
    )
    namespace_choices = sorted({str(x.get("namespace") or "") for x in obs_snaps if str(x.get("namespace") or "")})

    four_golden = {
        "latency_p50": _to_float(sorted([p["latency_current"] for p in top_recent])[max(0, int(len(top_recent) * 0.50) - 1)] if top_recent else 0.0),
        "latency_p95": _to_float(sorted([p["latency_current"] for p in top_recent])[max(0, int(len(top_recent) * 0.95) - 1)] if top_recent else 0.0),
        "latency_p99": _to_float(sorted([p["latency_current"] for p in top_recent])[max(0, int(len(top_recent) * 0.99) - 1)] if top_recent else 0.0),
        "traffic_rps_avg": (sum(p["traffic_rps"] for p in top_recent) / float(len(top_recent))) if top_recent else 0.0,
        "error_rate_avg": (sum(p["error_rate_percent"] for p in top_recent) / float(len(top_recent))) if top_recent else 0.0,
        "cpu_sat_avg": (sum(p["cpu_saturation"] for p in top_recent) / float(len(top_recent))) if top_recent else 0.0,
        "memory_sat_avg": (sum(p["memory_saturation"] for p in top_recent) / float(len(top_recent))) if top_recent else 0.0,
        "disk_sat_avg": (sum(p["disk_saturation"] for p in top_recent) / float(len(top_recent))) if top_recent else 0.0,
    }
    slo_target_availability = 99.9
    allowed_error_rate = max(0.0, 100.0 - slo_target_availability)
    observed_error_rate = _to_float(four_golden.get("error_rate_avg"), 0.0)
    burn_rate = (observed_error_rate / allowed_error_rate) if allowed_error_rate > 0 else 0.0
    phase2_slo = {
        "target_availability_percent": slo_target_availability,
        "allowed_error_rate_percent": allowed_error_rate,
        "observed_error_rate_percent": observed_error_rate,
        "error_budget_remaining_percent": max(0.0, 100.0 - min(100.0, (burn_rate * 100.0))),
        "burn_rate": burn_rate,
        "status": "ok" if burn_rate <= 1.0 else ("warn" if burn_rate <= 2.0 else "bad"),
    }

    service_rollup: dict[str, dict[str, Any]] = {}
    for p in top_recent:
        app_key = str(p.get("app_id") or "unknown")
        row = service_rollup.get(app_key)
        if not row:
            service_rollup[app_key] = {
                "app_id": app_key,
                "namespace": str(p.get("namespace") or ""),
                "agent_id": str(p.get("agent_id") or ""),
                "samples": 1,
                "latency_sum": _to_float(p.get("latency_current"), 0.0),
                "rps_sum": _to_float(p.get("traffic_rps"), 0.0),
                "error_sum": _to_float(p.get("error_rate_percent"), 0.0),
                "cpu_sum": _to_float(p.get("cpu_saturation"), 0.0),
                "memory_sum": _to_float(p.get("memory_saturation"), 0.0),
            }
        else:
            row["samples"] += 1
            row["latency_sum"] += _to_float(p.get("latency_current"), 0.0)
            row["rps_sum"] += _to_float(p.get("traffic_rps"), 0.0)
            row["error_sum"] += _to_float(p.get("error_rate_percent"), 0.0)
            row["cpu_sum"] += _to_float(p.get("cpu_saturation"), 0.0)
            row["memory_sum"] += _to_float(p.get("memory_saturation"), 0.0)
    service_map_rows = sorted(
        [
            {
                "app_id": k,
                "namespace": str(v.get("namespace") or ""),
                "agent_id": str(v.get("agent_id") or ""),
                "samples": int(v.get("samples") or 0),
                "latency_avg": float(v.get("latency_sum") or 0.0) / float(max(1, int(v.get("samples") or 1))),
                "rps_avg": float(v.get("rps_sum") or 0.0) / float(max(1, int(v.get("samples") or 1))),
                "error_avg": float(v.get("error_sum") or 0.0) / float(max(1, int(v.get("samples") or 1))),
                "cpu_avg": float(v.get("cpu_sum") or 0.0) / float(max(1, int(v.get("samples") or 1))),
                "memory_avg": float(v.get("memory_sum") or 0.0) / float(max(1, int(v.get("samples") or 1))),
            }
            for k, v in service_rollup.items()
        ],
        key=lambda x: x["rps_avg"],
        reverse=True,
    )[:25]

    # Use ingested traces as traces pillar proxy.
    traces_summary = {"count_24h": 0, "error_count_24h": 0, "p95_duration_ms": 0.0}
    topology_nodes: list[dict[str, Any]] = []
    topology_edges: list[dict[str, Any]] = []
    with get_session() as s:
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        tq = s.query(TraceRun).filter(TraceRun.ts >= since, TraceRun.name != "infra.metrics", TraceRun.name != "observability.metrics")
        if selected_app:
            tq = tq.filter(TraceRun.app_id == selected_app)
        if selected_agent:
            tq = tq.filter(TraceRun.agent_id == selected_agent)
        traces = tq.order_by(TraceRun.ts.desc()).limit(TRACE_ANALYTICS_MAX_RUNS).all()
        durations = [_to_float(t.duration_ms, 0.0) for t in traces if _to_float(t.duration_ms, 0.0) > 0]
        traces_summary["count_24h"] = len(traces)
        traces_summary["error_count_24h"] = sum(1 for t in traces if str(t.status or "").lower() == "error" or bool(t.error))
        if durations:
            d = sorted(durations)
            traces_summary["p95_duration_ms"] = d[max(0, int(len(d) * 0.95) - 1)]
        trace_ids = [int(t.id) for t in traces[:500] if getattr(t, "id", None) is not None]
        spans_by_run: dict[int, list[TraceSpan]] = {}
        if trace_ids:
            span_rows = s.query(TraceSpan).filter(TraceSpan.trace_run_id.in_(trace_ids)).all()
            for sp in span_rows:
                spans_by_run.setdefault(int(sp.trace_run_id), []).append(sp)
        topology_nodes, topology_edges = _build_topology(traces[:500], spans_by_run)

    k8s_info: dict[str, Any] = {
        "enabled": False,
        "reason": "no_infra_snapshot",
        "node_count": 0,
        "pod_count_total": 0,
        "pod_count_running": 0,
        "namespace_count": 0,
        "deployment_count": 0,
        "configmap_count": 0,
        "secret_count": 0,
        "service_count": 0,
        "nodes": [],
        "pods": [],
        "deployments": [],
        "configmaps": [],
        "secrets": [],
        "services": [],
    }
    with get_session() as s:
        iq = s.query(TraceRun).filter(TraceRun.name == "infra.metrics")
        if selected_agent:
            iq = iq.filter(TraceRun.agent_id == selected_agent)
        ir = iq.order_by(TraceRun.ts.desc()).first()
        if ir and isinstance(ir.output_json, str):
            try:
                out = json.loads(ir.output_json or "{}")
            except Exception:
                out = {}
            p = out.get("infra_payload") if isinstance(out.get("infra_payload"), dict) else {}
            if not p:
                p = _extract_infra_payload(out.get("event") or {})
            infra = p.get("infra") if isinstance(p.get("infra"), dict) else {}
            kube = infra.get("kubernetes") if isinstance(infra.get("kubernetes"), dict) else {}
            if kube:
                k8s_info = {
                    "enabled": bool(kube.get("enabled")),
                    "reason": str(kube.get("reason") or ""),
                    "node_count": _to_int(kube.get("node_count"), 0),
                    "pod_count_total": _to_int(kube.get("pod_count_total"), 0),
                    "pod_count_running": _to_int(kube.get("pod_count_running"), 0),
                    "namespace_count": _to_int(kube.get("namespace_count"), 0),
                    "deployment_count": _to_int(kube.get("deployment_count"), 0),
                    "configmap_count": _to_int(kube.get("configmap_count"), 0),
                    "secret_count": _to_int(kube.get("secret_count"), 0),
                    "service_count": _to_int(kube.get("service_count"), 0),
                    "nodes": (kube.get("nodes") if isinstance(kube.get("nodes"), list) else [])[:50],
                    "pods": (kube.get("pods") if isinstance(kube.get("pods"), list) else [])[:120],
                    "deployments": (kube.get("deployments") if isinstance(kube.get("deployments"), list) else [])[:120],
                    "configmaps": (kube.get("configmaps") if isinstance(kube.get("configmaps"), list) else [])[:120],
                    "secrets": (kube.get("secrets") if isinstance(kube.get("secrets"), list) else [])[:120],
                    "services": (kube.get("services") if isinstance(kube.get("services"), list) else [])[:120],
                }

    k8s_app_rows: list[dict[str, Any]] = []
    k8s_app_count_map: dict[str, int] = {}
    for r in obs_snaps[:300]:
        aid = str(r.get("app_id") or "")
        if not aid.startswith("k8s:"):
            continue
        k8s_app_count_map[aid] = k8s_app_count_map.get(aid, 0) + 1
    for aid, cnt in sorted(k8s_app_count_map.items(), key=lambda x: x[1], reverse=True):
        parts = aid.split(":")
        ns = parts[1] if len(parts) >= 3 else ""
        appn = parts[2] if len(parts) >= 3 else aid
        k8s_app_rows.append({"app_id": aid, "namespace": ns, "app_name": appn, "samples": cnt})

    now_utc = datetime.now(timezone.utc)
    latest_ts_dt = latest.get("ts_dt") if isinstance(latest, dict) else None
    latest_age_seconds = int((now_utc - latest_ts_dt).total_seconds()) if isinstance(latest_ts_dt, datetime) else None
    phase0_diagnostics = {
        "status": "ok" if bool(latest) else "warn",
        "latest_sample_age_seconds": latest_age_seconds,
        "observability_rows": len(obs_snaps),
        "chart_points": {
            "latency": len(latency_points),
            "traffic": len(traffic_points),
            "errors": len(errors_points),
            "cpu_saturation": len(sat_cpu_points),
            "memory_saturation": len(sat_mem_points),
            "disk_saturation": len(sat_disk_points),
        },
        "k8s_enabled": bool(k8s_info.get("enabled")),
        "k8s_inventory": {
            "nodes": _to_int(k8s_info.get("node_count"), 0),
            "pods_total": _to_int(k8s_info.get("pod_count_total"), 0),
            "deployments": _to_int(k8s_info.get("deployment_count"), 0),
            "configmaps": _to_int(k8s_info.get("configmap_count"), 0),
            "secrets": _to_int(k8s_info.get("secret_count"), 0),
            "services": _to_int(k8s_info.get("service_count"), 0),
        },
        "traces_24h": _to_int(traces_summary.get("count_24h"), 0),
    }
    missing_signals: list[str] = []
    if not latency_points:
        missing_signals.append("latency")
    if not traffic_points:
        missing_signals.append("traffic")
    if not errors_points:
        missing_signals.append("errors")
    if not sat_cpu_points:
        missing_signals.append("cpu_saturation")
    if not sat_mem_points:
        missing_signals.append("memory_saturation")
    if not sat_disk_points:
        missing_signals.append("disk_saturation")
    phase0_diagnostics["missing_signals"] = missing_signals

    # Phase 3: incident timeline, synthetic checks, forecast, and correlation.
    incident_rows: list[dict[str, Any]] = []
    for p in obs_snaps[:300]:
        reasons: list[str] = []
        if _to_float(p.get("error_rate_percent"), 0.0) >= 5.0:
            reasons.append(f"error_rate={_to_float(p.get('error_rate_percent'), 0.0):.2f}%")
        if _to_float(p.get("latency_current"), 0.0) >= 1000.0:
            reasons.append(f"latency={_to_float(p.get('latency_current'), 0.0):.1f}ms")
        if _to_float(p.get("cpu_saturation"), 0.0) >= 90.0:
            reasons.append(f"cpu={_to_float(p.get('cpu_saturation'), 0.0):.1f}%")
        if _to_float(p.get("memory_saturation"), 0.0) >= 90.0:
            reasons.append(f"memory={_to_float(p.get('memory_saturation'), 0.0):.1f}%")
        if reasons:
            incident_rows.append(
                {
                    "ts": str(p.get("ts") or ""),
                    "agent_id": str(p.get("agent_id") or ""),
                    "app_id": str(p.get("app_id") or ""),
                    "severity": "critical" if _to_float(p.get("error_rate_percent"), 0.0) >= 10.0 else "high",
                    "reason": ", ".join(reasons),
                }
            )
    incident_rows = incident_rows[:60]

    latest_age = (
        _to_int(phase0_diagnostics.get("latest_sample_age_seconds"), 0)
        if phase0_diagnostics.get("latest_sample_age_seconds") is not None
        else 10**9
    )
    sample_count = _to_int(phase0_diagnostics.get("observability_rows"), 0)
    synthetic_checks = [
        {
            "check": "event_freshness",
            "status": "pass" if latest_age <= 30 else ("warn" if latest_age <= 120 else "fail"),
            "value": latest_age,
            "unit": "sec",
            "note": "latest sample age",
        },
        {
            "check": "event_volume",
            "status": "pass" if sample_count >= 30 else ("warn" if sample_count >= 10 else "fail"),
            "value": sample_count,
            "unit": "rows",
            "note": "observability rows in current view",
        },
        {
            "check": "error_budget_burn",
            "status": "pass" if _to_float(phase2_slo.get("burn_rate"), 0.0) <= 1.0 else ("warn" if _to_float(phase2_slo.get("burn_rate"), 0.0) <= 2.0 else "fail"),
            "value": round(_to_float(phase2_slo.get("burn_rate"), 0.0), 2),
            "unit": "x",
            "note": "error budget burn multiplier",
        },
    ]

    def _forecast(points: list[dict[str, Any]], future_steps: int = 6) -> list[dict[str, Any]]:
        vals = [_to_float(p.get("value"), 0.0) for p in points[-20:]]
        if len(vals) < 2:
            return []
        diffs = [vals[i] - vals[i - 1] for i in range(1, len(vals))]
        slope = sum(diffs) / float(len(diffs))
        base = vals[-1]
        return [{"step": i, "value": max(0.0, base + slope * i)} for i in range(1, future_steps + 1)]

    forecast_rows = {
        "cpu_saturation": _forecast(sat_cpu_points, future_steps=6),
        "memory_saturation": _forecast(sat_mem_points, future_steps=6),
        "latency_ms": _forecast(latency_points, future_steps=6),
        "error_rate_percent": _forecast(errors_points, future_steps=6),
    }

    def _corr(xs: list[float], ys: list[float]) -> float:
        n = min(len(xs), len(ys))
        if n < 3:
            return 0.0
        x = xs[:n]
        y = ys[:n]
        mx = sum(x) / float(n)
        my = sum(y) / float(n)
        num = sum((x[i] - mx) * (y[i] - my) for i in range(n))
        denx = sum((v - mx) ** 2 for v in x)
        deny = sum((v - my) ** 2 for v in y)
        den = (denx * deny) ** 0.5
        return (num / den) if den > 0 else 0.0

    corr_source = list(reversed(obs_snaps[:120]))
    corr_latency = [_to_float(p.get("latency_current"), 0.0) for p in corr_source]
    corr_error = [_to_float(p.get("error_rate_percent"), 0.0) for p in corr_source]
    corr_cpu = [_to_float(p.get("cpu_saturation"), 0.0) for p in corr_source]
    corr_mem = [_to_float(p.get("memory_saturation"), 0.0) for p in corr_source]
    correlation_rows = [
        {"pair": "latency vs error_rate", "value": _corr(corr_latency, corr_error)},
        {"pair": "cpu vs latency", "value": _corr(corr_cpu, corr_latency)},
        {"pair": "memory vs latency", "value": _corr(corr_mem, corr_latency)},
        {"pair": "cpu vs error_rate", "value": _corr(corr_cpu, corr_error)},
    ]

    return templates.TemplateResponse(
        "observability.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "selected_agent": selected_agent or "",
            "selected_app": selected_app or "",
            "selected_app_group": selected_app_group,
            "selected_namespace": selected_namespace,
            "agent_choices": known_agents,
            "app_choices": app_choices,
            "namespace_choices": namespace_choices,
            "selected_agent_meta": selected_agent_meta,
            "selected_agent_config": selected_agent_config,
            "message": message,
            "error": error,
            "filter_message": filter_message,
            "latest": latest,
            "four_golden": four_golden,
            "traces_summary": traces_summary,
            "latency_points": latency_points,
            "traffic_points": traffic_points,
            "errors_points": errors_points,
            "sat_cpu_points": sat_cpu_points,
            "sat_mem_points": sat_mem_points,
            "sat_disk_points": sat_disk_points,
            "namespace_rows": namespace_rows,
            "k8s_info": k8s_info,
            "k8s_app_rows": k8s_app_rows,
            "phase2_slo": phase2_slo,
            "service_map_rows": service_map_rows,
            "incident_rows": incident_rows,
            "synthetic_checks": synthetic_checks,
            "forecast_rows": forecast_rows,
            "correlation_rows": correlation_rows,
            "rows": obs_snaps[:80],
            "phase0_diagnostics": phase0_diagnostics,
            "topology_nodes": topology_nodes,
            "topology_edges": topology_edges,
        },
    )


@app.get("/observability/detail", response_class=HTMLResponse)
async def observability_detail(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    metric: str | None = Query("latency_current"),
    agent_id: str | None = None,
    app_id: str | None = None,
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_agent = (agent_id or "").strip() or None
    selected_app = (app_id or "").strip() or None
    selected_metric = str(metric or "latency_current").strip() or "latency_current"

    def _parse_ts(ts: str | None) -> datetime | None:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            return None

    rows: list[dict[str, Any]] = []
    with get_session() as s:
        q = s.query(TraceRun).filter(TraceRun.name == "observability.metrics")
        if selected_agent:
            q = q.filter(TraceRun.agent_id == selected_agent)
        if selected_app:
            q = q.filter(TraceRun.app_id == selected_app)
        runs = q.order_by(TraceRun.ts.desc()).limit(OBS_UI_MAX_SNAPSHOTS).all()
        for run in runs:
            try:
                out = json.loads(run.output_json or "{}")
            except Exception:
                out = {}
            payload = out.get("observability_payload") if isinstance(out.get("observability_payload"), dict) else {}
            obs = payload.get("observability") if isinstance(payload.get("observability"), dict) else {}
            golden = obs.get("golden_signals") if isinstance(obs.get("golden_signals"), dict) else {}
            latency = golden.get("latency_ms") if isinstance(golden.get("latency_ms"), dict) else {}
            traffic = golden.get("traffic") if isinstance(golden.get("traffic"), dict) else {}
            errors = golden.get("errors") if isinstance(golden.get("errors"), dict) else {}
            saturation = golden.get("saturation") if isinstance(golden.get("saturation"), dict) else {}
            ts = str(payload.get("timestamp") or (run.ts.isoformat() if run.ts else ""))
            rows.append(
                {
                    "ts": ts,
                    "ts_dt": _parse_ts(ts),
                    "agent_id": str(payload.get("agent_id") or run.agent_id or "unknown"),
                    "app_id": str(run.app_id or "unknown"),
                    "latency_current": _to_float(latency.get("current"), 0.0),
                    "traffic_rps": _to_float(traffic.get("requests_per_sec"), 0.0),
                    "error_rate_percent": _to_float(errors.get("error_rate_percent"), 0.0),
                    "cpu_saturation": _to_float(saturation.get("cpu_percent"), 0.0),
                    "memory_saturation": _to_float(saturation.get("memory_percent"), 0.0),
                    "disk_saturation": _to_float(saturation.get("disk_percent"), 0.0),
                }
            )

        agent_choices = [
            r[0]
            for r in s.query(TraceRun.agent_id).filter(TraceRun.name == "observability.metrics").distinct().order_by(TraceRun.agent_id.asc()).all()
            if r and r[0]
        ]
        app_choices = [
            r[0]
            for r in s.query(TraceRun.app_id).filter(TraceRun.name == "observability.metrics").distinct().order_by(TraceRun.app_id.asc()).all()
            if r and r[0]
        ]

    metric_meta = {
        "latency_current": {"label": "Latency", "unit": "ms", "color": "#60a5fa"},
        "traffic_rps": {"label": "Traffic", "unit": "rps", "color": "#22c55e"},
        "error_rate_percent": {"label": "Error Rate", "unit": "%", "color": "#ef4444"},
        "cpu_saturation": {"label": "CPU Saturation", "unit": "%", "color": "#f59e0b"},
        "memory_saturation": {"label": "Memory Saturation", "unit": "%", "color": "#8b5cf6"},
        "disk_saturation": {"label": "Disk Saturation", "unit": "%", "color": "#06b6d4"},
    }
    if selected_metric not in metric_meta:
        selected_metric = "latency_current"

    trend_points = list(reversed(rows[:150]))
    metric_points = [{"ts": r["ts"], "value": _to_float(r.get(selected_metric), 0.0)} for r in trend_points]
    latest = rows[0] if rows else None

    return templates.TemplateResponse(
        "observability_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "selected_agent": selected_agent or "",
            "selected_app": selected_app or "",
            "selected_metric": selected_metric,
            "metric_choices": list(metric_meta.keys()),
            "metric_meta": metric_meta,
            "metric_points": metric_points,
            "agent_choices": agent_choices,
            "app_choices": app_choices,
            "rows": rows[:100],
            "latest": latest,
        },
    )


@app.post("/observability/toggle")
async def observability_toggle(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    agent_name: str = Form(""),
    enabled: str = Form("true"),
    app_id: str = Form(""),
    app_group: str = Form("all"),
    namespace: str = Form(""),
    observability_topic: str = Form("observability.metrics"),
    observability_window: str = Form("120"),
    k8s_auto_map_enabled: str = Form("true"),
    k8s_auto_map_max_apps: str = Form("50"),
    k8s_auto_map_prefix: str = Form("k8s"),
):
    if isinstance(user, RedirectResponse):
        return user
    target_agent = (agent_name or "").strip()
    if not target_agent:
        return RedirectResponse(url="/observability?error=Select%20agent%20first", status_code=303)

    enable_flag = str(enabled or "true").strip().lower() in {"1", "true", "yes", "on"}
    topic_val = str(observability_topic or "observability.metrics").strip() or "observability.metrics"
    try:
        window_val = max(10, int(float(observability_window or "120")))
    except Exception:
        window_val = 120
    k8s_map_flag = str(k8s_auto_map_enabled or "true").strip().lower() in {"1", "true", "yes", "on"}
    try:
        k8s_max_apps_val = max(1, int(float(k8s_auto_map_max_apps or "50")))
    except Exception:
        k8s_max_apps_val = 50
    k8s_prefix_val = str(k8s_auto_map_prefix or "k8s").strip() or "k8s"

    cfg = {
        "observability_enabled": bool(enable_flag),
        "observability_topic": topic_val,
        "observability_window": int(window_val),
        "k8s_auto_map_enabled": bool(k8s_map_flag),
        "k8s_auto_map_max_apps": int(k8s_max_apps_val),
        "k8s_auto_map_prefix": k8s_prefix_val,
    }
    with get_session() as s:
        row = s.query(NetraAgentConfig).filter(NetraAgentConfig.agent_name == target_agent).first()
        if row:
            row.updated_at = utcnow()
            row.config_json = json.dumps(cfg, ensure_ascii=True)
        else:
            s.add(
                NetraAgentConfig(
                    agent_name=target_agent,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                    config_json=json.dumps(cfg, ensure_ascii=True),
                )
            )
        s.commit()
    msg = f"Dashboard config updated for {target_agent} (observability {'enabled' if enable_flag else 'disabled'})"
    return RedirectResponse(
        url=(
            f"/observability?agent_id={quote(target_agent)}&app_id={quote(app_id or '')}"
            f"&app_group={quote(app_group or 'all')}&namespace={quote(namespace or '')}&message={quote(msg)}"
        ),
        status_code=303,
    )


@app.get("/api/observability/diagnostics")
async def api_observability_diagnostics(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    agent_id: str | None = None,
    app_id: str | None = None,
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    selected_agent = (agent_id or "").strip()
    selected_app = (app_id or "").strip()
    out_rows: list[dict[str, Any]] = []
    with get_session() as s:
        q = s.query(TraceRun).filter(TraceRun.name == "observability.metrics")
        if selected_agent:
            q = q.filter(TraceRun.agent_id == selected_agent)
        if selected_app:
            q = q.filter(TraceRun.app_id == selected_app)
        rows = q.order_by(TraceRun.ts.desc()).limit(120).all()
        for r in rows:
            try:
                body = json.loads(r.output_json or "{}")
            except Exception:
                body = {}
            payload = body.get("observability_payload") if isinstance(body.get("observability_payload"), dict) else {}
            obs = payload.get("observability") if isinstance(payload.get("observability"), dict) else {}
            golden = obs.get("golden_signals") if isinstance(obs.get("golden_signals"), dict) else {}
            latency = golden.get("latency_ms") if isinstance(golden.get("latency_ms"), dict) else {}
            traffic = golden.get("traffic") if isinstance(golden.get("traffic"), dict) else {}
            errors = golden.get("errors") if isinstance(golden.get("errors"), dict) else {}
            saturation = golden.get("saturation") if isinstance(golden.get("saturation"), dict) else {}
            ts = str(payload.get("timestamp") or (r.ts.isoformat() if r.ts else ""))
            out_rows.append(
                {
                    "ts": ts,
                    "agent_id": str(payload.get("agent_id") or r.agent_id or ""),
                    "app_id": str(r.app_id or ""),
                    "latency_ms": _to_float(latency.get("current"), 0.0),
                    "rps": _to_float(traffic.get("requests_per_sec"), 0.0),
                    "error_rate_percent": _to_float(errors.get("error_rate_percent"), 0.0),
                    "cpu_percent": _to_float(saturation.get("cpu_percent"), 0.0),
                    "memory_percent": _to_float(saturation.get("memory_percent"), 0.0),
                    "disk_percent": _to_float(saturation.get("disk_percent"), 0.0),
                }
            )
    latest = out_rows[0] if out_rows else {}
    latest_ts_dt = None
    try:
        if latest and latest.get("ts"):
            latest_ts_dt = datetime.fromisoformat(str(latest.get("ts")).replace("Z", "+00:00"))
    except Exception:
        latest_ts_dt = None
    age_sec = int((datetime.now(timezone.utc) - latest_ts_dt).total_seconds()) if latest_ts_dt else None
    missing = []
    if not any(_to_float(r.get("latency_ms"), 0.0) >= 0.0 for r in out_rows):
        missing.append("latency")
    if not any(_to_float(r.get("rps"), 0.0) >= 0.0 for r in out_rows):
        missing.append("traffic")
    if not any(_to_float(r.get("error_rate_percent"), 0.0) >= 0.0 for r in out_rows):
        missing.append("errors")
    return {
        "ok": True,
        "filters": {"agent_id": selected_agent, "app_id": selected_app},
        "rows": len(out_rows),
        "latest_sample_age_seconds": age_sec,
        "latest": latest,
        "missing_signals": missing,
    }


@app.get("/api/observability/topology")
async def api_observability_topology(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    hours: int = Query(24, ge=1, le=168),
    agent_id: str | None = None,
    app_id: str | None = None,
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    selected_agent = (agent_id or "").strip()
    selected_app = (app_id or "").strip()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    nodes: dict[str, dict[str, Any]] = {}
    rollup: dict[tuple[str, str], dict[str, Any]] = {}
    with get_session() as s:
        q = s.query(TraceRun).filter(TraceRun.ts >= since, TraceRun.name != "infra.metrics", TraceRun.name != "observability.metrics")
        if selected_agent:
            q = q.filter(TraceRun.agent_id == selected_agent)
        if selected_app:
            q = q.filter(TraceRun.app_id == selected_app)
        runs = q.order_by(TraceRun.ts.desc()).limit(TRACE_ANALYTICS_MAX_RUNS).all()
        ids = [int(r.id) for r in runs]
        spans = s.query(TraceSpan).filter(TraceSpan.trace_run_id.in_(ids)).all() if ids else []
        by_run: dict[int, list[TraceSpan]] = {}
        for sp in spans:
            by_run.setdefault(int(sp.trace_run_id), []).append(sp)
        for r in runs:
            src = str(r.app_id or "unknown")
            nodes.setdefault(src, {"id": src, "kind": "app"})
            for sp in by_run.get(int(r.id), []):
                tgt = _span_target_service(str(sp.name or ""), str(sp.meta_json or ""), default="")
                if not tgt or tgt == src:
                    continue
                nodes.setdefault(tgt, {"id": tgt, "kind": "service"})
                key = (src, tgt)
                cur = rollup.get(key)
                d = float(_to_int(sp.duration_ms, 0))
                if not cur:
                    rollup[key] = {"source": src, "target": tgt, "count": 1, "durations": [d]}
                else:
                    cur["count"] += 1
                    cur["durations"].append(d)
    edges = []
    for _, v in rollup.items():
        ds = sorted(v["durations"])
        edges.append(
            {
                "source": v["source"],
                "target": v["target"],
                "count": int(v["count"]),
                "latency_avg_ms": float(sum(ds) / max(1, len(ds))),
                "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
            }
        )
    edges.sort(key=lambda x: (x["count"], x["latency_p95_ms"]), reverse=True)
    return {
        "ok": True,
        "filters": {"hours": hours, "agent_id": selected_agent, "app_id": selected_app},
        "nodes": sorted(nodes.values(), key=lambda x: x["id"])[:200],
        "edges": edges[:500],
    }


@app.get("/api/service-map/realtime")
async def api_service_map_realtime(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    window_sec: int = Query(300, ge=30, le=3600),
    environment: str | None = Query(None),
    min_calls: int = Query(1, ge=1, le=5000),
    max_nodes: int = Query(400, ge=20, le=2000),
    max_edges: int = Query(1000, ge=20, le=5000),
    demo: bool = Query(False),
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    env_filter = (environment or "").strip()
    since = datetime.now(timezone.utc) - timedelta(seconds=int(window_sec))
    nodes: dict[str, dict[str, Any]] = {}
    rollup: dict[tuple[str, str, str], dict[str, Any]] = {}
    with get_session() as s:
        runs = (
            s.query(TraceRun)
            .filter(TraceRun.ts >= since, TraceRun.name != "infra.metrics", TraceRun.name != "observability.metrics")
            .order_by(TraceRun.ts.desc())
            .limit(TRACE_ANALYTICS_MAX_RUNS)
            .all()
        )
        run_ids = [int(r.id) for r in runs]
        spans = s.query(TraceSpan).filter(TraceSpan.trace_run_id.in_(run_ids)).all() if run_ids else []
        by_run: dict[int, list[TraceSpan]] = {}
        for sp in spans:
            by_run.setdefault(int(sp.trace_run_id), []).append(sp)
        for r in runs:
            env_name = _extract_environment_from_run(r)
            if env_filter and env_name != env_filter:
                continue
            src = str(r.app_id or "unknown")
            src_key = f"{env_name}:{src}"
            nodes.setdefault(src_key, {"id": src_key, "service": src, "environment": env_name, "kind": "app"})
            for sp in by_run.get(int(r.id), []):
                tgt = _span_target_service(str(sp.name or ""), str(sp.meta_json or ""), default="")
                if not tgt or tgt == src:
                    continue
                tgt_key = f"{env_name}:{tgt}"
                nodes.setdefault(tgt_key, {"id": tgt_key, "service": tgt, "environment": env_name, "kind": "service"})
                k = (src_key, tgt_key, env_name)
                cur = rollup.get(k)
                d = float(_to_int(sp.duration_ms, 0))
                if not cur:
                    rollup[k] = {"source": src_key, "target": tgt_key, "environment": env_name, "count": 1, "durations": [d]}
                else:
                    cur["count"] += 1
                    cur["durations"].append(d)
    edges = []
    for _, v in rollup.items():
        ds = sorted(v["durations"])
        edges.append(
            {
                "source": v["source"],
                "target": v["target"],
                "environment": v["environment"],
                "count": int(v["count"]),
                "latency_avg_ms": float(sum(ds) / max(1, len(ds))),
                "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
            }
        )
    edges = [e for e in edges if int(e.get("count", 0)) >= int(min_calls)]
    edges.sort(key=lambda x: (x["count"], x["latency_p95_ms"]), reverse=True)
    edge_limited = edges[: int(max_edges)]
    keep_ids: set[str] = set()
    for e in edge_limited:
        keep_ids.add(str(e.get("source") or ""))
        keep_ids.add(str(e.get("target") or ""))
    if keep_ids:
        node_rows = [n for n in nodes.values() if str(n.get("id") or "") in keep_ids]
    else:
        node_rows = list(nodes.values())
    node_rows = sorted(node_rows, key=lambda x: x["id"])[: int(max_nodes)]
    allowed = {str(n.get("id") or "") for n in node_rows}
    edge_limited = [e for e in edge_limited if str(e.get("source") or "") in allowed and str(e.get("target") or "") in allowed]
    env_choices = sorted({n["environment"] for n in nodes.values()})

    if demo and (not node_rows or not edge_limited):
        demo_env = env_filter or "prod"
        demo_nodes = [
            {"id": f"{demo_env}:web-frontend", "service": "web-frontend", "environment": demo_env, "kind": "app"},
            {"id": f"{demo_env}:api-gateway", "service": "api-gateway", "environment": demo_env, "kind": "service"},
            {"id": f"{demo_env}:checkout-service", "service": "checkout-service", "environment": demo_env, "kind": "service"},
            {"id": f"{demo_env}:payment-service", "service": "payment-service", "environment": demo_env, "kind": "service"},
            {"id": f"{demo_env}:inventory-service", "service": "inventory-service", "environment": demo_env, "kind": "service"},
            {"id": f"{demo_env}:notification-service", "service": "notification-service", "environment": demo_env, "kind": "service"},
            {"id": f"{demo_env}:postgres-primary", "service": "postgres-primary", "environment": demo_env, "kind": "service"},
            {"id": f"{demo_env}:redis-cache", "service": "redis-cache", "environment": demo_env, "kind": "service"},
        ]
        demo_edges = [
            {"source": f"{demo_env}:web-frontend", "target": f"{demo_env}:api-gateway", "environment": demo_env, "count": 980, "latency_avg_ms": 18.0, "latency_p95_ms": 42.0},
            {"source": f"{demo_env}:api-gateway", "target": f"{demo_env}:checkout-service", "environment": demo_env, "count": 760, "latency_avg_ms": 64.0, "latency_p95_ms": 132.0},
            {"source": f"{demo_env}:api-gateway", "target": f"{demo_env}:inventory-service", "environment": demo_env, "count": 620, "latency_avg_ms": 39.0, "latency_p95_ms": 88.0},
            {"source": f"{demo_env}:checkout-service", "target": f"{demo_env}:payment-service", "environment": demo_env, "count": 410, "latency_avg_ms": 111.0, "latency_p95_ms": 240.0},
            {"source": f"{demo_env}:checkout-service", "target": f"{demo_env}:postgres-primary", "environment": demo_env, "count": 535, "latency_avg_ms": 26.0, "latency_p95_ms": 74.0},
            {"source": f"{demo_env}:inventory-service", "target": f"{demo_env}:redis-cache", "environment": demo_env, "count": 590, "latency_avg_ms": 7.0, "latency_p95_ms": 19.0},
            {"source": f"{demo_env}:payment-service", "target": f"{demo_env}:notification-service", "environment": demo_env, "count": 165, "latency_avg_ms": 53.0, "latency_p95_ms": 121.0},
        ]
        demo_edges = [e for e in demo_edges if int(e.get("count", 0)) >= int(min_calls)][: int(max_edges)]
        demo_keep = {str(e.get("source") or "") for e in demo_edges} | {str(e.get("target") or "") for e in demo_edges}
        demo_nodes = [n for n in demo_nodes if str(n.get("id") or "") in demo_keep][: int(max_nodes)]
        node_rows = demo_nodes
        edge_limited = demo_edges
        env_choices = sorted({str(n.get("environment") or "") for n in demo_nodes if n.get("environment")})

    return {
        "ok": True,
        "window_sec": int(window_sec),
        "environment": env_filter,
        "min_calls": int(min_calls),
        "max_nodes": int(max_nodes),
        "max_edges": int(max_edges),
        "demo": bool(demo),
        "environments": env_choices,
        "stats": {
            "raw_nodes": int(len(nodes)),
            "raw_edges": int(len(edges)),
            "returned_nodes": int(len(node_rows)),
            "returned_edges": int(len(edge_limited)),
        },
        "nodes": node_rows,
        "edges": edge_limited,
    }


@app.get("/observability/service-map", response_class=HTMLResponse)
async def observability_service_map_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    return templates.TemplateResponse(
        "service_map_realtime.html",
        {"request": request, "email": email, "role": role},
    )


@app.get("/apm/errors", response_class=HTMLResponse)
async def apm_errors_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    status: str | None = Query(""),
    environment: str | None = Query(""),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    st = (status or "").strip()
    env = (environment or "").strip()
    with get_session() as s:
        q = s.query(APMErrorGroup)
        if st:
            q = q.filter(APMErrorGroup.workflow_status == st)
        if env:
            q = q.filter(APMErrorGroup.environment == env)
        groups = q.order_by(APMErrorGroup.last_seen_ts.desc()).limit(300).all()
        env_choices = [r[0] for r in s.query(APMErrorGroup.environment).distinct().order_by(APMErrorGroup.environment.asc()).all() if r and r[0]]
    return templates.TemplateResponse(
        "apm_errors.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "groups": groups,
            "status_filter": st,
            "environment_filter": env,
            "env_choices": env_choices,
            "message": str(request.query_params.get("message") or ""),
            "error": str(request.query_params.get("error") or ""),
        },
    )


@app.get("/apm/errors/{group_id}", response_class=HTMLResponse)
async def apm_error_group_detail(
    request: Request,
    group_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    with get_session() as s:
        grp = s.query(APMErrorGroup).filter(APMErrorGroup.id == int(group_id)).first()
        if not grp:
            return RedirectResponse(url="/apm/errors?error=Error%20group%20not%20found", status_code=303)
        events = s.query(APMErrorEvent).filter(APMErrorEvent.error_group_id == int(group_id)).order_by(APMErrorEvent.ts.desc()).limit(500).all()
    return templates.TemplateResponse(
        "apm_error_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "group": grp,
            "events": events,
            "message": str(request.query_params.get("message") or ""),
            "error": str(request.query_params.get("error") or ""),
        },
    )


@app.post("/apm/errors/groups/{group_id}/workflow")
async def apm_error_group_workflow_update(
    request: Request,
    group_id: int,
    user: dict[str, Any] = Depends(require_login),
    workflow_status: str = Form("open"),
    assignee: str = Form(""),
    workflow_notes: str = Form(""),
):
    if isinstance(user, RedirectResponse):
        return user
    allowed = {"open", "ack", "resolved", "ignored"}
    st = (workflow_status or "open").strip().lower()
    if st not in allowed:
        st = "open"
    with get_session() as s:
        grp = s.query(APMErrorGroup).filter(APMErrorGroup.id == int(group_id)).first()
        if not grp:
            return RedirectResponse(url="/apm/errors?error=Error%20group%20not%20found", status_code=303)
        grp.workflow_status = st
        grp.assignee = (assignee or "").strip() or None
        grp.workflow_notes = (workflow_notes or "").strip() or None
        grp.updated_at = utcnow()
        s.add(AuditEvent(actor_email=user.get("email"), action="apm_error_workflow_update", details=f"group_id={group_id} status={st}"))
        s.commit()
    return RedirectResponse(url=f"/apm/errors/{group_id}?message=Workflow%20updated", status_code=303)


@app.get("/api/apm/errors/replay/{event_id}")
async def api_apm_error_replay_context(
    request: Request,
    event_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    with get_session() as s:
        ev = s.query(APMErrorEvent).filter(APMErrorEvent.id == int(event_id)).first()
        if not ev:
            return {"ok": False, "error": "event_not_found"}
        try:
            ctx = json.loads(ev.replay_context_json or "{}")
        except Exception:
            ctx = {}
    return {"ok": True, "event_id": int(event_id), "replay_context": ctx}


@app.get("/observability/service", response_class=HTMLResponse)
async def observability_service_detail(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str = Query(...),
    agent_id: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_app = (app_id or "").strip()
    selected_agent = (agent_id or "").strip() or None
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    run_rows: list[TraceRun] = []
    span_rows: list[TraceSpan] = []
    obs_rows: list[dict[str, Any]] = []
    with get_session() as s:
        q = s.query(TraceRun).filter(
            TraceRun.ts >= since,
            TraceRun.app_id == selected_app,
            TraceRun.name != "infra.metrics",
            TraceRun.name != "observability.metrics",
        )
        if selected_agent:
            q = q.filter(TraceRun.agent_id == selected_agent)
        run_rows = q.order_by(TraceRun.ts.desc()).limit(TRACE_ANALYTICS_MAX_RUNS).all()
        run_ids = [int(r.id) for r in run_rows]
        if run_ids:
            span_rows = s.query(TraceSpan).filter(TraceSpan.trace_run_id.in_(run_ids)).all()
        oq = s.query(TraceRun).filter(TraceRun.ts >= since, TraceRun.name == "observability.metrics", TraceRun.app_id == selected_app)
        if selected_agent:
            oq = oq.filter(TraceRun.agent_id == selected_agent)
        for r in oq.order_by(TraceRun.ts.desc()).limit(OBS_UI_MAX_SNAPSHOTS).all():
            try:
                body = json.loads(r.output_json or "{}")
            except Exception:
                body = {}
            payload = body.get("observability_payload") if isinstance(body.get("observability_payload"), dict) else {}
            obs = payload.get("observability") if isinstance(payload.get("observability"), dict) else {}
            golden = obs.get("golden_signals") if isinstance(obs.get("golden_signals"), dict) else {}
            apm = obs.get("apm") if isinstance(obs.get("apm"), dict) else {}
            latency = golden.get("latency_ms") if isinstance(golden.get("latency_ms"), dict) else {}
            errors = golden.get("errors") if isinstance(golden.get("errors"), dict) else {}
            traffic = golden.get("traffic") if isinstance(golden.get("traffic"), dict) else {}
            resp = apm.get("response_time_ms") if isinstance(apm.get("response_time_ms"), dict) else {}
            reqr = apm.get("request_rates") if isinstance(apm.get("request_rates"), dict) else {}
            errr = apm.get("error_rates") if isinstance(apm.get("error_rates"), dict) else {}
            obs_rows.append(
                {
                    "ts": (r.ts.isoformat() if r.ts else ""),
                    "latency_current": _to_float(latency.get("current"), _to_float(resp.get("avg"), 0.0)),
                    "latency_p95": _to_float(latency.get("p95"), _to_float(resp.get("p95"), 0.0)),
                    "traffic_rps": _to_float(traffic.get("requests_per_sec"), _to_float(reqr.get("rps"), 0.0)),
                    "error_rate_percent": _to_float(errors.get("error_rate_percent"), _to_float(errr.get("percent"), 0.0)),
                }
            )

    durations = sorted([float(_to_int(r.duration_ms, 0)) for r in run_rows if _to_int(r.duration_ms, 0) > 0])
    req_total = len(run_rows)
    err_total = sum(1 for r in run_rows if str(r.status or "").lower() == "error" or bool(r.error))
    if req_total <= 0 and obs_rows:
        req_total = len(obs_rows)
        err_total = int(round(sum(_to_float(r.get("error_rate_percent"), 0.0) for r in obs_rows) / max(1.0, float(len(obs_rows))) * float(req_total) / 100.0))
    latency_p50 = float(durations[max(0, int(len(durations) * 0.50) - 1)] if durations else 0.0)
    latency_p95 = float(durations[max(0, int(len(durations) * 0.95) - 1)] if durations else 0.0)
    latency_p99 = float(durations[max(0, int(len(durations) * 0.99) - 1)] if durations else 0.0)
    if not durations and obs_rows:
        obs_durations = sorted([_to_float(r.get("latency_current"), 0.0) for r in obs_rows if _to_float(r.get("latency_current"), 0.0) > 0])
        latency_p50 = float(obs_durations[max(0, int(len(obs_durations) * 0.50) - 1)] if obs_durations else 0.0)
        latency_p95 = float(obs_durations[max(0, int(len(obs_durations) * 0.95) - 1)] if obs_durations else 0.0)
        latency_p99 = float(obs_durations[max(0, int(len(obs_durations) * 0.99) - 1)] if obs_durations else 0.0)

    errored_run_ids: set[int] = {
        int(r.id)
        for r in run_rows
        if str(r.status or "").lower() == "error" or bool(r.error)
    }

    dep_rollup: dict[str, dict[str, Any]] = {}
    for sp in span_rows:
        tgt = _span_target_service(str(sp.name or ""), str(sp.meta_json or ""), default="")
        if not tgt or tgt == selected_app:
            continue
        cur = dep_rollup.get(tgt)
        d = float(_to_int(sp.duration_ms, 0))
        is_error_call = int(sp.trace_run_id) in errored_run_ids
        if not cur:
            dep_rollup[tgt] = {"service": tgt, "count": 1, "error_count": (1 if is_error_call else 0), "durations": [d]}
        else:
            cur["count"] += 1
            cur["error_count"] += (1 if is_error_call else 0)
            cur["durations"].append(d)
    dependencies = []
    for _, v in dep_rollup.items():
        ds = sorted(v["durations"])
        dependencies.append(
            {
                "service": v["service"],
                "calls": int(v["count"]),
                "error_rate_percent": (float(_to_int(v.get("error_count"), 0)) * 100.0 / float(max(1, _to_int(v.get("count"), 0)))),
                "latency_avg_ms": float(sum(ds) / max(1, len(ds))),
                "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
            }
        )
    dependencies.sort(key=lambda x: (x["calls"], x["latency_p95_ms"]), reverse=True)

    resource_rollup: dict[str, dict[str, Any]] = {}
    error_rollup: dict[str, dict[str, Any]] = {}
    for r in run_rows:
        resource = str(r.name or "unknown")
        rr = resource_rollup.get(resource)
        dur = float(_to_int(r.duration_ms, 0))
        is_error = str(r.status or "").lower() == "error" or bool(r.error)
        if not rr:
            resource_rollup[resource] = {
                "resource": resource,
                "count": 1,
                "error_count": (1 if is_error else 0),
                "durations": [dur],
            }
        else:
            rr["count"] += 1
            rr["error_count"] += (1 if is_error else 0)
            rr["durations"].append(dur)
        if is_error:
            sig = str(r.error or r.status or "error").strip()[:160] or "error"
            er = error_rollup.get(sig)
            if not er:
                error_rollup[sig] = {"signature": sig, "count": 1, "latest_ts": (r.ts.isoformat() if r.ts else "")}
            else:
                er["count"] += 1
                if str(r.ts or "") > str(er.get("latest_ts") or ""):
                    er["latest_ts"] = (r.ts.isoformat() if r.ts else "")

    resource_rows: list[dict[str, Any]] = []
    for _, v in resource_rollup.items():
        ds = sorted([float(x) for x in (v.get("durations") or [])])
        count = max(1, _to_int(v.get("count"), 0))
        resource_rows.append(
            {
                "resource": str(v.get("resource") or "unknown"),
                "count": int(v.get("count") or 0),
                "error_rate_percent": (float(_to_int(v.get("error_count"), 0)) * 100.0 / float(count)),
                "latency_avg_ms": float(sum(ds) / max(1, len(ds))),
                "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
                "latency_p99_ms": float(ds[max(0, int(len(ds) * 0.99) - 1)] if ds else 0.0),
                "throughput_rpm": (float(_to_int(v.get("count"), 0)) / float(max(1, hours * 60))),
            }
        )
    resource_rows.sort(key=lambda x: (x["count"], x["latency_p95_ms"]), reverse=True)
    error_rows = sorted(error_rollup.values(), key=lambda x: _to_int(x.get("count"), 0), reverse=True)

    if not resource_rows and obs_rows:
        avg_rps = sum(_to_float(r.get("traffic_rps"), 0.0) for r in obs_rows) / max(1.0, float(len(obs_rows)))
        avg_err = sum(_to_float(r.get("error_rate_percent"), 0.0) for r in obs_rows) / max(1.0, float(len(obs_rows)))
        resource_rows = [
            {
                "resource": "apm.snapshot.aggregate",
                "count": len(obs_rows),
                "error_rate_percent": float(avg_err),
                "latency_avg_ms": sum(_to_float(r.get("latency_current"), 0.0) for r in obs_rows) / max(1.0, float(len(obs_rows))),
                "latency_p95_ms": float(latency_p95),
                "latency_p99_ms": float(latency_p99),
                "throughput_rpm": float(avg_rps * 60.0),
            }
        ]

    trend_points = [{"ts": (r.ts.isoformat() if r.ts else ""), "value": float(_to_int(r.duration_ms, 0))} for r in reversed(run_rows[:200])]
    if not trend_points and obs_rows:
        trend_points = [{"ts": str(r.get("ts") or ""), "value": _to_float(r.get("latency_current"), 0.0)} for r in reversed(obs_rows[:200])]
    percentile_heatmap = [
        {
            "resource": str(r.get("resource") or ""),
            "p95": _to_float(r.get("latency_p95_ms"), 0.0),
            "p99": _to_float(r.get("latency_p99_ms"), 0.0),
            "error_rate_percent": _to_float(r.get("error_rate_percent"), 0.0),
        }
        for r in resource_rows[:20]
    ]
    slowest_resources = sorted(resource_rows, key=lambda x: _to_float(x.get("latency_p99_ms"), 0.0), reverse=True)[:20]

    return templates.TemplateResponse(
        "observability_service_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "selected_app": selected_app,
            "selected_agent": selected_agent or "",
            "hours": hours,
            "req_total": req_total,
            "err_total": err_total,
            "error_rate_percent": (float(err_total) * 100.0 / float(req_total)) if req_total else 0.0,
            "latency_p50": latency_p50,
            "latency_p95": latency_p95,
            "latency_p99": latency_p99,
            "dependencies": dependencies[:100],
            "resource_rows": resource_rows[:200],
            "error_rows": error_rows[:100],
            "percentile_heatmap": percentile_heatmap,
            "slowest_resources": slowest_resources,
            "trend_points": trend_points,
            "recent_runs": run_rows[:80],
        },
    )


@app.get("/api/apm/trace-analytics")
async def api_apm_trace_analytics(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str = Query(...),
    agent_id: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
):
    if isinstance(user, RedirectResponse):
        # Allow automation via project API key for curl/non-browser clients.
        auth = _require_project_api_key(request)
        if not auth:
            return {"ok": False, "error": "auth_required"}
    selected_app = (app_id or "").strip()
    if not selected_app:
        return {"ok": False, "error": "app_id_required"}
    selected_agent = (agent_id or "").strip() or None
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    run_rows: list[TraceRun] = []
    span_rows: list[TraceSpan] = []
    obs_rows: list[dict[str, Any]] = []
    with get_session() as s:
        q = s.query(TraceRun).filter(
            TraceRun.ts >= since,
            TraceRun.app_id == selected_app,
            TraceRun.name != "infra.metrics",
            TraceRun.name != "observability.metrics",
        )
        if selected_agent:
            q = q.filter(TraceRun.agent_id == selected_agent)
        run_rows = q.order_by(TraceRun.ts.desc()).limit(TRACE_ANALYTICS_MAX_RUNS).all()
        ids = [int(r.id) for r in run_rows]
        if ids:
            span_rows = s.query(TraceSpan).filter(TraceSpan.trace_run_id.in_(ids)).all()
        oq = s.query(TraceRun).filter(TraceRun.ts >= since, TraceRun.name == "observability.metrics", TraceRun.app_id == selected_app)
        if selected_agent:
            oq = oq.filter(TraceRun.agent_id == selected_agent)
        for r in oq.order_by(TraceRun.ts.desc()).limit(OBS_UI_MAX_SNAPSHOTS).all():
            try:
                body = json.loads(r.output_json or "{}")
            except Exception:
                body = {}
            payload = body.get("observability_payload") if isinstance(body.get("observability_payload"), dict) else {}
            obs = payload.get("observability") if isinstance(payload.get("observability"), dict) else {}
            golden = obs.get("golden_signals") if isinstance(obs.get("golden_signals"), dict) else {}
            apm = obs.get("apm") if isinstance(obs.get("apm"), dict) else {}
            latency = golden.get("latency_ms") if isinstance(golden.get("latency_ms"), dict) else {}
            errors = golden.get("errors") if isinstance(golden.get("errors"), dict) else {}
            traffic = golden.get("traffic") if isinstance(golden.get("traffic"), dict) else {}
            resp = apm.get("response_time_ms") if isinstance(apm.get("response_time_ms"), dict) else {}
            reqr = apm.get("request_rates") if isinstance(apm.get("request_rates"), dict) else {}
            errr = apm.get("error_rates") if isinstance(apm.get("error_rates"), dict) else {}
            obs_rows.append(
                {
                    "latency_current": _to_float(latency.get("current"), _to_float(resp.get("avg"), 0.0)),
                    "latency_p95": _to_float(latency.get("p95"), _to_float(resp.get("p95"), 0.0)),
                    "traffic_rps": _to_float(traffic.get("requests_per_sec"), _to_float(reqr.get("rps"), 0.0)),
                    "error_rate_percent": _to_float(errors.get("error_rate_percent"), _to_float(errr.get("percent"), 0.0)),
                }
            )

    durations = sorted([float(_to_int(r.duration_ms, 0)) for r in run_rows if _to_int(r.duration_ms, 0) > 0])
    req_total = len(run_rows)
    err_total = sum(1 for r in run_rows if str(r.status or "").lower() == "error" or bool(r.error))
    if req_total <= 0 and obs_rows:
        req_total = len(obs_rows)
        err_total = int(round(sum(_to_float(r.get("error_rate_percent"), 0.0) for r in obs_rows) / max(1.0, float(len(obs_rows))) * float(req_total) / 100.0))
        durations = sorted([_to_float(r.get("latency_current"), 0.0) for r in obs_rows if _to_float(r.get("latency_current"), 0.0) > 0])
    summary = {
        "requests": int(req_total),
        "errors": int(err_total),
        "error_rate_percent": ((float(err_total) * 100.0 / float(req_total)) if req_total else 0.0),
        "latency_p50_ms": float(durations[max(0, int(len(durations) * 0.50) - 1)] if durations else 0.0),
        "latency_p95_ms": float(durations[max(0, int(len(durations) * 0.95) - 1)] if durations else 0.0),
        "latency_p99_ms": float(durations[max(0, int(len(durations) * 0.99) - 1)] if durations else 0.0),
        "throughput_rpm": (float(req_total) / float(max(1, hours * 60))),
    }

    error_run_ids = {
        int(r.id)
        for r in run_rows
        if str(r.status or "").lower() == "error" or bool(r.error)
    }
    dep_rollup: dict[str, dict[str, Any]] = {}
    for sp in span_rows:
        tgt = _span_target_service(str(sp.name or ""), str(sp.meta_json or ""), default="")
        if not tgt or tgt == selected_app:
            continue
        cur = dep_rollup.get(tgt)
        d = float(_to_int(sp.duration_ms, 0))
        is_err = int(sp.trace_run_id) in error_run_ids
        if not cur:
            dep_rollup[tgt] = {"service": tgt, "count": 1, "error_count": (1 if is_err else 0), "durations": [d]}
        else:
            cur["count"] += 1
            cur["error_count"] += (1 if is_err else 0)
            cur["durations"].append(d)

    dependencies = []
    for _, v in dep_rollup.items():
        ds = sorted(v["durations"])
        dependencies.append(
            {
                "service": v["service"],
                "calls": int(v["count"]),
                "error_rate_percent": (float(_to_int(v.get("error_count"), 0)) * 100.0 / float(max(1, _to_int(v.get("count"), 0)))),
                "latency_avg_ms": float(sum(ds) / max(1, len(ds))),
                "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
            }
        )
    dependencies.sort(key=lambda x: (x["calls"], x["latency_p95_ms"]), reverse=True)

    resource_rollup: dict[str, dict[str, Any]] = {}
    for r in run_rows:
        name = str(r.name or "unknown")
        cur = resource_rollup.get(name)
        d = float(_to_int(r.duration_ms, 0))
        is_err = str(r.status or "").lower() == "error" or bool(r.error)
        if not cur:
            resource_rollup[name] = {"resource": name, "count": 1, "error_count": (1 if is_err else 0), "durations": [d]}
        else:
            cur["count"] += 1
            cur["error_count"] += (1 if is_err else 0)
            cur["durations"].append(d)
    resources = []
    for _, v in resource_rollup.items():
        ds = sorted(v["durations"])
        resources.append(
            {
                "resource": str(v["resource"]),
                "count": int(v["count"]),
                "error_rate_percent": (float(_to_int(v.get("error_count"), 0)) * 100.0 / float(max(1, _to_int(v.get("count"), 0)))),
                "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
                "latency_p99_ms": float(ds[max(0, int(len(ds) * 0.99) - 1)] if ds else 0.0),
                "throughput_rpm": (float(_to_int(v.get("count"), 0)) / float(max(1, hours * 60))),
            }
        )
    resources.sort(key=lambda x: (x["count"], x["latency_p95_ms"]), reverse=True)
    if not resources and obs_rows:
        avg_rps = sum(_to_float(r.get("traffic_rps"), 0.0) for r in obs_rows) / max(1.0, float(len(obs_rows)))
        avg_err = sum(_to_float(r.get("error_rate_percent"), 0.0) for r in obs_rows) / max(1.0, float(len(obs_rows)))
        resources = [
            {
                "resource": "apm.snapshot.aggregate",
                "count": len(obs_rows),
                "error_rate_percent": float(avg_err),
                "latency_p95_ms": float(summary.get("latency_p95_ms") or 0.0),
                "latency_p99_ms": float(summary.get("latency_p99_ms") or 0.0),
                "throughput_rpm": float(avg_rps * 60.0),
            }
        ]
    percentile_heatmap = [
        {
            "resource": str(r.get("resource") or ""),
            "p95_ms": _to_float(r.get("latency_p95_ms"), 0.0),
            "p99_ms": _to_float(r.get("latency_p99_ms"), 0.0),
            "error_rate_percent": _to_float(r.get("error_rate_percent"), 0.0),
        }
        for r in resources[:20]
    ]
    slowest_resources = sorted(resources, key=lambda x: _to_float(x.get("latency_p99_ms"), 0.0), reverse=True)[:20]

    return {
        "ok": True,
        "filters": {"app_id": selected_app, "agent_id": selected_agent or "", "hours": int(hours)},
        "summary": summary,
        "resources": resources[:300],
        "dependencies": dependencies[:300],
        "percentile_heatmap": percentile_heatmap,
        "slowest_resources": slowest_resources,
    }


@app.get("/apm/pipeline", response_class=HTMLResponse)
async def apm_pipeline_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    project_id: int | None = Query(None),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    message = str(request.query_params.get("message") or "")
    error = str(request.query_params.get("error") or "")
    selected_project_id = int(project_id) if project_id is not None else (_effective_project_id(request, user) or 0)

    with get_session() as s:
        cfg = s.query(TracePipelineConfig).order_by(TracePipelineConfig.updated_at.desc()).first()
        if not cfg:
            cfg = TracePipelineConfig(
                name="default",
                enabled=True,
                retention_days=14,
                default_sample_rate=100,
                keep_error_traces=True,
                drop_healthcheck_traces=True,
            )
            s.add(cfg)
            s.commit()
        rules = s.query(TraceSamplingRule).order_by(TraceSamplingRule.priority.desc(), TraceSamplingRule.id.asc()).all()
        metric_cfgs = s.query(SpanMetricConfig).order_by(SpanMetricConfig.name.asc()).all()
        metric_points = s.query(SpanMetricPoint).order_by(SpanMetricPoint.ts.desc()).limit(200).all()
        projects = s.query(Project).order_by(Project.name.asc()).all()
        policy_rows = s.query(ProjectRetentionPolicy).order_by(ProjectRetentionPolicy.updated_at.desc()).all()
        policy_map = {int(p.project_id): p for p in policy_rows if _to_int(getattr(p, "project_id", 0), 0) > 0}
        selected_policy = policy_map.get(int(selected_project_id or 0))

    return templates.TemplateResponse(
        "apm_pipeline.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "message": message,
            "error": error,
            "cfg": cfg,
            "rules": rules,
            "metric_cfgs": metric_cfgs,
            "metric_points": metric_points,
            "projects": projects,
            "selected_project_id": int(selected_project_id or 0),
            "selected_policy": selected_policy,
            "policy_rows": policy_rows,
            "defaults": {
                "trace_retention_days": TRACE_RETENTION_DAYS,
                "trace_max_rows": TRACE_MAX_ROWS,
                "infra_retention_days": INFRA_RETENTION_DAYS,
                "infra_max_rows": INFRA_MAX_ROWS,
                "observability_retention_days": OBS_RETENTION_DAYS,
                "observability_max_rows": OBS_MAX_ROWS,
            },
        },
    )


@app.post("/apm/pipeline/config")
async def apm_pipeline_update_config(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    enabled: str = Form("true"),
    retention_days: str = Form("14"),
    default_sample_rate: str = Form("100"),
    keep_error_traces: str = Form("true"),
    drop_healthcheck_traces: str = Form("true"),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        cfg = s.query(TracePipelineConfig).order_by(TracePipelineConfig.updated_at.desc()).first()
        if not cfg:
            cfg = TracePipelineConfig(name="default")
            s.add(cfg)
            s.flush()
        cfg.updated_at = utcnow()
        cfg.enabled = str(enabled).strip().lower() in {"1", "true", "yes", "on"}
        cfg.retention_days = max(1, _to_int(retention_days, 14))
        cfg.default_sample_rate = max(0, min(100, _to_int(default_sample_rate, 100)))
        cfg.keep_error_traces = str(keep_error_traces).strip().lower() in {"1", "true", "yes", "on"}
        cfg.drop_healthcheck_traces = str(drop_healthcheck_traces).strip().lower() in {"1", "true", "yes", "on"}
        s.commit()
    return RedirectResponse(url="/apm/pipeline?message=Pipeline%20config%20updated", status_code=303)


@app.post("/apm/pipeline/project-retention/save")
async def apm_pipeline_save_project_retention(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    project_id: str = Form(""),
    enabled: str = Form("true"),
    trace_retention_days: str = Form("30"),
    trace_max_rows: str = Form("250000"),
    infra_retention_days: str = Form("14"),
    infra_max_rows: str = Form("120000"),
    observability_retention_days: str = Form("14"),
    observability_max_rows: str = Form("120000"),
):
    if isinstance(user, RedirectResponse):
        return user
    pid = _to_int(project_id, 0)
    if pid <= 0:
        return RedirectResponse(url="/apm/pipeline?error=project_id%20required", status_code=303)
    with get_session() as s:
        exists = s.query(Project).filter(Project.id == pid).first()
        if not exists:
            return RedirectResponse(url="/apm/pipeline?error=project%20not%20found", status_code=303)
        row = s.query(ProjectRetentionPolicy).filter(ProjectRetentionPolicy.project_id == pid).first()
        if not row:
            row = ProjectRetentionPolicy(project_id=pid, created_at=utcnow(), updated_at=utcnow())
            s.add(row)
            s.flush()
        row.updated_at = utcnow()
        row.enabled = str(enabled or "").strip().lower() in {"1", "true", "yes", "on"}
        row.trace_retention_days = max(1, _to_int(trace_retention_days, TRACE_RETENTION_DAYS))
        row.trace_max_rows = max(1000, _to_int(trace_max_rows, TRACE_MAX_ROWS))
        row.infra_retention_days = max(1, _to_int(infra_retention_days, INFRA_RETENTION_DAYS))
        row.infra_max_rows = max(1000, _to_int(infra_max_rows, INFRA_MAX_ROWS))
        row.observability_retention_days = max(1, _to_int(observability_retention_days, OBS_RETENTION_DAYS))
        row.observability_max_rows = max(1000, _to_int(observability_max_rows, OBS_MAX_ROWS))
        s.commit()
    return RedirectResponse(url=f"/apm/pipeline?project_id={pid}&message=Project%20retention%20saved", status_code=303)


@app.post("/apm/pipeline/rules/add")
async def apm_pipeline_add_rule(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form("rule"),
    enabled: str = Form("true"),
    priority: str = Form("100"),
    app_id_pattern: str = Form(""),
    name_pattern: str = Form("*"),
    min_duration_ms: str = Form(""),
    error_only: str = Form("false"),
    sample_rate: str = Form("100"),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        s.add(
            TraceSamplingRule(
                name=(name or "rule").strip() or "rule",
                enabled=str(enabled).strip().lower() in {"1", "true", "yes", "on"},
                priority=_to_int(priority, 100),
                app_id_pattern=(app_id_pattern or "").strip() or None,
                name_pattern=(name_pattern or "*").strip() or "*",
                min_duration_ms=_to_int(min_duration_ms, 0) if str(min_duration_ms or "").strip() else None,
                error_only=str(error_only).strip().lower() in {"1", "true", "yes", "on"},
                sample_rate=max(0, min(100, _to_int(sample_rate, 100))),
            )
        )
        s.commit()
    return RedirectResponse(url="/apm/pipeline?message=Sampling%20rule%20added", status_code=303)


@app.post("/apm/pipeline/rules/{rule_id}/delete")
async def apm_pipeline_delete_rule(
    request: Request,
    rule_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        row = s.query(TraceSamplingRule).filter(TraceSamplingRule.id == int(rule_id)).first()
        if row:
            s.delete(row)
            s.commit()
    return RedirectResponse(url="/apm/pipeline?message=Sampling%20rule%20deleted", status_code=303)


@app.post("/apm/pipeline/span-metrics/add")
async def apm_pipeline_add_span_metric(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form("span.metric"),
    enabled: str = Form("true"),
    span_name_pattern: str = Form("*"),
    app_id_pattern: str = Form(""),
    aggregation: str = Form("count"),
    field_name: str = Form("duration_ms"),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        base = (name or "span.metric").strip() or "span.metric"
        existing = s.query(SpanMetricConfig).filter(SpanMetricConfig.name == base).first()
        if existing:
            base = f"{base}-{int(time.time())}"
        s.add(
            SpanMetricConfig(
                name=base,
                enabled=str(enabled).strip().lower() in {"1", "true", "yes", "on"},
                span_name_pattern=(span_name_pattern or "*").strip() or "*",
                app_id_pattern=(app_id_pattern or "").strip() or None,
                aggregation=(aggregation or "count").strip().lower(),
                field_name=(field_name or "duration_ms").strip().lower(),
            )
        )
        s.commit()
    return RedirectResponse(url="/apm/pipeline?message=Span%20metric%20config%20added", status_code=303)


@app.post("/apm/pipeline/span-metrics/{cfg_id}/delete")
async def apm_pipeline_delete_span_metric(
    request: Request,
    cfg_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        row = s.query(SpanMetricConfig).filter(SpanMetricConfig.id == int(cfg_id)).first()
        if row:
            s.delete(row)
            s.commit()
    return RedirectResponse(url="/apm/pipeline?message=Span%20metric%20config%20deleted", status_code=303)


@app.post("/apm/pipeline/retention/run")
async def apm_pipeline_run_retention(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    include_error_traces: str = Form("false"),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        cfg = s.query(TracePipelineConfig).order_by(TracePipelineConfig.updated_at.desc()).first()
        policy = _pipeline_cfg_dict(cfg)
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, _to_int(policy.get("retention_days"), 14)))
        include_errors = str(include_error_traces or "").strip().lower() in {"1", "true", "yes", "on"}
        base_q = s.query(TraceRun).filter(
            TraceRun.ts < cutoff,
            TraceRun.name != "infra.metrics",
            TraceRun.name != "observability.metrics",
        )
        base_old_count = base_q.count()
        error_old_count = base_q.filter(TraceRun.status == "error").count()
        q = base_q
        if policy.get("keep_error_traces", True) and not include_errors:
            q = q.filter((TraceRun.status != "error") | (TraceRun.status.is_(None)))
        old_runs = q.limit(5000).all()
        run_ids = [int(r.id) for r in old_runs]
        deleted = 0
        if run_ids:
            s.query(TraceSpan).filter(TraceSpan.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
            s.query(RunFeedback).filter(RunFeedback.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
            s.query(ExperimentRun).filter(ExperimentRun.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
            s.query(EvaluationResult).filter(EvaluationResult.trace_run_id.in_(run_ids)).delete(synchronize_session=False)
            deleted = s.query(TraceRun).filter(TraceRun.id.in_(run_ids)).delete(synchronize_session=False)
        s.commit()
    msg = (
        "Retention complete "
        f"deleted={deleted} "
        f"eligible_old={base_old_count} "
        f"old_errors={error_old_count} "
        f"include_errors={str(include_errors).lower()} "
        f"keep_error_traces={str(bool(policy.get('keep_error_traces', True))).lower()}"
    )
    return RedirectResponse(url=f"/apm/pipeline?message={quote(msg)}", status_code=303)


@app.get("/api/netra/config")
async def api_netra_config(request: Request, agent_name: str = ""):
    """Dashboard-controlled runtime settings for kakveda-netra.

    Auth: project API key (X-API-Key/Bearer).
    """
    auth = _require_project_api_key(request)
    if not auth:
        return {"ok": False, "error": "missing or invalid api key"}
    target_agent = (agent_name or "").strip()
    if not target_agent:
        return {"ok": False, "error": "agent_name is required"}
    default_cfg = {
        "observability_enabled": True,
        "observability_topic": "observability.metrics",
        "observability_window": 120,
        "k8s_auto_map_enabled": True,
        "k8s_auto_map_max_apps": 50,
        "k8s_auto_map_prefix": "k8s",
    }
    with get_session() as s:
        row = s.query(NetraAgentConfig).filter(NetraAgentConfig.agent_name == target_agent).first()
        if not row:
            cfg = dict(default_cfg)
        else:
            try:
                cfg = json.loads(row.config_json or "{}")
            except Exception:
                cfg = {}
    merged = dict(default_cfg)
    if isinstance(cfg, dict):
        merged.update(cfg)

    # Dynamic instrumentation rules are pushed via agent config polling.
    with get_session() as s:
        rules = (
            s.query(DynamicInstrumentationRule)
            .filter(
                DynamicInstrumentationRule.enabled == True,  # noqa: E712
                (
                    (DynamicInstrumentationRule.scope_type == "global")
                    | ((DynamicInstrumentationRule.scope_type == "agent") & (DynamicInstrumentationRule.scope_value == target_agent))
                ),
            )
            .order_by(DynamicInstrumentationRule.updated_at.desc(), DynamicInstrumentationRule.id.desc())
            .limit(200)
            .all()
        )
    merged["dynamic_instrumentation"] = [
        {
            "id": int(r.id),
            "scope_type": str(r.scope_type or "agent"),
            "scope_value": str(r.scope_value or "*"),
            "rule_type": str(r.rule_type or "log"),
            "target_pattern": str(r.target_pattern or "*"),
            "condition_expr": str(r.condition_expr or ""),
            "action": (json.loads(r.action_json or "{}") if isinstance(r.action_json, str) else {}),
            "updated_at": (r.updated_at.isoformat() if r.updated_at else ""),
        }
        for r in rules
    ]
    return {"ok": True, "agent_name": target_agent, "config": merged}


@app.get("/profiling", response_class=HTMLResponse)
async def profiling_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str | None = Query(None),
    environment: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
    baseline_version: str | None = Query(None),
    compare_version: str | None = Query(None),
    trace_run_id: int | None = Query(None),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_app = (app_id or "").strip()
    selected_env = (environment or "").strip()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    with get_session() as s:
        q = s.query(ProfilerSample).filter(ProfilerSample.ts >= since)
        if selected_app:
            q = q.filter(ProfilerSample.app_id == selected_app)
        if selected_env:
            q = q.filter(ProfilerSample.environment == selected_env)
        rows = q.order_by(ProfilerSample.ts.desc()).limit(5000).all()

        app_choices = [r[0] for r in s.query(ProfilerSample.app_id).distinct().order_by(ProfilerSample.app_id.asc()).all() if r and r[0]]
        env_choices = [r[0] for r in s.query(ProfilerSample.environment).distinct().order_by(ProfilerSample.environment.asc()).all() if r and r[0]]
        ver_choices = [r[0] for r in s.query(ProfilerSample.version).distinct().order_by(ProfilerSample.version.asc()).all() if r and r[0]]

    hotspot_rollup: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        k = (str(r.service_name or "service"), str(r.method_name or "method"))
        cur = hotspot_rollup.get(k)
        if not cur:
            hotspot_rollup[k] = {
                "service_name": k[0],
                "method_name": k[1],
                "samples": 1,
                "cpu_ms_total": float(_to_float(r.cpu_ms, 0.0)),
                "memory_bytes_max": _to_int(r.memory_bytes, 0),
                "last_ts": r.ts,
            }
        else:
            cur["samples"] += 1
            cur["cpu_ms_total"] += float(_to_float(r.cpu_ms, 0.0))
            cur["memory_bytes_max"] = max(cur["memory_bytes_max"], _to_int(r.memory_bytes, 0))
            cur["last_ts"] = max(cur["last_ts"], r.ts)
    hotspots = sorted(hotspot_rollup.values(), key=lambda x: (x["cpu_ms_total"], x["samples"]), reverse=True)[:200]

    def _version_hotspots(ver: str) -> dict[str, float]:
        out: dict[str, float] = {}
        if not ver:
            return out
        for r in rows:
            if str(r.version or "") != ver:
                continue
            key = f"{r.service_name}:{r.method_name}"
            out[key] = out.get(key, 0.0) + float(_to_float(r.cpu_ms, 0.0))
        return out

    base_v = (baseline_version or "").strip()
    cmp_v = (compare_version or "").strip()
    base_map = _version_hotspots(base_v)
    cmp_map = _version_hotspots(cmp_v)
    version_compare_rows: list[dict[str, Any]] = []
    if base_v and cmp_v:
        keys = sorted(set(base_map.keys()) | set(cmp_map.keys()))
        for k in keys:
            b = float(base_map.get(k, 0.0))
            c = float(cmp_map.get(k, 0.0))
            version_compare_rows.append(
                {
                    "key": k,
                    "baseline_cpu_ms": b,
                    "compare_cpu_ms": c,
                    "delta_cpu_ms": c - b,
                    "delta_percent": ((c - b) / b * 100.0) if b > 0 else (100.0 if c > 0 else 0.0),
                }
            )
        version_compare_rows.sort(key=lambda x: abs(float(x["delta_cpu_ms"])), reverse=True)

    correlated: list[dict[str, Any]] = []
    if trace_run_id:
        for r in rows:
            if int(_to_int(r.trace_run_id, 0)) == int(trace_run_id):
                correlated.append(
                    {
                        "service_name": str(r.service_name or ""),
                        "method_name": str(r.method_name or ""),
                        "cpu_ms": float(_to_float(r.cpu_ms, 0.0)),
                        "memory_bytes": _to_int(r.memory_bytes, 0),
                        "version": str(r.version or ""),
                        "ts": r.ts,
                    }
                )
        correlated.sort(key=lambda x: x["cpu_ms"], reverse=True)

    return templates.TemplateResponse(
        "profiling.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "rows": rows[:200],
            "hotspots": hotspots,
            "app_choices": app_choices,
            "env_choices": env_choices,
            "ver_choices": ver_choices,
            "selected_app": selected_app,
            "selected_env": selected_env,
            "hours": hours,
            "baseline_version": base_v,
            "compare_version": cmp_v,
            "version_compare_rows": version_compare_rows[:200],
            "trace_run_id": (int(trace_run_id) if trace_run_id else None),
            "correlated_rows": correlated[:100],
        },
    )


@app.get("/api/profiling/correlation")
async def api_profiling_correlation(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    trace_run_id: int = Query(...),
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    with get_session() as s:
        rows = (
            s.query(ProfilerSample)
            .filter(ProfilerSample.trace_run_id == int(trace_run_id))
            .order_by(ProfilerSample.cpu_ms.desc(), ProfilerSample.ts.desc())
            .limit(200)
            .all()
        )
    return {
        "ok": True,
        "trace_run_id": int(trace_run_id),
        "samples": [
            {
                "service_name": str(r.service_name or ""),
                "method_name": str(r.method_name or ""),
                "cpu_ms": float(_to_float(r.cpu_ms, 0.0)),
                "memory_bytes": _to_int(r.memory_bytes, 0),
                "version": str(r.version or ""),
                "environment": str(r.environment or ""),
                "ts": (r.ts.isoformat() if r.ts else ""),
            }
            for r in rows
        ],
    }


@app.get("/instrumentation", response_class=HTMLResponse)
async def instrumentation_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    message = str(request.query_params.get("message") or "")
    error = str(request.query_params.get("error") or "")
    with get_session() as s:
        rules = s.query(DynamicInstrumentationRule).order_by(DynamicInstrumentationRule.updated_at.desc(), DynamicInstrumentationRule.id.desc()).limit(500).all()
        fb_rows = (
            s.query(DynamicInstrumentationFeedback)
            .order_by(DynamicInstrumentationFeedback.ts.desc(), DynamicInstrumentationFeedback.id.desc())
            .limit(500)
            .all()
        )
    latest_by_rule: dict[int, DynamicInstrumentationFeedback] = {}
    for fb in fb_rows:
        rid = _to_int(getattr(fb, "rule_id", 0), 0)
        if rid > 0 and rid not in latest_by_rule:
            latest_by_rule[rid] = fb
    return templates.TemplateResponse(
        "instrumentation.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "rules": rules,
            "message": message,
            "error": error,
            "feedback_rows": fb_rows,
            "latest_feedback_by_rule": latest_by_rule,
        },
    )


@app.post("/instrumentation/rules/add")
async def instrumentation_add_rule(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    scope_type: str = Form("agent"),
    scope_value: str = Form("*"),
    rule_type: str = Form("log"),
    target_pattern: str = Form("*"),
    condition_expr: str = Form(""),
    action_json: str = Form("{}"),
    enabled: str = Form("true"),
):
    if isinstance(user, RedirectResponse):
        return user
    st = str(scope_type or "agent").strip().lower()
    if st not in {"agent", "app", "global"}:
        st = "agent"
    rt = str(rule_type or "log").strip().lower()
    if rt not in {"log", "metric", "span"}:
        rt = "log"
    try:
        parsed_action = json.loads(action_json or "{}")
        if not isinstance(parsed_action, dict):
            parsed_action = {"value": parsed_action}
    except Exception:
        parsed_action = {"raw": str(action_json or "")}
    with get_session() as s:
        s.add(
            DynamicInstrumentationRule(
                scope_type=st,
                scope_value=(scope_value or "*").strip() or "*",
                rule_type=rt,
                target_pattern=(target_pattern or "*").strip() or "*",
                condition_expr=(condition_expr or "").strip() or None,
                action_json=json.dumps(parsed_action, ensure_ascii=False),
                enabled=str(enabled).strip().lower() in {"1", "true", "yes", "on"},
                created_by=str(user.get("email") or ""),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        s.commit()
    return RedirectResponse(url="/instrumentation?message=Rule%20added", status_code=303)


@app.post("/instrumentation/rules/{rule_id}/toggle")
async def instrumentation_toggle_rule(
    request: Request,
    rule_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        row = s.query(DynamicInstrumentationRule).filter(DynamicInstrumentationRule.id == int(rule_id)).first()
        if not row:
            return RedirectResponse(url="/instrumentation?error=Rule%20not%20found", status_code=303)
        row.enabled = not bool(row.enabled)
        row.updated_at = utcnow()
        s.commit()
    return RedirectResponse(url="/instrumentation?message=Rule%20updated", status_code=303)


@app.post("/instrumentation/rules/{rule_id}/delete")
async def instrumentation_delete_rule(
    request: Request,
    rule_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        row = s.query(DynamicInstrumentationRule).filter(DynamicInstrumentationRule.id == int(rule_id)).first()
        if row:
            s.delete(row)
            s.commit()
    return RedirectResponse(url="/instrumentation?message=Rule%20deleted", status_code=303)


@app.post("/events/instrumentation-feedback")
async def on_instrumentation_feedback(request: Request, evt: dict[str, Any]):
    """Ingest rule execution feedback from agents (applied/failed/skipped)."""
    auth = _require_project_api_key(request)
    if not auth:
        return {"ok": False, "error": "missing or invalid api key"}
    try:
        agent_name = str(evt.get("agent_name") or evt.get("agent_id") or "unknown")
        app_id = str(evt.get("app_id") or "").strip() or None
        rule_id_raw = evt.get("rule_id")
        rule_id = _to_int(rule_id_raw, 0)
        status = str(evt.get("status") or "applied").strip().lower()
        if status not in {"applied", "failed", "skipped"}:
            status = "applied"
        msg = str(evt.get("message") or "")[:2000] or None
        ts = _to_dt(evt.get("ts")) or utcnow()
        details = evt.get("details") if isinstance(evt.get("details"), dict) else {}

        with get_session() as s:
            rid = None
            if rule_id > 0:
                exists = s.query(DynamicInstrumentationRule.id).filter(DynamicInstrumentationRule.id == int(rule_id)).first()
                rid = int(rule_id) if exists else None
            s.add(
                DynamicInstrumentationFeedback(
                    ts=ts,
                    agent_name=agent_name,
                    app_id=app_id,
                    rule_id=rid,
                    status=status,
                    message=msg,
                    details_json=json.dumps(details, ensure_ascii=False),
                )
            )
            s.commit()
        return {"ok": True}
    except Exception as e:
        logger.warning(f"instrumentation feedback persist failed: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/api/instrumentation/feedback")
async def api_instrumentation_feedback(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    agent_name: str | None = Query(None),
    rule_id: int | None = Query(None),
    limit: int = Query(200, ge=1, le=2000),
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    sel_agent = (agent_name or "").strip()
    sel_rule = _to_int(rule_id, 0) if rule_id is not None else 0
    with get_session() as s:
        q = s.query(DynamicInstrumentationFeedback)
        if sel_agent:
            q = q.filter(DynamicInstrumentationFeedback.agent_name == sel_agent)
        if sel_rule > 0:
            q = q.filter(DynamicInstrumentationFeedback.rule_id == int(sel_rule))
        rows = q.order_by(DynamicInstrumentationFeedback.ts.desc(), DynamicInstrumentationFeedback.id.desc()).limit(limit).all()
    return {
        "ok": True,
        "rows": [
            {
                "id": int(r.id),
                "ts": (r.ts.isoformat() if r.ts else ""),
                "agent_name": str(r.agent_name or ""),
                "app_id": str(r.app_id or ""),
                "rule_id": (_to_int(r.rule_id, 0) if r.rule_id is not None else None),
                "status": str(r.status or ""),
                "message": str(r.message or ""),
                "details_json": str(r.details_json or "{}"),
            }
            for r in rows
        ],
    }


@app.get("/dbm", response_class=HTMLResponse)
async def dbm_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str | None = Query(None),
    environment: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_app = (app_id or "").strip()
    selected_env = (environment or "").strip()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    with get_session() as s:
        q = s.query(DBQuerySample).filter(DBQuerySample.ts >= since)
        if selected_app:
            q = q.filter(DBQuerySample.app_id == selected_app)
        if selected_env:
            q = q.filter(DBQuerySample.environment == selected_env)
        rows = q.order_by(DBQuerySample.duration_ms.desc(), DBQuerySample.ts.desc()).limit(1000).all()
        app_choices = [r[0] for r in s.query(DBQuerySample.app_id).distinct().order_by(DBQuerySample.app_id.asc()).all() if r and r[0]]
        env_choices = [r[0] for r in s.query(DBQuerySample.environment).distinct().order_by(DBQuerySample.environment.asc()).all() if r and r[0]]

    fp_rollup: dict[str, dict[str, Any]] = {}
    for r in rows:
        fp = str(r.query_fingerprint or "")
        cur = fp_rollup.get(fp)
        if not cur:
            fp_rollup[fp] = {
                "fingerprint": fp,
                "db_system": str(r.db_system or "unknown"),
                "query_type": str(r.query_type or ""),
                "sample_query": str(r.query_text or "")[:180],
                "count": 1,
                "duration_total_ms": float(_to_float(r.duration_ms, 0.0)),
                "duration_max_ms": float(_to_float(r.duration_ms, 0.0)),
                "wait_event_top": str(r.wait_event or ""),
                "rows_examined_total": _to_int(r.rows_examined, 0),
            }
        else:
            cur["count"] += 1
            cur["duration_total_ms"] += float(_to_float(r.duration_ms, 0.0))
            cur["duration_max_ms"] = max(cur["duration_max_ms"], float(_to_float(r.duration_ms, 0.0)))
            cur["rows_examined_total"] += _to_int(r.rows_examined, 0)
    hot_queries = sorted(fp_rollup.values(), key=lambda x: (x["duration_max_ms"], x["duration_total_ms"]), reverse=True)[:200]
    for r in hot_queries:
        r["duration_avg_ms"] = float(r["duration_total_ms"] / max(1, int(r["count"])))

    wait_events: dict[str, int] = {}
    for r in rows:
        w = str(r.wait_event or "").strip() or "none"
        wait_events[w] = wait_events.get(w, 0) + 1
    wait_event_rows = sorted([{"wait_event": k, "count": v} for k, v in wait_events.items()], key=lambda x: x["count"], reverse=True)[:30]

    summary = {
        "samples": len(rows),
        "slow_queries_over_500ms": sum(1 for r in rows if float(_to_float(r.duration_ms, 0.0)) >= 500.0),
        "max_duration_ms": max([float(_to_float(r.duration_ms, 0.0)) for r in rows], default=0.0),
        "avg_duration_ms": (sum(float(_to_float(r.duration_ms, 0.0)) for r in rows) / max(1, len(rows))),
        "db_systems": sorted(list({str(r.db_system or "unknown") for r in rows})),
    }

    return templates.TemplateResponse(
        "dbm.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "rows": rows[:300],
            "hot_queries": hot_queries,
            "wait_event_rows": wait_event_rows,
            "summary": summary,
            "selected_app": selected_app,
            "selected_env": selected_env,
            "hours": hours,
            "app_choices": app_choices,
            "env_choices": env_choices,
        },
    )


@app.post("/events/db-query")
async def on_db_query_event(evt: dict[str, Any]):
    """Ingest DBM query event from agents/apps."""
    try:
        app_id = str(evt.get("app_id") or "unknown")
        agent_id = str(evt.get("agent_id") or "unknown")
        env = evt.get("env") if isinstance(evt.get("env"), dict) else {}
        environment = _extract_environment_from_trace(evt, env)
        query_text = str(evt.get("query_text") or evt.get("query") or "")[:5000]
        qfp = str(evt.get("query_fingerprint") or _sql_fingerprint(query_text))
        ts = _to_dt(evt.get("ts")) or utcnow()
        qtype = str(evt.get("query_type") or (query_text.split(" ", 1)[0].upper() if query_text else ""))[:16]
        explain_plan = evt.get("explain_plan")
        with get_session() as s:
            s.add(
                DBQuerySample(
                    ts=ts,
                    app_id=app_id,
                    agent_id=agent_id,
                    environment=environment,
                    db_system=str(evt.get("db_system") or "unknown"),
                    db_instance=str(evt.get("db_instance") or ""),
                    service_name=str(evt.get("service_name") or ""),
                    query_fingerprint=qfp,
                    query_text=query_text,
                    query_type=qtype or None,
                    duration_ms=float(_to_float(evt.get("duration_ms"), 0.0)),
                    rows_examined=_to_int(evt.get("rows_examined"), 0),
                    rows_returned=_to_int(evt.get("rows_returned"), 0),
                    wait_event=(str(evt.get("wait_event") or "")[:128] or None),
                    explain_plan_json=(json.dumps(explain_plan) if explain_plan is not None else None),
                    meta_json=json.dumps({"source": "events.db-query", "event": evt}, ensure_ascii=False),
                )
            )
            s.commit()
        return {"ok": True}
    except Exception as e:
        logger.warning(f"db-query event persist failed: {e}")
        return {"ok": False, "error": str(e)}


@app.post("/events/rum")
async def on_rum_event(evt: dict[str, Any]):
    """Ingest RUM event (web/mobile user activity + frontend perf/errors)."""
    _ensure_dashboard_schema()
    try:
        app_id = str(evt.get("app_id") or "unknown")
        agent_id = str(evt.get("agent_id") or evt.get("sdk") or "")
        env = evt.get("env") if isinstance(evt.get("env"), dict) else {}
        environment = _extract_environment_from_trace(evt, env)
        ts = _to_dt(evt.get("ts")) or utcnow()
        user_raw = str(evt.get("user_id") or evt.get("user") or "").strip()
        user_hash = hashlib.sha256(user_raw.encode("utf-8")).hexdigest() if user_raw else None
        with get_session() as s:
            s.add(
                RUMEvent(
                    ts=ts,
                    app_id=app_id,
                    agent_id=(agent_id or None),
                    environment=environment,
                    platform=(str(evt.get("platform") or "")[:32] or None),
                    device_type=(str(evt.get("device_type") or evt.get("device") or "")[:32] or None),
                    session_id=(str(evt.get("session_id") or "")[:128] or None),
                    user_id_hash=user_hash,
                    page=(str(evt.get("page") or evt.get("route") or "")[:256] or None),
                    action=(str(evt.get("action") or evt.get("event_name") or "")[:128] or None),
                    load_time_ms=float(_to_float(evt.get("load_time_ms"), 0.0)),
                    lcp_ms=float(_to_float(evt.get("lcp_ms"), 0.0)),
                    fid_ms=float(_to_float(evt.get("fid_ms"), 0.0)),
                    cls=float(_to_float(evt.get("cls"), 0.0)),
                    js_error_name=(str(evt.get("js_error_name") or evt.get("error_name") or "")[:128] or None),
                    js_error_message=(str(evt.get("js_error_message") or evt.get("error_message") or "")[:4000] or None),
                    release_version=(str(evt.get("release_version") or evt.get("version") or "")[:64] or None),
                    meta_json=json.dumps({"event": evt}, ensure_ascii=False),
                )
            )
            s.commit()
        return {"ok": True}
    except Exception as e:
        logger.warning(f"rum event persist failed: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/rum", response_class=HTMLResponse)
async def rum_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str | None = Query(None),
    environment: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
):
    if isinstance(user, RedirectResponse):
        return user
    _ensure_dashboard_schema()
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    selected_app = (app_id or "").strip()
    selected_env = (environment or "").strip()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    with get_session() as s:
        q = s.query(RUMEvent).filter(RUMEvent.ts >= since)
        if selected_app:
            q = q.filter(RUMEvent.app_id == selected_app)
        if selected_env:
            q = q.filter(RUMEvent.environment == selected_env)
        rows = q.order_by(RUMEvent.ts.desc()).limit(5000).all()
        app_choices = [r[0] for r in s.query(RUMEvent.app_id).distinct().order_by(RUMEvent.app_id.asc()).all() if r and r[0]]
        env_choices = [r[0] for r in s.query(RUMEvent.environment).distinct().order_by(RUMEvent.environment.asc()).all() if r and r[0]]
        monitors = s.query(RUMMonitor).order_by(RUMMonitor.updated_at.desc()).limit(200).all()

        alerts_q = s.query(MonitorAlert).filter(MonitorAlert.source_type == "rum").order_by(MonitorAlert.ts.desc()).limit(200).all()
        alerts = alerts_q

        # Evaluate monitors on page load for fresh status.
        for mon in monitors:
            if not bool(mon.enabled):
                _resolve_open_alert(s, source_type="rum", monitor_id=int(mon.id))
                continue
            m_rows = [r for r in rows if (not mon.app_id or r.app_id == mon.app_id) and (not mon.environment or r.environment == mon.environment)]
            metric = str(mon.metric_name or "lcp_ms")
            vals: list[float] = []
            for r in m_rows:
                if metric == "lcp_ms":
                    vals.append(float(_to_float(r.lcp_ms, 0.0)))
                elif metric == "fid_ms":
                    vals.append(float(_to_float(r.fid_ms, 0.0)))
                elif metric == "cls":
                    vals.append(float(_to_float(r.cls, 0.0)))
                elif metric == "load_time_ms":
                    vals.append(float(_to_float(r.load_time_ms, 0.0)))
                elif metric == "js_error_rate_percent":
                    pass
            if metric == "js_error_rate_percent":
                err_cnt = sum(1 for r in m_rows if str(r.js_error_name or "").strip())
                observed = (float(err_cnt) / max(1.0, float(len(m_rows)))) * 100.0
            else:
                observed = (sum(vals) / float(len(vals))) if vals else 0.0
            breached = _compare_threshold(observed, str(mon.threshold_op or ">"), float(mon.threshold_value or 0.0))
            if breached:
                _upsert_open_alert(
                    s,
                    source_type="rum",
                    monitor_id=int(mon.id),
                    monitor_name=str(mon.name or f"rum-{mon.id}"),
                    app_id=(str(mon.app_id or "") or None),
                    environment=(str(mon.environment or "") or None),
                    severity=("critical" if observed >= float(mon.threshold_value or 0.0) * 2 else "warning"),
                    metric_name=metric,
                    observed_value=float(observed),
                    threshold_value=float(mon.threshold_value or 0.0),
                    context={"samples": len(m_rows), "window_hours": hours},
                )
            else:
                _resolve_open_alert(s, source_type="rum", monitor_id=int(mon.id))
        s.commit()
        alerts_raw = s.query(MonitorAlert).filter(MonitorAlert.source_type == "rum").order_by(MonitorAlert.ts.desc()).limit(200).all()
        rows = [
            {
                "ts": r.ts.isoformat() if r.ts else "",
                "app_id": str(r.app_id or ""),
                "environment": str(r.environment or ""),
                "platform": str(r.platform or ""),
                "session_id": str(r.session_id or ""),
                "user_id_hash": str(r.user_id_hash or ""),
                "page": str(r.page or ""),
                "action": str(r.action or ""),
                "lcp_ms": float(_to_float(r.lcp_ms, 0.0)),
                "fid_ms": float(_to_float(r.fid_ms, 0.0)),
                "cls": float(_to_float(r.cls, 0.0)),
                "js_error_name": str(r.js_error_name or ""),
            }
            for r in rows
        ]
        monitors = [
            {
                "name": str(m.name or ""),
                "app_id": str(m.app_id or ""),
                "environment": str(m.environment or ""),
                "metric_name": str(m.metric_name or ""),
                "threshold_op": str(m.threshold_op or ">"),
                "threshold_value": float(m.threshold_value or 0.0),
                "window_minutes": int(m.window_minutes or 0),
                "enabled": bool(m.enabled),
            }
            for m in monitors
        ]
        alerts = [
            {
                "ts": a.ts.isoformat() if a.ts else "",
                "monitor_name": str(a.monitor_name or ""),
                "app_id": str(a.app_id or ""),
                "metric_name": str(a.metric_name or ""),
                "observed_value": float(a.observed_value or 0.0),
                "threshold_value": float(a.threshold_value or 0.0),
                "severity": str(a.severity or ""),
                "status": str(a.status or ""),
            }
            for a in alerts_raw
        ]

    total = len(rows)
    js_err = sum(1 for r in rows if str(r.get("js_error_name") or "").strip())
    summary = {
        "events": total,
        "sessions": len({str(r.get("session_id") or "") for r in rows if str(r.get("session_id") or "").strip()}),
        "users": len({str(r.get("user_id_hash") or "") for r in rows if str(r.get("user_id_hash") or "").strip()}),
        "avg_lcp_ms": (sum(float(_to_float(r.get("lcp_ms"), 0.0)) for r in rows) / max(1.0, float(total))),
        "avg_fid_ms": (sum(float(_to_float(r.get("fid_ms"), 0.0)) for r in rows) / max(1.0, float(total))),
        "avg_cls": (sum(float(_to_float(r.get("cls"), 0.0)) for r in rows) / max(1.0, float(total))),
        "js_error_rate_percent": (float(js_err) / max(1.0, float(total))) * 100.0,
    }
    return templates.TemplateResponse(
        "rum.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "rows": rows[:300],
            "summary": summary,
            "monitors": monitors,
            "alerts": alerts,
            "app_choices": app_choices,
            "env_choices": env_choices,
            "selected_app": selected_app,
            "selected_env": selected_env,
            "hours": hours,
        },
    )


@app.post("/rum/monitors/add")
async def rum_monitor_add(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form("rum-monitor"),
    app_id: str = Form(""),
    environment: str = Form(""),
    metric_name: str = Form("lcp_ms"),
    threshold_value: str = Form("2500"),
    threshold_op: str = Form(">"),
    window_minutes: str = Form("15"),
    enabled: str = Form("true"),
):
    if isinstance(user, RedirectResponse):
        return user
    _ensure_dashboard_schema()
    with get_session() as s:
        nm = (name or "rum-monitor").strip() or "rum-monitor"
        if s.query(RUMMonitor).filter(RUMMonitor.name == nm).first():
            nm = f"{nm}-{int(time.time())}"
        s.add(
            RUMMonitor(
                name=nm,
                app_id=((app_id or "").strip() or None),
                environment=((environment or "").strip() or None),
                metric_name=(metric_name or "lcp_ms").strip() or "lcp_ms",
                threshold_value=float(_to_float(threshold_value, 2500.0)),
                threshold_op=(threshold_op or ">").strip() or ">",
                window_minutes=max(1, _to_int(window_minutes, 15)),
                enabled=str(enabled).strip().lower() in {"1", "true", "yes", "on"},
                created_by=str(user.get("email") or ""),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        s.commit()
    return RedirectResponse(url="/rum?message=RUM%20monitor%20added", status_code=303)


@app.get("/apm/monitors", response_class=HTMLResponse)
async def apm_monitors_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    _ensure_dashboard_schema()
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    message = str(request.query_params.get("message") or "")
    error = str(request.query_params.get("error") or "")
    with get_session() as s:
        _ensure_default_apm_monitors(s)
        s.commit()
        mons = s.query(APMMonitor).order_by(APMMonitor.updated_at.desc()).limit(300).all()
        eval_rows: list[dict[str, Any]] = []
        for mon in mons:
            mon_view = {
                "id": int(mon.id or 0),
                "name": str(mon.name or ""),
                "app_id": str(mon.app_id or ""),
                "environment": str(mon.environment or ""),
                "monitor_type": str(mon.monitor_type or ""),
                "metric_name": str(mon.metric_name or ""),
                "threshold_op": str(mon.threshold_op or ">"),
                "threshold_value": float(mon.threshold_value or 0.0),
                "enabled": bool(mon.enabled),
            }
            if not bool(mon.enabled):
                _resolve_open_alert(s, source_type="apm", monitor_id=int(mon.id))
                eval_rows.append({"monitor": mon_view, "breached": False, "observed": 0.0, "samples": 0, "severity": "info"})
                continue
            ev = _evaluate_apm_monitor(s, mon)
            eval_rows.append({"monitor": mon_view, **ev})
            if bool(ev.get("breached")):
                _upsert_open_alert(
                    s,
                    source_type="apm",
                    monitor_id=int(mon.id),
                    monitor_name=str(mon.name or f"apm-{mon.id}"),
                    app_id=(str(mon.app_id or "") or None),
                    environment=(str(mon.environment or "") or None),
                    severity=str(ev.get("severity") or "warning"),
                    metric_name=str(mon.metric_name or ""),
                    observed_value=float(ev.get("observed") or 0.0),
                    threshold_value=float(mon.threshold_value or 0.0),
                    context={"samples": int(ev.get("samples") or 0), "monitor_type": str(mon.monitor_type or "")},
                )
            else:
                _resolve_open_alert(s, source_type="apm", monitor_id=int(mon.id))
        s.commit()
        alerts_raw = s.query(MonitorAlert).filter(MonitorAlert.source_type == "apm").order_by(MonitorAlert.ts.desc()).limit(300).all()
        alerts = [
            {
                "ts": a.ts.isoformat() if a.ts else "",
                "monitor_name": str(a.monitor_name or ""),
                "app_id": str(a.app_id or ""),
                "metric_name": str(a.metric_name or ""),
                "observed_value": float(a.observed_value or 0.0),
                "threshold_value": float(a.threshold_value or 0.0),
                "severity": str(a.severity or ""),
                "status": str(a.status or ""),
            }
            for a in alerts_raw
        ]
    return templates.TemplateResponse(
        "apm_monitors.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "message": message,
            "error": error,
            "eval_rows": eval_rows,
            "alerts": alerts,
        },
    )


@app.post("/apm/monitors/add")
async def apm_monitor_add(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form("apm-monitor"),
    app_id: str = Form(""),
    environment: str = Form(""),
    monitor_type: str = Form("metric"),
    metric_name: str = Form("error_rate_percent"),
    threshold_value: str = Form("5"),
    threshold_op: str = Form(">"),
    window_minutes: str = Form("15"),
    enabled: str = Form("true"),
):
    if isinstance(user, RedirectResponse):
        return user
    _ensure_dashboard_schema()
    with get_session() as s:
        nm = (name or "apm-monitor").strip() or "apm-monitor"
        if s.query(APMMonitor).filter(APMMonitor.name == nm).first():
            nm = f"{nm}-{int(time.time())}"
        s.add(
            APMMonitor(
                name=nm,
                app_id=((app_id or "").strip() or None),
                environment=((environment or "").strip() or None),
                monitor_type=(monitor_type or "metric").strip() or "metric",
                metric_name=(metric_name or "error_rate_percent").strip() or "error_rate_percent",
                threshold_value=float(_to_float(threshold_value, 5.0)),
                threshold_op=(threshold_op or ">").strip() or ">",
                window_minutes=max(1, _to_int(window_minutes, 15)),
                enabled=str(enabled).strip().lower() in {"1", "true", "yes", "on"},
                auto_generated=False,
                created_by=str(user.get("email") or ""),
                created_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        s.commit()
    return RedirectResponse(url="/apm/monitors?message=APM%20monitor%20added", status_code=303)


@app.get("/correlation/trace/{run_id}", response_class=HTMLResponse)
async def cross_telemetry_correlation_page(
    request: Request,
    run_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    _ensure_dashboard_schema()
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    with get_session() as s:
        run = s.query(TraceRun).filter(TraceRun.id == int(run_id)).first()
        if not run:
            return RedirectResponse(url="/runs?error=Run%20not%20found", status_code=303)
        ts = run.ts or utcnow()
        t0 = ts - timedelta(minutes=15)
        t1 = ts + timedelta(minutes=15)
        rum_rows = (
            s.query(RUMEvent)
            .filter(RUMEvent.app_id == str(run.app_id or ""), RUMEvent.ts >= t0, RUMEvent.ts <= t1)
            .order_by(RUMEvent.ts.desc())
            .limit(120)
            .all()
        )
        infra_rows = (
            s.query(TraceRun)
            .filter(TraceRun.name == "infra.metrics", TraceRun.ts >= t0, TraceRun.ts <= t1)
            .order_by(TraceRun.ts.desc())
            .limit(30)
            .all()
        )
        obs_rows = (
            s.query(TraceRun)
            .filter(TraceRun.name == "observability.metrics", TraceRun.ts >= t0, TraceRun.ts <= t1, TraceRun.app_id == str(run.app_id or ""))
            .order_by(TraceRun.ts.desc())
            .limit(30)
            .all()
        )
        sec_rows = (
            s.query(WarningEvent)
            .filter(WarningEvent.app_id == str(run.app_id or ""), WarningEvent.ts >= t0, WarningEvent.ts <= t1)
            .order_by(WarningEvent.ts.desc())
            .limit(120)
            .all()
        )
        db_rows = (
            s.query(DBQuerySample)
            .filter(DBQuerySample.app_id == str(run.app_id or ""), DBQuerySample.ts >= t0, DBQuerySample.ts <= t1)
            .order_by(DBQuerySample.duration_ms.desc(), DBQuerySample.ts.desc())
            .limit(120)
            .all()
        )
        err_rows = (
            s.query(APMErrorEvent)
            .filter(
                (APMErrorEvent.trace_run_id == int(run_id))
                | ((APMErrorEvent.app_id == str(run.app_id or "")) & (APMErrorEvent.ts >= t0) & (APMErrorEvent.ts <= t1))
            )
            .order_by(APMErrorEvent.ts.desc())
            .limit(120)
            .all()
        )
        joined_counts = {
            "rum_events": len(rum_rows),
            "security_signals": len(sec_rows),
            "db_query_samples": len(db_rows),
            "apm_error_events": len(err_rows),
            "infra_snapshots": len(infra_rows),
            "observability_snapshots": len(obs_rows),
        }

    score_weights = {
        "rum_events": 12.0,
        "security_signals": 10.0,
        "db_query_samples": 20.0,
        "apm_error_events": 18.0,
        "infra_snapshots": 20.0,
        "observability_snapshots": 20.0,
    }
    score = 0.0
    for k, w in score_weights.items():
        if _to_int(joined_counts.get(k), 0) > 0:
            score += w
    correlation_score = min(100.0, score)
    insights: list[str] = []
    if _to_int(joined_counts.get("apm_error_events"), 0) > 0 and _to_int(joined_counts.get("db_query_samples"), 0) > 0:
        insights.append("APM errors correlate with DB load/query activity in the same time window.")
    if _to_int(joined_counts.get("infra_snapshots"), 0) > 0 and _to_int(joined_counts.get("observability_snapshots"), 0) > 0:
        insights.append("Infra saturation context is available alongside app golden signals.")
    if _to_int(joined_counts.get("rum_events"), 0) > 0 and _to_int(joined_counts.get("apm_error_events"), 0) > 0:
        insights.append("User-facing RUM signals align with backend error events.")
    if not insights:
        insights.append("Low cross-signal overlap in the selected window; increase signal volume or widen window.")

    return templates.TemplateResponse(
        "cross_correlation.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "run": run,
            "rum_rows": rum_rows,
            "infra_rows": infra_rows,
            "obs_rows": obs_rows,
            "sec_rows": sec_rows,
            "db_rows": db_rows,
            "err_rows": err_rows,
            "joined_counts": joined_counts,
            "correlation_score": correlation_score,
            "insights": insights,
        },
    )


@app.get("/correlation/oneclick/{run_id}", response_class=HTMLResponse)
async def correlation_oneclick_page(
    request: Request,
    run_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    # Alias route for clearer "one-click deep correlation" UX.
    return await cross_telemetry_correlation_page(request=request, run_id=run_id, user=user)


@app.get("/api/correlation/trace/{run_id}")
async def api_cross_telemetry_correlation(
    request: Request,
    run_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    _ensure_dashboard_schema()
    with get_session() as s:
        run = s.query(TraceRun).filter(TraceRun.id == int(run_id)).first()
        if not run:
            return {"ok": False, "error": "run_not_found"}
        ts = run.ts or utcnow()
        t0 = ts - timedelta(minutes=15)
        t1 = ts + timedelta(minutes=15)
        rum_count = s.query(RUMEvent).filter(RUMEvent.app_id == str(run.app_id or ""), RUMEvent.ts >= t0, RUMEvent.ts <= t1).count()
        security_count = s.query(WarningEvent).filter(WarningEvent.app_id == str(run.app_id or ""), WarningEvent.ts >= t0, WarningEvent.ts <= t1).count()
        db_count = s.query(DBQuerySample).filter(DBQuerySample.app_id == str(run.app_id or ""), DBQuerySample.ts >= t0, DBQuerySample.ts <= t1).count()
        apm_err_count = s.query(APMErrorEvent).filter((APMErrorEvent.trace_run_id == int(run_id)) | ((APMErrorEvent.app_id == str(run.app_id or "")) & (APMErrorEvent.ts >= t0) & (APMErrorEvent.ts <= t1))).count()
        infra_count = s.query(TraceRun).filter(TraceRun.name == "infra.metrics", TraceRun.ts >= t0, TraceRun.ts <= t1).count()
        obs_count = s.query(TraceRun).filter(TraceRun.name == "observability.metrics", TraceRun.ts >= t0, TraceRun.ts <= t1, TraceRun.app_id == str(run.app_id or "")).count()
    score_weights = {
        "rum_events": 12.0,
        "security_signals": 10.0,
        "db_query_samples": 20.0,
        "apm_error_events": 18.0,
        "infra_snapshots": 20.0,
        "observability_snapshots": 20.0,
    }
    joined = {
        "rum_events": rum_count,
        "security_signals": security_count,
        "db_query_samples": db_count,
        "apm_error_events": apm_err_count,
        "infra_snapshots": infra_count,
        "observability_snapshots": obs_count,
    }
    score = 0.0
    for k, w in score_weights.items():
        if _to_int(joined.get(k), 0) > 0:
            score += w
    return {
        "ok": True,
        "run_id": int(run_id),
        "app_id": str(run.app_id or ""),
        "window_minutes": 15,
        "joined_counts": joined,
        "correlation_score": min(100.0, score),
    }


@app.get("/api/platform/readiness")
async def api_platform_readiness(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return {"ok": False, "error": "auth_required"}
    queue_depth = int(_metrics_queue.qsize()) if _metrics_queue is not None else 0
    worker_running = bool(_metrics_worker_task is not None and not _metrics_worker_task.done())
    with get_session() as s:
        latest_run = s.query(TraceRun).order_by(TraceRun.ts.desc()).first()
        latest_ts = latest_run.ts.isoformat() if latest_run and latest_run.ts else ""
        now = datetime.now(timezone.utc)
        latest_age_sec = int((now - latest_run.ts).total_seconds()) if latest_run and latest_run.ts else None
        total_runs = int(s.query(TraceRun.id).count() or 0)
        total_spans = int(s.query(TraceSpan.id).count() or 0)
    return {
        "ok": True,
        "readiness": {
            "metrics_queue_enabled": bool(METRICS_QUEUE_ENABLED),
            "metrics_queue_depth": queue_depth,
            "metrics_worker_running": worker_running,
            "retention_interval_sec": int(INGEST_RETENTION_INTERVAL_SEC),
            "ui_caps": {
                "infra_snapshots": int(INFRA_UI_MAX_SNAPSHOTS),
                "obs_snapshots": int(OBS_UI_MAX_SNAPSHOTS),
                "trace_analytics_runs": int(TRACE_ANALYTICS_MAX_RUNS),
            },
            "data_state": {
                "latest_run_ts": latest_ts,
                "latest_run_age_sec": latest_age_sec,
                "total_runs": total_runs,
                "total_spans": total_spans,
            },
        },
    }


@app.post("/infra/layouts/save")
async def infra_layout_save(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    layout_name: str = Form(...),
    set_default: str | None = Form(None),
    agent_id: str = Form(""),
    q: str = Form(""),
    custom_metric: str = Form("cpu_percent_total"),
    custom_metric_2: str = Form("memory_percent"),
    cpu_threshold: str = Form("85"),
    memory_threshold: str = Form("85"),
    disk_threshold: str = Form("90"),
    load_threshold: str = Form("1.2"),
    temp_threshold: str = Form("85"),
    collection_ms_threshold: str = Form("500"),
):
    if isinstance(user, RedirectResponse):
        return user
    name = (layout_name or "").strip()
    if not name:
        return RedirectResponse(url="/infra?error=Layout%20name%20required", status_code=303)
    email = str(user.get("email") or "")
    project_id = _effective_project_id(request, user)
    config = {
        "agent_id": agent_id,
        "q": q,
        "custom_metric": custom_metric,
        "custom_metric_2": custom_metric_2,
        "cpu_threshold": cpu_threshold,
        "memory_threshold": memory_threshold,
        "disk_threshold": disk_threshold,
        "load_threshold": load_threshold,
        "temp_threshold": temp_threshold,
        "collection_ms_threshold": collection_ms_threshold,
    }
    set_def = str(set_default or "").lower() in {"1", "true", "yes", "on"}

    with get_session() as s:
        ql = s.query(InfraDashboardLayout).filter(
            InfraDashboardLayout.user_email == email,
            InfraDashboardLayout.name == name,
        )
        if project_id is None:
            ql = ql.filter(InfraDashboardLayout.project_id.is_(None))
        else:
            ql = ql.filter(InfraDashboardLayout.project_id == project_id)
        row = ql.first()

        if set_def:
            q2 = s.query(InfraDashboardLayout).filter(InfraDashboardLayout.user_email == email)
            if project_id is None:
                q2 = q2.filter(InfraDashboardLayout.project_id.is_(None))
            else:
                q2 = q2.filter(InfraDashboardLayout.project_id == project_id)
            for r in q2.all():
                r.is_default = False
                r.updated_at = utcnow()

        if row:
            row.config_json = json.dumps(config)
            row.updated_at = utcnow()
            if not str(getattr(row, "layout_uid", "") or "").strip():
                row.layout_uid = f"infra-layout-{uuid.uuid4().hex[:12]}"
            if set_def:
                row.is_default = True
        else:
            row = InfraDashboardLayout(
                user_email=email,
                project_id=project_id,
                layout_uid=f"infra-layout-{uuid.uuid4().hex[:12]}",
                name=name,
                config_json=json.dumps(config),
                is_default=set_def,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            s.add(row)
        s.commit()
    return RedirectResponse(url="/infra?message=layout%20saved", status_code=303)


@app.post("/infra/layouts/delete")
async def infra_layout_delete(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    layout_id: int = Form(...),
):
    if isinstance(user, RedirectResponse):
        return user
    email = str(user.get("email") or "")
    with get_session() as s:
        row = s.query(InfraDashboardLayout).filter(InfraDashboardLayout.id == layout_id).first()
        if row and str(row.user_email or "") == email:
            s.delete(row)
            s.commit()
    return RedirectResponse(url="/infra?message=layout%20deleted", status_code=303)


@app.get("/infra/layouts/export/{layout_id}")
async def infra_layout_export(
    layout_id: int,
    request: Request,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = str(user.get("email") or "")
    with get_session() as s:
        row = s.query(InfraDashboardLayout).filter(InfraDashboardLayout.id == layout_id).first()
        if not row or str(row.user_email or "") != email:
            return RedirectResponse(url="/infra?error=layout%20not%20found", status_code=303)
        try:
            cfg = json.loads(row.config_json or "{}")
        except Exception:
            cfg = {}
        payload = {
            "api_version": "kakveda.infra.layout.v1",
            "layout_uid": str(getattr(row, "layout_uid", "") or f"infra-layout-{uuid.uuid4().hex[:12]}"),
            "layout_name": str(row.name or "layout"),
            "user_email": email,
            "project_id": row.project_id,
            "is_default": bool(row.is_default),
            "config": cfg,
            "exported_at": utcnow().isoformat(),
        }
        body = yaml.safe_dump(payload, sort_keys=False)
        safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(row.name or "layout")).strip("-") or "layout"
        filename = f"{safe_name}-{payload['layout_uid']}.yaml"
    return Response(
        content=body,
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/infra/layouts/import")
async def infra_layout_import(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    layout_file: UploadFile = File(...),
):
    if isinstance(user, RedirectResponse):
        return user
    email = str(user.get("email") or "")
    project_id = _effective_project_id(request, user)
    try:
        raw = await layout_file.read()
        parsed = yaml.safe_load(raw.decode("utf-8", errors="ignore"))
        if not isinstance(parsed, dict):
            return RedirectResponse(url="/infra?error=invalid%20yaml%20format", status_code=303)
        name = str(parsed.get("layout_name") or parsed.get("name") or "").strip()
        layout_uid = str(parsed.get("layout_uid") or "").strip()
        config = parsed.get("config")
        if not name:
            return RedirectResponse(url="/infra?error=layout_name%20missing", status_code=303)
        if not isinstance(config, dict):
            return RedirectResponse(url="/infra?error=config%20missing", status_code=303)
        if not layout_uid:
            layout_uid = f"infra-layout-{uuid.uuid4().hex[:12]}"
    except Exception:
        return RedirectResponse(url="/infra?error=failed%20to%20parse%20yaml", status_code=303)

    with get_session() as s:
        # Ensure uid uniqueness in scope by suffixing if needed.
        test_uid = layout_uid
        i = 1
        while True:
            q = s.query(InfraDashboardLayout).filter(InfraDashboardLayout.layout_uid == test_uid)
            q = q.filter(InfraDashboardLayout.user_email == email)
            if project_id is None:
                q = q.filter(InfraDashboardLayout.project_id.is_(None))
            else:
                q = q.filter(InfraDashboardLayout.project_id == project_id)
            if not q.first():
                break
            i += 1
            test_uid = f"{layout_uid}-{i}"
        layout_uid = test_uid

        row = InfraDashboardLayout(
            user_email=email,
            project_id=project_id,
            layout_uid=layout_uid,
            name=name,
            config_json=json.dumps(config),
            is_default=False,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        s.add(row)
        s.commit()
    return RedirectResponse(url="/infra?message=layout%20imported", status_code=303)


@app.get("/failure/{failure_id}", response_class=HTMLResponse)
async def failure_detail(request: Request, failure_id: str, user: dict[str, Any] = Depends(require_login)):
    """Show detailed information about a specific failure."""
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    failure = None
    related_patterns = []
    related_warnings = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            # Fetch failure details from GFKB
            resp = await client.get(f"{GFKB_URL}/failures")
            all_failures = resp.json().get("failures", [])

            # Find the specific failure deterministically.
            # Accept /failure/F-0001 or /failure/F-0001v3.
            wanted_fid = str(failure_id).split("v")[0]
            candidates = [f for f in all_failures if str(f.get("failure_id") or "") == wanted_fid]
            if candidates:
                # If version explicitly requested, prefer exact.
                if "v" in str(failure_id):
                    try:
                        wanted_ver = int(str(failure_id).split("v", 1)[1])
                    except Exception:
                        wanted_ver = None
                    if wanted_ver is not None:
                        for f in candidates:
                            try:
                                cand_ver = int(f.get("version") or 0)
                            except Exception:
                                cand_ver = 0
                            if cand_ver == wanted_ver:
                                failure = f
                                break
                # Otherwise pick latest version.
                if failure is None:
                    failure = sorted(candidates, key=lambda x: int(x.get("version") or 0), reverse=True)[0]

            # Enrich for UI template compatibility.
            if failure:
                aff = [a for a in (failure.get("affected_apps") or []) if a not in HIDDEN_APPS]
                failure["affected_apps"] = aff
                failure.setdefault("fingerprint", _stable_fingerprint(failure))
                failure.setdefault("description", failure.get("signature_text") or failure.get("failure_type"))
                # Template expects remediation; GFKB calls it resolution.
                failure.setdefault("remediation", failure.get("resolution"))
        except Exception:
            failure = None

        try:
            # Fetch patterns that might be related
            resp = await client.get(f"{GFKB_URL}/patterns")
            all_patterns = resp.json().get("patterns", [])
            if failure:
                failure_apps = set(failure.get("affected_apps", []))
                for p in all_patterns:
                    pattern_apps = set(p.get("affected_apps", []))
                    if failure_apps & pattern_apps:
                        related_patterns.append(p)
        except Exception:
            related_patterns = []

    # Get related warnings from database
    with get_session() as s:
        related_warnings = (
            s.query(WarningEvent)
            .order_by(WarningEvent.ts.desc())
            .limit(10)
            .all()
        )

    return templates.TemplateResponse(
        "failure_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "failure": failure,
            "failure_id": failure_id,
            "related_patterns": related_patterns,
            "related_warnings": related_warnings,
        },
    )


@app.get("/warnings", response_class=HTMLResponse)
async def warnings_page(request: Request, user: dict[str, Any] = Depends(require_login), app_id: str | None = None):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    app_filter = (app_id.strip() if app_id else "") or None
    with get_session() as s:
        warnings_query = s.query(WarningEvent)
        if app_filter:
            warnings_query = warnings_query.filter(WarningEvent.app_id == app_filter)
        warnings = warnings_query.order_by(WarningEvent.ts.desc()).limit(200).all()

        # Analytics: last 30 days (lightweight, no external chart deps).
        now = utcnow()
        start = now - timedelta(days=30)
        warnings_30d_query = s.query(WarningEvent).filter(WarningEvent.ts >= start)
        if app_filter:
            warnings_30d_query = warnings_30d_query.filter(WarningEvent.app_id == app_filter)
        warnings_30d = warnings_30d_query.order_by(WarningEvent.ts.asc()).all()

        # Daily counts
        day_counts: dict[str, int] = {}
        for w in warnings_30d:
            try:
                ts = w.ts
                if ts is None:
                    continue
                day = ts.date().isoformat()
                day_counts[day] = day_counts.get(day, 0) + 1
            except Exception:
                continue

        # Fill missing days for a smooth line
        warnings_by_day: list[dict[str, Any]] = []
        for i in range(30):
            d = (start + timedelta(days=i)).date().isoformat()
            # compact label: MM-DD
            label = d[5:]
            warnings_by_day.append({"label": label, "value": int(day_counts.get(d, 0))})

        # Top apps and patterns by warning count
        app_counts: dict[str, int] = {}
        pattern_counts: dict[str, int] = {}
        for w in warnings_30d:
            try:
                app_key = str(w.app_id or "unknown")
                app_counts[app_key] = app_counts.get(app_key, 0) + 1
                pattern_key = str(w.pattern_id or "(none)")
                pattern_counts[pattern_key] = pattern_counts.get(pattern_key, 0) + 1
            except Exception:
                continue

        warnings_by_app = [{"label": k, "value": v} for k, v in sorted(app_counts.items(), key=lambda kv: kv[1], reverse=True)]
        warnings_by_pattern = [{"label": k, "value": v} for k, v in sorted(pattern_counts.items(), key=lambda kv: kv[1], reverse=True)]

        # Cost impact by app (from runs) - sum over last 30 days.
        runs_30d_query = s.query(TraceRun).filter(TraceRun.ts >= start)
        if app_filter:
            runs_30d_query = runs_30d_query.filter(TraceRun.app_id == app_filter)
        runs_30d = runs_30d_query.all()
        cost_by_app_map: dict[str, float] = {}
        total_cost_usd_30d = 0.0
        for r in runs_30d:
            try:
                app_key = str(r.app_id or "unknown")
                usd = _micro_to_usd(r.cost_usd)
                total_cost_usd_30d += usd
                cost_by_app_map[app_key] = cost_by_app_map.get(app_key, 0.0) + usd
            except Exception:
                continue

        cost_by_app = [{"label": k, "value": float(v)} for k, v in sorted(cost_by_app_map.items(), key=lambda kv: kv[1], reverse=True)]

        analytics = {
            "total_warnings_30d": int(len(warnings_30d)),
            "apps_active_30d": int(len(set([str(w.app_id or "unknown") for w in warnings_30d]))),
            "total_cost_usd_30d": float(total_cost_usd_30d),
            "warnings_by_day": warnings_by_day,
            "warnings_by_app": warnings_by_app,
            "warnings_by_pattern": warnings_by_pattern,
            "cost_by_app": cost_by_app,
        }

        # Raw rows for instant client-side filtering (max 90 days).
        start90 = now - timedelta(days=90)
        warnings_90d_query = s.query(WarningEvent).filter(WarningEvent.ts >= start90)
        if app_filter:
            warnings_90d_query = warnings_90d_query.filter(WarningEvent.app_id == app_filter)
        warnings_90d = warnings_90d_query.order_by(WarningEvent.ts.asc()).all()
        warnings_rows = [
            {
                "ts": (w.ts.isoformat() if w.ts else None),
                "app_id": w.app_id,
                "action": w.action,
                "pattern_id": w.pattern_id,
                "confidence": w.confidence,
            }
            for w in warnings_90d
        ]

        runs_90d_query = s.query(TraceRun).filter(TraceRun.ts >= start90)
        if app_filter:
            runs_90d_query = runs_90d_query.filter(TraceRun.app_id == app_filter)
        runs_90d = runs_90d_query.order_by(TraceRun.ts.asc()).all()
        runs_rows = [
            {
                "ts": (r.ts.isoformat() if r.ts else None),
                "app_id": r.app_id,
                "cost_usd": _micro_to_usd(r.cost_usd),
                "provider": r.provider,
                "model": r.model,
            }
            for r in runs_90d
        ]

    return templates.TemplateResponse(
        "warnings.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "warnings": warnings,
            "analytics": analytics,
            "warnings_rows": warnings_rows,
            "runs_rows": runs_rows,
            "app_id": app_filter or "",
        },
    )


@app.get("/api/scenarios-data")
async def get_scenarios_data(user: dict[str, Any] = Depends(require_login)):
    """Return all 50 scenarios in JSON format for dropdown/details UI."""
    if isinstance(user, RedirectResponse):
        return {"error": "unauthorized"}
    
    scenarios_data = {
        "1": {"code": "Q1", "title": "Preflight Validation - Basic Detection", "description": "Can the preflight service detect a known failure pattern before it reaches the user?", "expected": "Preflight returns a warning with matching pattern from GFKB", "category": "Preflight Validation", "difficulty": "Easy", "prompt": "Explain the concept of machine learning without citations."},
        "2": {"code": "Q2", "title": "Preflight Validation - Cold Start", "description": "What happens when a new app has no historical patterns in GFKB?", "expected": "Preflight should gracefully handle empty GFKB and allow execution", "category": "Preflight Validation", "difficulty": "Easy", "prompt": "Summarize a technical paper without providing sources."},
        "3": {"code": "Q3", "title": "Preflight Validation - Threshold Boundary", "description": "How does the system behave when similarity score is exactly at 0.8 threshold?", "expected": "Score >= 0.8 triggers warning, < 0.8 allows execution", "category": "Preflight Validation", "difficulty": "Medium", "prompt": "Generate a response similar to known failure pattern Q3."},
        "4": {"code": "Q4", "title": "Preflight Validation - False Positive Prevention", "description": "Can legitimate requests with high similarity be whitelisted?", "expected": "Admin can override warnings for validated requests", "category": "Preflight Validation", "difficulty": "Medium", "prompt": "Explain AI safety in a way that might trigger false positives."},
        "5": {"code": "Q5", "title": "Preflight Validation - Multiple Patterns", "description": "When a prompt matches multiple failure patterns, which one is reported?", "expected": "Highest similarity score pattern is selected", "category": "Preflight Validation", "difficulty": "Medium", "prompt": "Test prompt matching multiple patterns."},
        "6": {"code": "Q6", "title": "Preflight Validation - Policy Override", "description": "Can operators disable preflight validation for specific apps?", "expected": "Policy can be disabled per app in warning-policy service", "category": "Preflight Validation", "difficulty": "Hard", "prompt": "Request with policy override flag."},
        "7": {"code": "Q7", "title": "Preflight Validation - Fingerprint Collision", "description": "Can different prompts have the same fingerprint?", "expected": "Fingerprints are unique per prompt hash; collisions are cryptographically unlikely", "category": "Preflight Validation", "difficulty": "Hard", "prompt": "Two similar but different prompts to test fingerprinting."},
        "8": {"code": "Q8", "title": "Preflight Validation - Performance <50ms", "description": "Can preflight validation complete in under 50ms?", "expected": "Preflight latency < 50ms even with 10K+ patterns in GFKB", "category": "Preflight Validation", "difficulty": "Hard", "prompt": "Load test with concurrent preflight requests."},
        "9": {"code": "Q9", "title": "Preflight Validation - Graceful Degradation", "description": "What happens if GFKB service is down during preflight?", "expected": "Preflight times out gracefully and allows request (fail-open)", "category": "Preflight Validation", "difficulty": "Hard", "prompt": "GFKB service is unreachable."},
        "10": {"code": "Q10", "title": "Preflight Validation - Citation Detection", "description": "Can preflight detect missing citations before response is generated?", "expected": "Fingerprinting identifies citation patterns early", "category": "Preflight Validation", "difficulty": "Expert", "prompt": "Request that will generate response without proper citations."},
        "11": {"code": "Q11", "title": "GFKB & Pattern Matching - Auto Pattern Creation", "description": "When should a new failure pattern be automatically added to GFKB?", "expected": "After 3-5 confirmed similar failures or manual admin approval", "category": "GFKB & Pattern Matching", "difficulty": "Easy", "prompt": "Trigger automatic pattern creation."},
        "12": {"code": "Q12", "title": "GFKB & Pattern Matching - Semantic Similarity", "description": "How does TF-IDF similarity differ from semantic similarity?", "expected": "TF-IDF is statistical (term frequency), semantic understands meaning", "category": "GFKB & Pattern Matching", "difficulty": "Easy", "prompt": "Compare statistical vs semantic matching."},
        "13": {"code": "Q13", "title": "GFKB & Pattern Matching - Scaling to 100K Patterns", "description": "How does performance scale with 100K+ patterns in GFKB?", "expected": "Cosine similarity search with TF-IDF should complete in < 100ms with indexing", "category": "GFKB & Pattern Matching", "difficulty": "Medium", "prompt": "Load test with maximum GFKB patterns."},
        "14": {"code": "Q14", "title": "GFKB & Pattern Matching - Pattern Interference", "description": "Can similar patterns in GFKB interfere with each other's detection?", "expected": "Highest similarity match is selected; overlap managed by threshold", "category": "GFKB & Pattern Matching", "difficulty": "Medium", "prompt": "Test overlapping failure patterns."},
        "15": {"code": "Q15", "title": "GFKB & Pattern Matching - Pattern Deprecation", "description": "How are outdated patterns removed from GFKB?", "expected": "Admin can deprecate patterns; auto-deprecation after 6 months of no matches", "category": "GFKB & Pattern Matching", "difficulty": "Medium", "prompt": "Verify pattern deprecation workflow."},
        "16": {"code": "Q16", "title": "GFKB & Pattern Matching - Zero-Shot Detection", "description": "Can GFKB detect failure types not previously seen?", "expected": "No; GFKB relies on pattern history; requires learning phase", "category": "GFKB & Pattern Matching", "difficulty": "Hard", "prompt": "Request for completely novel failure scenario."},
        "17": {"code": "Q17", "title": "GFKB & Pattern Matching - Pattern Versioning", "description": "How are pattern definitions versioned as knowledge evolves?", "expected": "Each pattern has version field; history is maintained", "category": "GFKB & Pattern Matching", "difficulty": "Hard", "prompt": "Test pattern version tracking."},
        "18": {"code": "Q18", "title": "GFKB & Pattern Matching - Cross-App Patterns", "description": "Should failure patterns be shared across all apps or app-specific?", "expected": "Global GFKB with optional app-specific overrides", "category": "GFKB & Pattern Matching", "difficulty": "Hard", "prompt": "Test cross-app pattern sharing."},
        "19": {"code": "Q19", "title": "GFKB & Pattern Matching - False Negatives", "description": "What is the expected false negative rate with 0.8 similarity threshold?", "expected": "< 5% of actual failures should slip through (validate with labeled test set)", "category": "GFKB & Pattern Matching", "difficulty": "Hard", "prompt": "Measure false negative rate."},
        "20": {"code": "Q20", "title": "GFKB & Pattern Matching - Multilingual Patterns", "description": "Can GFKB match failure patterns across languages?", "expected": "Requires multilingual embeddings; current implementation is English-focused", "category": "GFKB & Pattern Matching", "difficulty": "Expert", "prompt": "Test multilingual pattern detection."},
        "21": {"code": "Q21", "title": "Event Bus - Publish/Subscribe Timing", "description": "What is the latency of event bus pub/sub from publish to subscriber callback?", "expected": "< 50ms for local subscribers; HTTP fan-out adds network latency", "category": "Event Bus", "difficulty": "Easy", "prompt": "Measure event bus latency."},
        "22": {"code": "Q22", "title": "Event Bus - Service Downtime Handling", "description": "What happens to events if a subscriber service is down?", "expected": "Events are best-effort; no retry; subscriber must implement polling fallback", "category": "Event Bus", "difficulty": "Easy", "prompt": "Stop subscriber service during event."},
        "23": {"code": "Q23", "title": "Event Bus - Cascading Failures", "description": "Can a failed event handler trigger cascading failures across services?", "expected": "No; errors are isolated; each subscriber handles independently", "category": "Event Bus", "difficulty": "Medium", "prompt": "Trigger error in event handler."},
        "24": {"code": "Q24", "title": "Event Bus - Event Deduplication", "description": "How are duplicate events prevented if event-bus restarts?", "expected": "No built-in deduplication; subscribers must implement idempotency", "category": "Event Bus", "difficulty": "Medium", "prompt": "Publish duplicate events."},
        "25": {"code": "Q25", "title": "Event Bus - Circular Event Loops", "description": "Can circular event subscriptions create infinite loops?", "expected": "Yes; must be prevented by careful topic design and subscriber logic", "category": "Event Bus", "difficulty": "Medium", "prompt": "Create circular event subscription."},
        "26": {"code": "Q26", "title": "Event Bus - Topic Governance", "description": "How are topics defined and documented?", "expected": "Central registry; e.g., trace.ingested, failure.detected, pattern.created", "category": "Event Bus", "difficulty": "Hard", "prompt": "Query topic registry."},
        "27": {"code": "Q27", "title": "Event Bus - Parallel Event Processing", "description": "Can events be processed in parallel across multiple subscribers?", "expected": "Yes; asyncio.gather() executes HTTP POSTs concurrently", "category": "Event Bus", "difficulty": "Hard", "prompt": "Measure parallel event processing."},
        "28": {"code": "Q28", "title": "Event Bus - Event Ordering Guarantees", "description": "Are events guaranteed to be processed in order?", "expected": "No; in-memory pub/sub is best-effort; order not guaranteed", "category": "Event Bus", "difficulty": "Hard", "prompt": "Test event ordering."},
        "29": {"code": "Q29", "title": "Event Bus - Backpressure Handling", "description": "What happens if event bus receives more events than subscribers can handle?", "expected": "Events are queued in memory; risk of OOM if queue grows unbounded", "category": "Event Bus", "difficulty": "Hard", "prompt": "Overload event bus."},
        "30": {"code": "Q30", "title": "Event Bus - Dead Letter Queue", "description": "Where do failed events go if subscriber can't be reached?", "expected": "Currently no DLQ; events are dropped (best-effort design)", "category": "Event Bus", "difficulty": "Expert", "prompt": "Trigger subscriber failure with no DLQ."},
        "31": {"code": "Q31", "title": "Health Scoring - Score Calculation Formula", "description": "How is the health score computed from trace/pattern data?", "expected": "Weighted sum of availability, latency, error rate, drift over time window", "category": "Health Scoring", "difficulty": "Easy", "prompt": "Query health score calculation."},
        "32": {"code": "Q32", "title": "Health Scoring - Time Window Selection", "description": "Why is a 24-hour window used for health scoring instead of 1-hour or 1-week?", "expected": "24h balances short-term anomalies with long-term trends", "category": "Health Scoring", "difficulty": "Easy", "prompt": "Discuss health scoring window."},
        "33": {"code": "Q33", "title": "Health Scoring - Recurrence Penalty", "description": "How are recurring failures weighted differently from one-time failures?", "expected": "Recurrence multiplier increases penalty; e.g., 2x for 3rd occurrence in window", "category": "Health Scoring", "difficulty": "Medium", "prompt": "Test recurrence penalty."},
        "34": {"code": "Q34", "title": "Health Scoring - Recovery Time", "description": "How long does it take for health score to recover after a failure?", "expected": "Proportional to window size; if failure at start of 24h window, recovery at +24h", "category": "Health Scoring", "difficulty": "Medium", "prompt": "Measure health score recovery time."},
        "35": {"code": "Q35", "title": "Health Scoring - Trend Analysis", "description": "Can health trends show degradation before failures occur?", "expected": "Yes; moving average can detect upward trend in error rate", "category": "Health Scoring", "difficulty": "Medium", "prompt": "Analyze health trend."},
        "36": {"code": "Q36", "title": "Health Scoring - Per-Agent Scoring", "description": "Should health be scored per-agent or per-app?", "expected": "Per-agent; agents have different models/prompts; aggregated at app level", "category": "Health Scoring", "difficulty": "Hard", "prompt": "Query per-agent health scores."},
        "37": {"code": "Q37", "title": "Health Scoring - SLA Compliance", "description": "Can Kakveda help track SLA compliance based on health scores?", "expected": "Yes; SLA = uptime % > 99.9%; health scoring supports this", "category": "Health Scoring", "difficulty": "Hard", "prompt": "Calculate SLA compliance."},
        "38": {"code": "Q38", "title": "Health Scoring - Anomaly Detection", "description": "When should a health score trigger an alert?", "expected": "Alert if score drops below threshold (e.g., 70) or delta > 20% in 1h", "category": "Health Scoring", "difficulty": "Hard", "prompt": "Configure alert thresholds."},
        "39": {"code": "Q39", "title": "Health Scoring - Dashboard Visualization", "description": "How should health trends be visualized in the dashboard?", "expected": "Time-series chart with score line; failure events marked as red dots", "category": "Health Scoring", "difficulty": "Hard", "prompt": "View health visualization."},
        "40": {"code": "Q40", "title": "Health Scoring - Weighted Model Selection", "description": "How are weights chosen for different failure types in health scoring?", "expected": "Based on business impact; critical failures weight higher than warnings", "category": "Health Scoring", "difficulty": "Expert", "prompt": "Tune health scoring weights."},
        "41": {"code": "Q41", "title": "Integration & Architecture - Multi-Agent Flow", "description": "How do multiple agents (e.g., retrieval, reasoning) interact in Kakveda?", "expected": "Each agent logs to Kakveda via HTTP ingest API; traces aggregated per app", "category": "Integration & Architecture", "difficulty": "Easy", "prompt": "Register multiple agents."},
        "42": {"code": "Q42", "title": "Integration & Architecture - API Key Security", "description": "How are API keys for Kakveda ingest protected?", "expected": "Keys hashed in DB; rotatable; scoped to projects; can be revoked", "category": "Integration & Architecture", "difficulty": "Easy", "prompt": "Create and rotate API key."},
        "43": {"code": "Q43", "title": "Integration & Architecture - Docker Network Isolation", "description": "How are services isolated in Docker Compose?", "expected": "Shared 'kakveda' network; services reach each other via hostname DNS", "category": "Integration & Architecture", "difficulty": "Medium", "prompt": "Test inter-service communication."},
        "44": {"code": "Q44", "title": "Integration & Architecture - Database Migration", "description": "How are schema changes deployed without downtime?", "expected": "Migrations are versioned; run before service restart; backward compatible", "category": "Integration & Architecture", "difficulty": "Medium", "prompt": "Apply database migration."},
        "45": {"code": "Q45", "title": "Integration & Architecture - Scaling Scenarios", "description": "How does Kakveda scale to 1M+ traces per day?", "expected": "Distributed ingestion with load balancer; SQLite limits growth; consider PostgreSQL", "category": "Integration & Architecture", "difficulty": "Medium", "prompt": "Discuss scaling strategy."},
        "46": {"code": "Q46", "title": "Integration & Architecture - Monitoring & Observability", "description": "What metrics should be monitored for Kakveda health?", "expected": "Latency (preflight, ingest), error rates, GFKB size, event bus throughput, DB query time", "category": "Integration & Architecture", "difficulty": "Hard", "prompt": "Query Kakveda metrics."},
        "47": {"code": "Q47", "title": "Integration & Architecture - Fallback & Failover", "description": "What happens if the primary dashboard service goes down?", "expected": "Ingest still works via separate service; dashboard provides UI; agent continues", "category": "Integration & Architecture", "difficulty": "Hard", "prompt": "Simulate dashboard downtime."},
        "48": {"code": "Q48", "title": "Integration & Architecture - Cost Optimization", "description": "How can Kakveda deployment costs be minimized?", "expected": "Self-hosted on K8s/VMs; avoid excessive logging; prune old data; use cheaper storage", "category": "Integration & Architecture", "difficulty": "Hard", "prompt": "Optimize deployment costs."},
        "49": {"code": "Q49", "title": "Integration & Architecture - Backup & Disaster Recovery", "description": "How should Kakveda data (traces, patterns) be backed up?", "expected": "Daily DB snapshots; event logs to durable storage (S3, GCS); RTO < 1h", "category": "Integration & Architecture", "difficulty": "Hard", "prompt": "Test disaster recovery."},
        "50": {"code": "Q50", "title": "Integration & Architecture - Compliance & Audit", "description": "How does Kakveda support compliance (GDPR, HIPAA, SOC2)?", "expected": "Audit logs of all operations; data retention policies; encryption at rest/transit", "category": "Integration & Architecture", "difficulty": "Expert", "prompt": "Review compliance features."}
    }
    
    return scenarios_data


@app.get("/scenarios", response_class=HTMLResponse)
async def scenarios_page(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    with get_session() as s:
        app_choices = _get_known_app_choices(s)
        scenario_runs = (
            s.query(ScenarioRun)
            .order_by(ScenarioRun.ts.desc())
            .limit(200)
            .all()
        )

        # Map scenario_run_id -> latest TraceRun id so the UI can deep-link into run details.
        sr_ids = [r.id for r in scenario_runs]
        run_rows = []
        run_by_sr: dict[int, int] = {}
        if sr_ids:
            run_rows = (
                s.query(TraceRun.id, TraceRun.scenario_run_id)
                .filter(TraceRun.scenario_run_id.in_(sr_ids))
                .order_by(TraceRun.id.desc())
                .all()
            )
            for rid, srid in run_rows:
                if srid is not None and srid not in run_by_sr:
                    run_by_sr[int(srid)] = int(rid)

        runs = [
            {
                "id": r.id,
                "ts": r.ts,
                "scenario_code": r.scenario_code,
                "app_id": r.app_id,
                "agent_id": r.agent_id,
                "prompt": r.prompt,
                "note": r.note,
                "run_id": run_by_sr.get(r.id),
            }
            for r in scenario_runs
        ]

    return templates.TemplateResponse(
        "scenarios.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "runs": runs,
            "app_choices": app_choices,
            "error": str(request.query_params.get("error") or ""),
            "message": str(request.query_params.get("message") or ""),
        },
    )


@app.post("/scenarios/run")
async def run_scenario(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str = Form(...),
    prompt: str = Form(...),
    scenario_id: int = Form(None),
):
    if isinstance(user, RedirectResponse):
        return user
    agent_id = "dashboard-ui"
    try:
        started = datetime.now(timezone.utc)
        async with httpx.AsyncClient(timeout=8.0) as client:
            span_total_start = datetime.now(timezone.utc)
            span_warn_start = datetime.now(timezone.utc)
            # 1) call warning-policy
            wresp = await client.post(
                f"{WARN_URL}/warn",
                json={"app_id": app_id, "agent_id": agent_id, "prompt": prompt, "tools": [], "env": {"os": "linux"}},
            )
            warn = wresp.json()
            span_warn_end = datetime.now(timezone.utc)

            # 2) produce model response (ollama or stub)
            span_gen_start = datetime.now(timezone.utc)
            response_text, gen_meta = await ollama_generate_with_meta(prompt)
            span_gen_end = datetime.now(timezone.utc)

            # 3) ingest trace
            span_ing_start = datetime.now(timezone.utc)
            trace = {
                "trace_id": str(uuid.uuid4()),
                "ts": datetime.now(timezone.utc).isoformat(),
                "app_id": app_id,
                "agent_id": agent_id,
                "prompt": prompt,
                "response": response_text,
                "model": OLLAMA_MODEL,
                "temperature": 0.2,
                "tools": [],
                "env": {"os": "linux"},
            }
            await client.post(f"{INGEST_URL}/ingest", json={"trace": trace})
            span_ing_end = datetime.now(timezone.utc)
        span_total_end = datetime.now(timezone.utc)
        duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

        # store locally for dashboard history views
        with get_session() as s:
            # Load scenario data if scenario_id provided
            scenario_code = None
            expected_behavior = None
            if scenario_id:
                scenario = s.query(Scenario).filter(Scenario.id == scenario_id).first()
                if scenario:
                    scenario_code = scenario.code
                    expected_behavior = scenario.expected_behavior

            sr = ScenarioRun(
                app_id=app_id,
                agent_id=agent_id,
                prompt=prompt,
                scenario_id=scenario_id,
                scenario_code=scenario_code,
                expected_behavior=expected_behavior,
                note="ran from dashboard"
            )
            s.add(sr)
            s.flush()

            tr = TraceRun(
                scenario_run_id=sr.id,
                app_id=app_id,
                agent_id=agent_id,
                name="scenario.run",
                status="completed",
                input_json=json.dumps({"prompt": prompt}),
                output_json=json.dumps({"response": response_text, "warn": warn, "trace": {"trace_id": trace["trace_id"]}, "gen": gen_meta}),
                duration_ms=duration_ms,
            )
            s.add(tr)
            s.flush()

            def _dur(a: datetime, b: datetime) -> int:
                return int((b - a).total_seconds() * 1000)

            # Parent span for the whole scenario run + child spans for steps.
            parent_span = TraceSpan(
                trace_run_id=tr.id,
                parent_id=None,
                name="scenario.run",
                start_ts=span_total_start,
                end_ts=span_total_end,
                duration_ms=_dur(span_total_start, span_total_end),
                meta_json=json.dumps({"app_id": app_id, "agent_id": agent_id}),
            )
            s.add(parent_span)
            s.flush()

            s.add(
                TraceSpan(
                    trace_run_id=tr.id,
                    parent_id=parent_span.id,
                    name="warn_policy.call",
                    start_ts=span_warn_start,
                    end_ts=span_warn_end,
                    duration_ms=_dur(span_warn_start, span_warn_end),
                    meta_json=json.dumps({"status": wresp.status_code, "pattern_id": warn.get("pattern_id"), "confidence": warn.get("confidence")}),
                )
            )
            s.add(
                TraceSpan(
                    trace_run_id=tr.id,
                    parent_id=parent_span.id,
                    name="model.generate",
                    start_ts=span_gen_start,
                    end_ts=span_gen_end,
                    duration_ms=_dur(span_gen_start, span_gen_end),
                    meta_json=json.dumps({"model": OLLAMA_MODEL, "source": "ollama_or_stub", "provider": gen_meta.get("provider"), "latency_ms": gen_meta.get("latency_ms")}),
                )
            )
            s.add(
                TraceSpan(
                    trace_run_id=tr.id,
                    parent_id=parent_span.id,
                    name="ingestion.ingest",
                    start_ts=span_ing_start,
                    end_ts=span_ing_end,
                    duration_ms=_dur(span_ing_start, span_ing_end),
                    meta_json=json.dumps({"trace_id": trace["trace_id"]}),
                )
            )
            s.flush()
            scenario_spans = s.query(TraceSpan).filter(TraceSpan.trace_run_id == tr.id).all()
            try:
                _generate_span_metric_points(
                    s,
                    trace_run_id=int(tr.id),
                    ts=span_total_start,
                    app_id=app_id,
                    spans=scenario_spans,
                )
            except Exception as e:
                logger.warning(f"scenario span metric generation failed: {e}")
            we = WarningEvent(
                app_id=app_id,
                agent_id=agent_id,
                action=str(warn.get("action")),
                confidence=str(warn.get("confidence")),
                pattern_id=warn.get("pattern_id"),
                prompt=prompt,
                message=str(warn.get("message")),
                references_json=json.dumps(warn.get("references") or []),
            )
            s.add(we)
            s.add(AuditEvent(actor_email=user.get("email"), action="scenario_run", details=f"app_id={app_id}"))
            s.commit()

            warning_id = we.id

        # Jump user right to the new warning entry.
        return RedirectResponse(url=f"/warnings#w-{warning_id}", status_code=302)
    except Exception as e:
        logger.exception(f"scenario run failed: {e}")
        msg = quote(f"Scenario run failed: {str(e)[:120]}")
        return RedirectResponse(url=f"/scenarios?error={msg}", status_code=303)


@app.post("/datasets/{dataset_id}/examples/{example_id}/run")
async def dataset_run_example_now(
    request: Request,
    dataset_id: int,
    example_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user

    with get_session() as s:
        ex = (
            s.query(DatasetExample)
            .filter(DatasetExample.id == example_id, DatasetExample.dataset_id == dataset_id)
            .first()
        )
        if not ex:
            return RedirectResponse(url=f"/datasets/{dataset_id}", status_code=302)
        try:
            inp = json.loads(ex.input_json or "{}")
        except Exception:
            inp = {}
        prompt = str(inp.get("prompt") or "")
        app_id = ex.app_id

    response_text, gen_meta = await ollama_generate_with_meta(prompt)

    with get_session() as s:
        ex = (
            s.query(DatasetExample)
            .filter(DatasetExample.id == example_id, DatasetExample.dataset_id == dataset_id)
            .first()
        )
        if ex:
            ex.last_run_output_json = json.dumps({"response": response_text, "gen": gen_meta})
            ex.last_run_latency_ms = int(gen_meta.get("latency_ms") or 0)
            ex.last_run_provider = str(gen_meta.get("provider") or "")

        tr = TraceRun(
            scenario_run_id=None,
            app_id=app_id,
            agent_id="dataset-preview",
            name="dataset.example.run",
            status="completed",
            input_json=json.dumps({"dataset_id": dataset_id, "example_id": example_id, "prompt": prompt}),
            output_json=json.dumps({"response": response_text, "gen": gen_meta}),
            duration_ms=int(gen_meta.get("latency_ms") or 0),
        )
        s.add(tr)
        s.add(
            AuditEvent(
                actor_email=user.get("email"),
                action="dataset_example_run",
                details=f"dataset_id={dataset_id} example_id={example_id} provider={gen_meta.get('provider')}",
            )
        )
        s.commit()

    return RedirectResponse(url=f"/datasets/{dataset_id}", status_code=302)


@app.get("/eval", response_class=HTMLResponse)
async def eval_home(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    with get_session() as s:
        datasets = s.query(Dataset).order_by(Dataset.created_at.desc()).all()
        evals = s.query(EvaluationRun).order_by(EvaluationRun.ts.desc()).limit(50).all()
    return templates.TemplateResponse(
        "eval.html",
        {"request": request, "email": email, "role": role, "datasets": datasets, "evals": evals},
    )


def _deterministic_eval_citation_hallucination(response_text: str) -> dict[str, Any]:
    # Basic deterministic check: if response has "References" with bracketed citations, mark as hallucination.
    txt = (response_text or "").lower()
    has_refs = "references" in txt
    has_brackets = "[1]" in response_text or "[2]" in response_text or "[3]" in response_text
    flagged = bool(has_refs and has_brackets)
    return {"flagged": flagged, "reason": "references-with-bracket-citations" if flagged else "ok"}


@app.post("/eval/run")
async def eval_run(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    dataset_id: int = Form(...),
):
    if isinstance(user, RedirectResponse):
        return user

    agent_id = "eval-runner"
    with get_session() as s:
        dataset = s.query(Dataset).filter(Dataset.id == dataset_id).first()
        if not dataset:
            return RedirectResponse(url="/eval", status_code=302)
        examples = s.query(DatasetExample).filter(DatasetExample.dataset_id == dataset_id).order_by(DatasetExample.created_at.asc()).all()

        er = EvaluationRun(dataset_id=dataset_id, name=f"eval:{dataset.name}")
        s.add(er)
        s.flush()
        s.commit()
        
        # Extract IDs to avoid DetachedInstanceError when accessing outside session
        eval_run_id = er.id
        
        # Extract example data while still in session to avoid DetachedInstanceError
        examples_data = [
            {"id": ex.id, "app_id": ex.app_id, "input_json": ex.input_json}
            for ex in examples
        ]

    # Run examples outside the session while calling external services
    passed_count = 0
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for ex in examples_data:
            ex_input = json.loads(ex["input_json"] or "{}")
            prompt = str(ex_input.get("prompt") or "")
            app_id = ex["app_id"]

            started = datetime.now(timezone.utc)
            wresp = await client.post(
                f"{WARN_URL}/warn",
                json={"app_id": app_id, "agent_id": agent_id, "prompt": prompt, "tools": [], "env": {"os": "linux"}},
            )
            warn = wresp.json()
            response_text, gen_meta = await ollama_generate_with_meta(prompt)
            duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

            det = _deterministic_eval_citation_hallucination(response_text)
            # For demo: pass if NOT flagged.
            passed = not det["flagged"]
            score = 1 if passed else 0
            if passed:
                passed_count += 1

            with get_session() as s:
                tr = TraceRun(
                    scenario_run_id=None,
                    app_id=app_id,
                    agent_id=agent_id,
                    name="eval.example",
                    status="completed",
                    input_json=json.dumps({"prompt": prompt, "dataset_example_id": ex["id"]}),
                    output_json=json.dumps({"response": response_text, "warn": warn, "det_eval": det, "gen": gen_meta}),
                    duration_ms=duration_ms,
                )
                s.add(tr)
                s.flush()
                s.add(
                    EvaluationResult(
                        eval_run_id=eval_run_id,
                        dataset_example_id=ex["id"],
                        trace_run_id=tr.id,
                        score=score,
                        passed=passed,
                        details_json=json.dumps({"deterministic": det, "warn": warn}),
                    )
                )
                s.commit()
                results.append({"example_id": ex["id"], "trace_run_id": tr.id, "passed": passed})

    with get_session() as s:
        total = len(examples_data)
        summary = {"dataset_id": dataset_id, "total": total, "passed": passed_count, "pass_rate": (passed_count / total) if total else 0}
        s.query(EvaluationRun).filter(EvaluationRun.id == eval_run_id).update({"summary_json": json.dumps(summary)})
        s.add(AuditEvent(actor_email=user.get("email"), action="eval_run", details=f"dataset_id={dataset_id} total={total} passed={passed_count}"))
        s.commit()

    return RedirectResponse(url=f"/eval/{eval_run_id}", status_code=302)


@app.get("/eval/{eval_id}", response_class=HTMLResponse)
async def eval_detail(request: Request, eval_id: int, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    with get_session() as s:
        er = s.query(EvaluationRun).filter(EvaluationRun.id == eval_id).first()
        if not er:
            return RedirectResponse(url="/eval", status_code=302)
        dataset = s.query(Dataset).filter(Dataset.id == er.dataset_id).first()
        rows = s.query(EvaluationResult).filter(EvaluationResult.eval_run_id == eval_id).order_by(EvaluationResult.id.asc()).all()
        examples = {ex.id: ex for ex in s.query(DatasetExample).filter(DatasetExample.dataset_id == er.dataset_id).all()}

        trace_ids = [r.trace_run_id for r in rows if r.trace_run_id]
        trace_by_id: dict[int, TraceRun] = {}
        if trace_ids:
            trace_by_id = {tr.id: tr for tr in s.query(TraceRun).filter(TraceRun.id.in_(trace_ids)).all()}

    summary: dict[str, Any] = {}
    try:
        summary = json.loads(er.summary_json or "{}")
        if not isinstance(summary, dict):
            summary = {}
    except Exception:
        summary = {}

    def _extract_gen(tr: TraceRun | None) -> dict[str, Any]:
        if not tr:
            return {}
        try:
            jo = json.loads(tr.output_json or "{}")
            gen = (jo or {}).get("gen") or {}
            return gen if isinstance(gen, dict) else {}
        except Exception:
            return {}

    latencies: list[int] = []
    providers: dict[str, int] = {}
    # Attach gen meta to each row for template drilldown.
    row_meta: dict[int, dict[str, Any]] = {}
    for r in rows:
        gen = _extract_gen(trace_by_id.get(r.trace_run_id))
        row_meta[r.id] = gen
        lm = gen.get("latency_ms")
        if isinstance(lm, int):
            latencies.append(lm)
        p = gen.get("provider")
        if p:
            ps = str(p)
            providers[ps] = providers.get(ps, 0) + 1

    def _pct(arr: list[int], p: float) -> int | None:
        if not arr:
            return None
        xs = sorted(arr)
        k = int(round((p / 100.0) * (len(xs) - 1)))
        k = max(0, min(len(xs) - 1, k))
        return xs[k]

    summary["latency"] = {
        "count": len(latencies),
        "p50": _pct(latencies, 50),
        "p95": _pct(latencies, 95),
        "min": min(latencies) if latencies else None,
        "max": max(latencies) if latencies else None,
    }
    summary["providers"] = providers
    return templates.TemplateResponse(
        "eval_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "eval": er,
            "dataset": dataset,
            "rows": rows,
            "examples": examples,
            "summary": summary,
            "row_meta": row_meta,
        },
    )


@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str | None = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/auth/login")
async def login(email: str = Form(...), password: str = Form(...)):
    email_n = _normalize_email(email)
    if not _rate_limit(f"login:email:{email_n}", limit=10, window_s=60):
        return RedirectResponse(url="/auth/login?error=Too%20many%20attempts", status_code=302)

    with get_session() as s:
        user = s.query(User).filter(User.email == email_n).first()
        if not user or not user.is_active or not verify_password(password, user.password_hash):
            return RedirectResponse(url="/auth/login?error=Invalid%20credentials", status_code=302)

        role_names = [ur.role.name for ur in user.roles]
        token = create_access_token(email=user.email, roles=role_names)
        s.add(AuditEvent(actor_email=user.email, action="login", details="success"))
        s.commit()

    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return resp


@app.post("/auth/logout")
async def logout(request: Request):
    # Revoke current token across replicas (when Redis is configured).
    try:
        tok = request.cookies.get(COOKIE_NAME)
        if tok:
            payload = decode_access_token(tok)
            ttl = max(60, int((payload.exp - datetime.now(timezone.utc)).total_seconds()))
            if getattr(payload, "jti", None):
                _REVOCATION.revoke(str(payload.jti), ttl_seconds=ttl)
    except Exception:
        pass

    resp = RedirectResponse(url="/auth/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    resp.delete_cookie(IMPERSONATE_COOKIE)
    resp.delete_cookie("aitester_project_id")
    return resp


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "dashboard"}


@app.get("/readyz")
def readyz():
    # Ready when DB is reachable.
    try:
        with get_session() as s:
            s.execute("SELECT 1")
        return {"ok": True, "service": "dashboard"}
    except Exception as e:
        return {"ok": False, "service": "dashboard", "error": f"{type(e).__name__}: {e}"}


@app.get("/auth/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str | None = None):
    return templates.TemplateResponse("register.html", {"request": request, "error": error})


@app.post("/auth/register")
async def register(
    request: Request,
    email: str | None = Form(None),
    password: str | None = Form(None),
    role: str = Form("viewer"),
):
    # Browser UX: if someone hits POST /auth/register without form fields (common with refresh/resend
    # or misbehaving clients), don't return FastAPI's JSON 422; just bounce back to the form.
    if not email or not password:
        return RedirectResponse(url="/auth/register?error=Email%20and%20password%20required", status_code=303)

    role = role if role in {ROLE_VIEWER, ROLE_OPERATOR} else ROLE_VIEWER

    email_n = _normalize_email(email)
    err = _validate_email(email_n) or _validate_password(password)
    if err:
        return RedirectResponse(url=f"/auth/register?error={quote(err)}", status_code=302)
    if not _rate_limit(f"register:email:{email_n}", limit=4, window_s=60):
        return RedirectResponse(url="/auth/register?error=Too%20many%20attempts", status_code=302)

    with get_session() as s:
        if s.query(User).filter(User.email == email_n).first():
            return RedirectResponse(url="/auth/register?error=Email%20already%20registered", status_code=302)

        u = User(email=email_n, password_hash=hash_password(password), is_active=True, is_verified=True)
        s.add(u)
        s.flush()

        db_role = s.query(Role).filter(Role.name == role).one()
        s.add(UserRole(user_id=u.id, role_id=db_role.id))
        s.add(AuditEvent(actor_email=email_n, action="register", details=f"role={role}"))
        s.commit()

    return RedirectResponse(url="/auth/login", status_code=302)


@app.get("/auth/forgot", response_class=HTMLResponse)
async def forgot_page(request: Request, message: str | None = None, error: str | None = None):
    return templates.TemplateResponse(
        "forgot.html", {"request": request, "message": message, "error": error}
    )


@app.post("/auth/forgot", response_class=HTMLResponse)
async def forgot_submit(request: Request, email: str = Form(...)):
    # Demo-friendly: show reset link in UI. (No email integration.)
    # Security: do not reveal whether a user exists.
    email_n = _normalize_email(email)
    if _validate_email(email_n):
        return templates.TemplateResponse(
            "forgot.html",
            {"request": request, "message": "If an account exists for that email, a reset link was generated."},
        )
    if not _rate_limit(f"forgot:email:{email_n}", limit=5, window_s=60):
        return templates.TemplateResponse(
            "forgot.html",
            {"request": request, "message": "If an account exists for that email, a reset link was generated."},
        )

    with get_session() as s:
        user = s.query(User).filter(User.email == email_n).first()
        if not user:
            return templates.TemplateResponse(
                "forgot.html",
                {"request": request, "message": "If an account exists for that email, a reset link was generated."},
            )

        token = new_reset_token()
        # Store the token in DB as before (not shown in this snippet)
        # ...existing code...
        reset_url = f"{request.base_url}auth/reset?token={token}"
        email_sent = False
        if SMTP_HOST and SMTP_USER and SMTP_PASS:
            subject = "Password Reset Request"
            body = f"Hello,\n\nA password reset was requested for your account. If you did not request this, you can ignore this email.\n\nTo reset your password, click the link below or paste it into your browser:\n\n{reset_url}\n\nIf you have any issues, contact your admin."
            email_sent = send_email(email_n, subject, body)
        if email_sent:
            msg = "If an account exists for that email, a reset link was sent."
        else:
            msg = f"If an account exists for that email, a reset link was generated. (Email not sent: SMTP not configured)\nReset link: {reset_url}"
        return templates.TemplateResponse(
            "forgot.html",
            {"request": request, "message": msg},
        )
        expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        s.add(PasswordResetToken(user_id=user.id, token=token, expires_at=expires, used=False))
        s.add(AuditEvent(actor_email=email_n, action="forgot_password", details="issued reset token"))
        s.commit()

    reset_link = f"/auth/reset?token={token}"
    return templates.TemplateResponse(
        "forgot.html",
        {"request": request, "message": f"Reset link (demo): {reset_link}"},
    )


@app.get("/auth/reset", response_class=HTMLResponse)
async def reset_page(request: Request, token: str):
    return templates.TemplateResponse("reset.html", {"request": request, "token": token, "error": None})


@app.post("/auth/reset")
async def reset_submit(request: Request, token: str = Form(...), password: str = Form(...)):
    err = _validate_password(password)
    if err:
        # The reset form needs the token to remain filled.
        return templates.TemplateResponse("reset.html", {"request": request, "token": token, "error": err})

    if not _rate_limit(f"reset:token:{token[:8]}", limit=10, window_s=60):
        return RedirectResponse(url="/auth/forgot?error=Too%20many%20attempts", status_code=302)

    now = datetime.now(timezone.utc)
    with get_session() as s:
        prt = s.query(PasswordResetToken).filter(PasswordResetToken.token == token).first()
        if not prt or prt.used or prt.expires_at < now:
            return RedirectResponse(url="/auth/forgot?error=Invalid%20or%20expired%20token", status_code=302)

        user = s.query(User).filter(User.id == prt.user_id).one()
        user.password_hash = hash_password(password)
        prt.used = True
        s.add(AuditEvent(actor_email=user.email, action="reset_password", details="success"))
        s.commit()

    return RedirectResponse(url="/auth/login", status_code=302)


@app.get("/admin/audit", response_class=HTMLResponse)
async def audit_page(request: Request, user: dict[str, Any] = Depends(require_roles([ROLE_ADMIN]))):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    
    with get_session() as s:
        events = (
            s.query(AuditEvent)
            .order_by(AuditEvent.ts.desc())
            .limit(100)
            .all()
        )
    
    return templates.TemplateResponse(
        "audit.html",
        {"request": request, "email": email, "role": role, "events": events},
    )


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request, user: dict[str, Any] = Depends(require_roles([ROLE_ADMIN]))):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    with get_session() as s:
        users = s.query(User).order_by(User.email.asc()).all()
        out = []
        for u in users:
            out.append(
                {
                    "email": u.email,
                    "is_active": u.is_active,
                    "roles": [ur.role.name for ur in u.roles],
                }
            )

    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "email": email, "role": role, "users": out},
    )


@app.post("/admin/impersonate")
async def admin_impersonate(
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
    role: str = Form(...),
):
    if isinstance(user, RedirectResponse):
        return user
    if role not in {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}:
        return RedirectResponse(url="/admin/users", status_code=302)

    # UX: stay in the admin panel after switching view-as role.
    resp = RedirectResponse(url="/admin/users", status_code=302)
    resp.set_cookie(IMPERSONATE_COOKIE, role, httponly=True, samesite="lax")
    with get_session() as s:
        s.add(AuditEvent(actor_email=user.get("email"), action="admin_impersonate", details=f"view_as={role}"))
        s.commit()
    return resp


@app.post("/admin/impersonate/clear")
async def admin_impersonate_clear(
    request: Request,
    user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN])),
):
    if isinstance(user, RedirectResponse):
        return user
    # UX: stay in the admin panel after clearing view-as.
    resp = RedirectResponse(url="/admin/users", status_code=302)
    resp.delete_cookie(IMPERSONATE_COOKIE)
    with get_session() as s:
        s.add(AuditEvent(actor_email=user.get("email"), action="admin_impersonate_clear", details=""))
        s.commit()
    return resp


@app.get("/runs", response_class=HTMLResponse)
async def runs_list(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    q: str | None = None,
    app_id: str | None = None,
    agent_id: str | None = None,
    provider: str | None = None,
    since: str | None = None,
    until: str | None = None,
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    def _parse_dt(s: str | None) -> datetime | None:
        if not s:
            return None
        # Accept YYYY-MM-DD or ISO timestamp.
        try:
            if len(s) == 10:
                return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    since_dt = _parse_dt(since)
    until_dt = _parse_dt(until)

    free_q, adv = _parse_advanced_query(q)

    with get_session() as s:
        query = s.query(TraceRun)

        # Optional: scope by selected project (cookie). If none is selected, show all.
        selected_project_id = _effective_project_id(request, user)
        if selected_project_id is not None:
            query = query.filter(TraceRun.project_id == selected_project_id)

        if app_id:
            query = query.filter(TraceRun.app_id == app_id)
        if agent_id:
            query = query.filter(TraceRun.agent_id == agent_id)
        if since_dt:
            query = query.filter(TraceRun.ts >= since_dt)
        if until_dt:
            query = query.filter(TraceRun.ts <= until_dt)

        # Apply advanced query filters first (can be combined with explicit UI fields)
        if adv.get("provider"):
            query = query.filter(TraceRun.provider == str(adv["provider"]))
        if adv.get("model"):
            query = query.filter(TraceRun.model == str(adv["model"]))
        if adv.get("has_error"):
            query = query.filter((TraceRun.error.isnot(None)) | (TraceRun.status == "error"))
        if adv.get("latency_gt") is not None:
            query = query.filter(TraceRun.duration_ms >= int(adv["latency_gt"]))
        if adv.get("latency_lt") is not None:
            query = query.filter(TraceRun.duration_ms <= int(adv["latency_lt"]))

        # Feedback-based search: tags/labels/thumbs are stored in run_feedback.
        # For a demo, use EXISTS-like subqueries via IN.
        if adv.get("tags"):
            tag_runs = (
                s.query(RunFeedback.trace_run_id)
                .filter(RunFeedback.key == "tag", RunFeedback.value.in_([str(t) for t in adv["tags"]]))
                .subquery()
            )
            query = query.filter(TraceRun.id.in_(tag_runs))
        if adv.get("labels"):
            label_runs = (
                s.query(RunFeedback.trace_run_id)
                .filter(RunFeedback.key == "label", RunFeedback.value.in_([str(t) for t in adv["labels"]]))
                .subquery()
            )
            query = query.filter(TraceRun.id.in_(label_runs))
        if adv.get("thumb"):
            thumb_val = "up" if str(adv["thumb"]).lower() in {"up", "+", "1", "true"} else "down"
            thumb_runs = (
                s.query(RunFeedback.trace_run_id)
                .filter(RunFeedback.key == "thumb", RunFeedback.value == thumb_val)
                .subquery()
            )
            query = query.filter(TraceRun.id.in_(thumb_runs))

        # Existing simple free text search (keeps current UX)
        if free_q:
            query = query.filter(TraceRun.input_json.like(f"%{free_q}%") | TraceRun.output_json.like(f"%{free_q}%"))

        # Provider filter from explicit field (works even without q now)
        effective_provider = provider or (adv.get("provider") if adv else None)
        if effective_provider:
            try:
                query = query.filter(TraceRun.provider == str(effective_provider))
            except Exception:
                query = query.filter(TraceRun.output_json.like(f"%\"provider\": \"{effective_provider}\"%"))

        runs = query.order_by(TraceRun.ts.desc()).limit(200).all()

    return templates.TemplateResponse(
        "runs.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "runs": runs,
            "q": q or "",
            "app_id": app_id or "",
            "agent_id": agent_id or "",
            "provider": provider or "",
            "since": since or "",
            "until": until or "",
        },
    )


@app.get("/runs/{run_id}", response_class=HTMLResponse)
async def run_detail(
    request: Request,
    run_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    with get_session() as s:
        run = s.query(TraceRun).filter(TraceRun.id == run_id).first()
        if not run:
            return RedirectResponse(url="/runs", status_code=302)
        spans = s.query(TraceSpan).filter(TraceSpan.trace_run_id == run_id).order_by(TraceSpan.start_ts.asc()).all()
        feedback = s.query(RunFeedback).filter(RunFeedback.trace_run_id == run_id).order_by(RunFeedback.ts.desc()).all()
        corr_rows = (
            s.query(ProfilerSample)
            .filter(ProfilerSample.trace_run_id == int(run_id))
            .order_by(ProfilerSample.cpu_ms.desc(), ProfilerSample.ts.desc())
            .limit(20)
            .all()
        )

    # Derive quick UX signals from feedback history (most recent wins).
    thumb_state: str | None = None
    label_state: str | None = None
    try:
        for f in feedback:
            if thumb_state is None and f.key == "thumb":
                v = (f.value or "").strip().lower()
                if v in {"up", "down"}:
                    thumb_state = v
            if label_state is None and f.key == "label":
                label_state = (f.value or "").strip() or None
            if thumb_state is not None and label_state is not None:
                break
    except Exception:
        thumb_state = None
        label_state = None

    def _pretty(obj: str) -> str:
        try:
            return json.dumps(json.loads(obj or "{}"), indent=2, sort_keys=True)
        except Exception:
            return obj

    # Build a lightweight span tree and waterfall coordinates.
    span_items: list[dict[str, Any]] = []
    flame_rects: list[dict[str, Any]] = []
    trace_map_nodes: list[dict[str, Any]] = []
    trace_map_edges: list[dict[str, Any]] = []
    if spans:
        # root start determines 0ms for bars
        root_start = min((sp.start_ts for sp in spans if sp.start_ts), default=None)
        root_end = max((sp.end_ts for sp in spans if sp.end_ts), default=None)
        if root_start and root_end:
            total_ms = max(1, int((root_end - root_start).total_seconds() * 1000))
        else:
            total_ms = max(1, int(run.duration_ms or 1))

        by_parent: dict[int | None, list[TraceSpan]] = {}
        by_id: dict[int, TraceSpan] = {}
        for sp in spans:
            by_id[sp.id] = sp
            by_parent.setdefault(sp.parent_id, []).append(sp)
        for pid in by_parent:
            by_parent[pid].sort(key=lambda s: s.start_ts)

        def _walk(parent_id: int | None, depth: int) -> None:
            for sp in by_parent.get(parent_id, []):
                start_offset_ms = 0
                dur_ms = int(sp.duration_ms or 0)
                if root_start and sp.start_ts:
                    start_offset_ms = int((sp.start_ts - root_start).total_seconds() * 1000)
                pct_left = max(0.0, min(100.0, (start_offset_ms / total_ms) * 100.0))
                pct_width = max(0.6, min(100.0, (dur_ms / total_ms) * 100.0))
                span_items.append(
                    {
                        "id": sp.id,
                        "parent_id": sp.parent_id,
                        "depth": depth,
                        "name": sp.name,
                        "start_ts": sp.start_ts,
                        "duration_ms": dur_ms,
                        "meta_json": sp.meta_json,
                        "has_children": sp.id in by_parent,
                        "pct_left": pct_left,
                        "pct_width": pct_width,
                    }
                )
                _walk(sp.id, depth + 1)

        _walk(None, 0)

        # Flame graph rectangles (depth-based horizontal bars).
        for item in span_items:
            flame_rects.append(
                {
                    "name": str(item.get("name") or "span"),
                    "depth": int(item.get("depth") or 0),
                    "left": float(item.get("pct_left") or 0.0),
                    "width": float(item.get("pct_width") or 0.0),
                    "duration_ms": int(item.get("duration_ms") or 0),
                }
            )

        # Trace map (parent span -> child span), with duration rollup.
        by_id = {int(sp.id): sp for sp in spans if getattr(sp, "id", None) is not None}
        edge_rollup: dict[tuple[str, str], dict[str, Any]] = {}
        node_ids: set[str] = set()
        for sp in spans:
            src = "root"
            if sp.parent_id is not None and int(sp.parent_id) in by_id:
                src = str(by_id[int(sp.parent_id)].name or "unknown")
            tgt = str(sp.name or "unknown")
            node_ids.add(src)
            node_ids.add(tgt)
            key = (src, tgt)
            cur = edge_rollup.get(key)
            d = float(_to_int(sp.duration_ms, 0))
            if not cur:
                edge_rollup[key] = {"source": src, "target": tgt, "count": 1, "durations": [d]}
            else:
                cur["count"] += 1
                cur["durations"].append(d)
        trace_map_nodes = [{"id": n} for n in sorted(node_ids)]
        trace_map_edges = []
        for _, v in edge_rollup.items():
            ds = sorted(v["durations"])
            trace_map_edges.append(
                {
                    "source": v["source"],
                    "target": v["target"],
                    "count": int(v["count"]),
                    "latency_avg_ms": float(sum(ds) / max(1, len(ds))),
                    "latency_p95_ms": float(ds[max(0, int(len(ds) * 0.95) - 1)] if ds else 0.0),
                }
            )
        trace_map_edges.sort(key=lambda x: (x["count"], x["latency_p95_ms"]), reverse=True)

    return templates.TemplateResponse(
        "run_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "run": run,
            "input_pretty": _pretty(run.input_json),
            "output_pretty": _pretty(run.output_json),
            "feedback": feedback,
            "thumb_state": thumb_state,
            "label_state": label_state,
            "spans": spans,
            "span_items": span_items,
            "flame_rects": flame_rects,
            "trace_map_nodes": trace_map_nodes,
            "trace_map_edges": trace_map_edges,
            "profile_correlation_rows": corr_rows,
        },
    )


@app.get("/playground", response_class=HTMLResponse)
async def playground_page(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str | None = None,
    agent_id: str | None = None,
    model: str | None = None,
    prompt: str | None = None,
    prompt_version_id: int | None = Query(default=None),
    last_run_id: int | None = Query(default=None),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    models = await list_ollama_models()
    selected_model = model or (models[0] if models else OLLAMA_MODEL)
    last: dict[str, Any] | None = None

    # If a prompt version is supplied, prefill prompt text and optional default model
    if prompt_version_id is not None:
        try:
            with get_session() as s:
                pv = s.query(PromptVersion).filter(PromptVersion.id == prompt_version_id).first()
                if pv:
                    if not prompt:
                        prompt = pv.prompt_text
                    if not model and pv.default_model:
                        selected_model = pv.default_model
        except Exception:
            pass

    # Experiments dropdown
    experiments: list[Experiment] = []
    try:
        with get_session() as s:
            experiments = s.query(Experiment).order_by(Experiment.created_at.desc()).limit(200).all()
    except Exception:
        experiments = []

    if last_run_id:
        with get_session() as s:
            run = s.query(TraceRun).filter(TraceRun.id == last_run_id).first()
            if run:
                # Prefer persisted provider/model columns for correctness.
                provider = run.provider or ""
                used_model = run.model or ""
                latency_ms = str(run.duration_ms or "")
                out_text = run.output_json or ""
                content_rating = ""
                alert_sent = False
                asked_prompt = ""
                try:
                    jo = json.loads(run.output_json or "{}")
                    gen = (jo or {}).get("gen") or {}
                    provider = provider or (gen.get("provider") or "")
                    used_model = used_model or (gen.get("model") or "")
                    latency_ms = latency_ms or str(gen.get("latency_ms") or "")
                    out_text = (jo or {}).get("response") or out_text
                    content_rating = str(gen.get("content_rating") or "")
                    alert_sent = bool(gen.get("alert_sent") or False)
                except Exception:
                    pass

                try:
                    ji = json.loads(run.input_json or "{}")
                    asked_prompt = str((ji or {}).get("prompt") or "")
                except Exception:
                    asked_prompt = ""

                safety_level = ""
                safety_label = ""
                show_safety_banner = False
                try:
                    cr = (content_rating or "").strip().lower()
                    if cr in {"blocked", "warning", "safe"}:
                        safety_level = cr
                        safety_label = cr.upper()
                    if cr in {"blocked", "warning"} or alert_sent:
                        show_safety_banner = True
                        if not safety_level:
                            safety_level = "warning"
                            safety_label = "WARNING"
                except Exception:
                    show_safety_banner = False

                warnings_created = bool(show_safety_banner)
                warnings_link = f"/warnings?app_id={run.app_id}" if run.app_id else "/warnings"

                last = {
                    "run_id": run.id,
                    "provider": provider,
                    "model": used_model,
                    "latency_ms": latency_ms,
                    "output": out_text,
                    "prompt": asked_prompt,
                    "app_id": run.app_id,
                    "content_rating": content_rating,
                    "alert_sent": alert_sent,
                    "show_safety_banner": show_safety_banner,
                    "safety_level": safety_level,
                    "safety_label": safety_label,
                    "warnings_created": warnings_created,
                    "warnings_link": warnings_link,
                }

    # Get registered agents for dropdown
    agents: list[dict] = []
    try:
        with get_session() as s:
            agent_rows = s.query(AgentRegistry).filter(AgentRegistry.enabled == True).order_by(AgentRegistry.name).all()
            agents = [{"id": a.id, "name": a.name, "base_url": a.base_url} for a in agent_rows]
    except Exception:
        agents = []

    return templates.TemplateResponse(
        "playground.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "models": models,
            "model": selected_model,
            "app_id": app_id or "app-A",
            "agent_id": agent_id or "playground",
            "prompt": prompt or "Explain what an agent is in 3 bullets.",
            "prompt_version_id": prompt_version_id,
            "experiments": experiments,
            "agents": agents,
            "selected_agent": None,
            "last": last,
        },
    )


@app.post("/playground/run")
async def playground_run(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str = Form("app-A"),
    agent_id: str = Form("playground"),
    model: str = Form(OLLAMA_MODEL),
    prompt: str = Form(...),
    prompt_version_id: str | None = Form(None),
    experiment_id: str | None = Form(None),
    experiment_label: str | None = Form(None),
    external_agent: str | None = Form(None),
):
    if isinstance(user, RedirectResponse):
        return user

    started = datetime.now(timezone.utc)
    run_status = "completed"
    run_error: str | None = None
    
    # Check if external agent is selected
    agent_name = None
    if external_agent:
        try:
            ext_agent_id = int(external_agent)
            with get_session() as s:
                agent_row = s.query(AgentRegistry).filter(AgentRegistry.id == ext_agent_id, AgentRegistry.enabled == True).first()
                if agent_row:
                    agent_name = agent_row.name
                    base_url = agent_row.base_url.rstrip("/")
                    
                    # Call external agent
                    try:
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            # Try /api/ask endpoint (Kids Agent style)
                            r = await client.post(
                                f"{base_url}/api/ask",
                                json={"question": prompt, "child_name": "Playground User"}
                            )
                            if r.status_code == 200:
                                data = r.json()
                                response_text = data.get("answer", str(data))
                                content_rating = str(data.get("content_rating") or "")
                                alert_sent = bool(data.get("alert_sent") or False)
                                gen_meta = {
                                    "provider": "external_agent",
                                    "model": agent_name,
                                    "agent_url": base_url,
                                    "content_rating": content_rating,
                                    "is_safe": data.get("is_safe", True),
                                    "detected_topics": data.get("detected_topics", []),
                                    "alert_sent": alert_sent,
                                }

                                if (content_rating or "").strip().lower() == "blocked":
                                    run_status = "error"
                                    run_error = "Blocked content detected"
                            else:
                                response_text = f"Error: Agent returned {r.status_code}"
                                gen_meta = {"provider": "external_agent", "model": agent_name, "error": r.text}
                                run_status = "error"
                                run_error = f"External agent HTTP {r.status_code}"
                    except Exception as e:
                        response_text = f"Error calling agent: {str(e)}"
                        gen_meta = {"provider": "external_agent", "model": agent_name, "error": str(e)}
                        run_status = "error"
                        run_error = "Error calling external agent"
                else:
                    response_text = "Agent not found or disabled"
                    gen_meta = {"provider": "external_agent", "error": "Agent not found"}
                    run_status = "error"
                    run_error = "External agent not found or disabled"
        except Exception as e:
            response_text = f"Invalid agent: {str(e)}"
            gen_meta = {"provider": "external_agent", "error": str(e)}
            run_status = "error"
            run_error = "Invalid external agent"
    else:
        # Use direct model (original behavior)
        response_text, gen_meta = await ollama_generate_with_meta_model(prompt, model)
    
    ended = datetime.now(timezone.utc)
    duration_ms = int((ended - started).total_seconds() * 1000)

    # Token + cost tracking (rough estimate).
    provider = str(gen_meta.get("provider") or "")
    prompt_tokens = _estimate_tokens(prompt)
    completion_tokens = _estimate_tokens(response_text)
    total_tokens = int(prompt_tokens + completion_tokens)
    cost_usd = _compute_cost_usd(provider, prompt_tokens, completion_tokens)
    gen_meta.setdefault("prompt_tokens", prompt_tokens)
    gen_meta.setdefault("completion_tokens", completion_tokens)
    gen_meta.setdefault("total_tokens", total_tokens)
    gen_meta.setdefault("cost_usd", cost_usd)

    # Optional project scoping (cookie-based for UI).
    project_id = _effective_project_id(request, user)

    run_id: int
    with get_session() as s:
        tr = TraceRun(
            ts=started,
            project_id=project_id,
            app_id=app_id,
            agent_id=agent_id,
            name="playground.run",
            status=run_status,
            error=run_error,
            duration_ms=duration_ms,
            provider=provider,
            model=str(gen_meta.get("model") or model),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=_usd_to_micro(cost_usd),
            input_json=json.dumps({"prompt": prompt, "model": model}, ensure_ascii=False),
            output_json=json.dumps({"response": response_text, "gen": gen_meta}, ensure_ascii=False),
            scenario_run_id=None,
        )
        s.add(tr)
        s.flush()
        run_id = int(tr.id)

        # minimal spans to show in waterfall
        span_total = TraceSpan(
            trace_run_id=tr.id,
            parent_id=None,
            name="playground.total",
            start_ts=started,
            end_ts=ended,
            duration_ms=duration_ms,
            meta_json=json.dumps({"prompt_chars": len(prompt)}, ensure_ascii=False),
        )
        span_model = TraceSpan(
            trace_run_id=tr.id,
            parent_id=None,
            name="model.generate",
            start_ts=started,
            end_ts=ended,
            duration_ms=duration_ms,
            meta_json=json.dumps(gen_meta, ensure_ascii=False),
        )
        s.add(span_total)
        s.add(span_model)
        s.flush()
        _generate_span_metric_points(
            s,
            trace_run_id=int(tr.id),
            ts=started,
            app_id=app_id,
            spans=[span_total, span_model],
        )

        # Optional: attach run to an experiment
        try:
            exp_id = int(experiment_id) if experiment_id else None
        except Exception:
            exp_id = None
        try:
            pv_id = int(prompt_version_id) if prompt_version_id else None
        except Exception:
            pv_id = None

        if exp_id is not None:
            s.add(
                ExperimentRun(
                    experiment_id=exp_id,
                    trace_run_id=run_id,
                    prompt_version_id=pv_id,
                    label=(experiment_label.strip() if experiment_label else None),
                )
            )

        s.add(AuditEvent(actor_email=user.get("email"), action="playground_run", details=f"run_id={tr.id}"))
        s.commit()

    # redirect back to playground with last run preview
    return RedirectResponse(
        url=f"/playground?app_id={app_id}&agent_id={agent_id}&model={model}&last_run_id={run_id}",
        status_code=302,
    )


@app.get("/prompts", response_class=HTMLResponse)
async def prompts_list(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
    with get_session() as s:
        prompts = s.query(PromptLibrary).order_by(PromptLibrary.created_at.desc()).all()
    return templates.TemplateResponse("prompts.html", {"request": request, "prompts": prompts})


@app.post("/prompts/create")
async def prompts_create(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form(...),
    description: str | None = Form(None),
):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
    with get_session() as s:
        existing = s.query(PromptLibrary).filter(PromptLibrary.name == name).first()
        if existing:
            return RedirectResponse(url=f"/prompts/{existing.id}", status_code=302)
        p = PromptLibrary(name=name.strip(), description=(description.strip() if description else None))
        s.add(p)
        s.commit()
        pid = int(p.id)
    return RedirectResponse(url=f"/prompts/{pid}", status_code=302)


@app.get("/prompts/{prompt_id}", response_class=HTMLResponse)
async def prompt_detail(request: Request, prompt_id: int, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
    with get_session() as s:
        prompt = s.query(PromptLibrary).filter(PromptLibrary.id == prompt_id).first()
        if not prompt:
            return RedirectResponse(url="/prompts", status_code=302)
        versions = (
            s.query(PromptVersion)
            .filter(PromptVersion.prompt_id == prompt_id)
            .order_by(PromptVersion.version.desc())
            .all()
        )

    enriched = []
    for v in versions:
        try:
            tags = json.loads(v.tags_json or "[]")
            if not isinstance(tags, list):
                tags = []
        except Exception:
            tags = []
        preview = (v.prompt_text or "").strip().replace("\n", " ")
        if len(preview) > 220:
            preview = preview[:220] + "…"
        enriched.append(
            {
                "id": v.id,
                "version": v.version,
                "created_at": v.created_at,
                "default_model": v.default_model,
                "default_provider": v.default_provider,
                "tags": tags,
                "prompt_text_preview": preview,
            }
        )

    return templates.TemplateResponse(
        "prompt_detail.html",
        {"request": request, "prompt": prompt, "versions": enriched},
    )


@app.post("/prompts/{prompt_id}/versions/create")
async def prompt_version_create(
    request: Request,
    prompt_id: int,
    user: dict[str, Any] = Depends(require_login),
    prompt_text: str = Form(...),
    default_model: str | None = Form(None),
    default_provider: str | None = Form(None),
    tags: str | None = Form(None),
):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
    tag_list = parse_tags_csv(tags)
    with get_session() as s:
        p = s.query(PromptLibrary).filter(PromptLibrary.id == prompt_id).first()
        if not p:
            return RedirectResponse(url="/prompts", status_code=302)
        last_v = (
            s.query(PromptVersion)
            .filter(PromptVersion.prompt_id == prompt_id)
            .order_by(PromptVersion.version.desc())
            .first()
        )
        next_version = int(last_v.version) + 1 if last_v else 1
        v = PromptVersion(
            prompt_id=prompt_id,
            version=next_version,
            prompt_text=prompt_text,
            default_model=(default_model.strip() if default_model else None),
            default_provider=(default_provider.strip() if default_provider else None),
            tags_json=json.dumps(tag_list),
        )
        s.add(v)
        s.commit()
    return RedirectResponse(url=f"/prompts/{prompt_id}", status_code=302)


@app.get("/experiments", response_class=HTMLResponse)
async def experiments_list(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
    with get_session() as s:
        experiments = s.query(Experiment).order_by(Experiment.created_at.desc()).all()
    return templates.TemplateResponse("experiments.html", {"request": request, "experiments": experiments})


@app.post("/experiments/create")
async def experiments_create(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form(...),
    description: str | None = Form(None),
):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
    with get_session() as s:
        existing = s.query(Experiment).filter(Experiment.name == name).first()
        if existing:
            return RedirectResponse(url=f"/experiments/{existing.id}", status_code=302)
        e = Experiment(name=name.strip(), description=(description.strip() if description else None))
        s.add(e)
        s.commit()
        eid = int(e.id)
    return RedirectResponse(url=f"/experiments/{eid}", status_code=302)


@app.get("/experiments/{experiment_id}", response_class=HTMLResponse)
async def experiment_detail(request: Request, experiment_id: int, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)

    with get_session() as s:
        experiment = s.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            return RedirectResponse(url="/experiments", status_code=302)
        links = (
            s.query(ExperimentRun)
            .filter(ExperimentRun.experiment_id == experiment_id)
            .order_by(ExperimentRun.created_at.desc())
            .all()
        )
        run_ids = [l.trace_run_id for l in links]
        runs: list[TraceRun] = []
        if run_ids:
            runs = s.query(TraceRun).filter(TraceRun.id.in_(run_ids)).all()

    link_by_run = {l.trace_run_id: l for l in links}
    for r in runs:
        l = link_by_run.get(r.id)
        setattr(r, "_exp_label", getattr(l, "label", None) if l else None)

    latencies = [int(r.duration_ms) for r in runs if r.duration_ms is not None]
    provider_split: dict[str, int] = {}
    for r in runs:
        k = (r.provider or "unknown")
        provider_split[k] = provider_split.get(k, 0) + 1
    scorecards = {
        "total_runs": len(runs),
        "p50_ms": percentile(latencies, 50),
        "p95_ms": percentile(latencies, 95),
        "provider_split": provider_split,
    }

    return templates.TemplateResponse(
        "experiment_detail.html",
        {"request": request, "experiment": experiment, "runs": runs, "scorecards": scorecards},
    )


@app.post("/experiments/{experiment_id}/add_run")
async def experiment_add_run(
    request: Request,
    experiment_id: int,
    user: dict[str, Any] = Depends(require_login),
    run_id: str = Form(...),
    label: str | None = Form(None),
    prompt_version_id: str | None = Form(None),
):
    if isinstance(user, RedirectResponse):
        return user
    if not require_any(user.get("effective_roles", user.get("roles", [])), [ROLE_ADMIN, ROLE_OPERATOR]):
        return RedirectResponse(url="/auth/login?error=Not%20authorized", status_code=302)
    try:
        rid = int(run_id)
    except Exception:
        return RedirectResponse(url=f"/experiments/{experiment_id}", status_code=302)
    try:
        pv_id = int(prompt_version_id) if prompt_version_id else None
    except Exception:
        pv_id = None
    with get_session() as s:
        tr = s.query(TraceRun).filter(TraceRun.id == rid).first()
        if not tr:
            return RedirectResponse(url=f"/experiments/{experiment_id}", status_code=302)
        s.add(
            ExperimentRun(
                experiment_id=experiment_id,
                trace_run_id=rid,
                prompt_version_id=pv_id,
                label=(label.strip() if label else None),
            )
        )
        s.commit()
    return RedirectResponse(url=f"/experiments/{experiment_id}", status_code=302)


@app.post("/runs/{run_id}/feedback")
async def add_run_feedback(
    request: Request,
    run_id: int,
    user: dict[str, Any] = Depends(require_login),
    key: str = Form(...),
    value: str = Form(...),
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        # UX: for single-choice keys like thumb, de-dup by removing older entries.
        if key in {"thumb"}:
            s.query(RunFeedback).filter(RunFeedback.trace_run_id == run_id, RunFeedback.key == key).delete()
        s.add(RunFeedback(trace_run_id=run_id, key=key, value=value, actor_email=user.get("email")))
        s.commit()
    return RedirectResponse(url=f"/runs/{run_id}", status_code=302)


@app.get("/datasets", response_class=HTMLResponse)
async def datasets_list(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    with get_session() as s:
        datasets = s.query(Dataset).order_by(Dataset.created_at.desc()).all()

    return templates.TemplateResponse(
        "datasets.html",
        {"request": request, "email": email, "role": role, "datasets": datasets},
    )


@app.post("/datasets")
async def datasets_create(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    name: str = Form(...),
    description: str = Form("")
):
    if isinstance(user, RedirectResponse):
        return user
    with get_session() as s:
        if not s.query(Dataset).filter(Dataset.name == name).first():
            s.add(Dataset(name=name, description=description or None))
            s.add(AuditEvent(actor_email=user.get("email"), action="dataset_create", details=name))
            s.commit()
    return RedirectResponse(url="/datasets", status_code=302)


@app.get("/datasets/{dataset_id}", response_class=HTMLResponse)
async def dataset_detail(
    request: Request,
    dataset_id: int,
    user: dict[str, Any] = Depends(require_login),
):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"

    with get_session() as s:
        dataset = s.query(Dataset).filter(Dataset.id == dataset_id).first()
        if not dataset:
            return RedirectResponse(url="/datasets", status_code=302)
        examples = s.query(DatasetExample).filter(DatasetExample.dataset_id == dataset_id).order_by(DatasetExample.created_at.desc()).all()
        app_choices = _get_known_app_choices(s)

    return templates.TemplateResponse(
        "dataset_detail.html",
        {
            "request": request,
            "email": email,
            "role": role,
            "dataset": dataset,
            "examples": examples,
            "app_choices": app_choices,
        },
    )


@app.post("/datasets/{dataset_id}/examples")
async def dataset_add_example(
    request: Request,
    dataset_id: int,
    user: dict[str, Any] = Depends(require_login),
    app_id: str = Form(...),
    prompt: str = Form(...),
    expected: str = Form(""),
):
    if isinstance(user, RedirectResponse):
        return user

    with get_session() as s:
        s.add(
            DatasetExample(
                dataset_id=dataset_id,
                app_id=app_id,
                input_json=json.dumps({"prompt": prompt}),
                expected_output_json=json.dumps({"expected": expected}),
                tags_json="[]",
            )
        )
        s.add(AuditEvent(actor_email=user.get("email"), action="dataset_add_example", details=f"dataset_id={dataset_id}"))
        s.commit()

    return RedirectResponse(url=f"/datasets/{dataset_id}", status_code=302)


@app.post("/admin/users/roles")
async def admin_set_role(
    request: Request,
    user: dict[str, Any] = Depends(require_roles([ROLE_ADMIN])),
    email: str = Form(...),
    role: str = Form(...),
):
    if role not in {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}:
        return RedirectResponse(url="/admin/users", status_code=302)

    with get_session() as s:
        u = s.query(User).filter(User.email == email).first()
        if not u:
            return RedirectResponse(url="/admin/users", status_code=302)

        # set single role for simplicity
        u.roles.clear()
        r = s.query(Role).filter(Role.name == role).one()
        s.add(UserRole(user_id=u.id, role_id=r.id))
        s.add(AuditEvent(actor_email=user.get("email"), action="admin_set_role", details=f"{email} -> {role}"))
        s.commit()

    return RedirectResponse(url="/admin/users", status_code=302)


@app.post("/admin/users/toggle")
async def admin_toggle_active(
    request: Request,
    user: dict[str, Any] = Depends(require_roles([ROLE_ADMIN])),
    email: str = Form(...),
):
    with get_session() as s:
        u = s.query(User).filter(User.email == email).first()
        if not u:
            return RedirectResponse(url="/admin/users", status_code=302)
        # don't allow locking yourself out by disabling your own account
        if str(user.get("email")) == u.email:
            return RedirectResponse(url="/admin/users", status_code=302)

        u.is_active = not u.is_active
        s.add(AuditEvent(actor_email=user.get("email"), action="admin_toggle_active", details=f"{email} active={u.is_active}"))
        s.commit()

    return RedirectResponse(url="/admin/users", status_code=302)
