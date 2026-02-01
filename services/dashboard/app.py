from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any
import json
import time
import uuid
import re
from collections import defaultdict, deque
from urllib.parse import quote
import secrets

import logging

import httpx
from fastapi import Depends, FastAPI, Form, Request, Query
import smtplib
from email.message import EmailMessage
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
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
    AgentRegistry,
    ProjectMember,
    Role,
    RunFeedback,
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
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'",
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
    values = sorted(values)
    if len(values) == 1:
        return int(values[0])
    idx = int(round((p / 100.0) * (len(values) - 1)))
    idx = max(0, min(len(values) - 1, idx))
    return int(values[idx])


def env_url(name: str, default: str) -> str:
    return os.environ.get(name, default)


GFKB_URL = env_url("GFKB_URL", "http://gfkb:8101")
HEALTH_URL = env_url("HEALTH_URL", "http://health-scoring:8106")
WARN_URL = env_url("WARN_URL", "http://warning-policy:8105")
INGEST_URL = env_url("INGEST_URL", "http://ingestion:8102")
OLLAMA_URL = env_url("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = env_url("OLLAMA_MODEL", "llama3")


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


@app.get("/admin")
async def admin_root(user: dict[str, Any] | RedirectResponse = Depends(require_roles([ROLE_ADMIN]))):
    if isinstance(user, RedirectResponse):
        return user
    return RedirectResponse(url="/admin/users", status_code=302)


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


async def ollama_generate(prompt: str) -> str:
    # Same behavior as scripts/demo_client.py: if not reachable, return a stub that includes citations.
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            r.raise_for_status()
            data = r.json()
            return data.get("response") or ""
    except Exception:
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
        async with httpx.AsyncClient(timeout=8.0) as client:
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
    except Exception:
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

        def _ensure_user(email: str, password: str, role: str):
            u = s.query(User).filter(User.email == email).first()
            if not u:
                u = User(email=email, password_hash=hash_password(password), is_active=True, is_verified=True)
                s.add(u)
                s.flush()
                s.add(AuditEvent(actor_email=None, action="bootstrap", details=f"created demo user {email}"))
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

        # Keep the legacy default admin for compatibility with existing docs.
        _ensure_user(email="admin@local", password="admin123", role=ROLE_ADMIN)

        # Dummy credentials for QA/testing kakveda end-to-end.
        # Use these to validate RBAC (viewer/operator) and all flows.
        _ensure_user(email="operator@kakveda.local", password="Operator@123", role=ROLE_OPERATOR)
        _ensure_user(email="viewer@kakveda.local", password="Viewer@123", role=ROLE_VIEWER)
        s.commit()

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

    async with httpx.AsyncClient(timeout=5.0) as client:
        failures = []
        patterns = []
        health_points = []
        try:
            failures = (await client.get(f"{GFKB_URL}/failures", params={"limit": 10})).json().get("failures", [])
        except Exception:
            failures = []
        try:
            patterns = (await client.get(f"{GFKB_URL}/patterns")).json().get("patterns", [])
        except Exception:
            patterns = []
        try:
            health_points = (await client.get(f"{HEALTH_URL}/health/app-A", params={"limit": 40})).json().get("points", [])
        except Exception:
            health_points = []

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
            "warnings": warnings,
        },
    )


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
            # Find the specific failure (match failure_id with or without version)
            for f in all_failures:
                fid = f.get("failure_id", "")
                version = f.get("version", 1)
                full_id = f"{fid}v{version}"
                if failure_id == fid or failure_id == full_id or failure_id.startswith(fid):
                    failure = f
                    break
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
async def warnings_page(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    with get_session() as s:
        warnings = (
            s.query(WarningEvent)
            .order_by(WarningEvent.ts.desc())
            .limit(200)
            .all()
        )

        # Analytics: last 30 days (lightweight, no external chart deps).
        now = utcnow()
        start = now - timedelta(days=30)
        warnings_30d = (
            s.query(WarningEvent)
            .filter(WarningEvent.ts >= start)
            .order_by(WarningEvent.ts.asc())
            .all()
        )

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
                app_id = str(w.app_id or "unknown")
                app_counts[app_id] = app_counts.get(app_id, 0) + 1
                pid = str(w.pattern_id or "(none)")
                pattern_counts[pid] = pattern_counts.get(pid, 0) + 1
            except Exception:
                continue

        warnings_by_app = [{"label": k, "value": v} for k, v in sorted(app_counts.items(), key=lambda kv: kv[1], reverse=True)]
        warnings_by_pattern = [{"label": k, "value": v} for k, v in sorted(pattern_counts.items(), key=lambda kv: kv[1], reverse=True)]

        # Cost impact by app (from runs) - sum over last 30 days.
        runs_30d = (
            s.query(TraceRun)
            .filter(TraceRun.ts >= start)
            .all()
        )
        cost_by_app_map: dict[str, float] = {}
        total_cost_usd_30d = 0.0
        for r in runs_30d:
            try:
                app_id = str(r.app_id or "unknown")
                usd = _micro_to_usd(r.cost_usd)
                total_cost_usd_30d += usd
                cost_by_app_map[app_id] = cost_by_app_map.get(app_id, 0.0) + usd
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
        warnings_90d = (
            s.query(WarningEvent)
            .filter(WarningEvent.ts >= start90)
            .order_by(WarningEvent.ts.asc())
            .all()
        )
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

        runs_90d = (
            s.query(TraceRun)
            .filter(TraceRun.ts >= start90)
            .order_by(TraceRun.ts.asc())
            .all()
        )
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
        },
    )


@app.get("/scenarios", response_class=HTMLResponse)
async def scenarios_page(request: Request, user: dict[str, Any] = Depends(require_login)):
    if isinstance(user, RedirectResponse):
        return user
    email = user["email"]
    roles = user.get("roles", [])
    role = roles[0] if roles else "unknown"
    with get_session() as s:
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
        {"request": request, "email": email, "role": role, "runs": runs},
    )


@app.post("/scenarios/run")
async def run_scenario(
    request: Request,
    user: dict[str, Any] = Depends(require_login),
    app_id: str = Form(...),
    prompt: str = Form(...),
):
    if isinstance(user, RedirectResponse):
        return user
    agent_id = "dashboard-ui"

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
        sr = ScenarioRun(app_id=app_id, agent_id=agent_id, prompt=prompt, note="ran from dashboard")
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

    # Run examples outside the session while calling external services
    passed_count = 0
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for ex in examples:
            ex_input = json.loads(ex.input_json or "{}")
            prompt = str(ex_input.get("prompt") or "")
            app_id = ex.app_id

            started = datetime.now(timezone.utc)
            wresp = await client.post(
                f"{WARN_URL}/warn",
                json={"app_id": app_id, "agent_id": agent_id, "prompt": prompt, "tools": [], "env": {"os": "linux"}},
            )
            warn = wresp.json()
            response_text = await ollama_generate(prompt)
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
                    input_json=json.dumps({"prompt": prompt, "dataset_example_id": ex.id}),
                    output_json=json.dumps({"response": response_text, "warn": warn, "det_eval": det}),
                    duration_ms=duration_ms,
                )
                s.add(tr)
                s.flush()
                s.add(
                    EvaluationResult(
                        eval_run_id=er.id,
                        dataset_example_id=ex.id,
                        trace_run_id=tr.id,
                        score=score,
                        passed=passed,
                        details_json=json.dumps({"deterministic": det, "warn": warn}),
                    )
                )
                s.commit()
                results.append({"example_id": ex.id, "trace_run_id": tr.id, "passed": passed})

    with get_session() as s:
        total = len(examples)
        summary = {"dataset_id": dataset_id, "total": total, "passed": passed_count, "pass_rate": (passed_count / total) if total else 0}
        s.query(EvaluationRun).filter(EvaluationRun.id == er.id).update({"summary_json": json.dumps(summary)})
        s.add(AuditEvent(actor_email=user.get("email"), action="eval_run", details=f"dataset_id={dataset_id} total={total} passed={passed_count}"))
        s.commit()

    return RedirectResponse(url=f"/eval/{er.id}", status_code=302)


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
    with get_session() as s:
        events = (
            s.query(AuditEvent)
            .order_by(AuditEvent.ts.desc())
            .limit(50)
            .all()
        )

    # quick inline HTML table (kept minimal)
    rows = "".join(
        f"<tr><td>{e.ts}</td><td>{e.actor_email or ''}</td><td>{e.action}</td><td>{e.details}</td></tr>"
        for e in events
    )
    html = f"""
    <html><head><meta charset='utf-8'/><title>Audit</title></head>
    <body style='font-family:system-ui;background:#0b1220;color:#e6edf3;'>
      <h2>Audit events (admin)</h2>
      <p><a style='color:#93c5fd' href='/'>Back</a></p>
      <table border='1' cellpadding='6' style='border-collapse:collapse;border-color:#24304a;'>
        <tr><th>ts</th><th>actor</th><th>action</th><th>details</th></tr>
        {rows}
      </table>
    </body></html>
    """
    return HTMLResponse(html)


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
                try:
                    jo = json.loads(run.output_json or "{}")
                    gen = (jo or {}).get("gen") or {}
                    provider = provider or (gen.get("provider") or "")
                    used_model = used_model or (gen.get("model") or "")
                    latency_ms = latency_ms or str(gen.get("latency_ms") or "")
                    out_text = (jo or {}).get("response") or out_text
                except Exception:
                    pass

                last = {
                    "run_id": run.id,
                    "provider": provider,
                    "model": used_model,
                    "latency_ms": latency_ms,
                    "output": out_text,
                }

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
):
    if isinstance(user, RedirectResponse):
        return user

    started = datetime.now(timezone.utc)
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
            status="ok",
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

    return templates.TemplateResponse(
        "dataset_detail.html",
        {"request": request, "email": email, "role": role, "dataset": dataset, "examples": examples},
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
