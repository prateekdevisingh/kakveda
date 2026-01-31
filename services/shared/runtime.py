from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class RuntimeConfig:
    """Runtime configuration shared across services.

    This keeps production switches in *one* place and avoids copy/paste env parsing.
    """

    env: str
    log_level: str
    log_format: str
    request_id_header: str

    # Security / secrets
    dashboard_jwt_secret: str

    # Redis (optional)
    redis_url: str | None
    session_store_prefix: str
    rate_limit_prefix: str

    # Observability (optional)
    otel_enabled: bool
    otel_service_name: str
    otel_exporter_otlp_endpoint: str | None


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    if v is None:
        return default
    v = str(v).strip()
    return v if v != "" else default


def _env_bool(name: str, default: bool = False) -> bool:
    v = _env(name)
    if v is None:
        return default
    return v.lower() in {"1", "true", "yes", "y", "on"}


def get_runtime_config(*, service_name: str) -> RuntimeConfig:
    env = (_env("KAKVEDA_ENV", _env("ENV", "dev")) or "dev").lower()

    # Log format: json or text
    log_format = (_env("KAKVEDA_LOG_FORMAT", "json") or "json").lower()
    log_level = (_env("KAKVEDA_LOG_LEVEL", "INFO") or "INFO").upper()

    request_id_header = (_env("KAKVEDA_REQUEST_ID_HEADER", "x-request-id") or "x-request-id").lower()

    # Secrets
    dashboard_jwt_secret = _env("DASHBOARD_JWT_SECRET", "dev-secret-change-me") or "dev-secret-change-me"

    # Redis
    redis_url = _env("KAKVEDA_REDIS_URL")
    # Allow teams to plug an external redis with different prefixes for multi-env.
    session_store_prefix = _env("KAKVEDA_SESSION_PREFIX", "kakveda:sess") or "kakveda:sess"
    rate_limit_prefix = _env("KAKVEDA_RATE_LIMIT_PREFIX", "kakveda:rl") or "kakveda:rl"

    # OTel
    otel_enabled = _env_bool("KAKVEDA_OTEL_ENABLED", default=False)
    otel_service_name = _env("OTEL_SERVICE_NAME", service_name) or service_name
    otel_exporter_otlp_endpoint = _env("OTEL_EXPORTER_OTLP_ENDPOINT")

    return RuntimeConfig(
        env=env,
        log_level=log_level,
        log_format=log_format,
        request_id_header=request_id_header,
        dashboard_jwt_secret=dashboard_jwt_secret,
        redis_url=redis_url,
        session_store_prefix=session_store_prefix,
        rate_limit_prefix=rate_limit_prefix,
        otel_enabled=otel_enabled,
        otel_service_name=otel_service_name,
        otel_exporter_otlp_endpoint=otel_exporter_otlp_endpoint,
    )


def _json_log_record(level: str, msg: str, *, extra: Mapping[str, Any] | None = None) -> str:
    body: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "msg": msg,
    }
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            body[k] = v
    return json.dumps(body, ensure_ascii=False)


def setup_logging(*, service_name: str) -> None:
    cfg = get_runtime_config(service_name=service_name)
    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.log_level, logging.INFO))

    # Clear default handlers (uvicorn adds its own; this keeps tests predictable)
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(stream=sys.stdout)

    if cfg.log_format == "json":
        class JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
                extra = {
                    "logger": record.name,
                    "service": service_name,
                }
                # Allow app code to attach extra context
                for key in ("request_id", "path", "method", "status_code", "duration_ms"):
                    if hasattr(record, key):
                        extra[key] = getattr(record, key)
                return _json_log_record(record.levelname, record.getMessage(), extra=extra)

        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    root.addHandler(handler)


def ensure_request_id(incoming: str | None = None) -> str:
    """Return a request id; generate if missing."""
    v = (incoming or "").strip()
    if v:
        return v[:128]
    return uuid.uuid4().hex
