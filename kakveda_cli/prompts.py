from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Optional


def _prompt(text: str, default: Optional[str] = None) -> str:
    if default is None:
        s = input(f"{text}: ").strip()
        while not s:
            s = input(f"{text}: ").strip()
        return s

    s = input(f"{text} [{default}]: ").strip()
    return s if s else default


def _prompt_yes_no(text: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    s = input(f"{text} ({suffix}): ").strip().lower()
    if not s:
        return default
    return s in {"y", "yes", "true", "1"}


def _prompt_optional(text: str, default: Optional[str] = None) -> Optional[str]:
    if default is None:
        s = input(f"{text} (blank to skip): ").strip()
        return s or None

    s = input(f"{text} [{default}] (blank to skip): ").strip()
    return s or default


def gen_secret(length: int = 48) -> str:
    # URL-safe random string. Good enough for demo/prod-adjacent.
    return secrets.token_urlsafe(length)


@dataclass(frozen=True)
class AnswersRaw:
    use_prod_compose: bool
    dashboard_db_url: str
    dashboard_jwt_secret: str
    redis_url: Optional[str]
    otel_enabled: bool
    otel_exporter_otlp_endpoint: Optional[str]
    model_provider: str
    model_api_key: Optional[str]
    model_base_url: Optional[str]
    model_name: Optional[str]
    # SMTP config
    smtp_host: Optional[str] = None
    smtp_port: Optional[str] = None
    smtp_user: Optional[str] = None
    smtp_pass: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_tls: Optional[bool] = None


def collect_answers() -> AnswersRaw:
    print("\nKakveda setup wizard\n")

    use_prod = _prompt_yes_no(
        "Use production-like compose file (docker-compose.prod.yml)?",
        default=False,
    )

    if use_prod:
        dashboard_db_url_default = "postgresql+psycopg2://kakveda:change-me@postgres:5432/kakveda"
    else:
        dashboard_db_url_default = "sqlite:////app/data/dashboard.db"

    db_url = _prompt("Dashboard DB URL (DASHBOARD_DB_URL)", default=dashboard_db_url_default)

    want_random_secret = _prompt_yes_no(
        "Generate a strong JWT secret automatically?",
        default=True,
    )
    if want_random_secret:
        jwt_secret = gen_secret(48)
        print("Generated DASHBOARD_JWT_SECRET.")
    else:
        jwt_secret = _prompt("DASHBOARD_JWT_SECRET")

    redis_url = _prompt_optional("Redis URL for revocation/rate-limits (KAKVEDA_REDIS_URL)")

    otel_enabled = _prompt_yes_no("Enable OpenTelemetry export (KAKVEDA_OTEL_ENABLED)", default=False)
    otel_endpoint = None
    if otel_enabled:
        otel_endpoint = _prompt_optional("OTLP endpoint (OTEL_EXPORTER_OTLP_ENDPOINT)")

    # Model provider choice: keep it strict so users don't type "y" or other junk.
    allowed_providers = {"ollama", "openai", "other"}
    while True:
        model_provider = _prompt(
            "Model provider (ollama/openai/other)",
            default="ollama",
        ).strip().lower()

        if model_provider in allowed_providers:
            break

        print(
            f"Invalid provider: {model_provider!r}. Choose one of: ollama, openai, other."
        )

    model_api_key = None
    model_base_url = None
    model_name = None

    if model_provider in {"openai", "other"}:
        model_api_key = _prompt_optional("Model API key (KAKVEDA_MODEL_API_KEY)")
        model_base_url = _prompt_optional("Model base URL (KAKVEDA_MODEL_BASE_URL)")
        model_name = _prompt_optional("Model name (KAKVEDA_MODEL_NAME)")

    # SMTP config
    print("\nSMTP (for password reset emails)")
    smtp_host = _prompt_optional("SMTP host (SMTP_HOST)")
    smtp_port = _prompt_optional("SMTP port (SMTP_PORT)", default="587")
    smtp_user = _prompt_optional("SMTP username (SMTP_USER)")
    smtp_pass = _prompt_optional("SMTP password (SMTP_PASS)")
    smtp_from = _prompt_optional("SMTP from address (SMTP_FROM)", default="noreply@localhost")
    smtp_tls = _prompt_yes_no("Enable TLS for SMTP? (SMTP_TLS)", default=True)

    return AnswersRaw(
        use_prod_compose=use_prod,
        dashboard_db_url=db_url,
        dashboard_jwt_secret=jwt_secret,
        redis_url=redis_url,
        otel_enabled=otel_enabled,
        otel_exporter_otlp_endpoint=otel_endpoint,
        model_provider=model_provider,
        model_api_key=model_api_key,
        model_base_url=model_base_url,
        model_name=model_name,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_pass=smtp_pass,
        smtp_from=smtp_from,
        smtp_tls=smtp_tls,
    )
