from __future__ import annotations

from typing import Any


def setup_otel(*, service_name: str) -> None:
    """Best-effort OpenTelemetry initialization.

    This is intentionally optional and safe for open source demos:
    - Only activates when KAKVEDA_OTEL_ENABLED=1
    - Avoids hard dependency failures when packages aren't installed
    """

    import os

    enabled = os.environ.get("KAKVEDA_OTEL_ENABLED", "0").lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return

    try:
        from opentelemetry import trace  # type: ignore
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
    except Exception:
        # If deps not installed, keep app working.
        return

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")

    resource = Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", service_name)})
    provider = TracerProvider(resource=resource)

    exporter_kwargs: dict[str, Any] = {}
    if endpoint:
        exporter_kwargs["endpoint"] = endpoint

    exporter = OTLPSpanExporter(**exporter_kwargs)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)

    # Instrumentation happens per app; we expose helper the service can call.


def instrument_fastapi(app: Any) -> None:
    import os

    enabled = os.environ.get("KAKVEDA_OTEL_ENABLED", "0").lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore

        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        return
