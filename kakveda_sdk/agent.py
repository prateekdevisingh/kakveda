#!/usr/bin/env python3
"""Unified KakvedaAgent for governance + events + dashboard visibility."""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from .guard import KakvedaGuard
from .registration import register_agent, start_heartbeat
from .system_probe import ProbeLimits, SystemProbe, SystemProbeEngine


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if (v is not None and str(v).strip() != "") else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "y"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _default_base_url(agent_name: str) -> str:
    return _env("AGENT_BASE_URL", f"http://{agent_name}:8120").rstrip("/")


def _capabilities_from_env() -> list[str]:
    raw = _env("AGENT_CAPABILITIES", "")
    return [c.strip() for c in raw.split(",") if c.strip()]


class KakvedaAgent:
    """Unified integration wrapper for any tool-execution agent."""

    def __init__(
        self,
        *,
        agent_name: Optional[str] = None,
        app_id: Optional[str] = None,
        version: Optional[str] = None,
        dashboard_url: Optional[str] = None,
        dashboard_api_key: Optional[str] = None,
        auto_register: Optional[bool] = None,
        enable_heartbeat: Optional[bool] = None,
        enable_infra_metrics: Optional[bool] = None,
        infra_interval_sec: Optional[int] = None,
        guard: Optional[KakvedaGuard] = None,
        capabilities: Optional[list[str]] = None,
    ) -> None:
        self.agent_name = agent_name or _env("AGENT_NAME", "external-agent")
        self.app_id = app_id or _env("AGENT_APP_ID", self.agent_name)
        self.version = version or _env("AGENT_VERSION", "1.0.0")
        self.dashboard_url = dashboard_url or _env("DASHBOARD_URL", "http://dashboard:8110")
        self.dashboard_api_key = dashboard_api_key or _env("DASHBOARD_API_KEY", "")
        self.auto_register = auto_register if auto_register is not None else _env_bool("AUTO_REGISTER", True)
        self.enable_heartbeat = (
            enable_heartbeat if enable_heartbeat is not None else _env_bool("ENABLE_HEARTBEAT", True)
        )
        self.enable_infra_metrics = (
            enable_infra_metrics if enable_infra_metrics is not None else _env_bool("ENABLE_INFRA_METRICS", True)
        )
        self.infra_interval_sec = infra_interval_sec if infra_interval_sec is not None else _env_int(
            "INFRA_COLLECTION_INTERVAL_SEC", 5
        )
        self.base_url = _default_base_url(self.agent_name)
        self.capabilities = capabilities or _capabilities_from_env()

        self.guard = guard or KakvedaGuard(app_id=self.app_id)

        self.agent_id: Optional[int] = None
        if self.auto_register:
            self.agent_id = register_agent(
                agent_name=self.agent_name,
                app_id=self.app_id,
                version=self.version,
                dashboard_url=self.dashboard_url,
                api_key=self.dashboard_api_key,
                base_url=self.base_url,
                capabilities=self.capabilities,
            )

        if self.enable_heartbeat:
            interval = _env_int("HEARTBEAT_INTERVAL", 15)
            start_heartbeat(
                dashboard_url=self.dashboard_url,
                api_key=self.dashboard_api_key,
                agent_id=self.agent_id,
                interval_sec=interval,
            )

        self._system_probe_engine: Optional[SystemProbeEngine] = None
        if self.enable_infra_metrics:
            self._start_system_probe()

    def execute(
        self,
        *,
        prompt: str,
        tool_name: str,
        execute_fn: Callable[[], Any],
        metadata: Optional[dict[str, Any]] = None,
        model_name: Optional[str] = None,
        return_object: bool = False,
    ) -> Any:
        """Wrap tool execution with Kakveda governance + tracing."""
        return self.guard.guarded_execute(
            prompt=prompt,
            tool_name=tool_name,
            execute_fn=execute_fn,
            metadata=metadata,
            model_name=model_name,
            return_object=return_object,
        )

    def _start_system_probe(self) -> None:
        limits = ProbeLimits(
            max_interfaces=_env_int("INFRA_MAX_INTERFACES", 50),
            max_containers=_env_int("INFRA_MAX_CONTAINERS", 100),
            max_partitions=_env_int("INFRA_MAX_PARTITIONS", 20),
        )
        probe = SystemProbe(limits=limits)

        endpoint_enabled = _env_bool("INFRA_METRICS_ENDPOINT_ENABLED", False)
        if endpoint_enabled:
            host = _env("INFRA_METRICS_ENDPOINT_HOST", "0.0.0.0")
            port = _env_int("INFRA_METRICS_ENDPOINT_PORT", 9320)
            probe.start_metrics_endpoint(host=host, port=port)

        topic = _env("INFRA_METRICS_TOPIC", "infra.metrics")
        source_agent_id = self.agent_id if self.agent_id is not None else self.agent_name

        def _publish(payload: dict[str, Any]) -> None:
            event = {
                "trace_id": payload.get("timestamp"),
                "ts": payload.get("timestamp"),
                "app_id": self.app_id,
                "agent_id": source_agent_id,
                "node_metrics_payload": payload,
                "env": {
                    "event_name": topic,
                    "status": "completed",
                    "source": "system_probe",
                },
                "infra": payload.get("infra", {}),
            }
            self.guard.publish_event(topic, event)

        self._system_probe_engine = SystemProbeEngine(
            agent_id=str(source_agent_id),
            interval_sec=self.infra_interval_sec,
            on_payload=_publish,
            probe=probe,
        )
        self._system_probe_engine.start()
