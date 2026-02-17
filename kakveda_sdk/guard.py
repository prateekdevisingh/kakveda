#!/usr/bin/env python3
"""Kakveda guard implementation (production-grade)."""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

try:
    import requests
except ImportError:
    raise ImportError("requests library required. Install with: pip install requests")


class ExecutionStatus:
    completed = "completed"
    error = "error"
    blocked = "blocked"
    approval_required = "approval_required"


class KakvedaGuard:
    """Framework-agnostic middleware for Kakveda governance and observability."""

    def __init__(
        self,
        warn_url: Optional[str] = None,
        event_bus_url: Optional[str] = None,
        app_id: Optional[str] = None,
        environment: Optional[str] = None,
        fail_closed: Optional[bool] = None,
        timeout: int = 10,
    ):
        self.warn_url = warn_url or os.getenv(
            "KAKVEDA_WARN_URL",
            "http://warning-policy:8105/warn",
        )
        self.event_bus_url = event_bus_url or os.getenv(
            "KAKVEDA_EVENT_BUS_URL",
            "http://event-bus:8100/publish",
        )
        self.app_id = (
            app_id
            or os.getenv("AGENT_APP_ID")
            or os.getenv("KAKVEDA_APP_ID")
            or "external-agent"
        )
        self.agent_id = os.getenv("AGENT_NAME", "external-agent")
        self.environment = environment or os.getenv("KAKVEDA_ENVIRONMENT", "prod")
        self.fail_closed = fail_closed if fail_closed is not None else (
            os.getenv("KAKVEDA_FAIL_CLOSED", "true").lower() == "true"
        )
        self.timeout = timeout
        self.event_format = os.getenv("KAKVEDA_EVENT_FORMAT", "topic").strip().lower()
        self.warn_contract = os.getenv("KAKVEDA_WARN_CONTRACT", "dual").strip().lower()
        self.strict_mode = os.getenv("KAKVEDA_STRICT_MODE", "false").lower() == "true"

        deny_raw = os.getenv("KAKVEDA_LOCAL_DENY_TOOLS", "")
        self.local_deny_tools = {t.strip() for t in deny_raw.split(",") if t.strip()}

        self.retries = int(os.getenv("KAKVEDA_HTTP_RETRIES", "2") or 2)
        self.backoff_base_sec = float(
            os.getenv("KAKVEDA_HTTP_BACKOFF_BASE_SEC", "0.25") or 0.25
        )

        self.circuit_breaker_sec = int(os.getenv("KAKVEDA_CIRCUIT_BREAKER_SEC", "0") or 0)
        self._kakveda_unavailable_until = 0.0

        self.session = requests.Session()
        self.auth_token = os.getenv("KAKVEDA_AUTH_TOKEN", "").strip()
        self.response_max_len = int(os.getenv("KAKVEDA_RESPONSE_MAX_LEN", "5000") or 5000)

    def _now(self) -> float:
        return time.time()

    def _base_headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    def _sleep_backoff(self, attempt_idx: int) -> None:
        delay = self.backoff_base_sec * (2 ** attempt_idx)
        time.sleep(delay)

    def _circuit_open(self) -> bool:
        return self.circuit_breaker_sec > 0 and self._now() < self._kakveda_unavailable_until

    def _open_circuit(self) -> None:
        if self.circuit_breaker_sec > 0:
            self._kakveda_unavailable_until = self._now() + float(self.circuit_breaker_sec)

    def _post_json_with_retries(
        self,
        url: str,
        payload: Dict[str, Any],
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        idempotent: bool = True,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        t = timeout if timeout is not None else self.timeout
        attempts = 1 + max(0, int(self.retries))
        last_err: Optional[str] = None

        for i in range(attempts):
            try:
                r = self.session.post(url, json=payload, headers=headers, timeout=t)
                if r.status_code in {429, 500, 502, 503, 504} and idempotent and i < attempts - 1:
                    last_err = f"HTTP {r.status_code}"
                    self._sleep_backoff(i)
                    continue
                r.raise_for_status()
                if r.headers.get("content-type", "").startswith("application/json"):
                    return r.json(), None
                return {}, None
            except Exception as e:
                last_err = str(e)
                if not idempotent or i >= attempts - 1:
                    break
                self._sleep_backoff(i)

        return None, last_err

    def _safe_response_str(self, value: Any) -> str:
        if value is None:
            s = ""
        elif isinstance(value, (bytes, bytearray, memoryview)):
            s = f"<bytes len={len(value)}>"
        else:
            try:
                if isinstance(value, (dict, list, tuple)):
                    s = json.dumps(value, ensure_ascii=False, default=str)
                else:
                    s = str(value)
            except Exception:
                s = repr(value)

        mx = self.response_max_len
        if mx and mx > 0 and len(s) > mx:
            s = s[:mx] + "...[truncated]"
        return s

    def preflight(self, prompt: str, tool: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        metadata = metadata or {}

        if self._circuit_open():
            msg = "Kakveda circuit open; skipping preflight"
            if self.fail_closed:
                return {
                    "action": "block",
                    "confidence": 0.0,
                    "pattern_id": "kakveda-unavailable",
                    "message": msg,
                    "governance_error": msg,
                }
            return {
                "action": "silent",
                "confidence": 0.0,
                "pattern_id": "kakveda-unavailable",
                "message": msg,
                "governance_error": msg,
            }

        env_obj: Dict[str, Any] = {
            "app_id": self.app_id,
            "agent_id": self.agent_id,
            "environment": self.environment,
            **metadata,
        }

        payload: Dict[str, Any] = {"prompt": prompt, "tools": [tool], "env": env_obj}
        if self.warn_contract in {"dual", "top_level"}:
            payload["app_id"] = self.app_id
            payload["agent_id"] = self.agent_id

        headers = self._base_headers()
        tp = str(metadata.get("traceparent") or "").strip()
        ts_ = str(metadata.get("tracestate") or "").strip()
        if tp:
            headers["traceparent"] = tp
        if ts_:
            headers["tracestate"] = ts_

        data, err = self._post_json_with_retries(
            self.warn_url, payload, headers=headers, idempotent=True
        )
        if data is not None:
            return data

        self._open_circuit()
        if self.fail_closed:
            return {
                "action": "block",
                "confidence": 0.0,
                "pattern_id": "kakveda-unavailable",
                "message": f"Kakveda unreachable: {err}",
                "governance_error": err,
            }
        return {
            "action": "silent",
            "confidence": 0.0,
            "pattern_id": "kakveda-unavailable",
            "message": f"Kakveda unreachable, allowing execution: {err}",
            "governance_error": err,
        }

    def publish_event(self, topic: str, event: Dict[str, Any]) -> bool:
        fmt = self.event_format
        if fmt not in {"topic", "flat"}:
            fmt = "topic"

        if fmt == "topic":
            payload = {"topic": topic, "event": event}
        else:
            payload = {
                "event_type": topic,
                "app_id": str(event.get("app_id") or self.app_id),
                "payload": event,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        headers = self._base_headers()
        env = event.get("env") if isinstance(event.get("env"), dict) else {}
        tp = str(env.get("traceparent") or "").strip()
        ts_ = str(env.get("tracestate") or "").strip()
        if tp:
            headers["traceparent"] = tp
        if ts_:
            headers["tracestate"] = ts_

        data, err = self._post_json_with_retries(
            self.event_bus_url, payload, headers=headers, idempotent=True
        )
        if data is not None:
            return True

        print(f"[KAKVEDA] Event publishing failed ({topic}): {err}")
        return False

    def publish(self, event_type: str, payload: Dict[str, Any]) -> bool:
        return self.publish_event(event_type, payload)

    def guarded_execute(
        self,
        prompt: str,
        tool_name: str,
        execute_fn: Callable[[], Any],
        metadata: Optional[Dict[str, Any]] = None,
        model_name: Optional[str] = None,
        return_object: bool = False,
    ) -> Any:
        metadata = metadata or {}
        if os.getenv("KAKVEDA_RETURN_OBJECT", "false").lower() == "true":
            return_object = True

        correlation_id = str(metadata.get("correlation_id") or "").strip() or None
        trace_id = str(metadata.get("trace_id") or "").strip() or uuid.uuid4().hex
        ts = datetime.now(timezone.utc).isoformat()

        if tool_name in self.local_deny_tools:
            status = ExecutionStatus.blocked
            policy_action = "local_deny"
            env = {
                **metadata,
                "status": status,
                "event_name": "trace.ingested",
                "policy_action": policy_action,
                "correlation_id": correlation_id,
                "trace_id": trace_id,
                "governance_error": None,
                "execution_error": None,
                "error": "blocked_by_local_policy",
            }
            self.publish_event(
                "trace.ingested",
                {
                    "trace_id": trace_id,
                    "ts": ts,
                    "app_id": self.app_id,
                    "agent_id": self.agent_id,
                    "prompt": prompt,
                    "response": "",
                    "model": model_name,
                    "tools": [tool_name],
                    "env": env,
                },
            )
            if return_object:
                return {
                    "result": None,
                    "status": status,
                    "policy_action": policy_action,
                    "confidence": 0.0,
                    "trace_id": trace_id,
                }
            return None

        total_started = time.perf_counter()

        preflight_started = time.perf_counter()
        decision = self.preflight(prompt, tool_name, metadata)
        preflight_time_ms = int((time.perf_counter() - preflight_started) * 1000)
        action = decision.get("action", "silent")
        confidence = decision.get("confidence", 0.0)
        pattern_id = decision.get("pattern_id", "unknown")
        governance_error = decision.get("governance_error")
        policy_action = action

        if self.strict_mode and self.environment.lower() in {"prod", "production"}:
            if action in {"warn", "require-approval"}:
                action = "block"
                policy_action = "block(strict_mode)"
                governance_error = governance_error or "strict_mode_enforced"

        print(f"[KAKVEDA] preflight: action={action} confidence={confidence:.2f}")

        if action == "block":
            print("[KAKVEDA] Execution blocked by policy")
            total_time_ms = int((time.perf_counter() - total_started) * 1000)
            self.publish_event(
                "trace.ingested",
                {
                    "trace_id": trace_id,
                    "ts": ts,
                    "app_id": self.app_id,
                    "agent_id": self.agent_id,
                    "prompt": prompt,
                    "response": "",
                    "model": model_name,
                    "tools": [tool_name],
                    "env": {
                        **metadata,
                        "status": ExecutionStatus.blocked,
                        "event_name": "trace.ingested",
                        "duration_ms": total_time_ms,
                        "preflight_time_ms": preflight_time_ms,
                        "execution_time_ms": 0,
                        "total_time_ms": total_time_ms,
                        "policy_action": policy_action,
                        "pattern_id": pattern_id,
                        "confidence": confidence,
                        "correlation_id": correlation_id,
                        "trace_id": trace_id,
                        "governance_error": governance_error,
                        "execution_error": None,
                        "error": "blocked_by_policy",
                    },
                },
            )
            if return_object:
                return {
                    "result": None,
                    "status": ExecutionStatus.blocked,
                    "policy_action": policy_action,
                    "confidence": confidence,
                    "trace_id": trace_id,
                }
            return None

        if action == "require-approval":
            approval_env = os.getenv("KAKVEDA_AUTO_APPROVE", "false")
            approved = approval_env.lower() == "true"
            print(f"[KAKVEDA] Requires approval: auto_approve={approved}")
            if not approved:
                total_time_ms = int((time.perf_counter() - total_started) * 1000)
                self.publish_event(
                    "trace.ingested",
                    {
                        "trace_id": trace_id,
                        "ts": ts,
                        "app_id": self.app_id,
                        "agent_id": self.agent_id,
                        "prompt": prompt,
                        "response": "",
                        "model": model_name,
                        "tools": [tool_name],
                        "env": {
                            **metadata,
                            "status": ExecutionStatus.approval_required,
                            "event_name": "trace.ingested",
                            "duration_ms": total_time_ms,
                            "preflight_time_ms": preflight_time_ms,
                            "execution_time_ms": 0,
                            "total_time_ms": total_time_ms,
                            "policy_action": policy_action,
                            "pattern_id": pattern_id,
                            "confidence": confidence,
                            "correlation_id": correlation_id,
                            "trace_id": trace_id,
                            "governance_error": governance_error,
                            "execution_error": None,
                            "error": "approval_required",
                        },
                    },
                )
                if return_object:
                    return {
                        "result": None,
                        "status": ExecutionStatus.approval_required,
                        "policy_action": policy_action,
                        "confidence": confidence,
                        "trace_id": trace_id,
                    }
                return None

        if action == "warn":
            message = decision.get("message", "Warning issued")
            print(f"[KAKVEDA] Warning: {message}")

        exec_started = time.perf_counter()
        execution_result = None
        execution_error: Optional[str] = None
        try:
            execution_result = execute_fn()
            is_failure = False
        except Exception as e:
            execution_error = str(e)
            is_failure = True
            print(f"[KAKVEDA] Execution failed: {execution_error}")
        execution_time_ms = int((time.perf_counter() - exec_started) * 1000)

        total_time_ms = int((time.perf_counter() - total_started) * 1000)
        status = ExecutionStatus.error if is_failure else ExecutionStatus.completed
        self.publish_event(
            "trace.ingested",
            {
                "trace_id": trace_id,
                "ts": ts,
                "app_id": self.app_id,
                "agent_id": self.agent_id,
                "prompt": prompt,
                "response": self._safe_response_str(execution_result),
                "model": model_name,
                "tools": [tool_name],
                "env": {
                    **metadata,
                    "status": status,
                    "event_name": "trace.ingested",
                    "duration_ms": total_time_ms,
                    "preflight_time_ms": preflight_time_ms,
                    "execution_time_ms": execution_time_ms,
                    "total_time_ms": total_time_ms,
                    "policy_action": policy_action,
                    "pattern_id": pattern_id,
                    "confidence": confidence,
                    "correlation_id": correlation_id,
                    "trace_id": trace_id,
                    "governance_error": governance_error,
                    "execution_error": execution_error,
                    "error": execution_error,
                },
            },
        )

        if return_object:
            return {
                "result": execution_result,
                "status": status,
                "policy_action": policy_action,
                "confidence": confidence,
                "trace_id": trace_id,
            }
        return execution_result


class AsyncKakvedaGuard:
    """Async-compatible guard (minimal), using httpx."""

    def __init__(
        self,
        warn_url: Optional[str] = None,
        event_bus_url: Optional[str] = None,
        app_id: Optional[str] = None,
        environment: Optional[str] = None,
        timeout: float = 10.0,
    ):
        try:
            import httpx  # noqa: F401
        except Exception as e:
            raise ImportError("AsyncKakvedaGuard requires httpx. Install with: pip install httpx") from e

        self.warn_url = warn_url or os.getenv("KAKVEDA_WARN_URL", "http://warning-policy:8105/warn")
        self.event_bus_url = event_bus_url or os.getenv("KAKVEDA_EVENT_BUS_URL", "http://event-bus:8100/publish")
        self.app_id = app_id or os.getenv("AGENT_APP_ID") or os.getenv("KAKVEDA_APP_ID") or "external-agent"
        self.agent_id = os.getenv("AGENT_NAME", "external-agent")
        self.environment = environment or os.getenv("KAKVEDA_ENVIRONMENT", "prod")
        self.timeout = float(timeout)
        self.event_format = os.getenv("KAKVEDA_EVENT_FORMAT", "topic").strip().lower()
        self.warn_contract = os.getenv("KAKVEDA_WARN_CONTRACT", "dual").strip().lower()
        self.retries = int(os.getenv("KAKVEDA_HTTP_RETRIES", "2") or 2)
        self.backoff_base_sec = float(os.getenv("KAKVEDA_HTTP_BACKOFF_BASE_SEC", "0.25") or 0.25)
        self.circuit_breaker_sec = int(os.getenv("KAKVEDA_CIRCUIT_BREAKER_SEC", "0") or 0)
        self._warn_unavailable_until = 0.0
        self.auth_token = os.getenv("KAKVEDA_AUTH_TOKEN", "").strip()

    def _base_headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    async def _sleep_backoff(self, attempt_idx: int) -> None:
        import asyncio

        delay = self.backoff_base_sec * (2 ** attempt_idx)
        await asyncio.sleep(delay)

    async def preflight(self, prompt: str, tool: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        import httpx
        import time as _t

        metadata = metadata or {}
        if self.circuit_breaker_sec > 0 and _t.time() < self._warn_unavailable_until:
            return {
                "action": "silent",
                "confidence": 0.0,
                "pattern_id": "kakveda-unavailable",
                "message": "Kakveda circuit open; skipping preflight",
                "governance_error": "circuit_open",
            }

        env_obj: Dict[str, Any] = {
            "app_id": self.app_id,
            "agent_id": self.agent_id,
            "environment": self.environment,
            **metadata,
        }
        payload: Dict[str, Any] = {"prompt": prompt, "tools": [tool], "env": env_obj}
        if self.warn_contract in {"dual", "top_level"}:
            payload["app_id"] = self.app_id
            payload["agent_id"] = self.agent_id

        headers = self._base_headers()
        tp = str(metadata.get("traceparent") or "").strip()
        ts_ = str(metadata.get("tracestate") or "").strip()
        if tp:
            headers["traceparent"] = tp
        if ts_:
            headers["tracestate"] = ts_

        attempts = 1 + max(0, int(self.retries))
        last_err: Optional[str] = None
        for i in range(attempts):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    r = await client.post(self.warn_url, json=payload, headers=headers)
                    if r.status_code in {429, 500, 502, 503, 504} and i < attempts - 1:
                        last_err = f"HTTP {r.status_code}"
                        await self._sleep_backoff(i)
                        continue
                    r.raise_for_status()
                    return r.json()
            except Exception as e:
                last_err = str(e)
                if i >= attempts - 1:
                    break
                await self._sleep_backoff(i)

        if self.circuit_breaker_sec > 0:
            self._warn_unavailable_until = _t.time() + float(self.circuit_breaker_sec)
        return {
            "action": "silent",
            "confidence": 0.0,
            "pattern_id": "kakveda-unavailable",
            "message": f"Kakveda unreachable: {last_err}",
            "governance_error": last_err,
        }

    async def publish_event(self, topic: str, event: Dict[str, Any]) -> bool:
        import httpx

        fmt = self.event_format if self.event_format in {"topic", "flat"} else "topic"
        if fmt == "topic":
            payload = {"topic": topic, "event": event}
        else:
            payload = {
                "event_type": topic,
                "app_id": str(event.get("app_id") or self.app_id),
                "payload": event,
            }

        headers = self._base_headers()
        env = event.get("env") if isinstance(event.get("env"), dict) else {}
        tp = str(env.get("traceparent") or "").strip()
        ts_ = str(env.get("tracestate") or "").strip()
        if tp:
            headers["traceparent"] = tp
        if ts_:
            headers["tracestate"] = ts_

        attempts = 1 + max(0, int(self.retries))
        for i in range(attempts):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    r = await client.post(self.event_bus_url, json=payload, headers=headers)
                    if r.status_code in {429, 500, 502, 503, 504} and i < attempts - 1:
                        await self._sleep_backoff(i)
                        continue
                    r.raise_for_status()
                return True
            except Exception:
                if i >= attempts - 1:
                    return False
                await self._sleep_backoff(i)
        return False
