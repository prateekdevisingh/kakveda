#!/usr/bin/env python3
"""Dashboard registration + heartbeat utilities (best-effort)."""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Optional

import requests


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if (v is not None and str(v).strip() != "") else default


def _auth_headers(api_key: str) -> dict[str, str]:
    if not api_key:
        return {}
    return {"Authorization": f"Bearer {api_key}", "X-API-Key": api_key}


def register_agent(
    *,
    agent_name: str,
    app_id: str,
    version: str,
    dashboard_url: str,
    api_key: str,
    base_url: str,
    capabilities: Optional[list[str]] = None,
    description: Optional[str] = None,
    timeout: int = 4,
) -> Optional[int]:
    """Register agent in Kakveda dashboard. Never raises."""
    caps = capabilities or []
    payload: dict[str, Any] = {
        "name": agent_name,
        "base_url": base_url.rstrip("/"),
        "description": description or f"{agent_name} ({version})",
        "capabilities": caps,
        # app_id is stored inside metadata for trace alignment
        "metadata": {"app_id": app_id, "version": version},
    }

    try:
        r = requests.post(
            f"{dashboard_url.rstrip('/')}/api/agents/register",
            json=payload,
            headers=_auth_headers(api_key),
            timeout=timeout,
        )
        if not r.ok:
            print(
                "[KAKVEDA SDK] registration failed: "
                f"HTTP {r.status_code} {r.text[:200]}"
            )
            return None
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        agent_id = data.get("agent_id")
        if isinstance(agent_id, int):
            print(f"[KAKVEDA SDK] registered agent_id={agent_id} base_url={base_url}")
            return agent_id
        if isinstance(agent_id, str) and agent_id.isdigit():
            agent_id_int = int(agent_id)
            print(f"[KAKVEDA SDK] registered agent_id={agent_id_int} base_url={base_url}")
            return agent_id_int
        print(f"[KAKVEDA SDK] registration returned unexpected payload: {data}")
        return None
    except Exception as e:
        print(f"[KAKVEDA SDK] registration error: {e}")
        return None


def start_heartbeat(
    *,
    dashboard_url: str,
    api_key: str,
    agent_id: Optional[int],
    interval_sec: int,
) -> None:
    """Start a daemon heartbeat loop. Never raises."""
    if not agent_id:
        print("[KAKVEDA SDK] heartbeat disabled: missing agent_id")
        return

    def _loop() -> None:
        url = dashboard_url.rstrip("/")
        headers = _auth_headers(api_key)
        interval = max(1, int(interval_sec))

        while True:
            try:
                r = requests.post(
                    f"{url}/api/agents/{agent_id}/heartbeat",
                    headers=headers,
                    timeout=4,
                )
                if not r.ok:
                    print(
                        "[KAKVEDA SDK] heartbeat failed: "
                        f"HTTP {r.status_code} {r.text[:120]}"
                    )
            except Exception as e:
                print(f"[KAKVEDA SDK] heartbeat error: {e}")
            time.sleep(interval)

    t = threading.Thread(target=_loop, name="kakveda-heartbeat", daemon=True)
    t.start()
