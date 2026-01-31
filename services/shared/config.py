from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class HotReloadConfig:
    enabled: bool
    poll_seconds: int


class ConfigStore:
    """Simple file-backed config with polling-based hot reload.

    Demo goal: config-driven matchers/policies without shared mutable state between services.
    Each service loads its own config instance.
    """

    def __init__(self, config_path: str | Path | None = None):
        self._path = Path(config_path or os.environ.get("CONFIG_PATH", "/app/config/config.yaml"))
        self._last_mtime: float | None = None
        self._cache: dict[str, Any] = {}
        self._last_load_ts = 0.0

    def _read(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        with self._path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def get(self) -> dict[str, Any]:
        try:
            mtime = self._path.stat().st_mtime if self._path.exists() else None
        except OSError:
            mtime = None

        hot = self.hot_reload()
        now = time.time()

        should_poll = hot.enabled and (now - self._last_load_ts) >= hot.poll_seconds
        changed = (mtime is not None and mtime != self._last_mtime)

        if not self._cache or changed or should_poll:
            self._cache = self._read()
            self._last_mtime = mtime
            self._last_load_ts = now
        return self._cache

    def hot_reload(self) -> HotReloadConfig:
        data = self._cache or self._read() or {}
        hr = (data.get("hot_reload") or {})
        return HotReloadConfig(enabled=bool(hr.get("enabled", True)), poll_seconds=int(hr.get("poll_seconds", 2)))
