from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


try:
    # redis-py supports sync + asyncio in the same package.
    from redis import Redis  # type: ignore
except Exception:  # pragma: no cover
    Redis = None  # type: ignore


@dataclass(frozen=True)
class RedisClient:
    url: str

    def connect(self) -> Any:
        if Redis is None:
            raise RuntimeError("redis package not installed")
        # decode_responses=True keeps values as str which simplifies comparisons.
        return Redis.from_url(self.url, decode_responses=True)


class RevocationStore:
    """Store revoked JTIs with TTL.

    In production this should be Redis (shared across replicas).
    """

    def __init__(self, *, redis_url: str | None, prefix: str = "kakveda:sess"):
        self._redis_url = redis_url
        self._prefix = prefix
        self._local: set[str] = set()

    def _key(self, jti: str) -> str:
        return f"{self._prefix}:revoked:{jti}"

    def revoke(self, jti: str, *, ttl_seconds: int) -> None:
        jti = (jti or "").strip()
        if not jti:
            return
        if self._redis_url:
            r = RedisClient(self._redis_url).connect()
            # Value doesn't matter; we rely on existence.
            r.set(self._key(jti), "1", ex=max(1, int(ttl_seconds)))
        else:
            # demo fallback
            self._local.add(jti)

    def is_revoked(self, jti: str) -> bool:
        jti = (jti or "").strip()
        if not jti:
            return False
        if self._redis_url:
            r = RedisClient(self._redis_url).connect()
            return bool(r.exists(self._key(jti)))
        return jti in self._local


class RateLimiter:
    """Fixed-window limiter.

    - If redis_url is set: distributed limiter via INCR + EXPIRE
    - Else: caller should fall back to in-memory logic (or accept best-effort)
    """

    def __init__(self, *, redis_url: str | None, prefix: str = "kakveda:rl"):
        self._redis_url = redis_url
        self._prefix = prefix

    def allowed(self, key: str, *, limit: int, window_s: int) -> bool:
        if not self._redis_url:
            raise RuntimeError("redis not configured")
        now = int(time.time())
        bucket = int(now / max(1, int(window_s)))
        k = f"{self._prefix}:{key}:{bucket}"
        r = RedisClient(self._redis_url).connect()
        n = int(r.incr(k))
        # Expire slightly after window.
        if n == 1:
            r.expire(k, max(1, int(window_s) + 2))
        return n <= int(limit)
