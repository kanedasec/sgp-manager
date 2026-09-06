"""Distributed rate limiting for the pipeline evaluation endpoints.

The previous implementation kept hit counters in a process-local
``defaultdict``. That is invisible once the backend runs more than one
replica behind a load balancer: each replica enforces the configured limit
independently, so the effective limit becomes ``limit * replica_count``
without any error or log to reveal it.

This module counts hits in Redis (shared across replicas) using a fixed
60-second window aligned to the wall clock, incremented atomically via a
Lua script (INCR + conditional EXPIRE) to avoid a race between the two
commands. Redis unavailability degrades to the previous per-process
counter rather than blocking pipeline calls: this endpoint's rate limit is
an anti-abuse control, not the authorization/authentication boundary, so
fail-closed here is a worse trade-off than briefly widening the effective
limit under a Redis outage. Every fallback activation is logged so the
degradation is observable instead of silent.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from threading import Lock

from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings

logger = logging.getLogger("rate_limit")

# INCR the window key; set a TTL only the first time it is created in this
# window so concurrent requests cannot each reset the expiry indefinitely.
_INCR_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""

_WINDOW_SECONDS = 60
_WINDOW_TTL_SECONDS = 65  # small buffer over the window so a slow request still expires

_local_hits: dict[str, deque[float]] = defaultdict(deque)
_local_lock = Lock()

_redis_client: Redis | None = None
_redis_unavailable_logged = False


def _get_redis() -> Redis | None:
    global _redis_client
    settings = get_settings()
    if not settings.redis_url:
        return None
    if _redis_client is None:
        _redis_client = Redis.from_url(
            settings.redis_url,
            socket_connect_timeout=settings.rate_limit_redis_timeout_seconds,
            socket_timeout=settings.rate_limit_redis_timeout_seconds,
        )
    return _redis_client


def _local_hit_count(client: str, limit: int) -> int:
    now = time.monotonic()
    with _local_lock:
        bucket = _local_hits[client]
        while bucket and bucket[0] < now - _WINDOW_SECONDS:
            bucket.popleft()
        bucket.append(now)
        return len(bucket)


def _redis_hit_count(redis: Redis, client: str) -> int:
    window = int(time.time() // _WINDOW_SECONDS)
    key = f"sgp:ratelimit:{client}:{window}"
    return int(redis.eval(_INCR_SCRIPT, 1, key, _WINDOW_TTL_SECONDS))


def hit_count(client: str, limit: int) -> int:
    """Record one hit for ``client`` and return the count within the
    current window. Prefers the shared Redis counter; falls back to a
    process-local counter (logged once per outage) if Redis is configured
    but unreachable, and uses the local counter directly when no
    ``redis_url`` is configured (e.g. tests, single-replica deployments)."""
    global _redis_unavailable_logged
    redis = _get_redis()
    if redis is None:
        return _local_hit_count(client, limit)
    try:
        count = _redis_hit_count(redis, client)
        _redis_unavailable_logged = False
        return count
    except RedisError:
        if not _redis_unavailable_logged:
            logger.warning(
                "rate limit Redis backend unavailable, falling back to per-process counter",
                extra={"client": client},
            )
            _redis_unavailable_logged = True
        return _local_hit_count(client, limit)


def reset_for_tests() -> None:
    """Test-only helper to clear local state between cases."""
    with _local_lock:
        _local_hits.clear()
    global _redis_client, _redis_unavailable_logged
    _redis_client = None
    _redis_unavailable_logged = False
