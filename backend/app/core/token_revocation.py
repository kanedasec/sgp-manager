"""Server-side JWT revocation for admin session tokens.

The access token itself carries no server-side state, so logout could
only ever clear the browser's httpOnly cookie -- a stolen Bearer token
kept working for its full ~60 minute lifetime with no way to cut it off.
This module adds two independent, additive revocation mechanisms on top
of the existing stateless JWT, both backed by the same Redis instance
introduced in PR #14 for distributed rate limiting:

1. Single-token revocation (explicit logout): every access token now
   carries a random `jti` claim. Logging out adds that jti to a denylist
   with a TTL equal to the token's remaining lifetime, so the denylist
   entry never outlives the token it revokes and storage usage is
   naturally bounded.

2. Whole-user revocation (administrator force-logout): an administrator
   can invalidate every token already issued to a user (e.g. a
   compromised account) without knowing any of their individual jtis, by
   recording a "tokens issued before this instant are void" cutoff per
   user, with a TTL of the JWT's own max lifetime -- any token older than
   that would already be expired regardless.

Fail-open on a Redis outage: an unreachable revocation store causes the
revocation checks to log a warning and return "not revoked" rather than
rejecting every request. Before this feature existed no revocation was
possible at all, so this outage behavior is not a regression versus the
prior baseline -- it only means the *new* protection is temporarily
unavailable. This mirrors the existing rate limiter's
fail-open-on-Redis-outage convention (see app.core.rate_limit) rather
than the fail-closed convention used for authentication/authorization
decisions that predate Redis.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from uuid import UUID

from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings

logger = logging.getLogger("token_revocation")

_JTI_KEY_PREFIX = "sgp:revoked-jti:"
_USER_KEY_PREFIX = "sgp:revoked-after:"

_redis_client: Redis | None = None
_redis_unavailable_logged = False

# In-process fallback so single-replica/test deployments without REDIS_URL,
# or a Redis outage, still get real revocation instead of a silent no-op.
# Each value is (expires_at_monotonic, payload).
_local_revoked_jtis: dict[str, float] = {}
_local_revoked_after: dict[str, tuple[float, float]] = {}  # user_id -> (expires_at, cutoff_timestamp)


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


def _warn_once_on_outage() -> None:
    global _redis_unavailable_logged
    if not _redis_unavailable_logged:
        logger.warning("token revocation Redis backend unavailable, falling back to per-process store")
        _redis_unavailable_logged = True


def _prune_local_jtis() -> None:
    now = time.monotonic()
    for key in [key for key, expires_at in _local_revoked_jtis.items() if expires_at <= now]:
        _local_revoked_jtis.pop(key, None)


def _prune_local_users() -> None:
    now = time.monotonic()
    for key in [key for key, (expires_at, _) in _local_revoked_after.items() if expires_at <= now]:
        _local_revoked_after.pop(key, None)


def revoke_token(jti: str, ttl_seconds: int) -> None:
    """Denylists a single token by its jti until it would have expired
    anyway. Called on explicit /auth/logout."""
    if ttl_seconds <= 0:
        return
    redis = _get_redis()
    if redis is not None:
        try:
            redis.setex(f"{_JTI_KEY_PREFIX}{jti}", ttl_seconds, "1")
            return
        except RedisError:
            _warn_once_on_outage()
    _local_revoked_jtis[jti] = time.monotonic() + ttl_seconds


def is_token_revoked(jti: str) -> bool:
    redis = _get_redis()
    if redis is not None:
        try:
            return bool(redis.exists(f"{_JTI_KEY_PREFIX}{jti}"))
        except RedisError:
            _warn_once_on_outage()
    _prune_local_jtis()
    return jti in _local_revoked_jtis


def revoke_all_for_user(user_id: UUID, ttl_seconds: int) -> None:
    """Invalidates every token already issued to a user, without needing
    to know any individual jti. Used by an administrator's force-logout
    action. ttl_seconds should be at least the JWT's max lifetime -- any
    older token is already expired on its own."""
    if ttl_seconds <= 0:
        return
    # JWT "iat" round-trips through PyJWT as a whole-second integer (it
    # truncates a datetime to a POSIX second on encode). Storing the cutoff
    # with sub-second precision would make a token minted in the *same*
    # wall-clock second as this call compare as "issued before" the cutoff
    # purely due to floor() rounding, wrongly revoking a session that was
    # actually issued after the force-logout. Flooring the cutoff to whole
    # seconds too keeps the comparison consistent with iat's granularity.
    cutoff = float(int(datetime.now(UTC).timestamp()))
    redis = _get_redis()
    if redis is not None:
        try:
            redis.setex(f"{_USER_KEY_PREFIX}{user_id}", ttl_seconds, str(cutoff))
            return
        except RedisError:
            _warn_once_on_outage()
    _local_revoked_after[str(user_id)] = (time.monotonic() + ttl_seconds, cutoff)


def user_tokens_revoked_before(user_id: UUID) -> float | None:
    """Returns the UNIX timestamp before which every token for this user
    is void, or None if the user has no active force-logout in effect."""
    redis = _get_redis()
    if redis is not None:
        try:
            value = redis.get(f"{_USER_KEY_PREFIX}{user_id}")
            if value is None:
                return None
            return float(value)
        except RedisError:
            _warn_once_on_outage()
    _prune_local_users()
    entry = _local_revoked_after.get(str(user_id))
    return entry[1] if entry else None


def reset_for_tests() -> None:
    global _redis_client, _redis_unavailable_logged
    _local_revoked_jtis.clear()
    _local_revoked_after.clear()
    _redis_client = None
    _redis_unavailable_logged = False
