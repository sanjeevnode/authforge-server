"""Redis-backed fixed-window rate limiting for brute-force-prone auth endpoints."""

from fastapi import HTTPException, status

from app.core.redis_client import redis_client


def enforce_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    """Count one attempt against `key`. Raise 429 once attempts exceed `limit`
    within `window_seconds`.

    Fixed window: the first attempt starts a TTL, and the counter (plus the whole
    window) resets when that TTL expires.
    """
    count = redis_client.incr(key)
    if count == 1:
        # first hit in this window — start the expiry clock
        redis_client.expire(key, window_seconds)
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "detail": "Too many attempts. Try again later.",
                "code": "RATE_LIMITED",
            },
        )


# ponytail: fixed-window (not sliding). Simple + Redis-native; a burst at a window
# boundary can allow ~2x briefly. Upgrade to sliding-window only if that matters.
