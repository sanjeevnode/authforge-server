"""Refresh-token cookie helpers. The refresh token is delivered as an httpOnly
cookie (never in the JSON body / JS) so XSS can't steal it."""

from fastapi import Response

from app.config import settings


def set_refresh_cookie(response: Response, raw_refresh: str) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=raw_refresh,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,  # type: ignore[arg-type]
        domain=settings.cookie_domain or None,
        max_age=settings.refresh_token_expire_days * 24 * 3600,
        path="/",
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        domain=settings.cookie_domain or None,
        path="/",
    )
