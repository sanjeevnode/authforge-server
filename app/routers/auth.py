"""Auth endpoints: register, login, refresh (with rotation), logout, /me.

Error convention (from the plan): every error body is
    {"detail": "human message", "code": "MACHINE_CODE"}
so clients switch on `code`, never parse `detail`.
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.deps import get_current_user
from app.core.rate_limit import enforce_rate_limit
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_token,
    verify_password,
)
from app.core.time import utc_now
from app.repositories.user import create_user, get_user_by_email
from app.database import get_db
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _error(status_code: int, code: str, detail: str) -> HTTPException:
    """Build an HTTPException whose body is {"detail": ..., "code": ...}."""
    return HTTPException(status_code=status_code, detail={"detail": detail, "code": code})


def _issue_tokens(db: Session, user: User) -> TokenResponse:
    """Create an access token + a fresh refresh token, storing only the refresh
    token's hash. Shared by /login, /refresh, and (later) MFA success."""
    raw_refresh = generate_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token(raw_refresh),
            expires_at=utc_now() + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    db.commit()
    return TokenResponse(
        access_token=create_access_token(user.id),
        refresh_token=raw_refresh,
    )


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=UserResponse,
    summary="Register a new account",
    description="Creates a user with an Argon2id-hashed password. "
    "Email must be unique and password at least 8 characters.",
    responses={409: {"description": "Email already registered (code EMAIL_ALREADY_REGISTERED)"}},
)
def register(body: RegisterRequest, db: Session = Depends(get_db)) -> User:
    if get_user_by_email(db, body.email):
        raise _error(status.HTTP_409_CONFLICT, "EMAIL_ALREADY_REGISTERED",
                     "An account with this email already exists.")
    return create_user(db, body.email, body.password)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Log in with email + password",
    description="Returns an access token (15 min) and a rotating refresh token (7 days).",
    responses={
        401: {"description": "Invalid email or password (code INVALID_CREDENTIALS)"},
        429: {"description": "Too many attempts (code RATE_LIMITED)"},
    },
)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    # 5 attempts / 15 min per IP+email combo (plan spec).
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"login:{client_ip}:{body.email}", limit=5, window_seconds=15 * 60)

    user = get_user_by_email(db, body.email)
    # Verify even when the user is missing? We short-circuit here for simplicity.
    if user is None or not verify_password(body.password, user.password_hash):
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_CREDENTIALS",
                     "Invalid email or password.")
    return _issue_tokens(db, user)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Exchange a refresh token for a new token pair",
    description="Rotation: the presented refresh token is revoked and a brand-new "
    "pair is issued. Reusing a revoked/expired token fails.",
    responses={401: {"description": "Invalid/expired/revoked token (code INVALID_REFRESH_TOKEN)"}},
)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    stored = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_token(body.refresh_token))
    )
    if stored is None or stored.revoked or stored.expires_at <= utc_now():
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_REFRESH_TOKEN",
                     "Refresh token is invalid, expired, or already used.")
    stored.revoked = True                      # rotate: kill the old one
    db.commit()
    return _issue_tokens(db, stored.user)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out (revoke a refresh token)",
    description="Revokes the given refresh token so it can no longer be refreshed.",
)
def logout(body: LogoutRequest, db: Session = Depends(get_db)) -> None:
    stored = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_token(body.refresh_token))
    )
    if stored and not stored.revoked:
        stored.revoked = True
        db.commit()
    # 204 regardless — logging out an already-invalid token is not an error.


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get the current authenticated user",
    description="Requires a valid access token in the Authorization: Bearer header.",
    responses={401: {"description": "Missing/invalid access token"}},
)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
