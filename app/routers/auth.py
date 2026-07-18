"""Auth endpoints: register, login, refresh (with rotation), logout, /me.

Error convention (from the plan): every error body is
    {"detail": "human message", "code": "MACHINE_CODE"}
so clients switch on `code`, never parse `detail`.
"""

import uuid
from datetime import timedelta

import jwt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.cookies import clear_refresh_cookie, set_refresh_cookie
from app.core.deps import get_current_user
from app.core.rate_limit import enforce_rate_limit
from app.core.security import (
    create_access_token,
    create_mfa_token,
    decode_mfa_token,
    generate_refresh_token,
    hash_token,
    verify_password,
)
from app.core.time import utc_now
from app.core.totp import verify_code
from app.core.crypto import decrypt_secret
from app.core.device import device_name_from_ua, device_fingerprint
from app.models.trusted_device import TrustedDevice
from app.repositories.user import create_user, get_user_by_email, get_user_by_id
from app.repositories import recovery_code as recovery_repo
from app.database import get_db
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import (
    LoginMfaRequest,
    LoginRequest,
    LogoutRequest,
    MfaChallengeResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _error(status_code: int, code: str, detail: str) -> HTTPException:
    """Build an HTTPException whose body is {"detail": ..., "code": ...}."""
    return HTTPException(status_code=status_code, detail={"detail": detail, "code": code})


def _issue_tokens(
    db: Session, user: User, response: Response, request: Request | None = None
) -> TokenResponse:
    """Create an access token + a fresh refresh token (= a session row). The refresh
    token is set as an httpOnly cookie; only the access token is returned in the body."""
    ua = request.headers.get("user-agent") if request else None
    ip = request.client.host if request and request.client else None
    now = utc_now()
    raw_refresh = generate_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token(raw_refresh),
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
            device_name=device_name_from_ua(ua),
            ip_address=ip,
            last_active_at=now,
        )
    )
    db.commit()
    set_refresh_cookie(response, raw_refresh)
    return TokenResponse(access_token=create_access_token(user.id))


def _is_trusted_device(db: Session, user_id, request: Request) -> bool:
    """True if this device has a valid, unexpired trust record — lets login skip MFA."""
    fp = device_fingerprint(request.headers.get("user-agent"))
    match = db.scalar(
        select(TrustedDevice).where(
            TrustedDevice.user_id == user_id,
            TrustedDevice.device_fingerprint == fp,
            TrustedDevice.expires_at > utc_now(),
        )
    )
    return match is not None


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
    response_model=TokenResponse | MfaChallengeResponse,
    summary="Log in with email + password",
    description="Without MFA: returns an access + refresh token pair. With MFA enabled: "
    "returns {mfa_required, mfa_token}; finish at /login/mfa.",
    responses={
        401: {"description": "Invalid email or password (code INVALID_CREDENTIALS)"},
        429: {"description": "Too many attempts (code RATE_LIMITED)"},
    },
)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    # 5 attempts / 15 min per IP+email combo (plan spec).
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(f"login:{client_ip}:{body.email}", limit=5, window_seconds=15 * 60)

    user = get_user_by_email(db, body.email)
    if user is None or not verify_password(body.password, user.password_hash):
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_CREDENTIALS",
                     "Invalid email or password.")

    # MFA on -> challenge, UNLESS this device is trusted (then skip straight to tokens).
    if user.mfa_enabled and not _is_trusted_device(db, user.id, request):
        return MfaChallengeResponse(mfa_token=create_mfa_token(user.id))
    return _issue_tokens(db, user, response, request)


@router.post(
    "/login/mfa",
    response_model=TokenResponse,
    summary="Complete MFA login",
    description="Exchange the mfa_token + a valid OTP (or a recovery code) for a full "
    "token pair.",
    responses={401: {"description": "Invalid mfa_token or code (code INVALID_MFA / INVALID_OTP)"}},
)
def login_mfa(body: LoginMfaRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        payload = decode_mfa_token(body.mfa_token)
        user = get_user_by_id(db, uuid.UUID(payload["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        user = None
    if user is None or not user.mfa_enabled or user.mfa_secret is None:
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_MFA", "MFA session is invalid or expired.")

    # Accept a live OTP, or fall back to consuming a one-time recovery code.
    otp_ok = verify_code(decrypt_secret(user.mfa_secret), body.code)
    if not otp_ok and not recovery_repo.consume_code(db, user.id, body.code):
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_OTP", "Invalid OTP or recovery code.")

    # "Remember this device for 30 days" -> future logins from it skip MFA.
    if body.remember_device:
        ua = request.headers.get("user-agent")
        now = utc_now()
        db.add(
            TrustedDevice(
                user_id=user.id,
                device_fingerprint=device_fingerprint(ua),
                device_name=device_name_from_ua(ua),
                trusted_at=now,
                expires_at=now + timedelta(days=30),
            )
        )
        db.commit()

    return _issue_tokens(db, user, response, request)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Exchange a refresh token for a new token pair",
    description="Rotation: the presented refresh token is revoked and a brand-new "
    "pair is issued. Reusing a revoked/expired token fails.",
    responses={401: {"description": "Invalid/expired/revoked token (code INVALID_REFRESH_TOKEN)"}},
)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    body: RefreshRequest | None = None,
    authforge_refresh: str | None = Cookie(default=None),
) -> TokenResponse:
    # Prefer the httpOnly cookie; fall back to a body token (Flutter/curl clients).
    raw = authforge_refresh or (body.refresh_token if body else None)
    if not raw:
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_REFRESH_TOKEN",
                     "No refresh token provided.")
    stored = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw))
    )
    if stored is None or stored.revoked or stored.expires_at <= utc_now():
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_REFRESH_TOKEN",
                     "Refresh token is invalid, expired, or already used.")
    stored.revoked = True                      # rotate: kill the old one
    db.commit()
    return _issue_tokens(db, stored.user, response, request)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out (revoke a refresh token)",
    description="Revokes the given refresh token so it can no longer be refreshed.",
)
def logout(
    response: Response,
    db: Session = Depends(get_db),
    body: LogoutRequest | None = None,
    authforge_refresh: str | None = Cookie(default=None),
) -> Response:
    raw = authforge_refresh or (body.refresh_token if body else None)
    if raw:
        stored = db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw))
        )
        if stored and not stored.revoked:
            stored.revoked = True
            db.commit()
    # Clear the cookie and return 204 regardless (idempotent logout).
    resp = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_refresh_cookie(resp)
    return resp


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get the current authenticated user",
    description="Requires a valid access token in the Authorization: Bearer header.",
    responses={401: {"description": "Missing/invalid access token"}},
)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
