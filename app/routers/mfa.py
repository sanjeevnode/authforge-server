"""MFA endpoints (all under /api/v1/mfa, all require a valid access token).

Setup flow: /setup stores an ENCRYPTED secret but keeps mfa_enabled=false.
Only /verify (proving the user scanned it) flips mfa_enabled on and hands out
recovery codes — so a half-finished setup never locks anyone out.
"""

import io

import qrcode
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.deps import get_current_user
from app.core.security import verify_password
from app.core.totp import (
    build_otpauth_uri,
    generate_recovery_codes,
    generate_secret,
    verify_code,
)
from app.database import get_db
from app.models.user import User
from app.repositories import recovery_code as recovery_repo
from app.schemas.mfa import (
    MfaDisableRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    MfaVerifyResponse,
    RecoveryCountResponse,
)

router = APIRouter(prefix="/api/v1/mfa", tags=["mfa"])


def _error(status_code: int, code: str, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"detail": detail, "code": code})


@router.post("/setup", response_model=MfaSetupResponse, summary="Begin MFA setup",
             description="Generates and stores an encrypted TOTP secret (MFA not yet "
             "enabled) and returns the secret + otpauth URI to scan.")
def setup(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.mfa_enabled:
        raise _error(status.HTTP_409_CONFLICT, "MFA_ALREADY_ENABLED", "MFA is already enabled.")
    secret = generate_secret()
    current_user.mfa_secret = encrypt_secret(secret)   # stored encrypted, not enabled yet
    db.commit()
    return MfaSetupResponse(
        secret=secret,
        otpauth_uri=build_otpauth_uri(secret, current_user.email),
    )


@router.get("/qr", summary="QR code PNG for the pending TOTP secret",
            responses={200: {"content": {"image/png": {}}}})
def qr(current_user: User = Depends(get_current_user)):
    if current_user.mfa_secret is None:
        raise _error(status.HTTP_400_BAD_REQUEST, "MFA_NOT_SETUP", "Call /mfa/setup first.")
    uri = build_otpauth_uri(decrypt_secret(current_user.mfa_secret), current_user.email)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@router.post("/verify", response_model=MfaVerifyResponse, summary="Confirm setup + enable MFA",
             description="Verifies the first OTP, enables MFA, and returns 10 recovery "
             "codes ONCE.",
             responses={400: {"description": "Invalid OTP (code INVALID_OTP)"}})
def verify(body: MfaVerifyRequest, current_user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    if current_user.mfa_secret is None:
        raise _error(status.HTTP_400_BAD_REQUEST, "MFA_NOT_SETUP", "Call /mfa/setup first.")
    if not verify_code(decrypt_secret(current_user.mfa_secret), body.code):
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_OTP", "That code is incorrect.")

    current_user.mfa_enabled = True
    db.commit()
    codes = generate_recovery_codes()
    recovery_repo.replace_codes(db, current_user.id, codes)
    return MfaVerifyResponse(recovery_codes=codes)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT, summary="Disable MFA",
             description="Requires BOTH the account password and a current OTP.")
def disable(body: MfaDisableRequest, current_user: User = Depends(get_current_user),
            db: Session = Depends(get_db)):
    if not current_user.mfa_enabled or current_user.mfa_secret is None:
        raise _error(status.HTTP_400_BAD_REQUEST, "MFA_NOT_ENABLED", "MFA is not enabled.")
    if not verify_password(body.password, current_user.password_hash):
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_CREDENTIALS", "Wrong password.")
    if not verify_code(decrypt_secret(current_user.mfa_secret), body.code):
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_OTP", "That code is incorrect.")

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    recovery_repo.delete_all(db, current_user.id)


@router.get("/recovery", response_model=RecoveryCountResponse,
            summary="Count remaining recovery codes")
def recovery_count(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return RecoveryCountResponse(remaining=recovery_repo.count_unused(db, current_user.id))
