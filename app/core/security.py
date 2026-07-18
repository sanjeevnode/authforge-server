"""The crypto heart: password hashing, JWT access tokens, opaque refresh tokens.

Pure functions — no HTTP, no DB. Everything that touches a secret lives here so
there's exactly one place to audit.
"""

import hashlib
import secrets
from datetime import timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.config import settings
from app.core.time import utc_now

# One reusable hasher with argon2id defaults (memory/time cost tuned by the lib).
_ph = PasswordHasher()


# --- Passwords -------------------------------------------------------------

def hash_password(password: str) -> str:
    """Argon2id hash. Includes a random salt + params inside the returned string."""
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """True if password matches the stored hash. Never raises to the caller."""
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


# --- Access token (JWT, HS256) --------------------------------------------

def create_access_token(user_id: str) -> str:
    """Short-lived signed JWT. sub=user, plus iat/exp and a type tag so this
    token can't be replayed where a refresh/mfa token is expected."""
    now = utc_now()
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "type": "access",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> dict:
    """Verify signature + expiry and return the claims. Raises jwt.PyJWTError
    (ExpiredSignatureError / InvalidTokenError) on any problem — caller maps to 401."""
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


# --- MFA token (short-lived, single-purpose) ------------------------------

def create_mfa_token(user_id: str) -> str:
    """A 2-minute JWT usable ONLY at /login/mfa. type='mfa' so it can't be
    replayed as an access token."""
    now = utc_now()
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=2),
        "type": "mfa",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_mfa_token(token: str) -> dict:
    """Verify an mfa_token. Raises jwt.PyJWTError on any problem."""
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    if payload.get("type") != "mfa":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


# --- Refresh token (opaque, not a JWT) ------------------------------------

def generate_refresh_token() -> str:
    """A high-entropy random string. This raw value is given to the client ONCE;
    we only ever store its hash (below)."""
    return secrets.token_urlsafe(48)


def hash_token(raw_token: str) -> str:
    """SHA-256 of a refresh token. Deterministic (unlike argon2) so we can look a
    token up by its hash. A DB leak yields only hashes, never usable tokens."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def demo() -> None:
    # password roundtrip
    h = hash_password("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)
    assert h != hash_password("hunter2"), "salt must make each hash unique"

    # access token roundtrip
    tok = create_access_token("user-123")
    claims = decode_access_token(tok)
    assert claims["sub"] == "user-123" and claims["type"] == "access"

    # tampered / wrong-type tokens rejected
    try:
        decode_access_token(tok + "x")
        raise AssertionError("tampered token should not decode")
    except jwt.PyJWTError:
        pass

    # refresh token: raw != stored, hash is deterministic
    raw = generate_refresh_token()
    assert hash_token(raw) == hash_token(raw)
    assert hash_token(raw) != raw

    print("security.py demo OK")


if __name__ == "__main__":
    demo()
