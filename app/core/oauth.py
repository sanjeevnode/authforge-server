"""OAuth2 crypto helpers — PKCE, client secrets, id_token. Pure functions, no DB.

PKCE (RFC 7636) protects the authorization code: the client sends a random
`code_verifier` at /token, we hash it and compare to the `code_challenge` it
committed to at /authorize. A stolen code is useless without the verifier.
"""

import base64
import hashlib
import secrets
from datetime import timedelta

import jwt

from app.config import settings
from app.core.time import utc_now


def generate_client_id() -> str:
    """Public client identifier. Prefixed so it's greppable in logs."""
    return "afc_" + secrets.token_urlsafe(16)


def generate_client_secret() -> str:
    """Raw client secret — shown to the org owner ONCE, then only its hash is kept."""
    return "afs_" + secrets.token_urlsafe(32)


def generate_opaque_token() -> str:
    """A random authorization code or OAuth access token (not a JWT)."""
    return secrets.token_urlsafe(32)


def hash_token(raw: str) -> str:
    """SHA-256, deterministic so we can look a token/secret up by its hash."""
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """True if code_verifier matches the committed challenge.

    S256: challenge == base64url(sha256(verifier)) with padding stripped, per RFC.
    plain: challenge == verifier (weak; only for clients that can't do S256).
    """
    if method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(computed, code_challenge)


def create_id_token(user_id: str, email: str, client_id: str) -> str:
    """OIDC id_token: a signed JWT asserting who logged in, for whom (aud=client)."""
    now = utc_now()
    payload = {
        "iss": settings.oauth_issuer,
        "sub": str(user_id),
        "aud": client_id,
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=settings.oauth_access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def demo() -> None:
    # PKCE S256 roundtrip: a real verifier verifies, a wrong one doesn't.
    verifier = generate_opaque_token()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert verify_pkce(verifier, challenge, "S256")
    assert not verify_pkce("wrong-verifier", challenge, "S256")

    # plain method
    assert verify_pkce("abc", "abc", "plain")
    assert not verify_pkce("abc", "xyz", "plain")

    # hashing is deterministic and not identity
    raw = generate_client_secret()
    assert hash_token(raw) == hash_token(raw) and hash_token(raw) != raw

    print("oauth.py demo OK")


if __name__ == "__main__":
    demo()
