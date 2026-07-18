"""OAuth2 Authorization Code + PKCE flow — AuthForge as an Identity Provider.

The dance (SPA-friendly variant):
  1. Third-party app redirects the user's browser to the AuthForge portal's
     /authorize page with ?client_id&redirect_uri&scope&state&code_challenge.
  2. The portal (user logged in) calls GET /oauth/authorize to fetch consent
     info (which app, which scopes) and renders a consent screen.
  3. User clicks Allow -> portal calls POST /oauth/authorize/consent, which
     mints a one-time authorization code and returns the redirect URL. The
     portal navigates the browser there (back to the third-party app).
  4. The third-party app's backend calls POST /oauth/token with the code +
     its code_verifier (PKCE) -> gets an access_token + id_token.
  5. It calls GET /oauth/userinfo with the access_token to learn who logged in.

Why split GET (info) / POST (consent): the portal is a SPA that already holds
the user's session; it needs the consent data as JSON to render, then a
deliberate user action to actually issue the code. Keeps the code out of the
URL until the user agrees.
"""

import uuid
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core import oauth as oauth_crypto
from app.core.deps import get_current_user
from app.core.time import utc_now
from app.database import get_db
from app.models.oauth import OAuthClient, OAuthCode, OAuthToken
from app.models.user import User
from app.schemas.oauth import AuthorizeInfo, TokenGrant, UserInfo

router = APIRouter(prefix="/api/v1/oauth", tags=["oauth"])

_bearer = HTTPBearer()


def _error(status_code: int, code: str, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"detail": detail, "code": code})


def _get_client(db: Session, client_id: str) -> OAuthClient:
    client = db.scalar(select(OAuthClient).where(OAuthClient.client_id == client_id))
    if client is None:
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_CLIENT", "Unknown client_id.")
    return client


def _validate_request(client: OAuthClient, redirect_uri: str, scope: str) -> list[str]:
    """Reject anything the client isn't registered for. Exact redirect_uri match
    is the critical anti-redirect-hijack check."""
    if redirect_uri not in client.redirect_uris.split():
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_REDIRECT_URI",
                     "redirect_uri is not registered for this client.")
    allowed = set(client.allowed_scopes.split())
    requested = [s for s in scope.split() if s]
    if not requested:
        requested = ["openid"]
    for s in requested:
        if s not in allowed:
            raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_SCOPE",
                         f"Scope '{s}' is not allowed for this client.")
    return requested


@router.get(
    "/authorize",
    response_model=AuthorizeInfo,
    summary="Get consent-screen info for an OAuth authorization request",
    description="Called by the portal (user must be logged in) to render the "
    "consent screen. Validates the client, redirect_uri, and scopes. Does NOT "
    "issue a code — that happens on explicit consent.",
)
def authorize_info(
    client_id: str,
    redirect_uri: str,
    scope: str = "openid profile email",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AuthorizeInfo:
    client = _get_client(db, client_id)
    scopes = _validate_request(client, redirect_uri, scope)
    return AuthorizeInfo(client_name=client.name, client_id=client.client_id, scopes=scopes)


@router.post(
    "/authorize/consent",
    summary="Grant consent and mint an authorization code",
    description="Called when the user clicks Allow. Issues a one-time code bound "
    "to the PKCE challenge and returns the redirect URL (code + state) for the "
    "portal to navigate the browser to.",
)
def authorize_consent(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("openid profile email"),
    state: str = Form(""),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form("S256"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    client = _get_client(db, client_id)
    scopes = _validate_request(client, redirect_uri, scope)
    if code_challenge_method not in ("S256", "plain"):
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_CHALLENGE_METHOD",
                     "code_challenge_method must be S256 or plain.")

    raw_code = oauth_crypto.generate_opaque_token()
    db.add(
        OAuthCode(
            code_hash=oauth_crypto.hash_token(raw_code),
            client_id=client_id,
            user_id=current_user.id,
            redirect_uri=redirect_uri,
            scope=" ".join(scopes),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=utc_now() + timedelta(seconds=settings.oauth_code_expire_seconds),
        )
    )
    db.commit()

    params = {"code": raw_code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return {"redirect_url": f"{redirect_uri}{sep}{urlencode(params)}"}


@router.post(
    "/token",
    response_model=TokenGrant,
    summary="Exchange an authorization code for tokens (PKCE)",
    description="The third-party app's backend calls this. Verifies the code is "
    "unused/unexpired, the PKCE verifier matches, and (for confidential clients) "
    "the client_secret. Returns an OAuth access token + OIDC id_token.",
)
def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: str = Form(...),
    client_secret: str | None = Form(None),
    db: Session = Depends(get_db),
) -> TokenGrant:
    if grant_type != "authorization_code":
        raise _error(status.HTTP_400_BAD_REQUEST, "UNSUPPORTED_GRANT_TYPE",
                     "Only authorization_code is supported.")

    client = _get_client(db, client_id)
    # Confidential clients (those with a secret registered) must present it.
    if client.client_secret_hash is not None:
        if not client_secret or oauth_crypto.hash_token(client_secret) != client.client_secret_hash:
            raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_CLIENT_SECRET",
                         "Invalid client credentials.")

    stored = db.scalar(
        select(OAuthCode).where(OAuthCode.code_hash == oauth_crypto.hash_token(code))
    )
    if stored is None or stored.used or stored.expires_at <= utc_now():
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_GRANT",
                     "Authorization code is invalid, expired, or already used.")
    if stored.client_id != client_id or stored.redirect_uri != redirect_uri:
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_GRANT",
                     "Code does not match this client/redirect_uri.")
    if not oauth_crypto.verify_pkce(code_verifier, stored.code_challenge, stored.code_challenge_method):
        raise _error(status.HTTP_400_BAD_REQUEST, "INVALID_GRANT", "PKCE verification failed.")

    stored.used = True  # single-use: burn the code

    user = db.get(User, stored.user_id)
    raw_access = oauth_crypto.generate_opaque_token()
    expires = timedelta(minutes=settings.oauth_access_token_expire_minutes)
    db.add(
        OAuthToken(
            token_hash=oauth_crypto.hash_token(raw_access),
            client_id=client_id,
            user_id=stored.user_id,
            scope=stored.scope,
            expires_at=utc_now() + expires,
        )
    )
    db.commit()

    id_token = None
    if "openid" in stored.scope.split():
        id_token = oauth_crypto.create_id_token(str(user.id), user.email, client_id)

    return TokenGrant(
        access_token=raw_access,
        expires_in=int(expires.total_seconds()),
        scope=stored.scope,
        id_token=id_token,
    )


@router.get(
    "/userinfo",
    response_model=UserInfo,
    summary="Get the authenticated user's claims (OIDC userinfo)",
    description="The third-party app presents its OAuth access token here to learn "
    "who logged in. Claims are gated by the token's granted scopes.",
)
def userinfo(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> UserInfo:
    stored = db.scalar(
        select(OAuthToken).where(OAuthToken.token_hash == oauth_crypto.hash_token(creds.credentials))
    )
    if stored is None or stored.revoked or stored.expires_at <= utc_now():
        raise _error(status.HTTP_401_UNAUTHORIZED, "INVALID_TOKEN",
                     "OAuth access token is invalid, expired, or revoked.")
    user = db.get(User, stored.user_id)
    scopes = stored.scope.split()
    return UserInfo(
        sub=str(user.id),
        email=user.email if ("email" in scopes or "profile" in scopes) else None,
    )
