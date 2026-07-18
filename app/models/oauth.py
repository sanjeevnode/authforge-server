"""OAuth2 tables — AuthForge as an Identity Provider.

Three tables model the Authorization Code + PKCE flow:
- oauth_clients: a registered third-party app ("relying party") that wants to
  let users "Sign in with AuthForge".
- oauth_codes: a short-lived authorization code, issued at /authorize after the
  user consents, exchanged once at /token for tokens.
- oauth_tokens: an issued OAuth access token (opaque, hashed) that the client
  presents to /userinfo. Distinct from the portal's own login access tokens.

Secrets follow the project rule: never stored raw. client_secret and both token
values are SHA-256 hashed, so a DB leak yields nothing usable.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class OAuthClient(Base):
    """A registered relying-party application, owned by an org."""

    __tablename__ = "oauth_clients"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String)
    # Public identifier, sent in the URL — safe to expose.
    client_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    # SHA-256 of the client secret. Null for public (PKCE-only) clients.
    client_secret_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    # Space-separated exact-match redirect URIs. An attacker can't redirect the
    # code to their own site because it must match one of these exactly.
    redirect_uris: Mapped[str] = mapped_column(String)
    # Space-separated scopes this client is allowed to request (e.g. "openid profile email").
    allowed_scopes: Mapped[str] = mapped_column(String, default="openid profile email")


class OAuthCode(Base):
    """A one-time authorization code. Bound to a PKCE challenge so a stolen code
    can't be exchanged without the original verifier."""

    __tablename__ = "oauth_codes"

    code_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    redirect_uri: Mapped[str] = mapped_column(String)
    scope: Mapped[str] = mapped_column(String)
    # PKCE: SHA-256(code_verifier), base64url. Verified at /token.
    code_challenge: Mapped[str] = mapped_column(String)
    code_challenge_method: Mapped[str] = mapped_column(String, default="S256")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Single-use: flipped true the moment it's exchanged. Reuse is rejected.
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class OAuthToken(Base):
    """An issued OAuth access token, presented by the client to /userinfo."""

    __tablename__ = "oauth_tokens"

    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    scope: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
