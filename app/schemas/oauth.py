import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_serializer

from app.core.time import to_ist


# --- Client management (portal) ---

class ClientCreateRequest(BaseModel):
    name: str
    # Newline- or comma-separated in the UI; we normalize to space-separated.
    redirect_uris: list[str]
    scopes: list[str] = ["openid", "profile", "email"]


class ClientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    client_id: str
    redirect_uris: str
    allowed_scopes: str
    created_at: datetime

    @field_serializer("created_at")
    def _ist(self, value: datetime) -> str:
        return to_ist(value).isoformat()


class ClientCreatedResponse(ClientResponse):
    """Returned only at creation — carries the raw secret ONCE."""

    client_secret: str


class ClientList(BaseModel):
    items: list[ClientResponse]
    total: int


# --- Authorize / consent ---

class AuthorizeInfo(BaseModel):
    """What the consent screen needs to render: which app, wanting what."""

    client_name: str
    client_id: str
    scopes: list[str]


class TokenGrant(BaseModel):
    """The /oauth/token success response (RFC 6749 field names)."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str
    id_token: str | None = None


class UserInfo(BaseModel):
    """The /oauth/userinfo response (OIDC-style claims, scope-gated)."""

    sub: str
    email: str | None = None
