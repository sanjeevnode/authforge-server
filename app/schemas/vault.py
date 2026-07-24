from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_serializer

from app.core.time import to_ist


class VaultUpload(BaseModel):
    """Client -> server on backup. All fields are opaque to the server."""

    ciphertext: str
    nonce: str
    kdf_salt: str
    kdf_iterations: int
    # Last version the client saw; omit on first backup. Used for conflict check.
    version: int | None = None


class VaultResponse(BaseModel):
    """Server -> client. The client decrypts `ciphertext` locally."""

    model_config = ConfigDict(from_attributes=True)

    ciphertext: str
    nonce: str
    kdf_salt: str
    kdf_iterations: int
    version: int
    updated_at: datetime

    @field_serializer("updated_at")
    def _ist(self, value: datetime) -> str:
        return to_ist(value).isoformat()


class VaultMeta(BaseModel):
    """Lightweight ack after a successful backup."""

    model_config = ConfigDict(from_attributes=True)

    version: int
    updated_at: datetime

    @field_serializer("updated_at")
    def _ist(self, value: datetime) -> str:
        return to_ist(value).isoformat()
