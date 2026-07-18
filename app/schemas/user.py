import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, field_serializer

from app.core.time import to_ist


class UserResponse(BaseModel):
    # from_attributes lets Pydantic read straight off a SQLAlchemy User object
    # (user.id, user.email, ...) instead of needing a dict.
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    is_verified: bool
    mfa_enabled: bool
    role: str
    created_at: datetime

    # Stored UTC -> shown IST, only at the edge (serialization).
    @field_serializer("created_at")
    def serialize_created_at(self, value: datetime) -> str:
        return to_ist(value).isoformat()
