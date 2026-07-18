import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_serializer

from app.core.time import to_ist


class SessionItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_name: str | None
    ip_address: str | None
    last_active_at: datetime | None
    created_at: datetime
    is_current: bool = False

    @field_serializer("last_active_at", "created_at")
    def _ist(self, value: datetime | None) -> str | None:
        return to_ist(value).isoformat() if value else None


class SessionList(BaseModel):
    items: list[SessionItem]
    total: int


class DeviceItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_name: str | None
    trusted_at: datetime
    expires_at: datetime

    @field_serializer("trusted_at", "expires_at")
    def _ist(self, value: datetime) -> str:
        return to_ist(value).isoformat()


class DeviceList(BaseModel):
    items: list[DeviceItem]
    total: int
