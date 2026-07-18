import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TrustedDevice(Base):
    __tablename__ = "trusted_devices"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # SHA-256 of stable device signals (User-Agent). Matched at login to skip MFA.
    device_fingerprint: Mapped[str] = mapped_column(String, index=True)
    device_name: Mapped[str | None] = mapped_column(String, nullable=True)
    trusted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # trust isn't forever
