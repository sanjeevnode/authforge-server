import uuid

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # One-way hash (like a password) — codes are only ever compared, never shown again.
    code_hash: Mapped[str] = mapped_column(String, index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
