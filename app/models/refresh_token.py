import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    # FK to the owner. index=True per conventions (FKs are always indexed).
    # ondelete CASCADE at the DB level backs up the ORM cascade on User.
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # SHA-256 of the raw token — a DB leak never yields a usable token.
    token_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # rotation/logout flips this instead of deleting the row (audit trail).
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Session context (Phase 3) ---
    # This row IS a session: one login = one refresh token + its device info.
    device_name: Mapped[str | None] = mapped_column(String, nullable=True)  # "Chrome on Windows"
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    last_active_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")


from app.models.user import User  # noqa: E402
