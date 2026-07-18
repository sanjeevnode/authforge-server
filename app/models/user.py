from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    # unique + index: login looks users up by email constantly, and email must
    # be one-account-per-address.
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    # argon2id hash — never the raw password.
    password_hash: Mapped[str] = mapped_column(String)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # MFA. mfa_secret is Fernet-encrypted (reversible), nullable until enabled.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String, nullable=True)

    # ORM convenience: user.refresh_tokens -> list of that user's tokens.
    # cascade delete-orphan: deleting a user removes their tokens too.
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


# imported at end to avoid a circular import at module load time
from app.models.refresh_token import RefreshToken  # noqa: E402
