import uuid

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Organization(Base):
    """A tenant. Every user belongs to exactly one org; every OAuth client is
    owned by one org. This is the isolation boundary that makes AuthForge
    multi-tenant — one deployment can serve many independent customers."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String)
    # URL-safe unique handle, e.g. "acme". Used in URLs/logs; email is not.
    slug: Mapped[str] = mapped_column(String, unique=True, index=True)

    members: Mapped[list["User"]] = relationship(back_populates="organization")


from app.models.user import User  # noqa: E402
