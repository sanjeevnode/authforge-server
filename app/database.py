import uuid
from collections.abc import Generator
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import settings

# The engine owns the connection pool to Postgres. Created once, reused for the
# whole app's life. pool_pre_ping checks a connection is alive before handing it
# out, so a dropped/stale connection is transparently replaced instead of erroring.
engine = create_engine(settings.database_url, pool_pre_ping=True)

# A factory that produces Session objects. Each web request gets its own session.
# autoflush/autocommit off = we control exactly when SQL is sent and committed.
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# Every ORM model (User, RefreshToken, ...) inherits from this. It's how
# SQLAlchemy discovers your tables and their columns. The three columns here are
# shared by every table per our DB conventions, so models declare them once — here.
class Base(DeclarativeBase):
    # UUID v4 PK, generated in Python on insert. default= (not server_default=)
    # so the id exists on the object immediately, before the row is flushed.
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Set once by Postgres on insert.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Auto-bumped by SQLAlchemy on every UPDATE.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    # ponytail: updated_at lives on all tables incl. append-only ones (refresh_tokens);
    # unused column beats a second mixin. Split only if a table must forbid updates.


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: open a session, yield it to the route, always close it.

    The try/finally guarantees the connection returns to the pool even if the
    route raises — this is what prevents connection leaks under errors.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
