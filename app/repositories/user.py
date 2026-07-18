"""User repository. Pure data layer — knows SQLAlchemy, knows nothing about HTTP."""

import re
import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def get_user_by_id(db: Session, user_id: uuid.UUID) -> User | None:
    return db.get(User, user_id)


def _unique_slug(db: Session, base: str) -> str:
    """Turn a name/email into a URL-safe org slug, suffixing on collision."""
    slug = re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-") or "org"
    if db.scalar(select(Organization).where(Organization.slug == slug)) is None:
        return slug
    return f"{slug}-{secrets.token_hex(3)}"


def create_user(db: Session, email: str, password: str) -> User:
    """Create the user AND their own org (they become its owner). Each new
    registrant gets an isolated tenant — the multi-tenancy boundary.
    Caller checks for duplicate email first."""
    org = Organization(name=email.split("@")[0], slug=_unique_slug(db, email.split("@")[0]))
    db.add(org)
    db.flush()  # get org.id without a full commit
    user = User(
        email=email,
        password_hash=hash_password(password),
        org_id=org.id,
        role="owner",
    )
    db.add(user)
    db.commit()
    db.refresh(user)          # reload so server-generated id/created_at are populated
    return user
