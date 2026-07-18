"""Recovery-code repository. Pure data layer."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.totp import hash_recovery_code
from app.models.recovery_code import RecoveryCode


def replace_codes(db: Session, user_id: uuid.UUID, codes: list[str]) -> None:
    """Delete any existing codes for the user and store hashes of the new ones."""
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user_id).delete()
    for code in codes:
        db.add(RecoveryCode(user_id=user_id, code_hash=hash_recovery_code(code)))
    db.commit()


def count_unused(db: Session, user_id: uuid.UUID) -> int:
    return db.scalar(
        select(func.count())
        .select_from(RecoveryCode)
        .where(RecoveryCode.user_id == user_id, RecoveryCode.used.is_(False))
    )


def consume_code(db: Session, user_id: uuid.UUID, code: str) -> bool:
    """Mark a matching unused code as used. Returns True if one was consumed."""
    row = db.scalar(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user_id,
            RecoveryCode.code_hash == hash_recovery_code(code),
            RecoveryCode.used.is_(False),
        )
    )
    if row is None:
        return False
    row.used = True
    db.commit()
    return True


def delete_all(db: Session, user_id: uuid.UUID) -> None:
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user_id).delete()
    db.commit()
