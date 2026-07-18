"""Session management: list active sessions, revoke one, or revoke all others.

A "session" is a non-revoked, unexpired refresh_tokens row (one per login).
The caller may send its current refresh token as the `X-Refresh-Token` header so
we can flag which session is the current one (and protect it from bulk revoke).
"""

import uuid

from fastapi import APIRouter, Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.security import hash_token
from app.core.time import utc_now
from app.database import get_db
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.session import SessionItem, SessionList

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])


def _active_sessions(db: Session, user_id: uuid.UUID) -> list[RefreshToken]:
    return list(
        db.scalars(
            select(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked.is_(False),
                RefreshToken.expires_at > utc_now(),
            )
            .order_by(RefreshToken.created_at.desc())
        )
    )


@router.get("", response_model=SessionList, summary="List active sessions")
def list_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    authforge_refresh: str | None = Cookie(default=None),
):
    current_hash = hash_token(authforge_refresh) if authforge_refresh else None
    rows = _active_sessions(db, current_user.id)
    items = [
        SessionItem.model_validate(r).model_copy(
            update={"is_current": r.token_hash == current_hash}
        )
        for r in rows
    ]
    return SessionList(items=items, total=len(items))


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke one session",
)
def revoke_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.get(RefreshToken, session_id)
    if row is None or row.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Session not found.", "code": "SESSION_NOT_FOUND"},
        )
    row.revoked = True
    db.commit()


@router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all sessions except the current one",
)
def revoke_others(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    authforge_refresh: str | None = Cookie(default=None),
):
    current_hash = hash_token(authforge_refresh) if authforge_refresh else None
    for row in _active_sessions(db, current_user.id):
        if row.token_hash != current_hash:
            row.revoked = True
    db.commit()
