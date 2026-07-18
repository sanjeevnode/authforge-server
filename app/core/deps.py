"""FastAPI dependencies that protected routes declare to get an authenticated user."""

import uuid

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.repositories.user import get_user_by_id
from app.database import get_db
from app.models.user import User

# Parses the "Authorization: Bearer <token>" header; 403 if it's missing.
_bearer = HTTPBearer()


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Decode the access token, load the user. Raises 401 on any failure."""
    try:
        payload = decode_access_token(creds.credentials)
        user_id = uuid.UUID(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise _unauthorized()

    user = get_user_by_id(db, user_id)
    if user is None:
        raise _unauthorized()
    return user
