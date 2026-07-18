"""OAuth client management — org owners register the apps that may 'Sign in
with AuthForge'. All scoped to the caller's org (multi-tenancy: you only see
and manage your own org's clients)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import oauth as oauth_crypto
from app.core.deps import get_current_user
from app.database import get_db
from app.models.oauth import OAuthClient
from app.models.user import User
from app.schemas.oauth import (
    ClientCreatedResponse,
    ClientCreateRequest,
    ClientList,
    ClientResponse,
)

router = APIRouter(prefix="/api/v1/clients", tags=["oauth-clients"])


def _error(status_code: int, code: str, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"detail": detail, "code": code})


def _require_owner(user: User) -> None:
    if user.role != "owner":
        raise _error(status.HTTP_403_FORBIDDEN, "NOT_ORG_OWNER",
                     "Only the org owner can manage OAuth apps.")


@router.get("", response_model=ClientList, summary="List your org's OAuth apps")
def list_clients(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ClientList:
    rows = list(
        db.scalars(
            select(OAuthClient)
            .where(OAuthClient.org_id == current_user.org_id)
            .order_by(OAuthClient.created_at.desc())
        )
    )
    return ClientList(items=rows, total=len(rows))


@router.post(
    "",
    response_model=ClientCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new OAuth app (returns the secret ONCE)",
)
def create_client(
    body: ClientCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ClientCreatedResponse:
    _require_owner(current_user)
    if not body.redirect_uris:
        raise _error(status.HTTP_422_UNPROCESSABLE_ENTITY, "NO_REDIRECT_URI",
                     "At least one redirect URI is required.")

    raw_secret = oauth_crypto.generate_client_secret()
    client = OAuthClient(
        org_id=current_user.org_id,
        name=body.name,
        client_id=oauth_crypto.generate_client_id(),
        client_secret_hash=oauth_crypto.hash_token(raw_secret),
        redirect_uris=" ".join(u.strip() for u in body.redirect_uris if u.strip()),
        allowed_scopes=" ".join(body.scopes) or "openid profile email",
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    # Build the base response from the ORM object, then attach the raw secret —
    # the only time it's ever returned. model_construct skips re-validation so the
    # created_at datetime stays a datetime for the field_serializer.
    base = ClientResponse.model_validate(client)
    return ClientCreatedResponse.model_construct(
        **base.__dict__, client_secret=raw_secret
    )


@router.delete(
    "/{client_pk}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an OAuth app",
)
def delete_client(
    client_pk: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_owner(current_user)
    client = db.get(OAuthClient, client_pk)
    if client is None or client.org_id != current_user.org_id:
        raise _error(status.HTTP_404_NOT_FOUND, "CLIENT_NOT_FOUND", "OAuth app not found.")
    db.delete(client)
    db.commit()
