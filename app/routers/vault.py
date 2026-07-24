"""Encrypted vault backup/restore — end-to-end encrypted.

The server is a dumb blob store here: it receives ciphertext, stores it, and
hands it back. It NEVER decrypts (it can't — the key never leaves the Flutter
app). One vault per user, upserted on backup.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.database import get_db
from app.models.encrypted_vault import EncryptedVault
from app.models.user import User
from app.schemas.vault import VaultMeta, VaultResponse, VaultUpload

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


def _error(status_code: int, code: str, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"detail": detail, "code": code})


def _get_vault(db: Session, user_id) -> EncryptedVault | None:
    return db.scalar(select(EncryptedVault).where(EncryptedVault.user_id == user_id))


@router.get(
    "",
    response_model=VaultResponse,
    summary="Download the encrypted vault backup",
    description="Returns the user's encrypted vault blob for client-side decryption. "
    "404 if no backup exists yet.",
    responses={404: {"description": "No backup exists (code VAULT_NOT_FOUND)"}},
)
def get_vault(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EncryptedVault:
    vault = _get_vault(db, current_user.id)
    if vault is None:
        raise _error(status.HTTP_404_NOT_FOUND, "VAULT_NOT_FOUND", "No backup found for this account.")
    return vault


@router.put(
    "",
    response_model=VaultMeta,
    summary="Upload (create or replace) the encrypted vault backup",
    description="Upsert the user's encrypted vault. The server stores the ciphertext "
    "as-is; it cannot read it. Send the last-seen `version` to detect conflicts.",
    responses={409: {"description": "Stale version — someone else backed up first (code VAULT_CONFLICT)"}},
)
def put_vault(
    body: VaultUpload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EncryptedVault:
    vault = _get_vault(db, current_user.id)
    if vault is None:
        vault = EncryptedVault(
            user_id=current_user.id,
            ciphertext=body.ciphertext,
            nonce=body.nonce,
            kdf_salt=body.kdf_salt,
            kdf_iterations=body.kdf_iterations,
            version=1,
        )
        db.add(vault)
    else:
        # Optimistic concurrency: if the client's version is behind, refuse.
        if body.version is not None and body.version != vault.version:
            raise _error(
                status.HTTP_409_CONFLICT, "VAULT_CONFLICT",
                "This backup was updated elsewhere. Restore first, then back up again.",
            )
        vault.ciphertext = body.ciphertext
        vault.nonce = body.nonce
        vault.kdf_salt = body.kdf_salt
        vault.kdf_iterations = body.kdf_iterations
        vault.version += 1
    db.commit()
    db.refresh(vault)
    return vault


@router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete the encrypted vault backup",
)
def delete_vault(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vault = _get_vault(db, current_user.id)
    if vault is not None:
        db.delete(vault)
        db.commit()
