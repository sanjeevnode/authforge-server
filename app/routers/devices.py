"""Trusted device management: list devices the user chose to remember, and revoke
trust (which forces MFA again on the next login from that device)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.time import utc_now
from app.database import get_db
from app.models.trusted_device import TrustedDevice
from app.models.user import User
from app.schemas.session import DeviceItem, DeviceList

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


@router.get("", response_model=DeviceList, summary="List trusted devices")
def list_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = list(
        db.scalars(
            select(TrustedDevice)
            .where(
                TrustedDevice.user_id == current_user.id,
                TrustedDevice.expires_at > utc_now(),
            )
            .order_by(TrustedDevice.trusted_at.desc())
        )
    )
    return DeviceList(
        items=[DeviceItem.model_validate(r) for r in rows], total=len(rows)
    )


@router.delete(
    "/{device_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke trust for a device (forces MFA next login)",
)
def revoke_device(
    device_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.get(TrustedDevice, device_id)
    if row is None or row.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Device not found.", "code": "DEVICE_NOT_FOUND"},
        )
    db.delete(row)
    db.commit()
