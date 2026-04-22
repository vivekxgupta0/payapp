"""
Device binding API — registers a device's ECDSA P-256 public key
with the backend, creating a cryptographic binding between user and device.

This is a prerequisite for signed offline transactions: the backend will
only accept blobs signed by a key that has been registered here.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..auth import get_current_user
from ..models import User, DeviceBinding, generate_uuid
from ..services.signature_verification import decode_public_key_from_base64

router = APIRouter(prefix="/api/device", tags=["device"])


@router.post("/register")
def register_device(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Register a device's ECDSA P-256 public key for transaction signing.
    Each user can have at most 2 active device bindings (phone + tablet).
    """
    device_id = payload.get("device_id")
    public_key_pem = payload.get("public_key_pem", "")
    public_key_base64 = payload.get("public_key_base64", "")
    platform = payload.get("platform", "")
    os_version = payload.get("os_version", "")
    integrity_score = float(payload.get("integrity_score", 1.0))

    if not device_id:
        raise HTTPException(status_code=400, detail="device_id required")

    if not public_key_base64:
        raise HTTPException(status_code=400, detail="public_key_base64 required")

    # Validate the public key is a valid P-256 key
    pub_key = decode_public_key_from_base64(public_key_base64)
    if pub_key is None:
        raise HTTPException(status_code=400, detail="Invalid ECDSA P-256 public key")

    # Check if device already registered
    existing = (
        db.query(DeviceBinding)
        .filter(DeviceBinding.device_id == device_id)
        .first()
    )

    if existing:
        if existing.user_id != current_user.id:
            raise HTTPException(
                status_code=409,
                detail="Device already bound to a different user",
            )
        # Update existing binding
        existing.public_key_pem = public_key_pem
        existing.public_key_base64 = public_key_base64
        existing.platform = platform
        existing.os_version = os_version
        existing.integrity_score = integrity_score
        existing.is_active = True
        existing.revoked_at = None
        db.commit()
        return {
            "status": "updated",
            "device_id": device_id,
            "message": "Device binding updated",
        }

    # Enforce max 2 active devices per user
    active_count = (
        db.query(DeviceBinding)
        .filter(
            DeviceBinding.user_id == current_user.id,
            DeviceBinding.is_active == True,
        )
        .count()
    )
    if active_count >= 2:
        raise HTTPException(
            status_code=409,
            detail="Maximum 2 active devices per user. Revoke an existing device first.",
        )

    # Block registration if integrity score is too low
    if integrity_score < 0.3:
        raise HTTPException(
            status_code=403,
            detail="Device integrity check failed. Offline payments not available on this device.",
        )

    binding = DeviceBinding(
        id=generate_uuid(),
        user_id=current_user.id,
        device_id=device_id,
        public_key_pem=public_key_pem,
        public_key_base64=public_key_base64,
        platform=platform,
        os_version=os_version,
        integrity_score=integrity_score,
    )
    db.add(binding)
    db.commit()

    return {
        "status": "bound",
        "device_id": device_id,
        "message": "Device registered for offline payments",
    }


@router.post("/revoke")
def revoke_device(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke a device binding (lost device, security concern)."""
    device_id = payload.get("device_id")
    if not device_id:
        raise HTTPException(status_code=400, detail="device_id required")

    binding = (
        db.query(DeviceBinding)
        .filter(
            DeviceBinding.device_id == device_id,
            DeviceBinding.user_id == current_user.id,
        )
        .first()
    )
    if not binding:
        raise HTTPException(status_code=404, detail="Device not found")

    binding.is_active = False
    binding.revoked_at = datetime.utcnow()
    db.commit()

    return {"status": "revoked", "device_id": device_id}


@router.get("/list")
def list_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all device bindings for the current user."""
    bindings = (
        db.query(DeviceBinding)
        .filter(DeviceBinding.user_id == current_user.id)
        .all()
    )
    return {
        "devices": [
            {
                "device_id": b.device_id,
                "platform": b.platform,
                "is_active": b.is_active,
                "integrity_score": b.integrity_score,
                "created_at": b.created_at.isoformat() if b.created_at else None,
                "last_used_at": b.last_used_at.isoformat() if b.last_used_at else None,
                "revoked_at": b.revoked_at.isoformat() if b.revoked_at else None,
            }
            for b in bindings
        ]
    }
