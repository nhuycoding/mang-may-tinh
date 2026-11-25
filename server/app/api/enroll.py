"""Device enrollment, 8-char pairing codes, token refresh, and revocation (`/enroll`)."""

from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from server.app.config import get_settings
from server.app.crypto import encrypt_field, hash_token
from server.app.database import get_db
from server.app.models import Child, Device, DeviceToken, PairingCode, User, utcnow
from server.app.schemas import (
    DeviceOut,
    EnrollDeviceRequest,
    EnrollDeviceResponse,
    PairingCodeCreateRequest,
    PairingCodeOut,
    RefreshTokenRequest,
    RefreshTokenResponse,
)
from server.app.security import (
    _as_utc,
    authenticate_device_token,
    generate_pairing_code,
    generate_secure_token,
    get_client_ip,
    get_current_user,
    get_owned_child_or_404,
    get_owned_device_or_404,
    rate_limiter,
    require_roles,
)
from server.app.services.audit_service import record_audit_log

router = APIRouter(prefix="/enroll", tags=["enroll"])


@router.post("/pairing-code", response_model=PairingCodeOut, status_code=status.HTTP_201_CREATED)
def create_pairing_code(
    body: PairingCodeCreateRequest,
    request: Request,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> PairingCodeOut:
    """Generate a single-use 8-character pairing code (10-minute TTL) for a child."""
    child = get_owned_child_or_404(db, user, body.child_id)
    settings = get_settings()
    raw_code = generate_pairing_code(8)
    expires_at = utcnow() + timedelta(minutes=settings.pairing_code_ttl_minutes)

    pc = PairingCode(
        code_hash=hash_token(raw_code),
        parent_id=child.parent_id,
        child_id=child.id,
        expires_at=expires_at,
    )
    db.add(pc)

    record_audit_log(
        db,
        parent_id=child.parent_id,
        child_id=child.id,
        actor=user,
        action="enroll.pairing_code_created",
        resource_type="pairing_code",
        source_ip=get_client_ip(request),
        new_value={"child_id": child.id, "expires_at": expires_at.isoformat()},
    )
    db.commit()
    return PairingCodeOut(pairing_code=raw_code, child_id=child.id, expires_at=expires_at)


@router.post("", response_model=EnrollDeviceResponse, status_code=status.HTTP_201_CREATED)
def enroll_device(
    body: EnrollDeviceRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> EnrollDeviceResponse:
    """Enroll an Agent using an 8-char pairing code + device_fingerprint.

    Returns device_id, short-lived access_token (15-min TTL), long-lived refresh_token,
    and per-device HMAC secret for verifying signed policies.
    """
    ip = get_client_ip(request)
    settings = get_settings()
    if not rate_limiter.check(ip, "device_enroll", settings.login_rate_limit_per_minute):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")

    code_hash = hash_token(body.pairing_code.strip().upper())
    pc = db.execute(select(PairingCode).where(PairingCode.code_hash == code_hash)).scalar_one_or_none()
    now = utcnow()
    if pc is None or pc.used_at is not None or (_as_utc(pc.expires_at) is not None and _as_utc(pc.expires_at) <= now):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pairing code is invalid, already used, or expired.",
        )

    hmac_secret = secrets.token_hex(32)
    device = Device(
        parent_id=pc.parent_id,
        child_id=pc.child_id,
        device_name=body.device_name.strip(),
        device_fingerprint_hash=hash_token(body.device_fingerprint.strip()),
        os_version=body.os_version,
        agent_version=body.agent_version,
        hmac_secret_encrypted=encrypt_field(hmac_secret),
        status="online",
        last_heartbeat_at=now,
    )
    db.add(device)
    db.flush()

    pc.used_at = now
    pc.used_by_device_id = device.id

    raw_access = generate_secure_token(32)
    raw_refresh = generate_secure_token(48)
    access_exp = now + timedelta(minutes=settings.access_token_ttl_minutes)
    refresh_exp = now + timedelta(days=settings.refresh_token_ttl_days)

    db.add(
        DeviceToken(
            device_id=device.id,
            token_type="access",
            token_hash=hash_token(raw_access),
            expires_at=access_exp,
        )
    )
    db.add(
        DeviceToken(
            device_id=device.id,
            token_type="refresh",
            token_hash=hash_token(raw_refresh),
            expires_at=refresh_exp,
        )
    )
    db.commit()

    return EnrollDeviceResponse(
        device_id=device.id,
        child_id=device.child_id,
        access_token=raw_access,
        access_token_expires_at=access_exp,
        refresh_token=raw_refresh,
        refresh_token_expires_at=refresh_exp,
        hmac_secret=hmac_secret,
    )


@router.post("/refresh", response_model=RefreshTokenResponse)
def refresh_device_token(
    body: RefreshTokenRequest,
    db: Session = Depends(get_db),
) -> RefreshTokenResponse:
    """Issue a new short-lived access_token (15-min TTL) from a valid non-revoked refresh_token."""
    device = authenticate_device_token(db, body.refresh_token, expected_type="refresh")
    settings = get_settings()
    now = utcnow()
    raw_access = generate_secure_token(32)
    access_exp = now + timedelta(minutes=settings.access_token_ttl_minutes)

    db.add(
        DeviceToken(
            device_id=device.id,
            token_type="access",
            token_hash=hash_token(raw_access),
            expires_at=access_exp,
        )
    )
    db.commit()
    return RefreshTokenResponse(access_token=raw_access, access_token_expires_at=access_exp)


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> list[DeviceOut]:
    """List devices owned by the authenticated family (Anti-IDOR filtered)."""
    stmt = select(Device).order_by(Device.created_at.desc())
    if user.role == "parent":
        stmt = stmt.where(Device.parent_id == user.id)
    elif user.role == "child-view":
        child = db.execute(select(Child).where(Child.child_user_id == user.id)).scalar_one_or_none()
        if child is None:
            return []
        stmt = stmt.where(Device.child_id == child.id)
    devices = db.execute(stmt).scalars().all()
    return [DeviceOut.model_validate(d) for d in devices]


@router.delete("/devices/{device_id}")
def revoke_device(
    device_id: str,
    request: Request,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Revoke a device and invalidate all its access/refresh tokens in the revocation list (F5)."""
    device = get_owned_device_or_404(db, user, device_id)
    now = utcnow()
    old_status = device.status
    device.is_revoked = True
    device.status = "revoked"

    db.execute(
        update(DeviceToken)
        .where(DeviceToken.device_id == device.id, DeviceToken.revoked.is_(False))
        .values(revoked=True, revoked_at=now)
    )

    record_audit_log(
        db,
        parent_id=device.parent_id,
        child_id=device.child_id,
        actor=user,
        action="device.revoke",
        resource_type="device",
        resource_id=device.id,
        source_ip=get_client_ip(request),
        old_value={"status": old_status, "is_revoked": False},
        new_value={"status": "revoked", "is_revoked": True},
    )
    db.commit()
    return {"status": "revoked", "device_id": device.id}
