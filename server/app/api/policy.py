"""Policy retrieval (HMAC-SHA256 signed), updates with AuditLog, and domain catalog (`/policy`)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.app.crypto import decrypt_field
from server.app.database import get_db
from server.app.models import Device, DomainCategory, Policy, User
from server.app.schemas import PaginatedResponse, PolicyUpdateRequest, SignedPolicyResponse
from server.app.security import (
    get_client_ip,
    get_current_device,
    get_current_user,
    get_owned_child_or_404,
    normalize_second_level_domain,
    require_roles,
)
from server.app.services.audit_service import record_audit_log
from server.app.services.policy_service import (
    build_policy_payload,
    create_default_policy,
    sign_and_persist_policy,
    sign_policy_for_device,
)
from server.app.services.ws_manager import ws_manager

router = APIRouter(prefix="/policy", tags=["policy"])


@router.get("", response_model=SignedPolicyResponse)
def get_policy_for_agent(
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> SignedPolicyResponse:
    """Agent endpoint: returns latest versioned policy signed with device's HMAC-SHA256 secret."""
    policy = db.execute(select(Policy).where(Policy.child_id == device.child_id)).scalar_one_or_none()
    if policy is None:
        policy = create_default_policy(db, child_id=device.child_id, parent_id=device.parent_id)
        db.commit()
        db.refresh(policy)

    device_secret = decrypt_field(device.hmac_secret_encrypted)
    payload, payload_str, signature = sign_policy_for_device(policy, db, device_secret)
    return SignedPolicyResponse(
        policy_id=policy.id,
        child_id=policy.child_id,
        policy_version=policy.policy_version,
        payload=payload,
        payload_json=payload_str,
        signature_hmac=signature,
        updated_at=policy.updated_at,
    )


@router.get("/domains", response_model=PaginatedResponse)
def list_categorized_domains(
    category: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    _user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Paginated listing of the 6-category safe domain dataset."""
    stmt = select(DomainCategory)
    count_stmt = select(func.count(DomainCategory.id))

    if category:
        stmt = stmt.where(DomainCategory.category == category)
        count_stmt = count_stmt.where(DomainCategory.category == category)
    if search:
        like = f"%{search.strip().lower()}%"
        stmt = stmt.where(DomainCategory.domain.like(like))
        count_stmt = count_stmt.where(DomainCategory.domain.like(like))

    total = db.execute(count_stmt).scalar() or 0
    rows = (
        db.execute(
            stmt.order_by(DomainCategory.domain.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    return PaginatedResponse(
        items=[{"id": r.id, "domain": r.domain, "category": r.category} for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/{child_id}", response_model=SignedPolicyResponse)
def get_child_policy(
    child_id: int,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> SignedPolicyResponse:
    """Parent / Admin endpoint: fetch signed policy for an owned child."""
    child = get_owned_child_or_404(db, user, child_id)
    policy = db.execute(select(Policy).where(Policy.child_id == child.id)).scalar_one_or_none()
    if policy is None:
        policy = create_default_policy(db, child_id=child.id, parent_id=child.parent_id)
        db.commit()
        db.refresh(policy)

    payload = build_policy_payload(policy, db=db)
    return SignedPolicyResponse(
        policy_id=policy.id,
        child_id=policy.child_id,
        policy_version=policy.policy_version,
        payload=payload,
        payload_json=policy.payload_json,
        signature_hmac=policy.signature_hmac,
        updated_at=policy.updated_at,
    )


@router.put("/{child_id}", response_model=SignedPolicyResponse)
async def update_child_policy(
    child_id: int,
    body: PolicyUpdateRequest,
    request: Request,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> SignedPolicyResponse:
    """Update a child's policy, bump policy_version, re-sign HMAC-SHA256, write AuditLog, and push via WebSocket."""
    child = get_owned_child_or_404(db, user, child_id)
    policy = db.execute(select(Policy).where(Policy.child_id == child.id)).scalar_one_or_none()
    if policy is None:
        policy = create_default_policy(db, child_id=child.id, parent_id=child.parent_id)

    old_snapshot = {
        "policy_version": policy.policy_version,
        "weekday_quota_sec": policy.weekday_quota_sec,
        "weekend_quota_sec": policy.weekend_quota_sec,
        "grace_period_sec": policy.grace_period_sec,
        "idle_timeout_sec": policy.idle_timeout_sec,
        "offline_expiry_days": policy.offline_expiry_days,
        "offline_expiry_mode": policy.offline_expiry_mode,
        "safesearch_enabled": policy.safesearch_enabled,
        "blocked_categories": json.loads(policy.blocked_categories_json),
        "allowed_domains": json.loads(policy.allowed_domains_json),
        "blocked_domains": json.loads(policy.blocked_domains_json),
        "app_rules": json.loads(policy.app_rules_json),
    }

    if body.weekday_quota_sec is not None:
        policy.weekday_quota_sec = body.weekday_quota_sec
    if body.weekend_quota_sec is not None:
        policy.weekend_quota_sec = body.weekend_quota_sec
    if body.weekly_schedule is not None:
        policy.weekly_schedule_json = json.dumps(body.weekly_schedule, separators=(",", ":"))
    if body.grace_period_sec is not None:
        policy.grace_period_sec = body.grace_period_sec
    if body.idle_timeout_sec is not None:
        policy.idle_timeout_sec = body.idle_timeout_sec
    if body.offline_expiry_days is not None:
        policy.offline_expiry_days = body.offline_expiry_days
    if body.offline_expiry_mode is not None:
        policy.offline_expiry_mode = body.offline_expiry_mode
    if body.safesearch_enabled is not None:
        policy.safesearch_enabled = body.safesearch_enabled
    if body.blocked_categories is not None:
        policy.blocked_categories_json = json.dumps(body.blocked_categories, separators=(",", ":"))
    if body.allowed_domains is not None:
        try:
            normalized = sorted({normalize_second_level_domain(d) for d in body.allowed_domains if d.strip()})
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        policy.allowed_domains_json = json.dumps(normalized, separators=(",", ":"))
    if body.blocked_domains is not None:
        try:
            normalized = sorted({normalize_second_level_domain(d) for d in body.blocked_domains if d.strip()})
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        policy.blocked_domains_json = json.dumps(normalized, separators=(",", ":"))
    if body.app_rules is not None:
        policy.app_rules_json = json.dumps(
            [rule.model_dump() for rule in body.app_rules], separators=(",", ":")
        )

    policy.policy_version += 1
    sign_and_persist_policy(policy, db)

    new_snapshot = {
        "policy_version": policy.policy_version,
        "weekday_quota_sec": policy.weekday_quota_sec,
        "weekend_quota_sec": policy.weekend_quota_sec,
        "grace_period_sec": policy.grace_period_sec,
        "idle_timeout_sec": policy.idle_timeout_sec,
        "offline_expiry_days": policy.offline_expiry_days,
        "offline_expiry_mode": policy.offline_expiry_mode,
        "safesearch_enabled": policy.safesearch_enabled,
        "blocked_categories": json.loads(policy.blocked_categories_json),
        "allowed_domains": json.loads(policy.allowed_domains_json),
        "blocked_domains": json.loads(policy.blocked_domains_json),
        "app_rules": json.loads(policy.app_rules_json),
    }

    record_audit_log(
        db,
        parent_id=child.parent_id,
        child_id=child.id,
        actor=user,
        action="policy.update",
        resource_type="policy",
        resource_id=str(policy.id),
        source_ip=get_client_ip(request),
        old_value=old_snapshot,
        new_value=new_snapshot,
    )
    db.commit()
    db.refresh(policy)

    # Immediately push `policy_updated` over WebSocket to all connected devices of this child (< 5s latency)
    devices = (
        db.execute(
            select(Device).where(Device.child_id == child.id, Device.is_revoked.is_(False))
        )
        .scalars()
        .all()
    )
    for dev in devices:
        await ws_manager.push_command(
            dev.id,
            {
                "type": "policy_updated",
                "policy_id": policy.id,
                "child_id": child.id,
                "policy_version": policy.policy_version,
                "updated_at": policy.updated_at.isoformat(),
            },
        )

    payload = build_policy_payload(policy, db=db)
    return SignedPolicyResponse(
        policy_id=policy.id,
        child_id=policy.child_id,
        policy_version=policy.policy_version,
        payload=payload,
        payload_json=policy.payload_json,
        signature_hmac=policy.signature_hmac,
        updated_at=policy.updated_at,
    )
