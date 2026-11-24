"""Activity Events (strict F3 schema + idempotent offline sync), Heartbeat, and Extension Requests (`/events`)."""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.app.database import get_db
from server.app.models import Child, Command, Device, Event, Policy, TimeExtensionRequest, User, utcnow
from server.app.schemas import (
    EventBatchRequest,
    EventBatchResponse,
    EventOut,
    ExtensionRequestCreate,
    ExtensionRequestOut,
    HeartbeatRequest,
    HeartbeatResponse,
    PaginatedResponse,
    PendingCommandOut,
)
from server.app.security import (
    _as_utc,
    get_current_device,
    get_current_user,
    get_owned_child_or_404,
    sanitize_event_subject,
)

router = APIRouter(prefix="/events", tags=["events"])
DEVICE_REMAINING_CACHE: dict[str, int] = {}


@router.post("/batch", response_model=EventBatchResponse)
def ingest_event_batch(
    body: EventBatchRequest,
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> EventBatchResponse:
    """Ingest batched events from Agent with idempotency_key deduplication and strict F3 sanitization."""
    keys = [e.idempotency_key for e in body.events]
    existing_keys = set(
        db.execute(select(Event.idempotency_key).where(Event.idempotency_key.in_(keys))).scalars().all()
    )

    accepted = 0
    duplicates = 0
    seen_in_batch: set[str] = set()

    for item in body.events:
        if item.idempotency_key in existing_keys or item.idempotency_key in seen_in_batch:
            duplicates += 1
            continue
        seen_in_batch.add(item.idempotency_key)

        try:
            clean_subject = sanitize_event_subject(item.type, item.subject)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid event subject for {item.type}: {exc}",
            ) from exc

        ev = Event(
            idempotency_key=item.idempotency_key,
            ts=_as_utc(item.ts) or utcnow(),
            device_id=device.id,
            child_id=device.child_id,
            type=item.type,
            subject=clean_subject,
            duration_sec=item.duration_sec,
            policy_id=item.policy_id,
        )
        db.add(ev)
        accepted += 1

    db.commit()
    return EventBatchResponse(accepted=accepted, duplicates_skipped=duplicates)


@router.get("", response_model=PaginatedResponse)
def list_events(
    child_id: int | None = Query(default=None),
    event_type: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Paginated activity event listing with RBAC & Anti-IDOR ownership filtering."""
    stmt = select(Event)
    count_stmt = select(func.count(Event.id))

    if child_id is not None:
        child = get_owned_child_or_404(db, user, child_id)
        stmt = stmt.where(Event.child_id == child.id)
        count_stmt = count_stmt.where(Event.child_id == child.id)
    elif user.role == "parent":
        owned_ids = select(Child.id).where(Child.parent_id == user.id)
        stmt = stmt.where(Event.child_id.in_(owned_ids))
        count_stmt = count_stmt.where(Event.child_id.in_(owned_ids))
    elif user.role == "child-view":
        owned_ids = select(Child.id).where(Child.child_user_id == user.id)
        stmt = stmt.where(Event.child_id.in_(owned_ids))
        count_stmt = count_stmt.where(Event.child_id.in_(owned_ids))

    if event_type:
        stmt = stmt.where(Event.type == event_type)
        count_stmt = count_stmt.where(Event.type == event_type)

    total = db.execute(count_stmt).scalar() or 0
    rows = (
        db.execute(
            stmt.order_by(Event.ts.desc()).offset((page - 1) * page_size).limit(page_size)
        )
        .scalars()
        .all()
    )
    return PaginatedResponse(
        items=[EventOut.model_validate(r).model_dump() for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
def device_heartbeat(
    body: HeartbeatRequest,
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> HeartbeatResponse:
    """60s Agent heartbeat: cross-checks server_time vs client_time, updates quota, returns policy version & pending commands."""
    now = utcnow()
    client_ts = _as_utc(body.client_time) or now
    skew_sec = int((client_ts - now).total_seconds())

    device.last_heartbeat_at = now
    device.used_quota_sec_today = max(device.used_quota_sec_today, body.used_quota_sec_today)
    device.current_policy_version = body.current_policy_version
    device.last_clock_skew_sec = skew_sec
    if body.remaining_sec_today is not None:
        DEVICE_REMAINING_CACHE[device.id] = body.remaining_sec_today

    # Anti-clock tampering detection (F1): flag if clock skew > 120s or Agent reported tamper
    clock_tampered = body.clock_tamper_detected or abs(skew_sec) > 120
    device.status = "tampered" if clock_tampered else body.status

    policy = db.execute(select(Policy).where(Policy.child_id == device.child_id)).scalar_one_or_none()
    latest_version = policy.policy_version if policy is not None else 1

    if clock_tampered:
        db.add(
            Event(
                idempotency_key=f"tamper-{device.id}-{int(now.timestamp())}-{uuid.uuid4().hex[:8]}",
                ts=now,
                device_id=device.id,
                child_id=device.child_id,
                type="quota_warning",
                subject=f"clock_tamper_skew_{skew_sec}s",
                duration_sec=0,
                policy_id=policy.id if policy else None,
            )
        )

    pending_rows = (
        db.execute(
            select(Command)
            .where(Command.device_id == device.id, Command.status.in_(["pending", "sent"]))
            .order_by(Command.created_at.asc())
        )
        .scalars()
        .all()
    )
    pending_out: list[PendingCommandOut] = []
    for cmd in pending_rows:
        if cmd.status == "pending":
            cmd.status = "sent"
            cmd.delivered_at = now
        pending_out.append(
            PendingCommandOut(
                id=cmd.id,
                command_type=cmd.command_type,
                payload=json.loads(cmd.payload_json) if cmd.payload_json else None,
                created_at=cmd.created_at,
            )
        )

    db.commit()
    return HeartbeatResponse(
        server_time=now,
        latest_policy_version=latest_version,
        policy_update_required=body.current_policy_version != latest_version,
        clock_skew_sec=skew_sec,
        pending_commands=pending_out,
    )


@router.post("/extension-request", response_model=ExtensionRequestOut, status_code=status.HTTP_201_CREATED)
def submit_extension_request(
    body: ExtensionRequestCreate,
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> ExtensionRequestOut:
    """Agent/Child submits a 'Request more time' request to the Parent Dashboard queue."""
    now = utcnow()
    req = TimeExtensionRequest(
        child_id=device.child_id,
        device_id=device.id,
        requested_minutes=body.requested_minutes,
        reason=(body.reason or "Requesting extra study/play time").strip(),
        status="pending",
    )
    db.add(req)

    policy = db.execute(select(Policy).where(Policy.child_id == device.child_id)).scalar_one_or_none()
    db.add(
        Event(
            idempotency_key=f"unlockreq-{device.id}-{uuid.uuid4().hex[:12]}",
            ts=now,
            device_id=device.id,
            child_id=device.child_id,
            type="unlock_request",
            subject=f"request_{body.requested_minutes}_mins",
            duration_sec=body.requested_minutes * 60,
            policy_id=policy.id if policy else None,
        )
    )
    db.commit()
    db.refresh(req)
    return ExtensionRequestOut.model_validate(req)
