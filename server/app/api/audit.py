"""Transparent Audit Log endpoints (`/audit`) accessible to parents, child-view, admin, and Agent Tray UI."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.app.database import get_db
from server.app.models import AuditLog, Child, Device, User
from server.app.schemas import AuditLogOut, PaginatedResponse
from server.app.security import get_current_device, get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])


def _serialize_audit(entry: AuditLog) -> dict:
    return AuditLogOut(
        id=entry.id,
        parent_id=entry.parent_id,
        child_id=entry.child_id,
        actor_email=entry.actor_email,
        actor_role=entry.actor_role,
        action=entry.action,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        source_ip=entry.source_ip,
        old_value=json.loads(entry.old_value_json) if entry.old_value_json else None,
        new_value=json.loads(entry.new_value_json) if entry.new_value_json else None,
        timestamp=entry.timestamp,
    ).model_dump()


@router.get("", response_model=PaginatedResponse)
def list_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Paginated audit log of parent configuration changes (accessible to parent, child-view, admin)."""
    stmt = select(AuditLog)
    count_stmt = select(func.count(AuditLog.id))

    if user.role == "parent":
        stmt = stmt.where(AuditLog.parent_id == user.id)
        count_stmt = count_stmt.where(AuditLog.parent_id == user.id)
    elif user.role == "child-view":
        child = db.execute(select(Child).where(Child.child_user_id == user.id)).scalar_one_or_none()
        if child is None:
            return PaginatedResponse(items=[], total=0, page=page, page_size=page_size)
        stmt = stmt.where(AuditLog.parent_id == child.parent_id)
        count_stmt = count_stmt.where(AuditLog.parent_id == child.parent_id)

    total = db.execute(count_stmt).scalar() or 0
    rows = (
        db.execute(
            stmt.order_by(AuditLog.timestamp.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    return PaginatedResponse(
        items=[_serialize_audit(r) for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/agent", response_model=PaginatedResponse)
def list_audit_logs_for_agent(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Read-only Audit Log endpoint for the Agent Tray UI transparency screen."""
    stmt = select(AuditLog).where(AuditLog.parent_id == device.parent_id)
    count_stmt = select(func.count(AuditLog.id)).where(AuditLog.parent_id == device.parent_id)

    total = db.execute(count_stmt).scalar() or 0
    rows = (
        db.execute(
            stmt.order_by(AuditLog.timestamp.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    return PaginatedResponse(
        items=[_serialize_audit(r) for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )
