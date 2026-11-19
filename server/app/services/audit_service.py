"""Audit logging service (F4: actor, timestamp, source IP, old_value, new_value)."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from server.app.models import AuditLog, User, utcnow


def record_audit_log(
    db: Session,
    *,
    parent_id: int,
    actor: User,
    action: str,
    resource_type: str,
    source_ip: str,
    child_id: int | None = None,
    resource_id: str | None = None,
    old_value: Any | None = None,
    new_value: Any | None = None,
) -> AuditLog:
    """Persist an immutable AuditLog entry visible to both parents and the child."""
    entry = AuditLog(
        parent_id=parent_id,
        child_id=child_id,
        actor_id=actor.id,
        actor_email=actor.email,
        actor_role=actor.role,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        source_ip=source_ip[:45],
        old_value_json=json.dumps(old_value, ensure_ascii=False, sort_keys=True)
        if old_value is not None
        else None,
        new_value_json=json.dumps(new_value, ensure_ascii=False, sort_keys=True)
        if new_value is not None
        else None,
        timestamp=utcnow(),
    )
    db.add(entry)
    return entry
