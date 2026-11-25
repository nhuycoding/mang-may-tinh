"""Urgent Commands (WebSocket < 5s + Heartbeat fallback) and Extension Request Decisions (`/commands`)."""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.app.database import SessionLocal, get_db
from server.app.models import Child, Command, Device, Event, Policy, TimeExtensionRequest, User, utcnow
from server.app.schemas import (
    CommandAckRequest,
    CommandCreateRequest,
    CommandOut,
    ExtensionDecisionRequest,
    ExtensionRequestOut,
    PaginatedResponse,
)
from server.app.security import (
    authenticate_device_token,
    get_client_ip,
    get_current_device,
    get_current_user,
    get_owned_device_or_404,
    require_roles,
)
from server.app.services.audit_service import record_audit_log
from server.app.services.ws_manager import ws_manager

router = APIRouter(prefix="/commands", tags=["commands"])


@router.post("", response_model=CommandOut, status_code=status.HTTP_201_CREATED)
async def issue_command(
    body: CommandCreateRequest,
    request: Request,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> CommandOut:
    """Parent issues an urgent command (`lock_now`, `unlock`, `add_15_mins`, `wipe_local_data`)."""
    device = get_owned_device_or_404(db, user, body.device_id)
    if device.is_revoked:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device is revoked.")

    cmd = Command(
        device_id=device.id,
        issued_by_user_id=user.id,
        command_type=body.command_type,
        payload_json=json.dumps(body.payload) if body.payload is not None else None,
        status="pending",
    )
    db.add(cmd)
    db.flush()

    delivered = await ws_manager.push_command(
        device.id,
        {
            "type": "command",
            "command_id": cmd.id,
            "command_type": cmd.command_type,
            "payload": body.payload,
            "created_at": cmd.created_at.isoformat(),
        },
    )
    if delivered:
        cmd.status = "sent"
        cmd.delivered_at = utcnow()

    if body.command_type == "add_15_mins":
        mins = int((body.payload or {}).get("minutes", 15))
        policy = db.execute(select(Policy).where(Policy.child_id == device.child_id)).scalar_one_or_none()
        db.add(
            Event(
                idempotency_key=f"cmd-override-{cmd.id}-{uuid.uuid4().hex[:8]}",
                ts=utcnow(),
                device_id=device.id,
                child_id=device.child_id,
                type="override_granted",
                subject=f"add_{mins}_mins",
                duration_sec=mins * 60,
                policy_id=policy.id if policy else None,
            )
        )
    elif body.command_type == "lock_now":
        device.status = "locked"
    elif body.command_type == "unlock":
        device.status = "online"

    record_audit_log(
        db,
        parent_id=device.parent_id,
        child_id=device.child_id,
        actor=user,
        action=f"command.{body.command_type}",
        resource_type="device",
        resource_id=device.id,
        source_ip=get_client_ip(request),
        new_value={"command_id": cmd.id, "command_type": body.command_type, "delivered_ws": delivered},
    )
    db.commit()
    db.refresh(cmd)
    return CommandOut.model_validate(cmd)


@router.get("", response_model=PaginatedResponse)
def list_commands(
    device_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Paginated listing of commands for devices owned by the authenticated family."""
    stmt = select(Command)
    count_stmt = select(func.count(Command.id))

    if device_id:
        dev = get_owned_device_or_404(db, user, device_id)
        stmt = stmt.where(Command.device_id == dev.id)
        count_stmt = count_stmt.where(Command.device_id == dev.id)
    elif user.role == "parent":
        owned_devs = select(Device.id).where(Device.parent_id == user.id)
        stmt = stmt.where(Command.device_id.in_(owned_devs))
        count_stmt = count_stmt.where(Command.device_id.in_(owned_devs))
    elif user.role == "child-view":
        child = db.execute(select(Child).where(Child.child_user_id == user.id)).scalar_one_or_none()
        if child is None:
            return PaginatedResponse(items=[], total=0, page=page, page_size=page_size)
        owned_devs = select(Device.id).where(Device.child_id == child.id)
        stmt = stmt.where(Command.device_id.in_(owned_devs))
        count_stmt = count_stmt.where(Command.device_id.in_(owned_devs))

    total = db.execute(count_stmt).scalar() or 0
    rows = (
        db.execute(
            stmt.order_by(Command.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        )
        .scalars()
        .all()
    )
    return PaginatedResponse(
        items=[CommandOut.model_validate(r).model_dump() for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.post("/{command_id}/ack", response_model=CommandOut)
def acknowledge_command(
    command_id: str,
    body: CommandAckRequest,
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> CommandOut:
    """Agent acknowledges receipt and execution of a command."""
    cmd = db.execute(
        select(Command).where(Command.id == command_id, Command.device_id == device.id)
    ).scalar_one_or_none()
    if cmd is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Command not found.")

    cmd.status = body.status
    cmd.acked_at = utcnow()
    db.commit()
    db.refresh(cmd)
    return CommandOut.model_validate(cmd)


@router.get("/extension-requests", response_model=list[ExtensionRequestOut])
def list_extension_requests(
    status_filter: str | None = Query(default=None, alias="status"),
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> list[ExtensionRequestOut]:
    """List child time-extension requests owned by the authenticated family."""
    stmt = select(TimeExtensionRequest)
    if user.role == "parent":
        owned_children = select(Child.id).where(Child.parent_id == user.id)
        stmt = stmt.where(TimeExtensionRequest.child_id.in_(owned_children))
    elif user.role == "child-view":
        owned_children = select(Child.id).where(Child.child_user_id == user.id)
        stmt = stmt.where(TimeExtensionRequest.child_id.in_(owned_children))

    if status_filter:
        stmt = stmt.where(TimeExtensionRequest.status == status_filter)

    rows = db.execute(stmt.order_by(TimeExtensionRequest.created_at.desc()).limit(50)).scalars().all()
    return [ExtensionRequestOut.model_validate(r) for r in rows]


@router.post("/extension-requests/{request_id}/decision", response_model=ExtensionRequestOut)
async def decide_extension_request(
    request_id: int,
    body: ExtensionDecisionRequest,
    request: Request,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> ExtensionRequestOut:
    """Approve or deny a child's time-extension request. Approval pushes `add_15_mins` in real time."""
    req = db.get(TimeExtensionRequest, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Extension request not found.")

    # Anti-IDOR ownership check
    child = db.get(Child, req.child_id)
    if child is None or (user.role == "parent" and child.parent_id != user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Extension request not found.")

    if req.status != "pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request already decided.")

    now = utcnow()
    req.status = body.decision
    req.decided_by_user_id = user.id
    req.decided_at = now

    if body.decision == "approved":
        cmd = Command(
            device_id=req.device_id,
            issued_by_user_id=user.id,
            command_type="add_15_mins",
            payload_json=json.dumps({"minutes": req.requested_minutes, "request_id": req.id}),
            status="pending",
        )
        db.add(cmd)
        db.flush()

        delivered = await ws_manager.push_command(
            req.device_id,
            {
                "type": "command",
                "command_id": cmd.id,
                "command_type": "add_15_mins",
                "payload": {"minutes": req.requested_minutes, "request_id": req.id},
                "created_at": cmd.created_at.isoformat(),
            },
        )
        if delivered:
            cmd.status = "sent"
            cmd.delivered_at = now

        policy = db.execute(select(Policy).where(Policy.child_id == child.id)).scalar_one_or_none()
        db.add(
            Event(
                idempotency_key=f"override-{req.id}-{uuid.uuid4().hex[:8]}",
                ts=now,
                device_id=req.device_id,
                child_id=child.id,
                type="override_granted",
                subject=f"add_{req.requested_minutes}_mins",
                duration_sec=req.requested_minutes * 60,
                policy_id=policy.id if policy else None,
            )
        )

    record_audit_log(
        db,
        parent_id=child.parent_id,
        child_id=child.id,
        actor=user,
        action=f"extension.{body.decision}",
        resource_type="time_extension_request",
        resource_id=str(req.id),
        source_ip=get_client_ip(request),
        old_value={"status": "pending"},
        new_value={"status": body.decision, "minutes": req.requested_minutes},
    )
    db.commit()
    db.refresh(req)
    return ExtensionRequestOut.model_validate(req)


@router.websocket("/ws/{device_id}")
async def device_command_websocket(websocket: WebSocket, device_id: str) -> None:
    """Real-time WebSocket channel for pushing urgent commands to an Agent (< 5s latency).

    Authenticates using `token` query parameter or `Authorization: Bearer <access_token>` header.
    """
    raw_token = websocket.query_params.get("token", "")
    if not raw_token:
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[len("Bearer ") :].strip()

    with SessionLocal() as db:
        try:
            device = authenticate_device_token(db, raw_token, expected_type="access")
        except HTTPException:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if device.id != device_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await ws_manager.connect(device_id, websocket)
    try:
        # Flush any pending commands immediately upon connect
        with SessionLocal() as db:
            pending = (
                db.execute(
                    select(Command)
                    .where(Command.device_id == device_id, Command.status == "pending")
                    .order_by(Command.created_at.asc())
                )
                .scalars()
                .all()
            )
            now = utcnow()
            for cmd in pending:
                await websocket.send_json(
                    {
                        "type": "command",
                        "command_id": cmd.id,
                        "command_type": cmd.command_type,
                        "payload": json.loads(cmd.payload_json) if cmd.payload_json else None,
                        "created_at": cmd.created_at.isoformat(),
                    }
                )
                cmd.status = "sent"
                cmd.delivered_at = now
            db.commit()

        while True:
            msg = await websocket.receive_json()
            msg_type = msg.get("type")
            if msg_type == "ping":
                await websocket.send_json({"type": "pong", "server_time": utcnow().isoformat()})
            elif msg_type == "ack" and msg.get("command_id"):
                with SessionLocal() as db:
                    cmd = db.execute(
                        select(Command).where(
                            Command.id == msg["command_id"], Command.device_id == device_id
                        )
                    ).scalar_one_or_none()
                    if cmd is not None:
                        cmd.status = msg.get("status", "acknowledged")
                        cmd.acked_at = utcnow()
                        db.commit()
    except WebSocketDisconnect:
        await ws_manager.disconnect(device_id, websocket)
    except Exception:
        await ws_manager.disconnect(device_id, websocket)
