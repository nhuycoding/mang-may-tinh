"""Authentication, Web Sessions, Child Profiles, and Full Data Wipe endpoints (`/auth`)."""

from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from server.app.config import get_settings
from server.app.crypto import decrypt_field, encrypt_field
from server.app.database import get_db
from server.app.models import (
    Child,
    Command,
    Device,
    Event,
    TimeExtensionRequest,
    User,
    WebSession,
    utcnow,
)
from server.app.schemas import (
    ChildCreateRequest,
    ChildOut,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    UserOut,
)
from server.app.security import (
    SESSION_COOKIE_NAME,
    _as_utc,
    create_web_session,
    get_client_ip,
    get_current_session,
    get_current_user,
    get_owned_child_or_404,
    hash_password,
    rate_limiter,
    require_roles,
    verify_password,
)
from server.app.services.audit_service import record_audit_log
from server.app.services.policy_service import create_default_policy
from server.app.services.ws_manager import ws_manager

router = APIRouter(prefix="/auth", tags=["auth"])


def _child_to_out(child: Child) -> ChildOut:
    return ChildOut(
        id=child.id,
        parent_id=child.parent_id,
        name=decrypt_field(child.name_encrypted),
        age_group=child.age_group,
        timezone=child.timezone,
        child_user_id=child.child_user_id,
        created_at=child.created_at,
    )


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_parent(
    body: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> UserOut:
    """Register a new parent account (Argon2id, min 10-char password)."""
    ip = get_client_ip(request)
    settings = get_settings()
    if not rate_limiter.check(ip, "auth_register", settings.login_rate_limit_per_minute):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")

    email = body.email.strip().lower()
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered.")

    user = User(
        email=email,
        display_name=body.display_name.strip(),
        password_hash=hash_password(body.password),
        role="parent",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Authenticate parent/child-view/admin with Argon2id, 5-attempt 15-min lockout, and HttpOnly cookie."""
    ip = get_client_ip(request)
    settings = get_settings()
    if not rate_limiter.check(ip, "auth_login", settings.login_rate_limit_per_minute):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts from this IP. Please try again later.",
        )

    email = body.email.strip().lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    now = utcnow()

    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    locked_until = _as_utc(user.locked_until)
    if locked_until is not None and locked_until > now:
        remaining_sec = int((locked_until - now).total_seconds())
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account temporarily locked due to failed attempts. Retry in {remaining_sec}s.",
        )

    if not verify_password(body.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.max_failed_logins:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            user.failed_login_attempts = 0
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    # Successful login: reset lockout counters and issue server-side session
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    raw_token, ws = create_web_session(
        db=db,
        user=user,
        ip_address=ip,
        user_agent=request.headers.get("User-Agent"),
    )

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )
    return LoginResponse(
        user=UserOut.model_validate(user),
        csrf_token=ws.csrf_token,
        expires_at=ws.expires_at,
    )


@router.post("/logout")
def logout(
    response: Response,
    ctx: tuple[User, WebSession] = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Invalidate the server-side web session and clear the session cookie."""
    _user, ws = ctx
    ws.revoked_at = utcnow()
    db.commit()
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@router.get("/me", response_model=LoginResponse)
def get_me(
    ctx: tuple[User, WebSession] = Depends(get_current_session),
) -> LoginResponse:
    """Return currently authenticated user and active CSRF token."""
    user, ws = ctx
    return LoginResponse(
        user=UserOut.model_validate(user),
        csrf_token=ws.csrf_token,
        expires_at=ws.expires_at,
    )


@router.post("/children", response_model=ChildOut, status_code=status.HTTP_201_CREATED)
def create_child(
    body: ChildCreateRequest,
    request: Request,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> ChildOut:
    """Create a child profile (AES-GCM encrypted name) with default ages 6-11 signed policy."""
    child_user_id: int | None = None
    if body.child_view_email:
        if not body.child_view_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="child_view_password is required when child_view_email is provided.",
            )
        child_email = body.child_view_email.strip().lower()
        if db.execute(select(User).where(User.email == child_email)).scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Child email already exists.")
        child_user = User(
            email=child_email,
            display_name=body.name.strip(),
            password_hash=hash_password(body.child_view_password),
            role="child-view",
            parent_id=user.id,
        )
        db.add(child_user)
        db.flush()
        child_user_id = child_user.id

    child = Child(
        parent_id=user.id,
        child_user_id=child_user_id,
        name_encrypted=encrypt_field(body.name.strip()),
        age_group=body.age_group,
        timezone=body.timezone,
    )
    db.add(child)
    db.flush()

    policy = create_default_policy(db, child_id=child.id, parent_id=user.id)

    record_audit_log(
        db,
        parent_id=user.id,
        child_id=child.id,
        actor=user,
        action="child.create",
        resource_type="child",
        resource_id=str(child.id),
        source_ip=get_client_ip(request),
        old_value=None,
        new_value={"age_group": child.age_group, "policy_version": policy.policy_version},
    )
    db.commit()
    db.refresh(child)
    return _child_to_out(child)


@router.get("/children", response_model=list[ChildOut])
def list_children(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ChildOut]:
    """List child profiles owned by the authenticated user (Anti-IDOR filtered)."""
    stmt = select(Child).order_by(Child.id.asc())
    if user.role == "parent":
        stmt = stmt.where(Child.parent_id == user.id)
    elif user.role == "child-view":
        stmt = stmt.where(Child.child_user_id == user.id)
    children = db.execute(stmt).scalars().all()
    return [_child_to_out(c) for c in children]


@router.delete("/children/{child_id}/data")
async def delete_all_child_data(
    child_id: int,
    request: Request,
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> dict[str, int | str]:
    """F3: 'Delete all my child's data' — wipes Server events/requests AND pushes `wipe_local_data` to Agents."""
    child = get_owned_child_or_404(db, user, child_id)

    deleted_events = db.execute(delete(Event).where(Event.child_id == child.id)).rowcount or 0
    deleted_requests = (
        db.execute(delete(TimeExtensionRequest).where(TimeExtensionRequest.child_id == child.id)).rowcount
        or 0
    )

    devices = db.execute(
        select(Device).where(Device.child_id == child.id, Device.is_revoked.is_(False))
    ).scalars().all()

    pushed_count = 0
    for dev in devices:
        dev.used_quota_sec_today = 0
        cmd = Command(
            device_id=dev.id,
            issued_by_user_id=user.id,
            command_type="wipe_local_data",
            payload_json=json.dumps({"reason": "parent_requested_full_wipe"}),
            status="pending",
        )
        db.add(cmd)
        db.flush()
        delivered = await ws_manager.push_command(
            dev.id,
            {
                "type": "command",
                "command_id": cmd.id,
                "command_type": cmd.command_type,
                "payload": {"reason": "parent_requested_full_wipe"},
                "created_at": cmd.created_at.isoformat(),
            },
        )
        if delivered:
            cmd.status = "sent"
            cmd.delivered_at = utcnow()
            pushed_count += 1

    record_audit_log(
        db,
        parent_id=child.parent_id,
        child_id=child.id,
        actor=user,
        action="child.data_wipe",
        resource_type="child",
        resource_id=str(child.id),
        source_ip=get_client_ip(request),
        old_value={"events_count": int(deleted_events), "extension_requests": int(deleted_requests)},
        new_value={"wiped": True, "devices_notified": len(devices)},
    )
    db.commit()

    return {
        "status": "wiped",
        "deleted_events": int(deleted_events),
        "deleted_extension_requests": int(deleted_requests),
        "devices_queued": len(devices),
        "devices_pushed_realtime": pushed_count,
    }
