"""Authentication, Authorization (RBAC + Anti-IDOR), CSRF, Rate Limiting, and Sanitization."""

from __future__ import annotations

import ipaddress
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Iterable
from urllib.parse import urlparse

from argon2 import PasswordHasher, Type as Argon2Type
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from server.app.config import get_settings
from server.app.crypto import hash_token
from server.app.database import get_db
from server.app.models import Child, Device, DeviceToken, User, WebSession, utcnow

# Argon2id password hasher (F5)
_password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Argon2Type.ID,
)

SESSION_COOKIE_NAME = "ogk_session"
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_APP_NAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,120}$")


def hash_password(plain_password: str) -> str:
    """Hash password with Argon2id after enforcing minimum length >= 10."""
    if len(plain_password) < 10:
        raise ValueError("Password must be at least 10 characters long.")
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a password against an Argon2id hash."""
    try:
        return _password_hasher.verify(password_hash, plain_password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure URL-safe token."""
    return secrets.token_urlsafe(nbytes)


def generate_pairing_code(length: int = 8) -> str:
    """Generate an 8-character uppercase alphanumeric pairing code (ambiguous chars omitted)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_client_ip(request: Request) -> str:
    """Extract client IP address safely."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    if request.client and request.client.host:
        return request.client.host[:45]
    return "127.0.0.1"


def normalize_second_level_domain(raw_value: str) -> str:
    """Extract ONLY the second-level domain (e.g., 'youtube.com') from a domain or URL.

    Never stores full URLs, paths, or query parameters (F3 strict privacy rule).
    """
    value = raw_value.strip().lower()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        # Strip any path/query/port if accidentally provided
        host = value.split("/")[0].split("?")[0].split("#")[0].split(":")[0]

    host = host.strip(".")
    if not host:
        raise ValueError("Empty domain subject.")

    # Reject raw IP addresses as domain subjects (normalize cleanly)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    parts = [p for p in host.split(".") if p]
    if len(parts) < 2 or not all(_DOMAIN_LABEL_RE.match(p) for p in parts):
        raise ValueError(f"Invalid domain subject: {raw_value!r}")

    # Common multi-part public suffixes (e.g. co.uk, edu.vn, com.vn)
    multi_tlds = {"co.uk", "org.uk", "com.vn", "edu.vn", "gov.vn", "net.vn", "com.au", "co.jp"}
    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in multi_tlds:
        return ".".join(parts[-3:])
    return last_two


def sanitize_event_subject(event_type: str, raw_subject: str) -> str:
    """Enforce F3 strict subject rule: app name or second-level domain ONLY, never full URLs."""
    raw = raw_subject.strip()
    if not raw:
        raise ValueError("Event subject cannot be empty.")

    if event_type in ("domain_query", "blocked_domain"):
        return normalize_second_level_domain(raw)

    # For app/system events, strip any path separators so only the executable/app name or reason code remains
    if "/" in raw or "\\" in raw or "://" in raw:
        cleaned = raw.replace("\\", "/").split("/")[-1].split("?")[0]
        raw = cleaned or "unknown"

    raw = raw[:120]
    if not _APP_NAME_RE.match(raw):
        # Replace unsafe characters with underscore while preserving readability
        raw = re.sub(r"[^A-Za-z0-9._ -]", "_", raw)[:120]
    return raw


class InMemoryIPRateLimiter:
    """Sliding-window IP-based rate limiter."""

    def __init__(self) -> None:
        self._buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, ip: str, scope: str, limit: int, window_sec: int = 60) -> bool:
        """Return True if request is allowed, False if rate limit exceeded."""
        now = time.monotonic()
        key = (scope, ip)
        bucket = self._buckets[key]
        cutoff = now - window_sec
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

    def reset(self) -> None:
        """Clear all rate-limit buckets (used in tests)."""
        self._buckets.clear()


rate_limiter = InMemoryIPRateLimiter()


def create_web_session(
    db: Session,
    user: User,
    ip_address: str,
    user_agent: str | None = None,
) -> tuple[str, WebSession]:
    """Create a persisted server-side web session (12h TTL) and return (raw_cookie_token, WebSession)."""
    settings = get_settings()
    raw_token = generate_secure_token(32)
    csrf_token = generate_secure_token(24)
    now = utcnow()
    session_obj = WebSession(
        id=hash_token(raw_token),
        user_id=user.id,
        csrf_token=csrf_token,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255],
        created_at=now,
        expires_at=now + timedelta(hours=settings.session_ttl_hours),
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)
    return raw_token, session_obj


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def get_current_session(
    request: Request,
    ogk_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> tuple[User, WebSession]:
    """Resolve authenticated user and active server-side WebSession from HttpOnly cookie."""
    if not ogk_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    session_id = hash_token(ogk_session)
    ws = db.get(WebSession, session_id)
    now = utcnow()
    if (
        ws is None
        or ws.revoked_at is not None
        or (_as_utc(ws.expires_at) is not None and _as_utc(ws.expires_at) <= now)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or revoked.",
        )

    user = db.get(User, ws.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account inactive.",
        )

    # CSRF protection for state-changing web requests (F5)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        header_csrf = request.headers.get("X-CSRF-Token", "")
        if not header_csrf or not secrets.compare_digest(header_csrf, ws.csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing CSRF token.",
            )

    return user, ws


def get_current_user(
    ctx: tuple[User, WebSession] = Depends(get_current_session),
) -> User:
    return ctx[0]


def is_child_role(role: str) -> bool:
    """Return True if role represents a child/child-view account."""
    return role in ("child", "child-view")


def require_roles(allowed_roles: Iterable[str]):
    """RBAC dependency factory enforcing allowed roles (`parent`, `child-view`/`child`, `admin`)."""
    allowed = set(allowed_roles)
    if "child-view" in allowed or "child" in allowed:
        allowed.update({"child", "child-view"})

    def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' is not permitted for this operation.",
            )
        return user

    return _checker


def get_owned_child_or_404(db: Session, user: User, child_id: int) -> Child:
    """Anti-IDOR ownership check at the SQLAlchemy query layer for Child resources."""
    stmt = select(Child).where(Child.id == child_id)
    if user.role == "parent":
        stmt = stmt.where(Child.parent_id == user.id)
    elif is_child_role(user.role):
        stmt = stmt.where(Child.child_user_id == user.id)
    elif user.role == "admin":
        pass
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden.")

    child = db.execute(stmt).scalar_one_or_none()
    if child is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Child not found.")
    return child


def get_owned_device_or_404(db: Session, user: User, device_id: str) -> Device:
    """Anti-IDOR ownership check at the SQLAlchemy query layer for Device resources."""
    stmt = select(Device).where(Device.id == device_id)
    if user.role == "parent":
        stmt = stmt.where(Device.parent_id == user.id)
    elif is_child_role(user.role):
        child = db.execute(select(Child).where(Child.child_user_id == user.id)).scalar_one_or_none()
        if child is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")
        stmt = stmt.where(Device.child_id == child.id)
    elif user.role == "admin":
        pass
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden.")

    device = db.execute(stmt).scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")
    return device


def authenticate_device_token(
    db: Session,
    raw_token: str,
    expected_type: str = "access",
) -> Device:
    """Validate a Bearer device token against hashed DB records and revocation list."""
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing device token.")

    tok_hash = hash_token(raw_token)
    dt = db.execute(
        select(DeviceToken).where(
            DeviceToken.token_hash == tok_hash,
            DeviceToken.token_type == expected_type,
        )
    ).scalar_one_or_none()

    now = utcnow()
    if (
        dt is None
        or dt.revoked
        or (_as_utc(dt.expires_at) is not None and _as_utc(dt.expires_at) <= now)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device token invalid, expired, or revoked.",
        )

    device = db.get(Device, dt.device_id)
    if device is None or device.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device has been revoked.",
        )
    return device


def get_current_device(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Device:
    """FastAPI dependency authenticating an Agent via `Authorization: Bearer <access_token>`."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer access token.",
        )
    raw_token = authorization[len("Bearer ") :].strip()
    return authenticate_device_token(db, raw_token, expected_type="access")
