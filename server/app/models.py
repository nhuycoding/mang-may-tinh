"""SQLAlchemy ORM models for OGK-Server.

Data model supports:
- 1 parent : n children : m devices
- RBAC roles: parent, child-view, admin
- Web sessions with server-side invalidation & CSRF tokens
- Enrollment pairing codes (8-char, 10-min TTL) & hashed device tokens with revocation
- Versioned, HMAC-SHA256 signed policies (weekday/weekend quotas, 7x48 schedule, app rules, domain categories)
- Strict event schema (F3) with idempotency_key for offline batch sync
- Urgent commands (WebSocket + Heartbeat fallback)
- Child time-extension request queue
- Full audit log (actor, timestamp, source_ip, old_value, new_value)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.app.database import Base

# Enumerated constants enforced by DB CHECK constraints and validation
USER_ROLES = ("parent", "child-view", "admin")
DOMAIN_CATEGORIES = (
    "education",
    "entertainment",
    "social_media",
    "games",
    "inappropriate",
    "uncategorized",
)
EVENT_TYPES = (
    "app_start",
    "app_stop",
    "domain_query",
    "blocked_app",
    "blocked_domain",
    "quota_warning",
    "locked",
    "unlock_request",
    "override_granted",
)
COMMAND_TYPES = ("lock_now", "unlock", "add_15_mins", "wipe_local_data")
COMMAND_STATUSES = ("pending", "sent", "acknowledged", "failed", "expired")
DEVICE_STATUSES = ("online", "offline", "locked", "tampered", "revoked")
TOKEN_TYPES = ("access", "refresh")
EXTENSION_STATUSES = ("pending", "approved", "denied")
OFFLINE_MODES = ("fail_closed", "fail_open")


def utcnow() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)


def default_weekly_schedule_json() -> str:
    """Default 7x48 schedule matrix (ages 6-11): allowed 07:00-21:00 daily (slots 14..41)."""
    day_slots = [1 if 14 <= slot < 42 else 0 for slot in range(48)]
    matrix = [list(day_slots) for _ in range(7)]
    return json.dumps(matrix, separators=(",", ":"))


def default_blocked_categories_json() -> str:
    """Default blocked categories for ages 6-11."""
    return json.dumps(["inappropriate", "social_media"], separators=(",", ":"))


class User(Base):
    """Parent, Admin, or Child-view user account."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('parent', 'child-view', 'admin')",
            name="ck_users_role",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="parent")
    parent_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    # Relationships
    children: Mapped[list[Child]] = relationship(
        "Child",
        back_populates="parent",
        foreign_keys="Child.parent_id",
        cascade="all, delete-orphan",
    )
    sessions: Mapped[list[WebSession]] = relationship(
        "WebSession", back_populates="user", cascade="all, delete-orphan"
    )


class WebSession(Base):
    """Server-side web session supporting 12h TTL, revocation on logout, and CSRF protection."""

    __tablename__ = "web_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 of raw session cookie
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship("User", back_populates="sessions")


class Child(Base):
    """Child profile managed by a parent (1 parent : n children)."""

    __tablename__ = "children"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    child_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), unique=True, nullable=True
    )
    # AES-256-GCM encrypted child display name (F5 data-at-rest protection)
    name_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    age_group: Mapped[str] = mapped_column(String(20), nullable=False, default="6-11")
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="Asia/Ho_Chi_Minh")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    parent: Mapped[User] = relationship("User", back_populates="children", foreign_keys=[parent_id])
    child_user: Mapped[User | None] = relationship("User", foreign_keys=[child_user_id])
    devices: Mapped[list[Device]] = relationship(
        "Device", back_populates="child", cascade="all, delete-orphan"
    )
    policy: Mapped[Policy | None] = relationship(
        "Policy", back_populates="child", uselist=False, cascade="all, delete-orphan"
    )


class Device(Base):
    """Enrolled Windows 10/11 endpoint (n children : m devices)."""

    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(
            "status IN ('online', 'offline', 'locked', 'tampered', 'revoked')",
            name="ck_devices_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    parent_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    child_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("children.id", ondelete="CASCADE"), index=True, nullable=False
    )
    device_name: Mapped[str] = mapped_column(String(120), nullable=False)
    device_fingerprint_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Per-device HMAC secret encrypted with AES-256-GCM at rest
    hmac_secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    current_policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    used_quota_sec_today: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="offline")
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_clock_skew_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    child: Mapped[Child] = relationship("Child", back_populates="devices")
    tokens: Mapped[list[DeviceToken]] = relationship(
        "DeviceToken", back_populates="device", cascade="all, delete-orphan"
    )
    commands: Mapped[list[Command]] = relationship(
        "Command", back_populates="device", cascade="all, delete-orphan"
    )


class PairingCode(Base):
    """Short-lived 8-character enrollment pairing code (10-minute TTL)."""

    __tablename__ = "pairing_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    parent_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    child_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("children.id", ondelete="CASCADE"), index=True, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by_device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class DeviceToken(Base):
    """Hashed access (15-min TTL) and refresh (long-lived) tokens with revocation support."""

    __tablename__ = "device_tokens"
    __table_args__ = (
        CheckConstraint("token_type IN ('access', 'refresh')", name="ck_device_tokens_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_type: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    device: Mapped[Device] = relationship("Device", back_populates="tokens")


class Policy(Base):
    """Versioned, HMAC-SHA256 signed child policy (screen-time, schedule, apps, domains)."""

    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint(
            "offline_expiry_mode IN ('fail_closed', 'fail_open')",
            name="ck_policies_offline_mode",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    child_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("children.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    parent_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    weekday_quota_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=7200)
    weekend_quota_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=10800)
    weekly_schedule_json: Mapped[str] = mapped_column(
        Text, nullable=False, default=default_weekly_schedule_json
    )
    grace_period_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    idle_timeout_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    offline_expiry_days: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    offline_expiry_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="fail_closed")
    safesearch_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    blocked_categories_json: Mapped[str] = mapped_column(
        Text, nullable=False, default=default_blocked_categories_json
    )
    allowed_domains_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    blocked_domains_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    app_rules_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    signature_hmac: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    child: Mapped[Child] = relationship("Child", back_populates="policy")


class DomainCategory(Base):
    """6-category safe domain classification table (>= 200 seeded safe/simulated domains)."""

    __tablename__ = "domain_categories"
    __table_args__ = (
        CheckConstraint(
            "category IN ('education', 'entertainment', 'social_media', 'games', 'inappropriate', 'uncategorized')",
            name="ck_domain_categories_category",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    is_seed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Event(Base):
    """Strict F3 activity event table.

    Strictly stores ONLY: ts, device_id, child_id, type, subject, duration_sec, policy_id
    (plus technical PK id, idempotency_key for deduplicating offline sync, and created_at for 90-day retention).
    `subject` stores app name or second-level domain ONLY — NEVER full URLs.
    """

    __tablename__ = "events"
    __table_args__ = (
        CheckConstraint(
            "type IN ('app_start', 'app_stop', 'domain_query', 'blocked_app', "
            "'blocked_domain', 'quota_warning', 'locked', 'unlock_request', 'override_granted')",
            name="ck_events_type",
        ),
        Index("ix_events_child_ts", "child_id", "ts"),
        Index("ix_events_device_ts", "device_id", "ts"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    child_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("children.id", ondelete="CASCADE"), index=True, nullable=False
    )
    type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    duration_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    policy_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("policies.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Command(Base):
    """Urgent remote commands pushed over WebSocket (< 5s latency) or heartbeat fallback."""

    __tablename__ = "commands"
    __table_args__ = (
        CheckConstraint(
            "command_type IN ('lock_now', 'unlock', 'add_15_mins', 'wipe_local_data')",
            name="ck_commands_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'sent', 'acknowledged', 'failed', 'expired')",
            name="ck_commands_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    issued_by_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    command_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    device: Mapped[Device] = relationship("Device", back_populates="commands")


class TimeExtensionRequest(Base):
    """Child time-extension requests displayed in the Parent Dashboard queue."""

    __tablename__ = "time_extension_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'denied')",
            name="ck_time_extension_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    child_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("children.id", ondelete="CASCADE"), index=True, nullable=False
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    requested_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    decided_by_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    """Transparent audit trail of every configuration change (accessible to parents & child)."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_parent_ts", "parent_id", "timestamp"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    child_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("children.id", ondelete="SET NULL"), index=True, nullable=True
    )
    actor_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_email: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(20), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    old_value_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)
