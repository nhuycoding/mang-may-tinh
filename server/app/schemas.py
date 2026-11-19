"""Pydantic request and response schemas for OGK-Server APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from server.app.models import COMMAND_TYPES, DOMAIN_CATEGORIES, EVENT_TYPES, OFFLINE_MODES


# ---------------------------------------------------------------------------
# Auth & Family
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    display_name: str
    role: str


class LoginResponse(BaseModel):
    user: UserOut
    csrf_token: str
    expires_at: datetime


class ChildCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    age_group: str = Field(default="6-11", max_length=20)
    timezone: str = Field(default="Asia/Ho_Chi_Minh", max_length=64)
    child_view_email: str | None = Field(default=None, max_length=255)
    child_view_password: str | None = Field(default=None, min_length=10, max_length=128)


class ChildOut(BaseModel):
    id: int
    parent_id: int
    name: str
    age_group: str
    timezone: str
    child_user_id: int | None = None
    created_at: datetime


# ---------------------------------------------------------------------------
# Enrollment & Devices
# ---------------------------------------------------------------------------
class PairingCodeCreateRequest(BaseModel):
    child_id: int


class PairingCodeOut(BaseModel):
    pairing_code: str
    child_id: int
    expires_at: datetime


class EnrollDeviceRequest(BaseModel):
    pairing_code: str = Field(min_length=8, max_length=8)
    device_fingerprint: str = Field(min_length=8, max_length=256)
    device_name: str = Field(min_length=1, max_length=120)
    os_version: str | None = Field(default=None, max_length=120)
    agent_version: str | None = Field(default=None, max_length=32)


class EnrollDeviceResponse(BaseModel):
    device_id: str
    child_id: int
    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    refresh_token_expires_at: datetime
    hmac_secret: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=256)


class RefreshTokenResponse(BaseModel):
    access_token: str
    access_token_expires_at: datetime


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    child_id: int
    device_name: str
    os_version: str | None
    agent_version: str | None
    current_policy_version: int
    used_quota_sec_today: int
    status: str
    last_heartbeat_at: datetime | None
    last_clock_skew_sec: int
    is_revoked: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Policy (F1 & F2)
# ---------------------------------------------------------------------------
class AppRule(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    sha256: str = Field(default="", max_length=64)
    action: Literal["allow", "block"] = "block"
    reason: str = Field(default="Blocked by family policy", max_length=200)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        v = v.strip().lower()
        if v and (len(v) != 64 or any(c not in "0123456789abcdef" for c in v)):
            raise ValueError("sha256 must be empty or a valid 64-char hex digest.")
        return v


class PolicyUpdateRequest(BaseModel):
    weekday_quota_sec: int | None = Field(default=None, ge=60, le=86400)
    weekend_quota_sec: int | None = Field(default=None, ge=60, le=86400)
    weekly_schedule: list[list[int]] | None = None
    grace_period_sec: int | None = Field(default=None, ge=10, le=600)
    idle_timeout_sec: int | None = Field(default=None, ge=60, le=3600)
    offline_expiry_days: int | None = Field(default=None, ge=1, le=30)
    offline_expiry_mode: Literal["fail_closed", "fail_open"] | None = None
    safesearch_enabled: bool | None = None
    blocked_categories: list[str] | None = None
    allowed_domains: list[str] | None = None
    blocked_domains: list[str] | None = None
    app_rules: list[AppRule] | None = None

    @field_validator("weekly_schedule")
    @classmethod
    def validate_schedule_matrix(cls, v: list[list[int]] | None) -> list[list[int]] | None:
        if v is None:
            return None
        if len(v) != 7 or any(len(day) != 48 for day in v):
            raise ValueError("weekly_schedule must be a 7x48 matrix (7 days x 48 30-minute slots).")
        if any(cell not in (0, 1) for day in v for cell in day):
            raise ValueError("weekly_schedule cells must be 0 or 1.")
        return v

    @field_validator("blocked_categories")
    @classmethod
    def validate_categories(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        invalid = [c for c in v if c not in DOMAIN_CATEGORIES]
        if invalid:
            raise ValueError(f"Invalid categories: {invalid}")
        return list(dict.fromkeys(v))

    @field_validator("offline_expiry_mode")
    @classmethod
    def validate_offline_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in OFFLINE_MODES:
            raise ValueError(f"Invalid offline_expiry_mode: {v}")
        return v


class SignedPolicyResponse(BaseModel):
    policy_id: int
    child_id: int
    policy_version: int
    payload: dict[str, Any]
    payload_json: str
    signature_hmac: str
    updated_at: datetime


# ---------------------------------------------------------------------------
# Events & Heartbeat (F1, F3)
# ---------------------------------------------------------------------------
class EventIn(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=64)
    ts: datetime
    type: str
    subject: str = Field(min_length=1, max_length=255)
    duration_sec: int = Field(default=0, ge=0, le=86400)
    policy_id: int | None = None

    @field_validator("type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        if v not in EVENT_TYPES:
            raise ValueError(f"Event type must be one of {EVENT_TYPES}")
        return v


class EventBatchRequest(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)


class EventBatchResponse(BaseModel):
    accepted: int
    duplicates_skipped: int


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime
    device_id: str
    child_id: int
    type: str
    subject: str
    duration_sec: int
    policy_id: int | None


class HeartbeatRequest(BaseModel):
    status: Literal["online", "locked", "tampered"] = "online"
    used_quota_sec_today: int = Field(ge=0, le=86400)
    current_policy_version: int = Field(ge=0)
    client_time: datetime
    clock_tamper_detected: bool = False


class PendingCommandOut(BaseModel):
    id: str
    command_type: str
    payload: dict[str, Any] | None = None
    created_at: datetime


class HeartbeatResponse(BaseModel):
    server_time: datetime
    latest_policy_version: int
    policy_update_required: bool
    clock_skew_sec: int
    pending_commands: list[PendingCommandOut]


# ---------------------------------------------------------------------------
# Commands & Time Extension Requests
# ---------------------------------------------------------------------------
class CommandCreateRequest(BaseModel):
    device_id: str
    command_type: Literal["lock_now", "unlock", "add_15_mins", "wipe_local_data"]
    payload: dict[str, Any] | None = None

    @field_validator("command_type")
    @classmethod
    def validate_cmd_type(cls, v: str) -> str:
        if v not in COMMAND_TYPES:
            raise ValueError(f"Invalid command_type: {v}")
        return v


class CommandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    device_id: str
    command_type: str
    status: str
    created_at: datetime
    delivered_at: datetime | None
    acked_at: datetime | None


class CommandAckRequest(BaseModel):
    status: Literal["acknowledged", "failed"] = "acknowledged"


class ExtensionRequestCreate(BaseModel):
    requested_minutes: int = Field(default=15, ge=5, le=120)
    reason: str | None = Field(default=None, max_length=255)


class ExtensionDecisionRequest(BaseModel):
    decision: Literal["approved", "denied"]


class ExtensionRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    child_id: int
    device_id: str
    requested_minutes: int
    reason: str | None
    status: str
    decided_by_user_id: int | None
    decided_at: datetime | None
    created_at: datetime


# ---------------------------------------------------------------------------
# Audit Log & Pagination
# ---------------------------------------------------------------------------
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    parent_id: int
    child_id: int | None
    actor_email: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str | None
    source_ip: str
    old_value: Any | None = None
    new_value: Any | None = None
    timestamp: datetime


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int
