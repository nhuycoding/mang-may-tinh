"""Initial OGK-Server schema (12 tables with SQLite WAL & CHECK constraints).

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-19 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('parent', 'child-view', 'admin')", name="ck_users_role"),
        sa.ForeignKeyConstraint(["parent_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "web_sessions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_web_sessions_user_id", "web_sessions", ["user_id"], unique=False)
    op.create_index("ix_web_sessions_expires_at", "web_sessions", ["expires_at"], unique=False)

    op.create_table(
        "children",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=False),
        sa.Column("child_user_id", sa.Integer(), nullable=True),
        sa.Column("name_encrypted", sa.Text(), nullable=False),
        sa.Column("age_group", sa.String(length=20), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["child_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["parent_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("child_user_id"),
    )
    op.create_index("ix_children_parent_id", "children", ["parent_id"], unique=False)

    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=False),
        sa.Column("child_id", sa.Integer(), nullable=False),
        sa.Column("device_name", sa.String(length=120), nullable=False),
        sa.Column("device_fingerprint_hash", sa.String(length=64), nullable=False),
        sa.Column("os_version", sa.String(length=120), nullable=True),
        sa.Column("agent_version", sa.String(length=32), nullable=True),
        sa.Column("hmac_secret_encrypted", sa.Text(), nullable=False),
        sa.Column("current_policy_version", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("used_quota_sec_today", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="offline"),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_clock_skew_sec", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('online', 'offline', 'locked', 'tampered', 'revoked')",
            name="ck_devices_status",
        ),
        sa.ForeignKeyConstraint(["child_id"], ["children.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_devices_parent_id", "devices", ["parent_id"], unique=False)
    op.create_index("ix_devices_child_id", "devices", ["child_id"], unique=False)
    op.create_index("ix_devices_device_fingerprint_hash", "devices", ["device_fingerprint_hash"], unique=False)

    op.create_table(
        "pairing_codes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=False),
        sa.Column("child_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by_device_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["child_id"], ["children.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["used_by_device_id"], ["devices.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pairing_codes_code_hash", "pairing_codes", ["code_hash"], unique=True)
    op.create_index("ix_pairing_codes_parent_id", "pairing_codes", ["parent_id"], unique=False)
    op.create_index("ix_pairing_codes_child_id", "pairing_codes", ["child_id"], unique=False)
    op.create_index("ix_pairing_codes_expires_at", "pairing_codes", ["expires_at"], unique=False)

    op.create_table(
        "device_tokens",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("token_type", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("token_type IN ('access', 'refresh')", name="ck_device_tokens_type"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_device_tokens_device_id", "device_tokens", ["device_id"], unique=False)
    op.create_index("ix_device_tokens_token_hash", "device_tokens", ["token_hash"], unique=True)
    op.create_index("ix_device_tokens_expires_at", "device_tokens", ["expires_at"], unique=False)
    op.create_index("ix_device_tokens_revoked", "device_tokens", ["revoked"], unique=False)

    op.create_table(
        "policies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("child_id", sa.Integer(), nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("weekday_quota_sec", sa.Integer(), nullable=False, server_default=sa.text("7200")),
        sa.Column("weekend_quota_sec", sa.Integer(), nullable=False, server_default=sa.text("10800")),
        sa.Column("weekly_schedule_json", sa.Text(), nullable=False),
        sa.Column("grace_period_sec", sa.Integer(), nullable=False, server_default=sa.text("60")),
        sa.Column("idle_timeout_sec", sa.Integer(), nullable=False, server_default=sa.text("300")),
        sa.Column("offline_expiry_days", sa.Integer(), nullable=False, server_default=sa.text("3")),
        sa.Column("offline_expiry_mode", sa.String(length=16), nullable=False, server_default="fail_closed"),
        sa.Column("safesearch_enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("blocked_categories_json", sa.Text(), nullable=False),
        sa.Column("allowed_domains_json", sa.Text(), nullable=False),
        sa.Column("blocked_domains_json", sa.Text(), nullable=False),
        sa.Column("app_rules_json", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("signature_hmac", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "offline_expiry_mode IN ('fail_closed', 'fail_open')",
            name="ck_policies_offline_mode",
        ),
        sa.ForeignKeyConstraint(["child_id"], ["children.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("child_id"),
    )
    op.create_index("ix_policies_parent_id", "policies", ["parent_id"], unique=False)

    op.create_table(
        "domain_categories",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("is_seed", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "category IN ('education', 'entertainment', 'social_media', 'games', 'inappropriate', 'uncategorized')",
            name="ck_domain_categories_category",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_domain_categories_domain", "domain_categories", ["domain"], unique=True)
    op.create_index("ix_domain_categories_category", "domain_categories", ["category"], unique=False)

    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("child_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("duration_sec", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("policy_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "type IN ('app_start', 'app_stop', 'domain_query', 'blocked_app', "
            "'blocked_domain', 'quota_warning', 'locked', 'unlock_request', 'override_granted')",
            name="ck_events_type",
        ),
        sa.ForeignKeyConstraint(["child_id"], ["children.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_events_idempotency_key", "events", ["idempotency_key"], unique=True)
    op.create_index("ix_events_ts", "events", ["ts"], unique=False)
    op.create_index("ix_events_device_id", "events", ["device_id"], unique=False)
    op.create_index("ix_events_child_id", "events", ["child_id"], unique=False)
    op.create_index("ix_events_type", "events", ["type"], unique=False)
    op.create_index("ix_events_child_ts", "events", ["child_id", "ts"], unique=False)
    op.create_index("ix_events_device_ts", "events", ["device_id", "ts"], unique=False)

    op.create_table(
        "commands",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("issued_by_user_id", sa.Integer(), nullable=True),
        sa.Column("command_type", sa.String(length=32), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "command_type IN ('lock_now', 'unlock', 'add_15_mins', 'wipe_local_data')",
            name="ck_commands_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'sent', 'acknowledged', 'failed', 'expired')",
            name="ck_commands_status",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["issued_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_commands_device_id", "commands", ["device_id"], unique=False)
    op.create_index("ix_commands_status", "commands", ["status"], unique=False)

    op.create_table(
        "time_extension_requests",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("child_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("requested_minutes", sa.Integer(), nullable=False, server_default=sa.text("15")),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("decided_by_user_id", sa.Integer(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'denied')",
            name="ck_time_extension_status",
        ),
        sa.ForeignKeyConstraint(["child_id"], ["children.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["decided_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_time_extension_requests_child_id", "time_extension_requests", ["child_id"], unique=False)
    op.create_index("ix_time_extension_requests_device_id", "time_extension_requests", ["device_id"], unique=False)
    op.create_index("ix_time_extension_requests_status", "time_extension_requests", ["status"], unique=False)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=False),
        sa.Column("child_id", sa.Integer(), nullable=True),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor_email", sa.String(length=255), nullable=False),
        sa.Column("actor_role", sa.String(length=20), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("old_value_json", sa.Text(), nullable=True),
        sa.Column("new_value_json", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["child_id"], ["children.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["parent_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_parent_id", "audit_logs", ["parent_id"], unique=False)
    op.create_index("ix_audit_logs_child_id", "audit_logs", ["child_id"], unique=False)
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)
    op.create_index("ix_audit_parent_ts", "audit_logs", ["parent_id", "timestamp"], unique=False)


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("time_extension_requests")
    op.drop_table("commands")
    op.drop_table("events")
    op.drop_table("domain_categories")
    op.drop_table("policies")
    op.drop_table("device_tokens")
    op.drop_table("pairing_codes")
    op.drop_table("devices")
    op.drop_table("children")
    op.drop_table("web_sessions")
    op.drop_table("users")
