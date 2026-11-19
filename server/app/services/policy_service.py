"""Policy construction, canonical serialization, and HMAC-SHA256 signing."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from server.app.config import get_settings
from server.app.crypto import canonical_json, sign_policy_payload
from server.app.models import (
    DomainCategory,
    Policy,
    default_blocked_categories_json,
    default_weekly_schedule_json,
    utcnow,
)


def build_policy_payload(policy: Policy, db: Session | None = None) -> dict[str, Any]:
    """Build the canonical policy dictionary to be signed and delivered to Agents."""
    blocked_categories = json.loads(policy.blocked_categories_json)
    allowed_domains = json.loads(policy.allowed_domains_json)
    blocked_domains = json.loads(policy.blocked_domains_json)
    app_rules = json.loads(policy.app_rules_json)
    weekly_schedule = json.loads(policy.weekly_schedule_json)

    # Include categorized blocked domains from domain_categories so Agent DNS proxy works offline
    category_blocked_domains: list[str] = []
    if db is not None and blocked_categories:
        rows = db.execute(
            select(DomainCategory.domain).where(DomainCategory.category.in_(blocked_categories))
        ).scalars().all()
        category_blocked_domains = sorted(set(rows))

    return {
        "policy_id": policy.id,
        "child_id": policy.child_id,
        "policy_version": policy.policy_version,
        "weekday_quota_sec": policy.weekday_quota_sec,
        "weekend_quota_sec": policy.weekend_quota_sec,
        "weekly_schedule": weekly_schedule,
        "grace_period_sec": policy.grace_period_sec,
        "idle_timeout_sec": policy.idle_timeout_sec,
        "offline_expiry_days": policy.offline_expiry_days,
        "offline_expiry_mode": policy.offline_expiry_mode,
        "safesearch_enabled": policy.safesearch_enabled,
        "blocked_categories": blocked_categories,
        "category_blocked_domains": category_blocked_domains,
        "allowed_domains": allowed_domains,
        "blocked_domains": blocked_domains,
        "app_rules": app_rules,
    }


def sign_and_persist_policy(policy: Policy, db: Session) -> Policy:
    """Serialize canonical payload, sign with server HMAC key, and update Policy columns."""
    payload = build_policy_payload(policy, db=db)
    payload_str = canonical_json(payload)
    secret = get_settings().get_policy_hmac_key()
    policy.payload_json = payload_str
    policy.signature_hmac = sign_policy_payload(payload_str, secret)
    policy.updated_at = utcnow()
    db.add(policy)
    return policy


def sign_policy_for_device(
    policy: Policy,
    db: Session,
    device_hmac_secret: str,
) -> tuple[dict[str, Any], str, str]:
    """Produce (payload_dict, canonical_payload_json, hmac_sha256_hex) signed with device's secret."""
    payload = build_policy_payload(policy, db=db)
    payload_str = canonical_json(payload)
    signature = sign_policy_payload(payload_str, device_hmac_secret)
    return payload, payload_str, signature


def create_default_policy(db: Session, *, child_id: int, parent_id: int) -> Policy:
    """Create and HMAC-sign a default ages 6-11 policy for a newly created child."""
    policy = Policy(
        child_id=child_id,
        parent_id=parent_id,
        policy_version=1,
        weekday_quota_sec=7200,
        weekend_quota_sec=10800,
        weekly_schedule_json=default_weekly_schedule_json(),
        grace_period_sec=60,
        idle_timeout_sec=300,
        offline_expiry_days=3,
        offline_expiry_mode="fail_closed",
        safesearch_enabled=True,
        blocked_categories_json=default_blocked_categories_json(),
        allowed_domains_json="[]",
        blocked_domains_json="[]",
        app_rules_json="[]",
        payload_json="{}",
        signature_hmac="",
    )
    db.add(policy)
    db.flush()  # Assign policy.id before signing payload
    sign_and_persist_policy(policy, db)
    return policy
