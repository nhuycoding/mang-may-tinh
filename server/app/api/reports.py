"""Usage Reports & Child Transparency Summaries (`/reports`)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from server.app.crypto import decrypt_field
from server.app.database import get_db
from server.app.models import Device, Event, Policy, TimeExtensionRequest, User, utcnow
from server.app.security import get_current_user, get_owned_child_or_404

from server.app.api.events import DEVICE_REMAINING_CACHE

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/summary/{child_id}")
def get_child_report_summary(
    child_id: int,
    days: int = Query(default=7, ge=1, le=90),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Parent & Child-view report: daily/weekly usage charts, Top 10 apps, Top 10 domains, block counts."""
    child = get_owned_child_or_404(db, user, child_id)
    now = utcnow()
    since = now - timedelta(days=days)

    events = (
        db.execute(
            select(Event)
            .where(Event.child_id == child.id, Event.ts >= since)
            .order_by(Event.ts.asc())
        )
        .scalars()
        .all()
    )

    daily_usage_sec: dict[str, int] = defaultdict(int)
    app_usage_sec: dict[str, int] = defaultdict(int)
    domain_hits: dict[str, int] = defaultdict(int)
    blocked_apps_count = 0
    blocked_domains_count = 0

    for ev in events:
        day_key = ev.ts.strftime("%Y-%m-%d")
        if ev.type in ("app_stop", "app_start"):
            daily_usage_sec[day_key] += ev.duration_sec
            app_usage_sec[ev.subject] += ev.duration_sec
        elif ev.type == "domain_query":
            domain_hits[ev.subject] += 1
        elif ev.type == "blocked_app":
            blocked_apps_count += 1
        elif ev.type == "blocked_domain":
            blocked_domains_count += 1

    # Fill continuous date labels for the requested window
    chart_days: list[dict[str, Any]] = []
    for offset in range(days - 1, -1, -1):
        d_str = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
        sec = daily_usage_sec.get(d_str, 0)
        chart_days.append({"date": d_str, "minutes": round(sec / 60, 1), "seconds": sec})

    top_apps = [
        {"name": name, "seconds": sec, "minutes": round(sec / 60, 1)}
        for name, sec in sorted(app_usage_sec.items(), key=lambda kv: kv[1], reverse=True)[:10]
    ]
    top_domains = [
        {"domain": dom, "queries": cnt}
        for dom, cnt in sorted(domain_hits.items(), key=lambda kv: kv[1], reverse=True)[:10]
    ]

    policy = db.execute(select(Policy).where(Policy.child_id == child.id)).scalar_one_or_none()
    devices = db.execute(select(Device).where(Device.child_id == child.id)).scalars().all()
    used_today_sec = sum(d.used_quota_sec_today for d in devices if not d.is_revoked)

    pending_extensions = (
        db.execute(
            select(func.count(TimeExtensionRequest.id)).where(
                TimeExtensionRequest.child_id == child.id,
                TimeExtensionRequest.status == "pending",
            )
        ).scalar()
        or 0
    )

    is_weekend = now.weekday() >= 5
    daily_quota_sec = (
        (policy.weekend_quota_sec if is_weekend else policy.weekday_quota_sec) if policy else 7200
    )

    active_devs = [d for d in devices if not d.is_revoked]
    cached_rems = [DEVICE_REMAINING_CACHE[d.id] for d in active_devs if d.id in DEVICE_REMAINING_CACHE]
    remaining_today_sec = min(cached_rems) if cached_rems else max(0, daily_quota_sec - used_today_sec)

    return {
        "child_id": child.id,
        "child_name": decrypt_field(child.name_encrypted),
        "window_days": days,
        "used_today_sec": used_today_sec,
        "daily_quota_sec": daily_quota_sec,
        "remaining_today_sec": remaining_today_sec,
        "daily_chart": chart_days,
        "top_apps": top_apps,
        "top_domains": top_domains,
        "block_counts": {
            "blocked_apps": blocked_apps_count,
            "blocked_domains": blocked_domains_count,
            "total": blocked_apps_count + blocked_domains_count,
        },
        "pending_extension_requests": int(pending_extensions),
    }


@router.get("/today/{child_id}")
def get_today_child_transparency(
    child_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Child-friendly 'What I used today' summary (transparent, no full URLs)."""
    child = get_owned_child_or_404(db, user, child_id)
    now = utcnow()
    start_of_day = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

    events = (
        db.execute(
            select(Event)
            .where(Event.child_id == child.id, Event.ts >= start_of_day)
            .order_by(Event.ts.desc())
        )
        .scalars()
        .all()
    )

    apps_today: dict[str, int] = defaultdict(int)
    sites_today: dict[str, int] = defaultdict(int)
    blocked_today: list[dict[str, str]] = []

    for ev in events:
        if ev.type in ("app_stop", "app_start"):
            apps_today[ev.subject] += ev.duration_sec
        elif ev.type == "domain_query":
            sites_today[ev.subject] += 1
        elif ev.type in ("blocked_app", "blocked_domain"):
            blocked_today.append(
                {
                    "time": ev.ts.strftime("%H:%M"),
                    "kind": "App" if ev.type == "blocked_app" else "Website",
                    "name": ev.subject,
                }
            )

    policy = db.execute(select(Policy).where(Policy.child_id == child.id)).scalar_one_or_none()
    devices = db.execute(select(Device).where(Device.child_id == child.id)).scalars().all()
    used_today_sec = sum(d.used_quota_sec_today for d in devices if not d.is_revoked)
    is_weekend = now.weekday() >= 5
    daily_quota_sec = (
        (policy.weekend_quota_sec if is_weekend else policy.weekday_quota_sec) if policy else 7200
    )

    active_devs = [d for d in devices if not d.is_revoked]
    cached_rems = [DEVICE_REMAINING_CACHE[d.id] for d in active_devs if d.id in DEVICE_REMAINING_CACHE]
    remaining_today_sec = min(cached_rems) if cached_rems else max(0, daily_quota_sec - used_today_sec)

    return {
        "child_name": decrypt_field(child.name_encrypted),
        "date": start_of_day.strftime("%Y-%m-%d"),
        "used_minutes": round(used_today_sec / 60, 1),
        "quota_minutes": round(daily_quota_sec / 60, 1),
        "remaining_minutes": round(remaining_today_sec / 60, 1),
        "apps_used": [
            {"name": k, "minutes": round(v / 60, 1)}
            for k, v in sorted(apps_today.items(), key=lambda kv: kv[1], reverse=True)
        ],
        "websites_visited": [
            {"domain": k, "visits": v}
            for k, v in sorted(sites_today.items(), key=lambda kv: kv[1], reverse=True)[:10]
        ],
        "blocked_items": blocked_today[:20],
    }
