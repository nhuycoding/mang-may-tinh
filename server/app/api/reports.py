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
from server.app.security import _as_utc, get_owned_child_or_404, require_roles

router = APIRouter(prefix="/reports", tags=["reports"])


def _compute_today_bonus_sec(db: Session, child_id: int, start_of_day: datetime) -> int:
    """Sum approved extra-time override seconds granted today."""
    total = (
        db.execute(
            select(func.coalesce(func.sum(Event.duration_sec), 0)).where(
                Event.child_id == child_id,
                Event.type == "override_granted",
                Event.ts >= start_of_day,
            )
        ).scalar()
        or 0
    )
    return int(total)


@router.get("/summary/{child_id}")
def get_child_report_summary(
    child_id: int,
    days: int = Query(default=7, ge=1, le=90),
    user: User = Depends(require_roles(["parent", "admin"])),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Parent & Admin report: daily/weekly usage charts, Top 10 apps, Top 10 domains, block counts."""
    child = get_owned_child_or_404(db, user, child_id)
    now = utcnow()
    since = now - timedelta(days=days)
    start_of_day = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

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
    base_quota_sec = (
        (policy.weekend_quota_sec if is_weekend else policy.weekday_quota_sec) if policy else 7200
    )
    bonus_today_sec = _compute_today_bonus_sec(db, child.id, start_of_day)
    daily_quota_sec = base_quota_sec + bonus_today_sec

    return {
        "child_id": child.id,
        "child_name": decrypt_field(child.name_encrypted),
        "window_days": days,
        "used_today_sec": used_today_sec,
        "daily_quota_sec": daily_quota_sec,
        "bonus_today_sec": bonus_today_sec,
        "remaining_today_sec": max(0, daily_quota_sec - used_today_sec),
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
    user: User = Depends(require_roles(["child-view", "child", "admin"])),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Child-friendly 'What I used today' summary + live countdown state (strictly child-view & admin)."""
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
    devices = [
        d
        for d in db.execute(select(Device).where(Device.child_id == child.id)).scalars().all()
        if not d.is_revoked
    ]
    used_today_sec = sum(d.used_quota_sec_today for d in devices)
    is_locked = any(d.status == "locked" for d in devices)
    is_online = any(
        d.last_heartbeat_at is not None
        and (now - (_as_utc(d.last_heartbeat_at) or now)).total_seconds() <= 120
        and d.status in ("online", "locked")
        for d in devices
    )
    is_weekend = now.weekday() >= 5
    base_quota_sec = (
        (policy.weekend_quota_sec if is_weekend else policy.weekday_quota_sec) if policy else 7200
    )
    bonus_today_sec = _compute_today_bonus_sec(db, child.id, start_of_day)
    daily_quota_sec = base_quota_sec + bonus_today_sec
    remaining_today_sec = max(0, daily_quota_sec - used_today_sec)

    return {
        "child_id": child.id,
        "child_name": decrypt_field(child.name_encrypted),
        "date": start_of_day.strftime("%Y-%m-%d"),
        "server_time": now.isoformat(),
        "used_seconds": used_today_sec,
        "quota_seconds": daily_quota_sec,
        "bonus_seconds": bonus_today_sec,
        "remaining_seconds": remaining_today_sec,
        "is_locked": is_locked,
        "online": is_online,
        "used_minutes": round(used_today_sec / 60, 1),
        "quota_minutes": round(daily_quota_sec / 60, 1),
        "remaining_minutes": round(remaining_today_sec / 60, 1),
        "apps_used": [
            {"name": k, "minutes": round(v / 60, 1), "seconds": v}
            for k, v in sorted(apps_today.items(), key=lambda kv: kv[1], reverse=True)
        ],
        "websites_visited": [
            {"domain": k, "visits": v}
            for k, v in sorted(sites_today.items(), key=lambda kv: kv[1], reverse=True)[:10]
        ],
        "blocked_items": blocked_today[:20],
    }
