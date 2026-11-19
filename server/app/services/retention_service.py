"""Automated data retention service (F3: delete activity data older than 90 days)."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from server.app.config import get_settings
from server.app.database import SessionLocal
from server.app.models import Event, utcnow

logger = logging.getLogger("ogk.retention")


def purge_expired_events(db: Session, retention_days: int | None = None) -> int:
    """Delete Event rows older than `retention_days` (default 90). Returns count deleted."""
    days = retention_days if retention_days is not None else get_settings().data_retention_days
    cutoff = utcnow() - timedelta(days=days)
    result = db.execute(delete(Event).where(Event.ts < cutoff))
    db.commit()
    return int(result.rowcount or 0)


async def retention_background_loop(stop_event: asyncio.Event, interval_sec: int = 86400) -> None:
    """Run retention purge on startup and once every `interval_sec` until stopped."""
    while not stop_event.is_set():
        try:
            with SessionLocal() as db:
                deleted = purge_expired_events(db)
                if deleted:
                    logger.info("Retention job purged %d events older than retention window.", deleted)
        except Exception as exc:
            logger.exception("Retention purge error: %s", exc)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_sec)
        except asyncio.TimeoutError:
            continue
