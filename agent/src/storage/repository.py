"""Repository helpers over AgentLocalDB (SQLite WAL) for offline caching and sync."""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from agent.src.storage.db import AgentLocalDB
from agent.src.storage.dpapi import protect_secret, unprotect_secret


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentRepository:
    """High-level data access layer for OGK-Agent local SQLite storage."""

    def __init__(self, db: AgentLocalDB) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Device Identity & Tokens
    # ------------------------------------------------------------------
    def save_identity(
        self,
        *,
        device_id: str,
        child_id: int,
        server_url: str,
        server_cert_sha256: str,
        access_token: str,
        refresh_token: str,
        hmac_secret: str,
    ) -> str:
        """Persist enrolled device identity with DPAPI/AES-GCM encrypted secrets. Returns local_ipc_token."""
        ipc_token = secrets.token_hex(24)
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO device_identity (
                    id, device_id, child_id, server_url, server_cert_sha256,
                    access_token_enc, refresh_token_enc, hmac_secret_enc, local_ipc_token, enrolled_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    device_id=excluded.device_id,
                    child_id=excluded.child_id,
                    server_url=excluded.server_url,
                    server_cert_sha256=excluded.server_cert_sha256,
                    access_token_enc=excluded.access_token_enc,
                    refresh_token_enc=excluded.refresh_token_enc,
                    hmac_secret_enc=excluded.hmac_secret_enc,
                    local_ipc_token=excluded.local_ipc_token,
                    enrolled_at=excluded.enrolled_at
                """,
                (
                    device_id,
                    child_id,
                    server_url,
                    server_cert_sha256.lower(),
                    protect_secret(access_token),
                    protect_secret(refresh_token),
                    protect_secret(hmac_secret),
                    ipc_token,
                    utcnow_iso(),
                ),
            )
            conn.commit()
        return ipc_token

    def get_identity(self) -> dict[str, Any] | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM device_identity WHERE id = 1").fetchone()
        if row is None:
            return None
        return {
            "device_id": row["device_id"],
            "child_id": row["child_id"],
            "server_url": row["server_url"],
            "server_cert_sha256": row["server_cert_sha256"],
            "access_token": unprotect_secret(row["access_token_enc"]),
            "refresh_token": unprotect_secret(row["refresh_token_enc"]),
            "hmac_secret": unprotect_secret(row["hmac_secret_enc"]),
            "local_ipc_token": row["local_ipc_token"],
            "enrolled_at": row["enrolled_at"],
        }

    def update_access_token(self, access_token: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE device_identity SET access_token_enc = ? WHERE id = 1",
                (protect_secret(access_token),),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Cached Policy
    # ------------------------------------------------------------------
    def save_cached_policy(
        self,
        *,
        policy_id: int,
        policy_version: int,
        payload_json: str,
        signature_hmac: str,
        server_time_iso: str,
    ) -> None:
        payload = json.loads(payload_json)
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO cached_policy (
                    id, policy_id, policy_version, payload_json, signature_hmac,
                    fetched_at, last_verified_server_time, offline_expiry_days, offline_expiry_mode
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    policy_id=excluded.policy_id,
                    policy_version=excluded.policy_version,
                    payload_json=excluded.payload_json,
                    signature_hmac=excluded.signature_hmac,
                    fetched_at=excluded.fetched_at,
                    last_verified_server_time=excluded.last_verified_server_time,
                    offline_expiry_days=excluded.offline_expiry_days,
                    offline_expiry_mode=excluded.offline_expiry_mode
                """,
                (
                    policy_id,
                    policy_version,
                    payload_json,
                    signature_hmac,
                    utcnow_iso(),
                    server_time_iso,
                    int(payload.get("offline_expiry_days", 3)),
                    str(payload.get("offline_expiry_mode", "fail_closed")),
                ),
            )
            conn.commit()

    def touch_last_verified_server_time(self, server_time_iso: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE cached_policy SET last_verified_server_time = ? WHERE id = 1",
                (server_time_iso,),
            )
            conn.commit()

    def get_cached_policy(self) -> dict[str, Any] | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM cached_policy WHERE id = 1").fetchone()
        if row is None:
            return None
        return {
            "policy_id": row["policy_id"],
            "policy_version": row["policy_version"],
            "payload": json.loads(row["payload_json"]),
            "payload_json": row["payload_json"],
            "signature_hmac": row["signature_hmac"],
            "fetched_at": row["fetched_at"],
            "last_verified_server_time": row["last_verified_server_time"],
            "offline_expiry_days": row["offline_expiry_days"],
            "offline_expiry_mode": row["offline_expiry_mode"],
        }

    # ------------------------------------------------------------------
    # Offline Event Queue (Strict F3 Schema + Idempotency Key)
    # ------------------------------------------------------------------
    def enqueue_event(
        self,
        *,
        device_id: str,
        child_id: int,
        event_type: str,
        subject: str,
        duration_sec: int = 0,
        policy_id: int | None = None,
        ts_iso: str | None = None,
        idempotency_key: str | None = None,
    ) -> str:
        idem = idempotency_key or f"{device_id[:8]}-{uuid.uuid4().hex[:16]}"
        now_iso = ts_iso or utcnow_iso()
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO offline_events (
                    idempotency_key, ts, device_id, child_id, type, subject, duration_sec, policy_id, synced, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (idem, now_iso, device_id, child_id, event_type, subject, int(duration_sec), policy_id, now_iso),
            )
            conn.commit()
        return idem

    def get_unsynced_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM offline_events WHERE synced = 0 ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_events_synced(self, event_ids: list[int]) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self.db.connect() as conn:
            conn.execute(f"UPDATE offline_events SET synced = 1 WHERE id IN ({placeholders})", event_ids)
            conn.commit()

    def get_today_summary(self, usage_date: str) -> dict[str, Any]:
        """Return child-friendly 'What I used today' from local SQLite (works even offline)."""
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT type, subject, duration_sec, ts FROM offline_events WHERE substr(ts, 1, 10) = ? ORDER BY id DESC",
                (usage_date,),
            ).fetchall()

        apps: dict[str, int] = {}
        sites: dict[str, int] = {}
        blocked: list[dict[str, str]] = []
        for r in rows:
            t, subj, dur, ts = r["type"], r["subject"], int(r["duration_sec"]), r["ts"]
            if t in ("app_start", "app_stop"):
                apps[subj] = apps.get(subj, 0) + dur
            elif t == "domain_query":
                sites[subj] = sites.get(subj, 0) + 1
            elif t in ("blocked_app", "blocked_domain"):
                blocked.append({"time": ts[11:16], "kind": "App" if t == "blocked_app" else "Website", "name": subj})

        return {
            "date": usage_date,
            "apps_used": [{"name": k, "minutes": round(v / 60, 1)} for k, v in sorted(apps.items(), key=lambda kv: kv[1], reverse=True)[:10]],
            "websites_visited": [{"domain": k, "visits": v} for k, v in sorted(sites.items(), key=lambda kv: kv[1], reverse=True)[:10]],
            "blocked_items": blocked[:20],
        }

    # ------------------------------------------------------------------
    # Daily Usage Counter (Anti-Tamper Monotonic State)
    # ------------------------------------------------------------------
    def get_daily_usage(self, usage_date: str) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM daily_usage WHERE usage_date = ?", (usage_date,)).fetchone()
        if row is None:
            return {
                "usage_date": usage_date,
                "used_sec": 0,
                "bonus_sec": 0,
                "last_monotonic_sec": None,
                "last_server_time": None,
                "last_wall_time": None,
                "tamper_detected_count": 0,
            }
        return dict(row)

    def save_daily_usage(
        self,
        *,
        usage_date: str,
        used_sec: int,
        bonus_sec: int,
        last_monotonic_sec: float | None,
        last_server_time: str | None,
        last_wall_time: str | None,
        tamper_detected_count: int = 0,
    ) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO daily_usage (
                    usage_date, used_sec, bonus_sec, last_monotonic_sec,
                    last_server_time, last_wall_time, tamper_detected_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(usage_date) DO UPDATE SET
                    used_sec=excluded.used_sec,
                    bonus_sec=excluded.bonus_sec,
                    last_monotonic_sec=excluded.last_monotonic_sec,
                    last_server_time=excluded.last_server_time,
                    last_wall_time=excluded.last_wall_time,
                    tamper_detected_count=excluded.tamper_detected_count
                """,
                (
                    usage_date,
                    int(used_sec),
                    int(bonus_sec),
                    last_monotonic_sec,
                    last_server_time,
                    last_wall_time,
                    int(tamper_detected_count),
                ),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Audit Log Cache (for Tray UI Transparency Screen)
    # ------------------------------------------------------------------
    def replace_audit_cache(self, items: list[dict[str, Any]]) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM audit_log_cache")
            for item in items:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO audit_log_cache (
                        id, actor_email, actor_role, action, resource_type, source_ip,
                        old_value_json, new_value_json, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["id"],
                        item["actor_email"],
                        item["actor_role"],
                        item["action"],
                        item["resource_type"],
                        item["source_ip"],
                        json.dumps(item.get("old_value")) if item.get("old_value") is not None else None,
                        json.dumps(item.get("new_value")) if item.get("new_value") is not None else None,
                        str(item["timestamp"]),
                    ),
                )
            conn.commit()

    def get_audit_cache(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log_cache ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
