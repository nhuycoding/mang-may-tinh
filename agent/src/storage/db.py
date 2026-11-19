"""Local SQLite storage schema for OGK-Agent (WAL mode).

Stored in `C:\\ProgramData\\OGK-Agent\\ogk_agent.db` (protected by Windows ACLs so only
SYSTEM and Administrators have write permissions).

Stores:
- device_identity  : Enrolled device ID, pinned cert fingerprint, encrypted tokens/HMAC secret, IPC token.
- cached_policy    : Latest HMAC-verified policy + offline expiration metadata.
- domain_rules_cache: Local domain allow/block classification cache for the 127.0.0.1:53 DNS proxy.
- offline_events   : Strict F3 event buffer with idempotency_key for offline batch sync.
- daily_usage      : Monotonic-clock-backed screen-time counter & anti-tamper state.
- audit_log_cache  : Read-only cache of parent config changes for the Tray UI transparency screen.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

AGENT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS device_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    device_id TEXT NOT NULL,
    child_id INTEGER NOT NULL,
    server_url TEXT NOT NULL,
    server_cert_sha256 TEXT NOT NULL,
    access_token_enc BLOB NOT NULL,
    refresh_token_enc BLOB NOT NULL,
    hmac_secret_enc BLOB NOT NULL,
    local_ipc_token TEXT NOT NULL,
    enrolled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cached_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    policy_id INTEGER NOT NULL,
    policy_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    signature_hmac TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    last_verified_server_time TEXT NOT NULL,
    offline_expiry_days INTEGER NOT NULL DEFAULT 3,
    offline_expiry_mode TEXT NOT NULL DEFAULT 'fail_closed'
        CHECK (offline_expiry_mode IN ('fail_closed', 'fail_open'))
);

CREATE TABLE IF NOT EXISTS domain_rules_cache (
    domain TEXT PRIMARY KEY,
    category TEXT NOT NULL
        CHECK (category IN ('education', 'entertainment', 'social_media', 'games', 'inappropriate', 'uncategorized')),
    action TEXT NOT NULL CHECK (action IN ('allow', 'block'))
);

CREATE TABLE IF NOT EXISTS offline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    device_id TEXT NOT NULL,
    child_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK (
        type IN (
            'app_start', 'app_stop', 'domain_query', 'blocked_app',
            'blocked_domain', 'quota_warning', 'locked', 'unlock_request', 'override_granted'
        )
    ),
    subject TEXT NOT NULL,
    duration_sec INTEGER NOT NULL DEFAULT 0,
    policy_id INTEGER,
    synced INTEGER NOT NULL DEFAULT 0 CHECK (synced IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_offline_events_synced ON offline_events (synced, id);
CREATE INDEX IF NOT EXISTS ix_offline_events_ts ON offline_events (ts);

CREATE TABLE IF NOT EXISTS daily_usage (
    usage_date TEXT PRIMARY KEY,
    used_sec INTEGER NOT NULL DEFAULT 0,
    bonus_sec INTEGER NOT NULL DEFAULT 0,
    last_monotonic_sec REAL,
    last_server_time TEXT,
    last_wall_time TEXT,
    tamper_detected_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log_cache (
    id INTEGER PRIMARY KEY,
    actor_email TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    old_value_json TEXT,
    new_value_json TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_log_cache_ts ON audit_log_cache (timestamp DESC);
"""


class AgentLocalDB:
    """Thread-safe SQLite wrapper (WAL mode) for OGK-Agent local state."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(AGENT_SCHEMA_SQL)

    def wipe_all_local_data(self) -> None:
        """Erase all cached activity, usage counters, and audit logs on `wipe_local_data` command."""
        with self.connect() as conn:
            conn.execute("DELETE FROM offline_events;")
            conn.execute("DELETE FROM daily_usage;")
            conn.execute("DELETE FROM audit_log_cache;")
            conn.commit()


if __name__ == "__main__":
    from agent.src.config import AgentConfig

    cfg = AgentConfig.from_env()
    db = AgentLocalDB(cfg.db_path)
    with db.connect() as conn:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
            ).fetchall()
        ]
    print(f"[OGK-Agent] Local DB initialized at {cfg.db_path} (journal_mode={mode})")
    print(f"[OGK-Agent] Tables: {', '.join(tables)}")
