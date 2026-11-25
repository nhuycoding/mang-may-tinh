"""Configuration for OGK-Agent (Windows 10/11 x64)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    """Runtime paths and protocol settings for OGK-Agent."""

    data_dir: Path
    db_path: Path
    server_url: str
    server_cert_sha256: str
    ipc_host: str = "127.0.0.1"
    ipc_port: int = 47831
    dns_bind_host: str = "127.0.0.1"
    dns_bind_port: int = 53
    upstream_dns_host: str = "1.1.1.1"
    upstream_dns_port: int = 53
    heartbeat_interval_sec: int = 60
    tray_watchdog_timeout_sec: int = 90
    idle_threshold_sec: int = 300
    clock_skew_threshold_sec: int = 120
    dry_run: bool = False

    @classmethod
    def from_env(cls, *, dry_run: bool | None = None) -> "AgentConfig":
        default_dir = Path(os.environ.get("OGK_AGENT_DATA_DIR", r"C:\ProgramData\OGK-Agent"))
        env_dry_run = os.environ.get("KIDGATE_DRY_RUN", "").strip().lower() in ("1", "true", "yes", "on")
        return cls(
            data_dir=default_dir,
            db_path=default_dir / "ogk_agent.db",
            server_url=os.environ.get("OGK_SERVER_URL", "https://127.0.0.1:8443"),
            server_cert_sha256=os.environ.get("OGK_SERVER_CERT_SHA256", ""),
            ipc_port=int(os.environ.get("OGK_AGENT_IPC_PORT", "47831")),
            dns_bind_port=int(os.environ.get("OGK_AGENT_DNS_PORT", "53")),
            upstream_dns_host=os.environ.get("OGK_UPSTREAM_DNS", "1.1.1.1"),
            heartbeat_interval_sec=int(os.environ.get("OGK_HEARTBEAT_SEC", "60")),
            tray_watchdog_timeout_sec=int(os.environ.get("OGK_TRAY_WATCHDOG_SEC", "90")),
            dry_run=env_dry_run if dry_run is None else bool(dry_run),
        )
