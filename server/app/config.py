"""Configuration settings for OGK-Server loaded from environment variables."""

from __future__ import annotations

import base64
import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings. Sensitive keys are loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="OGK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = "development"
    host: str = "0.0.0.0"
    port: int = 8443

    # SQLite WAL database
    database_url: str = "sqlite:///./ogk_server.db"

    # 32-byte URL-safe base64 key for AES-GCM encryption at rest.
    # Never hardcode in production; falls back to ephemeral key only in dev/test.
    master_key: str = ""

    # Fallback HMAC signing secret (per-device secrets are stored encrypted in DB)
    policy_hmac_fallback_key: str = ""

    # TLS certificates
    tls_cert_path: str = "server/certs/server.crt"
    tls_key_path: str = "server/certs/server.key"
    tls_ca_path: str = "server/certs/ca.crt"

    # Session & Cookie security (F5)
    cookie_secure: bool = True
    session_ttl_hours: int = 12
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 30
    pairing_code_ttl_minutes: int = 10

    # Auth lockout & rate limiting (F5)
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    rate_limit_per_minute: int = 120
    login_rate_limit_per_minute: int = 15

    # Data retention (F3)
    data_retention_days: int = 90

    def get_master_key_bytes(self) -> bytes:
        """Decode 32-byte AES-256-GCM master key from env var."""
        raw = self.master_key.strip()
        if not raw or raw == "REPLACE_WITH_32_BYTE_BASE64URL_KEY":
            if self.env == "production":
                raise RuntimeError("OGK_MASTER_KEY must be set in production.")
            # Ephemeral key for local dev/testing (cached on instance via env)
            ephemeral = os.environ.get("_OGK_EPHEMERAL_MASTER_KEY")
            if not ephemeral:
                ephemeral = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
                os.environ["_OGK_EPHEMERAL_MASTER_KEY"] = ephemeral
            raw = ephemeral
        key = base64.urlsafe_b64decode(raw.encode("ascii"))
        if len(key) != 32:
            raise ValueError("OGK_MASTER_KEY must decode to exactly 32 bytes (AES-256).")
        return key

    def get_policy_hmac_key(self) -> str:
        """Return server-side HMAC key for policy signing."""
        raw = self.policy_hmac_fallback_key.strip()
        if not raw or raw == "REPLACE_WITH_RANDOM_HEX_SECRET":
            if self.env == "production":
                raise RuntimeError("OGK_POLICY_HMAC_FALLBACK_KEY must be set in production.")
            ephemeral = os.environ.get("_OGK_EPHEMERAL_HMAC_KEY")
            if not ephemeral:
                ephemeral = secrets.token_hex(32)
                os.environ["_OGK_EPHEMERAL_HMAC_KEY"] = ephemeral
            raw = ephemeral
        return raw


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


BASE_DIR = Path(__file__).resolve().parents[2]
