"""Shared pytest fixtures for OGK unit and integration tests."""

from __future__ import annotations

import base64
import os
import secrets
import tempfile
from pathlib import Path

# Configure isolated test environment BEFORE importing server modules
_TEST_TMP_DIR = Path(tempfile.mkdtemp(prefix="ogk_pytest_"))
_TEST_DB_PATH = _TEST_TMP_DIR / "ogk_test.db"

os.environ["OGK_DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH.as_posix()}"
os.environ["OGK_COOKIE_SECURE"] = "false"
os.environ["OGK_MASTER_KEY"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
os.environ["OGK_POLICY_HMAC_FALLBACK_KEY"] = secrets.token_hex(32)
os.environ["OGK_DISABLE_DPAPI"] = "1"

import pytest
from fastapi.testclient import TestClient

from server.app.database import Base, SessionLocal, engine
from server.app.main import app
from server.app.security import rate_limiter
from server.scripts.seed import seed_database


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure IP rate-limiter buckets start clean for every test."""
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest.fixture(scope="session")
def seeded_db():
    """Create schema and seed >= 200 safe domains + demo accounts once per test session."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        result = seed_database(db)
    assert result["total_domains"] >= 200
    return result


@pytest.fixture()
def client(seeded_db):
    """Return a fresh FastAPI TestClient per test."""
    with TestClient(app) as tc:
        yield tc
