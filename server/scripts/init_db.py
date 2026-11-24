"""Initialize OGK-Server database via Alembic migrations and verify SQLite WAL mode."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from server.app.database import engine


def init_database() -> str:
    """Apply all Alembic migrations to head and return active SQLite journal_mode."""
    alembic_ini = Path(__file__).resolve().parents[1] / "alembic.ini"
    cfg = Config(str(alembic_ini))
    command.upgrade(cfg, "head")

    with engine.connect() as conn:
        mode = conn.execute(text("PRAGMA journal_mode;")).scalar()
    return str(mode)


if __name__ == "__main__":
    journal_mode = init_database()
    print(f"[OGK] Server database migrated to head. SQLite journal_mode={journal_mode}")
