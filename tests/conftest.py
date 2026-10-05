import os
from pathlib import Path

import psycopg
import pytest

# Give Settings the values it needs so the app can be imported during unit tests.
# Unit tests never open these connections.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

SCHEMA_SQL = Path(__file__).resolve().parent.parent / "db" / "init" / "001_schema.sql"


@pytest.fixture(autouse=True)
def _fresh_settings():
    """Clear cached Settings so one test's env vars don't leak into another."""
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# --- PostgreSQL test database ---------------------------------------------------------
#
# Database tests need a real PostgreSQL, because the security guarantees we're testing
# (parameter binding, UNIQUE on citext, CHECK constraints) live in the database itself.
# Set TEST_DATABASE_URL to run them. Docker Compose sets it automatically. Without it,
# these tests are skipped, not silently passed.


@pytest.fixture(scope="session")
def test_database_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set; skipping PostgreSQL tests")
    dbname = psycopg.conninfo.conninfo_to_dict(url).get("dbname", "")
    # These tests DROP and TRUNCATE tables. Refuse anything that isn't clearly a test DB,
    # so a typo can never wipe development or production data.
    if not str(dbname).endswith("_test"):
        pytest.fail(f"TEST_DATABASE_URL must point to a database ending in _test (got {dbname!r})")
    return url


@pytest.fixture(scope="session")
def _schema(test_database_url):
    with psycopg.connect(test_database_url, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS users")
        conn.execute(SCHEMA_SQL.read_text())


@pytest.fixture
def db_conn(_schema, test_database_url):
    """A connection to an empty users table."""
    with psycopg.connect(test_database_url) as conn:
        conn.execute("TRUNCATE users")
        conn.commit()
        yield conn
        conn.rollback()
