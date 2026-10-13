from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg2
import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")

if not TEST_DATABASE_URL:
    raise RuntimeError(
        "TEST_DATABASE_URL must be explicitly configured. "
        "NetWatch tests refuse to run without a dedicated test database."
    )

os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["ALLOW_PUBLIC_SIGNUP"] = "true"
os.environ["ALLOWED_ORIGINS"] = "http://localhost:5173"
os.environ["SESSION_TTL_HOURS"] = "12"
os.environ["AGENT_STALE_SECONDS"] = "60"

from migrate import run_migrations  # noqa: E402

run_migrations()

from api_server import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_database():
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                TRUNCATE TABLE
                    alerts,
                    security_events,
                    agent_upload_batches,
                    device_observations,
                    device_profiles,
                    devices,
                    heartbeats,
                    agent_enrollment_tokens,
                    agents,
                    auth_sessions,
                    org_memberships,
                    users,
                    organizations
                RESTART IDENTITY CASCADE
                """
            )
        conn.commit()
    finally:
        conn.close()
    yield


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client
