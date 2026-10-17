

# tests/conftest.py

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

import pytest
from dotenv import load_dotenv

load_dotenv()

_TEST_URL = os.environ.get("TEST_DATABASE_URL")
if not _TEST_URL:
    pytest.exit("Set TEST_DATABASE_URL to a throwaway database.", returncode=2)
if "test" not in urlparse(_TEST_URL).path.lower():
    pytest.exit("TEST_DATABASE_URL must point at a database whose name contains "
                "'test'. This suite DROPS the schema.", returncode=2)

# Must happen before any backend module is imported (Settings reads env at import).
os.environ["DATABASE_URL"] = _TEST_URL
os.environ["JWT_SECRET"] = "t" * 48
os.environ["PIN_PEPPER"] = "p" * 48

from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from alembic import command  # noqa: E402
from backend.src.db.session import engine  # noqa: E402
from backend.src.main import app  # noqa: E402
from backend.src.models import Role  # noqa: E402
from tests._helpers import Actor, make_actor  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _database():
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(cfg, "head")  # exercises every migration for real
    yield


@pytest.fixture(autouse=True)
def _clean():
    yield
    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE truck_entries, visitor_entries, staff_entries, trucks, staff, "
            "officer_sessions, officers, counters, facilities RESTART IDENTITY CASCADE"))


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def officer_a(client: TestClient) -> Actor:
    return make_actor(client, code="OFF-001", facility="CNG-A")


@pytest.fixture
def officer_b(client: TestClient) -> Actor:
    # same code, other facility
    return make_actor(client, code="OFF-001", facility="CNG-B")


@pytest.fixture
def manager_a(client: TestClient) -> Actor:
    return make_actor(client, code="MGR-001", facility="CNG-A",
                      role=Role.FACILITY_MANAGER)


@pytest.fixture
def cso(client: TestClient) -> Actor:
    return make_actor(client, code="CSO-001", role=Role.CSO)


@pytest.fixture
def admin(client: TestClient) -> Actor:
    return make_actor(client, code="ADM-001", role=Role.CSO, is_admin=True)


@pytest.fixture
def super_admin(client: TestClient) -> Actor:
    return make_actor(client, code="SA-01", role=Role.CSO, is_admin=True,
                      is_super_admin=True)
