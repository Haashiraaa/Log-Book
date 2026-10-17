

# tests/_helpers.py

from __future__ import annotations

import uuid
from typing import Optional

from fastapi.testclient import TestClient

from backend.src.db.session import create_session
from backend.src.models import Role
from backend.src.security.accounts import create_officer, get_or_create_facility
from tests._schemas import Actor

PIN = "483920"


def make_account(
    *, code: str, facility: Optional[str] = None, role: Role = Role.OFFICER,
    is_admin: bool = False, is_super_admin: bool = False,
    must_change_pin: bool = False, pin: str = PIN,
) -> uuid.UUID:
    with create_session() as db:
        if facility:
            get_or_create_facility(db, facility, f"Station {facility}")
        officer = create_officer(
            db, officer_code=code, full_name=f"Test {code}", pin=pin, role=role,
            is_admin=is_admin, is_super_admin=is_super_admin,
            facility_code=facility)
        officer.must_change_pin = must_change_pin
        db.commit()
        return officer.id


def login_response(client: TestClient, code: str, facility: Optional[str] = None,
                   pin: str = PIN):
    return client.post("/api/auth/login", json={
        "facility_code": facility, "officer_code": code, "pin": pin})


def login(client: TestClient, code: str, facility: Optional[str] = None,
          pin: str = PIN) -> dict[str, str]:
    r = login_response(client, code, facility, pin)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def make_actor(client: TestClient, *, code: str, facility: Optional[str] = None,
               role: Role = Role.OFFICER, is_admin: bool = False,
               is_super_admin: bool = False, must_change_pin: bool = False) -> Actor:
    oid = make_account(code=code, facility=facility, role=role, is_admin=is_admin,
                       is_super_admin=is_super_admin, must_change_pin=must_change_pin)
    return Actor(oid, code, facility, login(client, code, facility))
