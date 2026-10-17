

# backend/src/api/account_ops.py

"""Account helpers shared by admin_service and super_admin_service.
Deliberately does NOT import security/accounts.py (CLI-only)."""

from __future__ import annotations

import uuid

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from backend.src.db.orm._helpers import normalize_code
from backend.src.db.orm.tables import Counter, Facility, Officer, OfficerSession
from backend.src.exceptions.errors import NotFoundError
from backend.src.models import CODE_PREFIX, FACILITY_ROLES, Role
from backend.src.security.passwords import generate_temp_pin, hash_pin
from backend.src.security.tokens import utcnow


def revoke_all_sessions(db: Session, officer_id: uuid.UUID) -> None:
    db.execute(
        update(OfficerSession)
        .where(OfficerSession.officer_id == officer_id,
               OfficerSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


def _next_facility_code(db: Session, facility: Facility, prefix: str) -> str:
    while True:
        seq = facility.next_officer_seq
        facility.next_officer_seq = seq + 1
        code = f"{prefix}-{seq:03d}"
        taken = db.scalar(select(Officer.id).where(
            Officer.facility_id == facility.id, Officer.officer_code == code))
        if taken is None:
            return code


def _next_global_code(db: Session, prefix: str) -> str:
    name = f"officer_code:{prefix}"
    db.execute(pg_insert(Counter).values(name=name, next_value=1)
               .on_conflict_do_nothing(index_elements=["name"]))
    row = db.scalar(select(Counter).where(
        Counter.name == name).with_for_update())
    assert row is not None
    while True:
        seq = row.next_value
        row.next_value = seq + 1
        code = f"{prefix}-{seq:03d}"
        taken = db.scalar(select(Officer.id).where(
            Officer.facility_id.is_(None), Officer.officer_code == code))
        if taken is None:
            return code


def create_account(
    db: Session,
    *,
    full_name: str,
    role: Role,
    facility_code: str | None,
    is_admin: bool,
) -> tuple[Officer, Facility | None, str]:
    """Creates the account with an auto-issued code and a temp PIN.
    Returns (officer, facility, plain_temp_pin). Caller commits."""
    facility: Facility | None = None
    if role in FACILITY_ROLES:
        if not facility_code:
            raise NotFoundError("Facility not found.")
        facility = db.scalar(
            select(Facility)
            .where(Facility.code == normalize_code(facility_code),
                   Facility.is_active.is_(True))
            .with_for_update()
            .execution_options(populate_existing=True))
        if facility is None:
            raise NotFoundError("Facility not found.")
        code = _next_facility_code(db, facility, CODE_PREFIX[role])
    else:
        code = _next_global_code(db, CODE_PREFIX[role])

    pin = generate_temp_pin()
    officer = Officer(
        facility_id=facility.id if facility else None,
        officer_code=code,
        full_name=full_name.strip(),
        pin_hash=hash_pin(pin),
        role=role,
        is_admin=is_admin,
        must_change_pin=True,
    )
    db.add(officer)
    db.flush()
    return officer, facility, pin
