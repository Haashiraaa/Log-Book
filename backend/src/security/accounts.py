

# backend/src/security/accounts.py

"""Account helpers for seed scripts / CLI ONLY.

Nothing in the API imports this module. That is how is_admin / is_super_admin
stay unreachable from a request body for CLI-managed accounts.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.src.db.orm._helpers import normalize_code
from backend.src.db.orm.tables import Facility, Officer
from backend.src.models import FACILITY_ROLES, Role
from backend.src.security.passwords import hash_pin, validate_pin_policy


def get_or_create_facility(db: Session, code: str, name: str) -> tuple[Facility, bool]:
    code = normalize_code(code)
    facility = db.scalar(select(Facility).where(Facility.code == code))
    if facility is not None:
        return facility, False
    facility = Facility(code=code, name=name)
    db.add(facility)
    db.flush()
    return facility, True


def find_officer(
    db: Session, *, officer_code: str, facility_code: str | None = None
) -> Officer:
    """Lookup by the same (facility, officer code) pair used at login."""
    stmt = select(Officer).where(
        Officer.officer_code == normalize_code(officer_code))
    if facility_code:
        stmt = stmt.join(Facility, Facility.id == Officer.facility_id).where(
            Facility.code == normalize_code(facility_code))
    else:
        stmt = stmt.where(Officer.facility_id.is_(None))
    officer = db.scalar(stmt.with_for_update(of=Officer))
    if officer is None:
        raise ValueError("No such officer for that facility/code.")
    return officer


def create_officer(
    db: Session,
    *,
    officer_code: str,
    full_name: str,
    pin: str,
    role: Role = Role.OFFICER,
    is_admin: bool = False,
    is_super_admin: bool = False,
    facility_code: str | None = None,
) -> Officer:
    """Raises ValueError on bad input or duplicates. Caller commits."""
    validate_pin_policy(pin)
    is_admin = is_admin or is_super_admin  # a super admin is always an admin

    facility_id = None
    if role in FACILITY_ROLES:
        if facility_code is None:
            raise ValueError(f"Role {role.value!r} needs a facility_code.")
        facility = db.scalar(select(Facility).where(
            Facility.code == normalize_code(facility_code)))
        if facility is None:
            raise ValueError(f"Facility {facility_code!r} does not exist.")
        facility_id = facility.id
    elif facility_code is not None:
        raise ValueError(
            f"Role {role.value!r} is global; do not pass a facility_code.")

    officer_code = normalize_code(officer_code)
    dup = select(Officer.id).where(
        Officer.officer_code == officer_code,
        Officer.facility_id == facility_id if facility_id is not None
        else Officer.facility_id.is_(None),
    )
    if db.scalar(dup) is not None:
        raise ValueError(
            f"Officer code {officer_code!r} already exists there.")

    officer = Officer(
        facility_id=facility_id,
        officer_code=officer_code,
        full_name=full_name.strip(),
        pin_hash=hash_pin(pin),
        role=role,
        is_admin=is_admin,
        is_super_admin=is_super_admin,
    )
    db.add(officer)
    db.flush()
    return officer
