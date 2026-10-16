

# backend/src/security/accounts.py

"""Account creation helpers for seed scripts / CLI ONLY.

Nothing in the API imports this module. That is how `is_admin` stays
unreachable from a request body: there is simply no route that can set it.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.src.db.orm._helpers import normalize_code
from backend.src.db.orm.tables import Facility, Officer
from backend.src.models import Role
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


def create_officer(
    db: Session,
    *,
    officer_code: str,
    full_name: str,
    pin: str,
    role: Role = Role.OFFICER,
    is_admin: bool = False,
    facility_code: str | None = None,
) -> Officer:
    """Create an officer / CSO / admin. Raises ValueError on bad input or
    duplicates. Caller commits."""
    validate_pin_policy(pin)

    facility_id = None
    if facility_code is not None:
        facility = db.scalar(
            select(Facility).where(Facility.code == normalize_code(facility_code)))
        if facility is None:
            raise ValueError(f"Facility {facility_code!r} does not exist.")
        facility_id = facility.id
    elif role == Role.OFFICER and not is_admin:
        raise ValueError("A plain officer needs a facility_code.")

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
    )
    db.add(officer)
    db.flush()
    return officer
