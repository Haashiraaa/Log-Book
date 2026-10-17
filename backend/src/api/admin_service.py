

# backend/src/api/admin_service.py

"""Admin operations. Same rule as auth/service.py: plain functions over a
Session. NOTHING here can create or modify an admin account: every officer
lookup filters is_admin = false, and create_officer hard-codes is_admin=False.
Admin accounts are managed from the CLI only (security/accounts.py)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.src.db.orm._helpers import normalize_code
from backend.src.db.orm.tables import Facility, Officer, OfficerSession
from backend.src.exceptions.errors import ConflictError, NotFoundError
from backend.src.models import Role
from backend.src.security.passwords import generate_temp_pin, hash_pin
from backend.src.security.tokens import utcnow

OFFICER_CODE_PREFIX = "OFF"


# ---- facilities ----

def create_facility(db: Session, *, code: str, name: str) -> Facility:
    facility = Facility(code=code, name=name.strip()
                        )  # code normalized by model
    db.add(facility)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError(
            f"Facility {normalize_code(code)!r} already exists.") from None
    return facility


def list_facilities(db: Session) -> list[Facility]:
    return list(db.scalars(select(Facility).order_by(Facility.code)))


# ---- officers ----

def _managed_officer(db: Session, officer_id: uuid.UUID) -> Officer:
    """Row-locked non-admin officer, or NotFound. Admins are invisible here."""
    officer = db.scalar(
        select(Officer)
        .where(Officer.id == officer_id, Officer.is_admin.is_(False))
        .with_for_update()
    )
    if officer is None:
        raise NotFoundError("Officer not found.")
    return officer


def _revoke_all_sessions(db: Session, officer_id: uuid.UUID, now: datetime) -> None:
    db.execute(
        update(OfficerSession)
        .where(OfficerSession.officer_id == officer_id,
               OfficerSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )


def create_officer(
    db: Session, *, facility_code: str, full_name: str
) -> tuple[Officer, Facility, str]:
    """Returns (officer, facility, temp_pin). The temp PIN exists in plain text
    only in this return value."""
    # Locking the facility row serialises concurrent creates for it, so two
    # admins can't be handed the same sequence number.
    facility = db.scalar(
        select(Facility)
        .where(Facility.code == normalize_code(facility_code),
               Facility.is_active.is_(True))
        .with_for_update()
    )
    if facility is None:
        raise NotFoundError("Facility not found.")

    # Skip numbers already taken (e.g. a code created by a script).
    while True:
        code = f"{OFFICER_CODE_PREFIX}-{facility.next_officer_seq:03d}"
        facility.next_officer_seq += 1
        taken = db.scalar(
            select(Officer.id).where(
                Officer.facility_id == facility.id,
                Officer.officer_code == code,
            )
        )
        if taken is None:
            break

    temp_pin = generate_temp_pin()
    officer = Officer(
        facility_id=facility.id,
        officer_code=code,
        full_name=full_name.strip(),
        pin_hash=hash_pin(temp_pin),
        role=Role.OFFICER,
        is_admin=False,
        must_change_pin=True,
    )
    db.add(officer)
    db.commit()
    return officer, facility, temp_pin


def list_officers(
    db: Session, facility_code: str | None = None
) -> list[tuple[Officer, Facility | None]]:
    stmt = (
        select(Officer, Facility)
        .outerjoin(Facility, Facility.id == Officer.facility_id)
        .where(Officer.is_admin.is_(False))
        .order_by(Facility.code, Officer.officer_code)
    )
    if facility_code:
        stmt = stmt.where(Facility.code == normalize_code(facility_code))
    return [(o, f) for o, f in db.execute(stmt).all()]


def reset_pin(
    db: Session, officer_id: uuid.UUID, now: datetime | None = None
) -> tuple[Officer, str]:
    """New temp PIN, must_change_pin on, lockout cleared, every phone signed out."""
    now = now or utcnow()
    officer = _managed_officer(db, officer_id)
    temp_pin = generate_temp_pin()
    officer.pin_hash = hash_pin(temp_pin)
    officer.must_change_pin = True
    officer.failed_pin_attempts = 0
    officer.locked_until = None
    _revoke_all_sessions(db, officer.id, now)
    db.commit()
    return officer, temp_pin


def set_officer_active(
    db: Session, officer_id: uuid.UUID, active: bool, now: datetime | None = None
) -> None:
    now = now or utcnow()
    officer = _managed_officer(db, officer_id)
    officer.is_active = active
    if not active:
        _revoke_all_sessions(db, officer.id, now)
    db.commit()


def revoke_sessions(
    db: Session, officer_id: uuid.UUID, now: datetime | None = None
) -> None:
    """Lost phone: sign the officer out everywhere, keep the account enabled."""
    now = now or utcnow()
    officer = _managed_officer(db, officer_id)
    _revoke_all_sessions(db, officer.id, now)
    db.commit()
