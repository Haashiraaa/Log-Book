

# backend/src/api/admin_service.py

"""Admin operations. Same rule as auth/service.py: plain functions over a
Session. Admins manage FACILITY accounts only (officer, facility_manager).
Every lookup filters is_admin = false AND role in FACILITY_ROLES, so an admin
can never touch another admin, a super admin, or a global (CSO) account.
Those are managed from the super-admin page or the CLI."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.src.api.account_ops import create_account, revoke_all_sessions
from backend.src.db.orm._helpers import normalize_code
from backend.src.db.orm.tables import Facility, Officer
from backend.src.exceptions.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
)
from backend.src.models import FACILITY_ROLES, Role
from backend.src.security.passwords import generate_temp_pin, hash_pin


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
    """Row-locked non-admin FACILITY account, or NotFound.
    Admins and global accounts (CSO) are invisible here."""
    officer = db.scalar(
        select(Officer)
        .where(
            Officer.id == officer_id,
            Officer.is_admin.is_(False),
            Officer.role.in_(list(FACILITY_ROLES)),
        )
        .with_for_update()
    )
    if officer is None:
        raise NotFoundError("Officer not found.")
    return officer


def create_officer(
    db: Session, *, facility_code: str, full_name: str, role: Role = Role.OFFICER
) -> tuple[Officer, Facility, str]:
    """Returns (officer, facility, temp_pin). The temp PIN exists in plain text
    only in this return value."""
    if role not in FACILITY_ROLES:
        raise PermissionDeniedError(
            "Admins can only create facility officers or managers.")
    officer, facility, pin = create_account(
        db, full_name=full_name, role=role,
        facility_code=facility_code, is_admin=False)
    db.commit()
    assert facility is not None  # guaranteed for FACILITY_ROLES
    return officer, facility, pin


def list_officers(
    db: Session, facility_code: str | None = None
) -> list[tuple[Officer, Facility | None]]:
    stmt = (
        select(Officer, Facility)
        .outerjoin(Facility, Facility.id == Officer.facility_id)
        .where(
            Officer.is_admin.is_(False),
            Officer.role.in_(list(FACILITY_ROLES)),
        )
        .order_by(Facility.code, Officer.officer_code)
    )
    if facility_code:
        stmt = stmt.where(Facility.code == normalize_code(facility_code))
    return [(o, f) for o, f in db.execute(stmt).all()]


def reset_pin(db: Session, officer_id: uuid.UUID) -> tuple[Officer, str]:
    """New temp PIN, must_change_pin on, lockout cleared, every phone signed out."""
    officer = _managed_officer(db, officer_id)
    pin = generate_temp_pin()
    officer.pin_hash = hash_pin(pin)
    officer.must_change_pin = True
    officer.failed_pin_attempts = 0
    officer.locked_until = None
    revoke_all_sessions(db, officer.id)
    db.commit()
    return officer, pin


def set_officer_active(db: Session, officer_id: uuid.UUID, active: bool) -> None:
    officer = _managed_officer(db, officer_id)
    officer.is_active = active
    if not active:
        revoke_all_sessions(db, officer.id)
    db.commit()


def revoke_sessions(db: Session, officer_id: uuid.UUID) -> None:
    """Lost phone: sign the officer out everywhere, keep the account enabled."""
    officer = _managed_officer(db, officer_id)
    revoke_all_sessions(db, officer.id)
    db.commit()
