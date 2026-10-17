

# backend/src/api/super_admin_service.py

"""Admin management. Every function here refuses to touch a super admin:
no API path can create, change, disable or remove one (CLI only)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.src.api.account_ops import create_account, revoke_all_sessions
from backend.src.db.orm.tables import Facility, Officer
from backend.src.exceptions.errors import ConflictError, NotFoundError
from backend.src.models import Role
from backend.src.security.passwords import generate_temp_pin, hash_pin


def _target(db: Session, officer_id: uuid.UUID, *, is_admin: bool) -> Officer:
    """Locks and returns a NON-super-admin account with the given admin state."""
    officer = db.scalar(
        select(Officer)
        .where(
            Officer.id == officer_id,
            Officer.is_admin.is_(is_admin),
            Officer.is_super_admin.is_(False),
        )
        .with_for_update()
    )
    if officer is None:
        raise NotFoundError()
    return officer


def _facility_of(db: Session, officer: Officer) -> Facility | None:
    return db.get(Facility, officer.facility_id) if officer.facility_id else None


def list_admins(db: Session) -> list[tuple[Officer, Facility | None]]:
    rows = db.execute(
        select(Officer, Facility)
        .outerjoin(Facility, Facility.id == Officer.facility_id)
        .where(Officer.is_admin.is_(True))
        .order_by(Officer.full_name)
    ).all()
    return [(o, f) for o, f in rows]


def create_admin(
    db: Session, *, full_name: str, role: Role, facility_code: str | None
) -> tuple[Officer, Facility | None, str]:
    officer, facility, pin = create_account(
        db, full_name=full_name, role=role,
        facility_code=facility_code, is_admin=True)
    db.commit()
    return officer, facility, pin


def grant_admin(db: Session, officer_id: uuid.UUID) -> tuple[Officer, Facility | None]:
    """Give an existing account admin powers. Role and facility are unchanged."""
    officer = _target(db, officer_id, is_admin=False)
    if not officer.is_active:
        raise ConflictError("That account is disabled.")
    officer.is_admin = True
    db.commit()
    return officer, _facility_of(db, officer)


def revoke_admin(db: Session, officer_id: uuid.UUID) -> tuple[Officer, Facility | None]:
    """'No longer an admin'. Role, facility and code stay exactly as they were.
    Takes effect on their next request (deps re-reads the DB every time)."""
    officer = _target(db, officer_id, is_admin=True)
    officer.is_admin = False
    db.commit()
    return officer, _facility_of(db, officer)


def disable_admin(db: Session, officer_id: uuid.UUID) -> tuple[Officer, Facility | None]:
    """'This person is gone.' Login fails, every session dies."""
    officer = _target(db, officer_id, is_admin=True)
    officer.is_active = False
    revoke_all_sessions(db, officer.id)
    db.commit()
    return officer, _facility_of(db, officer)


def enable_admin(db: Session, officer_id: uuid.UUID) -> tuple[Officer, Facility | None]:
    officer = _target(db, officer_id, is_admin=True)
    officer.is_active = True
    officer.failed_pin_attempts = 0
    officer.locked_until = None
    db.commit()
    return officer, _facility_of(db, officer)


def reset_admin_pin(
    db: Session, officer_id: uuid.UUID
) -> tuple[Officer, Facility | None, str]:
    officer = _target(db, officer_id, is_admin=True)
    pin = generate_temp_pin()
    officer.pin_hash = hash_pin(pin)
    officer.must_change_pin = True
    officer.failed_pin_attempts = 0
    officer.locked_until = None
    revoke_all_sessions(db, officer.id)
    db.commit()
    return officer, _facility_of(db, officer), pin
