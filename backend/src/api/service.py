

# backend/src/api/auth/service.py

"""Login / refresh / logout logic. Plain functions over a Session so they are
testable without FastAPI. Routes stay thin.

Session policy (deliberate, for an OFFLINE-FIRST app):
* Refresh tokens are NOT rotated. Rotation means a lost HTTP response (very
  common on a gate-house mobile connection) leaves the phone holding a dead
  token and the guard locked out mid-shift with a queue of unsynced entries.
  Instead the refresh token is long-lived, hashed at rest, revocable per
  session, and its expiry slides forward each time it is used.
* The access token is short-lived; every request re-checks the session and
  officer in the DB (see api/deps.py), so revocation is immediate.
"""

from __future__ import annotations


from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.src.config.settings import Settings
from backend.src.db.orm._helpers import normalize_code
from backend.src.db.orm.tables import Facility, Officer, OfficerSession
from backend.src.exceptions.errors import (
    AccountLockedError,
    InvalidCredentialsError,
    InvalidTokenError,
    SessionRevokedError,
)
from backend.src.security.passwords import (
    burn_verify_time,
    hash_pin,
    needs_rehash,
    verify_pin,
)
from backend.src.security.tokens import (
    create_access_token,
    hash_refresh_token,
    new_refresh_token,
    utcnow,
)
from backend.src.api.schemas import LoginResult, RefreshResult


def assert_session_usable(
    session: OfficerSession,
    officer: Officer,
    facility_active: bool | None,
    now: datetime,
) -> None:
    """Single source of truth for 'may this session act right now?'.
    Used by /auth/refresh AND by the get_current_officer dependency."""
    if session.revoked_at is not None or session.expires_at <= now:
        raise SessionRevokedError()
    if not officer.is_active:
        raise SessionRevokedError("This account has been disabled.")
    if officer.facility_id is not None and facility_active is not True:
        raise SessionRevokedError("This facility has been disabled.")


def authenticate(
    db: Session,
    *,
    facility_code: str | None,
    officer_code: str,
    pin: str,
    device_label: str | None = None,
    now: datetime | None = None,
) -> LoginResult:
    now = now or utcnow()

    stmt = select(Officer).where(
        Officer.officer_code == normalize_code(officer_code))
    if facility_code is not None and facility_code.strip():
        # The (facility, officer) PAIR must match: a right officer code with the
        # wrong facility finds nothing and fails exactly like a wrong PIN.
        stmt = stmt.join(Facility, Facility.id == Officer.facility_id).where(
            Facility.code == normalize_code(facility_code),
            Facility.is_active.is_(True),
        )
    else:
        stmt = stmt.where(Officer.facility_id.is_(None))

    # Row lock so two parallel wrong-PIN requests can't both read attempts=4
    # and slip past the lockout counter.
    officer = db.scalar(stmt.with_for_update(of=Officer))

    if officer is None or not officer.is_active:
        burn_verify_time(pin)
        raise InvalidCredentialsError()

    if officer.locked_until is not None and officer.locked_until > now:
        raise AccountLockedError(
            int((officer.locked_until - now).total_seconds()) + 1)

    if not verify_pin(pin, officer.pin_hash):
        officer.failed_pin_attempts += 1
        if officer.failed_pin_attempts >= Settings.MAX_PIN_ATTEMPTS:
            officer.locked_until = now + \
                timedelta(minutes=Settings.LOCKOUT_MINUTES)
            officer.failed_pin_attempts = 0
            db.commit()  # persist the counter BEFORE raising
            raise AccountLockedError(Settings.LOCKOUT_MINUTES * 60)
        db.commit()
        raise InvalidCredentialsError()

    officer.failed_pin_attempts = 0
    officer.locked_until = None
    if needs_rehash(officer.pin_hash):
        officer.pin_hash = hash_pin(pin)

    refresh_token = new_refresh_token()
    refresh_expires_at = now + timedelta(days=Settings.REFRESH_TOKEN_DAYS)
    session = OfficerSession(
        officer_id=officer.id,
        refresh_token_hash=hash_refresh_token(refresh_token),
        device_label=(device_label.strip() or None) if device_label else None,
        last_used_at=now,
        expires_at=refresh_expires_at,
    )
    db.add(session)
    db.flush()  # assigns session.id

    access_token, access_expires_at = create_access_token(
        officer.id, session.id, now)
    facility = db.get(
        Facility, officer.facility_id) if officer.facility_id else None
    db.commit()

    return LoginResult(
        officer=officer,
        facility=facility,
        access_token=access_token,
        access_expires_at=access_expires_at,
        refresh_token=refresh_token,
        refresh_expires_at=refresh_expires_at,
        session_id=session.id,
    )


def refresh_access(
    db: Session, refresh_token: str, now: datetime | None = None
) -> RefreshResult:
    now = now or utcnow()
    row = db.execute(
        select(OfficerSession, Officer, Facility.is_active)
        .join(Officer, Officer.id == OfficerSession.officer_id)
        .outerjoin(Facility, Facility.id == Officer.facility_id)
        .where(OfficerSession.refresh_token_hash == hash_refresh_token(refresh_token))
        .with_for_update(of=OfficerSession)
    ).first()
    if row is None:
        raise InvalidTokenError("Unknown refresh token.")

    session, officer, facility_active = row
    assert_session_usable(session, officer, facility_active, now)

    session.last_used_at = now
    session.expires_at = now + \
        timedelta(days=Settings.REFRESH_TOKEN_DAYS)  # sliding
    access_token, access_expires_at = create_access_token(
        officer.id, session.id, now)
    refresh_expires_at = session.expires_at
    db.commit()

    return RefreshResult(
        access_token=access_token,
        access_expires_at=access_expires_at,
        refresh_expires_at=refresh_expires_at,
    )


def revoke_refresh_token(
    db: Session, refresh_token: str, now: datetime | None = None
) -> None:
    """Idempotent: an unknown or already-revoked token is a silent no-op, so
    logout always 'works' from the phone's point of view."""
    now = now or utcnow()
    session = db.scalar(
        select(OfficerSession)
        .where(OfficerSession.refresh_token_hash == hash_refresh_token(refresh_token))
        .with_for_update()
    )
    if session is not None and session.revoked_at is None:
        session.revoked_at = now
        db.commit()
