

# backend/src/api/deps.py

"""Auth dependencies for protected routes.

get_session_officer does ONE query per request and checks the session, officer
and facility against the DB (service.assert_session_usable), never against the
token. Revoking a phone or disabling an officer bites on the next request.

get_current_officer = get_session_officer + "no temp PIN pending". Everything
except /auth/me and /auth/change-pin should depend on THIS one, directly or
through the gates below.

Entry endpoints:
    officer: CurrentOfficer = Depends(require_gate_officer)   # writes
    scope: Optional[UUID]   = Depends(get_facility_scope)     # reads
and filter with scoped(stmt, Model.facility_id, scope).
facility_id for a write is officer.facility_id, never the request body.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.src.api.schemas import CurrentOfficer
from backend.src.api.service import assert_session_usable
from backend.src.db.orm.tables import Facility, Officer, OfficerSession
from backend.src.db.session import get_db
from backend.src.exceptions.errors import (
    InvalidTokenError,
    MustChangePinError,
    PermissionDeniedError,
    SessionRevokedError,
)
from backend.src.models import Role
from backend.src.security.tokens import decode_access_token, utcnow

_bearer = HTTPBearer(auto_error=False)


def get_session_officer(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: Session = Depends(get_db),
) -> CurrentOfficer:
    if creds is None:
        raise InvalidTokenError()
    claims = decode_access_token(creds.credentials)  # raises Expired / Invalid

    row = db.execute(
        select(OfficerSession, Officer, Facility.is_active)
        .join(Officer, Officer.id == OfficerSession.officer_id)
        .outerjoin(Facility, Facility.id == Officer.facility_id)
        .where(
            OfficerSession.id == claims.session_id,
            Officer.id == claims.officer_id,
        )
    ).first()
    if row is None:
        raise SessionRevokedError()

    session, officer, facility_active = row
    assert_session_usable(session, officer, facility_active, utcnow())
    return CurrentOfficer(
        officer_id=officer.id,
        session_id=session.id,
        facility_id=officer.facility_id,
        role=officer.role,
        is_admin=officer.is_admin,
        is_super_admin=officer.is_super_admin,
        must_change_pin=officer.must_change_pin,
    )


def get_current_officer(
    current: CurrentOfficer = Depends(get_session_officer),
) -> CurrentOfficer:
    if current.must_change_pin:
        raise MustChangePinError()
    return current


# ---- role gates ----

def require_admin(
    current: CurrentOfficer = Depends(get_current_officer),
) -> CurrentOfficer:
    if not current.is_admin:
        raise PermissionDeniedError()
    return current


def require_gate_officer(
    current: CurrentOfficer = Depends(get_current_officer),
) -> CurrentOfficer:
    """For endpoints that WRITE log entries: a facility officer only.
    CSO is read-only, and a global admin has no facility to write into."""
    if current.role != Role.OFFICER or current.facility_id is None:
        raise PermissionDeniedError(
            "Only facility officers can write log entries.")
    return current


def require_super_admin(
    current: CurrentOfficer = Depends(get_current_officer),
) -> CurrentOfficer:
    if not current.is_super_admin:
        raise PermissionDeniedError()
    return current

# ---- facility scoping (reads) ----


def get_facility_scope(
    current: CurrentOfficer = Depends(get_current_officer),
) -> Optional[uuid.UUID]:
    """None = all facilities (CSO / admin); otherwise the officer's own."""
    return None if current.sees_all_facilities else current.facility_id


def scoped(stmt: Any, facility_column: Any, scope: Optional[uuid.UUID]) -> Any:
    """stmt = scoped(select(TruckEntry), TruckEntry.facility_id, scope)"""
    return stmt if scope is None else stmt.where(facility_column == scope)
