

# backend/src/api/routes/auth.py

"""NOTE: handlers are plain `def`, not `async def`, on purpose. argon2 and the
sync SQLAlchemy session both block; FastAPI runs `def` handlers in a threadpool
so they don't freeze the event loop."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from backend.src.api import service
from backend.src.api.deps import get_session_officer
from backend.src.api.schemas import (
    ChangePinRequest,
    CurrentOfficer,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    OfficerProfile,
    RefreshRequest,
    RefreshResponse,
)
from backend.src.db.orm.tables import Facility, Officer
from backend.src.db.session import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    result = service.authenticate(
        db,
        facility_code=body.facility_code,
        officer_code=body.officer_code,
        pin=body.pin,
        device_label=body.device_label,
    )
    return LoginResponse(
        access_token=result.access_token,
        access_expires_at=result.access_expires_at,
        refresh_token=result.refresh_token,
        refresh_expires_at=result.refresh_expires_at,
        officer=OfficerProfile.build(result.officer, result.facility),
    )


@router.post("/refresh", response_model=RefreshResponse)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)) -> RefreshResponse:
    result = service.refresh_access(db, body.refresh_token)
    return RefreshResponse(
        access_token=result.access_token,
        access_expires_at=result.access_expires_at,
        refresh_expires_at=result.refresh_expires_at,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: LogoutRequest, db: Session = Depends(get_db)) -> Response:
    # Takes the REFRESH token (not the bearer) so a guard can still log out
    # after the 15-minute access token has expired.
    service.revoke_refresh_token(db, body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# me and change-pin use get_session_officer (NOT get_current_officer) so an
# officer on a temp PIN can still reach them.

@router.get("/me", response_model=OfficerProfile)
def me(
    current: CurrentOfficer = Depends(get_session_officer),
    db: Session = Depends(get_db),
) -> OfficerProfile:
    officer = db.get(Officer, current.officer_id)
    assert officer is not None  # get_session_officer just loaded it
    facility = db.get(
        Facility, current.facility_id) if current.facility_id else None
    return OfficerProfile.build(officer, facility)


@router.post("/change-pin", status_code=status.HTTP_204_NO_CONTENT)
def change_pin(
    body: ChangePinRequest,
    current: CurrentOfficer = Depends(get_session_officer),
    db: Session = Depends(get_db),
) -> Response:
    service.change_pin(
        db,
        officer_id=current.officer_id,
        session_id=current.session_id,
        current_pin=body.current_pin,
        new_pin=body.new_pin,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
