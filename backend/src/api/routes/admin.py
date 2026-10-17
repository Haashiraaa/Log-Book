

# backend/src/api/routes/admin.py

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from backend.src.api import admin_service
from backend.src.api.deps import require_admin
from backend.src.api.schemas import (
    AdminOfficerOut,
    CreateFacilityRequest,
    CreateOfficerRequest,
    CreateOfficerResponse,
    FacilityOut,
    OfficerProfile,
    ResetPinResponse,
)
from backend.src.db.session import get_db

# Every route in this file is admin-only. Applied at router level so it
# cannot be forgotten on an individual endpoint.
router = APIRouter(
    prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)]
)


@router.get("/facilities", response_model=list[FacilityOut])
def list_facilities(db: Session = Depends(get_db)) -> list[FacilityOut]:
    return [FacilityOut.model_validate(f) for f in admin_service.list_facilities(db)]


@router.post("/facilities", response_model=FacilityOut,
             status_code=status.HTTP_201_CREATED)
def create_facility(
    body: CreateFacilityRequest, db: Session = Depends(get_db)
) -> FacilityOut:
    facility = admin_service.create_facility(
        db, code=body.code, name=body.name)
    return FacilityOut.model_validate(facility)


@router.get("/officers", response_model=list[AdminOfficerOut])
def list_officers(
    facility_code: Optional[str] = None, db: Session = Depends(get_db)
) -> list[AdminOfficerOut]:
    rows = admin_service.list_officers(db, facility_code)
    return [AdminOfficerOut.from_row(o, f) for o, f in rows]


@router.post("/officers", response_model=CreateOfficerResponse,
             status_code=status.HTTP_201_CREATED)
def create_officer(
    body: CreateOfficerRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> CreateOfficerResponse:
    officer, facility, temp_pin = admin_service.create_officer(
        db, facility_code=body.facility_code, full_name=body.full_name
    )
    response.headers["Cache-Control"] = "no-store"  # response holds a PIN
    return CreateOfficerResponse(
        officer=OfficerProfile.build(officer, facility), temp_pin=temp_pin
    )


@router.post("/officers/{officer_id}/reset-pin", response_model=ResetPinResponse)
def reset_pin(
    officer_id: uuid.UUID, response: Response, db: Session = Depends(get_db)
) -> ResetPinResponse:
    officer, temp_pin = admin_service.reset_pin(db, officer_id)
    response.headers["Cache-Control"] = "no-store"
    return ResetPinResponse(
        officer_code=officer.officer_code,
        full_name=officer.full_name,
        temp_pin=temp_pin,
    )


@router.post("/officers/{officer_id}/disable",
             status_code=status.HTTP_204_NO_CONTENT)
def disable_officer(
    officer_id: uuid.UUID, db: Session = Depends(get_db)
) -> Response:
    admin_service.set_officer_active(db, officer_id, False)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/officers/{officer_id}/enable",
             status_code=status.HTTP_204_NO_CONTENT)
def enable_officer(
    officer_id: uuid.UUID, db: Session = Depends(get_db)
) -> Response:
    admin_service.set_officer_active(db, officer_id, True)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/officers/{officer_id}/revoke-sessions",
             status_code=status.HTTP_204_NO_CONTENT)
def revoke_sessions(
    officer_id: uuid.UUID, db: Session = Depends(get_db)
) -> Response:
    admin_service.revoke_sessions(db, officer_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
