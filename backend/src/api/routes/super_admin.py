

# backend/src/api/routes/super_admin.py

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from backend.src.api import super_admin_service as service
from backend.src.api.deps import require_super_admin
from backend.src.api.schemas import (
    AdminSummary,
    CreateAdminRequest,
    TempPinResponse,
)
from backend.src.db.session import get_db

router = APIRouter(
    prefix="/super-admin",
    tags=["super-admin"],
    dependencies=[Depends(require_super_admin)],
)


def _no_store(response: Response) -> None:
    # temp PINs must not be cached
    response.headers["Cache-Control"] = "no-store"


@router.get("/admins", response_model=list[AdminSummary])
def list_admins(db: Session = Depends(get_db)) -> list[AdminSummary]:
    return [AdminSummary.from_officer(o, f) for o, f in service.list_admins(db)]


@router.post("/admins", response_model=TempPinResponse,
             status_code=status.HTTP_201_CREATED)
def create_admin(
    body: CreateAdminRequest, response: Response, db: Session = Depends(get_db)
) -> TempPinResponse:
    officer, facility, pin = service.create_admin(
        db, full_name=body.full_name, role=body.role,
        facility_code=body.facility_code)
    _no_store(response)
    return TempPinResponse(
        officer=AdminSummary.from_officer(officer, facility), temp_pin=pin)


@router.post("/admins/{officer_id}/grant", response_model=AdminSummary)
def grant_admin(officer_id: uuid.UUID, db: Session = Depends(get_db)) -> AdminSummary:
    return AdminSummary.from_officer(*service.grant_admin(db, officer_id))


@router.post("/admins/{officer_id}/revoke", response_model=AdminSummary)
def revoke_admin(officer_id: uuid.UUID, db: Session = Depends(get_db)) -> AdminSummary:
    return AdminSummary.from_officer(*service.revoke_admin(db, officer_id))


@router.post("/admins/{officer_id}/disable", response_model=AdminSummary)
def disable_admin(officer_id: uuid.UUID, db: Session = Depends(get_db)) -> AdminSummary:
    return AdminSummary.from_officer(*service.disable_admin(db, officer_id))


@router.post("/admins/{officer_id}/enable", response_model=AdminSummary)
def enable_admin(officer_id: uuid.UUID, db: Session = Depends(get_db)) -> AdminSummary:
    return AdminSummary.from_officer(*service.enable_admin(db, officer_id))


@router.post("/admins/{officer_id}/reset-pin", response_model=TempPinResponse)
def reset_admin_pin(
    officer_id: uuid.UUID, response: Response, db: Session = Depends(get_db)
) -> TempPinResponse:
    officer, facility, pin = service.reset_admin_pin(db, officer_id)
    _no_store(response)
    return TempPinResponse(
        officer=AdminSummary.from_officer(officer, facility), temp_pin=pin)
