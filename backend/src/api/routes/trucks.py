

# backend/src/api/routes/trucks.py

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from backend.src.api import truck_service
from backend.src.api.deps import get_facility_scope, require_gate_officer
from backend.src.api.schemas import (
    CurrentOfficer,
    TruckEntryOut,
    TruckLookupOut,
    TruckSignInRequest,
    TruckSignOutRequest,
)
from backend.src.db.queries import trucks as q
from backend.src.db.session import get_db
from backend.src.exceptions.errors import NotFoundError

router = APIRouter(prefix="/trucks", tags=["trucks"])


# ---- writes: facility officers only ----

@router.get("/lookup", response_model=Optional[TruckLookupOut])
def lookup(
    plate: str = Query(min_length=2, max_length=40),
    officer: CurrentOfficer = Depends(require_gate_officer),
    db: Session = Depends(get_db),
) -> Optional[TruckLookupOut]:
    """null = new truck. Otherwise stored driver details to CONFIRM, plus
    open_entry_id if the truck is currently inside."""
    return truck_service.lookup_by_plate(db, officer=officer, plate=plate)


@router.post("/entries", response_model=TruckEntryOut,
             status_code=status.HTTP_201_CREATED)
def sign_in(
    body: TruckSignInRequest,
    response: Response,
    officer: CurrentOfficer = Depends(require_gate_officer),
    db: Session = Depends(get_db),
) -> TruckEntryOut:
    entry, created = truck_service.sign_in(db, officer=officer, data=body)
    if not created:
        response.status_code = status.HTTP_200_OK  # idempotent replay
    return entry


@router.post("/entries/{entry_id}/sign-out", response_model=TruckEntryOut)
def sign_out(
    entry_id: uuid.UUID,
    body: Optional[TruckSignOutRequest] = None,
    officer: CurrentOfficer = Depends(require_gate_officer),
    db: Session = Depends(get_db),
) -> TruckEntryOut:
    return truck_service.sign_out(db, officer=officer, entry_id=entry_id, data=body)


# ---- reads: every role, scoped by get_facility_scope ----

@router.get("/entries", response_model=list[TruckEntryOut])
def list_entries(
    open_only: bool = Query(False, alias="open"),
    plate: Optional[str] = Query(None, max_length=40),
    facility_code: Optional[str] = Query(None, max_length=32),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    scope: Optional[uuid.UUID] = Depends(get_facility_scope),
    db: Session = Depends(get_db),
) -> list[TruckEntryOut]:
    rows = q.list_entries(
        db, scope=scope, facility_code=facility_code, open_only=open_only,
        plate=plate, date_from=date_from, date_to=date_to,
        limit=limit, offset=offset)
    return [TruckEntryOut.from_row(r) for r in rows]


@router.get("/entries/{entry_id}/signature")
def get_signature(
    entry_id: uuid.UUID,
    scope: Optional[uuid.UUID] = Depends(get_facility_scope),
    db: Session = Depends(get_db),
) -> Response:
    row = q.get_signature(db, entry_id, scope)
    if row is None or row[0] is None:
        raise NotFoundError("No signature for that entry.")
    return Response(content=row[0], media_type="image/png",
                    headers={"Cache-Control": "private, max-age=3600"})
