

# backend/src/db/queries/trucks.py

"""SQL only: no commits, no business rules (those live in api/truck_service.py)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, aliased

from backend.src.db.orm._helpers import normalize_code, normalize_plate
from backend.src.db.orm.tables import Facility, Officer, Truck, TruckEntry

_IN = aliased(Officer)
_OUT = aliased(Officer)


def _entry_select() -> Any:
    """Rows are (TruckEntry, facility_code, has_signature, in_name, out_name).
    The signature blob itself stays deferred; we only ask whether it exists."""
    return (
        select(
            TruckEntry,
            Facility.code,
            TruckEntry.signature_in.is_not(None),
            _IN.full_name,
            _OUT.full_name,
        )
        .join(Facility, Facility.id == TruckEntry.facility_id)
        .join(_IN, _IN.id == TruckEntry.signed_in_by)
        .outerjoin(_OUT, _OUT.id == TruckEntry.signed_out_by)
        .execution_options(populate_existing=True)
    )


def find_truck(db: Session, facility_id: uuid.UUID, plate: str) -> Truck | None:
    return db.scalar(select(Truck).where(
        Truck.facility_id == facility_id,
        Truck.plate_number == normalize_plate(plate)))


def find_open_entry_id(
    db: Session, facility_id: uuid.UUID, truck_id: uuid.UUID
) -> uuid.UUID | None:
    return db.scalar(
        select(TruckEntry.id)
        .where(TruckEntry.facility_id == facility_id,
               TruckEntry.truck_id == truck_id,
               TruckEntry.signed_out_at.is_(None))
        .order_by(TruckEntry.signed_in_at.desc())
        .limit(1))


def upsert_truck(
    db: Session, *, facility_id: uuid.UUID, plate: str, driver_name: str,
    driver_phone: Optional[str], company: Optional[str],
) -> uuid.UUID:
    """Registry keeps the LATEST confirmed driver details. Core upserts skip
    the model's @validates, so the plate is normalized here."""
    stmt = pg_insert(Truck).values(
        id=uuid.uuid4(), facility_id=facility_id,
        plate_number=normalize_plate(plate), driver_name=driver_name,
        driver_phone=driver_phone, company=company)
    stmt = stmt.on_conflict_do_update(
        index_elements=["facility_id", "plate_number"],
        set_={
            "driver_name": stmt.excluded.driver_name,
            "driver_phone": stmt.excluded.driver_phone,
            "company": stmt.excluded.company,
            "updated_at": func.now(),
        },
    ).returning(Truck.id)
    return db.execute(stmt).scalar_one()


def insert_entry(
    db: Session, *, entry_id: uuid.UUID, facility_id: uuid.UUID,
    truck_id: uuid.UUID, plate: str, driver_name: str,
    driver_phone: Optional[str], company: Optional[str],
    scm_purchased: Optional[Decimal], signed_in_at: datetime,
    signature: Optional[bytes], signed_in_by: uuid.UUID,
    device_id: Optional[str],
) -> bool:
    """True if inserted, False if that id already existed (retry). Never
    overwrites an existing row."""
    stmt = (
        pg_insert(TruckEntry)
        .values(
            id=entry_id, facility_id=facility_id, truck_id=truck_id,
            plate_number=normalize_plate(plate), driver_name=driver_name,
            driver_phone=driver_phone, company=company,
            scm_purchased=scm_purchased, signed_in_at=signed_in_at,
            signature_in=signature, signed_in_by=signed_in_by,
            device_id=device_id)
        .on_conflict_do_nothing(index_elements=["id"])
        .returning(TruckEntry.id)
    )
    return db.execute(stmt).scalar_one_or_none() is not None


def sign_out_entry(
    db: Session, *, entry_id: uuid.UUID, facility_id: uuid.UUID,
    officer_id: uuid.UUID, signed_out_at: datetime,
    scm_purchased: Optional[Decimal],
) -> bool:
    """True if this call closed the entry. False = not found OR already out."""
    values: dict[str, Any] = {
        "signed_out_at": signed_out_at,
        "signed_out_by": officer_id,
        "updated_at": func.now(),
    }
    if scm_purchased is not None:
        values["scm_purchased"] = scm_purchased
    stmt = (
        update(TruckEntry)
        .where(TruckEntry.id == entry_id,
               TruckEntry.facility_id == facility_id,
               TruckEntry.signed_out_at.is_(None))
        .values(**values)
        .returning(TruckEntry.id)
        .execution_options(synchronize_session=False)
    )
    return db.execute(stmt).scalar_one_or_none() is not None


def get_entry(
    db: Session, entry_id: uuid.UUID, scope: uuid.UUID | None
) -> Any | None:
    stmt = _entry_select().where(TruckEntry.id == entry_id)
    if scope is not None:
        stmt = stmt.where(TruckEntry.facility_id == scope)
    return db.execute(stmt).first()


def get_signature(
    db: Session, entry_id: uuid.UUID, scope: uuid.UUID | None
) -> Any | None:
    """Row (bytes | None,) or None if the entry is not visible."""
    stmt = select(TruckEntry.signature_in).where(TruckEntry.id == entry_id)
    if scope is not None:
        stmt = stmt.where(TruckEntry.facility_id == scope)
    return db.execute(stmt).first()


def list_entries(
    db: Session, *, scope: uuid.UUID | None, facility_code: Optional[str],
    open_only: bool, plate: Optional[str], date_from: Optional[datetime],
    date_to: Optional[datetime], limit: int, offset: int,
) -> list[Any]:
    """scope=None means the caller sees every facility (CSO/admin); only then
    is facility_code honoured. date_to is exclusive."""
    stmt = _entry_select()
    if scope is not None:
        stmt = stmt.where(TruckEntry.facility_id == scope)
    elif facility_code:
        stmt = stmt.where(Facility.code == normalize_code(facility_code))
    if open_only:
        stmt = stmt.where(TruckEntry.signed_out_at.is_(None))
    if plate:
        needle = normalize_plate(plate)
        if needle:
            stmt = stmt.where(TruckEntry.plate_number.contains(needle))
    if date_from is not None:
        stmt = stmt.where(TruckEntry.signed_in_at >= date_from)
    if date_to is not None:
        stmt = stmt.where(TruckEntry.signed_in_at < date_to)
    stmt = (stmt.order_by(TruckEntry.signed_in_at.desc(), TruckEntry.id)
            .limit(limit).offset(offset))
    return list(db.execute(stmt).all())
