

# backend/src/api/schemas.py

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.src.db.orm._helpers import normalize_plate
from backend.src.db.orm.tables import Facility, Officer
from backend.src.models import FACILITY_ROLES, Role

# ---- helpers -----


def _require_tz(v: Optional[datetime]) -> Optional[datetime]:
    if v is not None and v.tzinfo is None:
        raise ValueError(
            "Timestamp must include a timezone offset, e.g. 2026-10-17T19:00:00+01:00")
    return v


# ---- dataclass models -----


@dataclass(frozen=True)
class CurrentOfficer:
    officer_id: uuid.UUID
    session_id: uuid.UUID
    facility_id: uuid.UUID | None
    role: Role
    is_admin: bool
    is_super_admin: bool
    must_change_pin: bool

    @property
    def sees_all_facilities(self) -> bool:
        return self.is_admin or self.role == Role.CSO


@dataclass(frozen=True)
class LoginResult:
    officer: Officer
    facility: Facility | None
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    session_id: uuid.UUID


@dataclass(frozen=True)
class RefreshResult:
    access_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


# ---- pydantic models: auth ----

class LoginRequest(BaseModel):
    # None/absent = global account (CSO or admin with no facility).
    facility_code: Optional[str] = Field(default=None, max_length=32)
    officer_code: str = Field(min_length=1, max_length=32)
    # Only a length cap here: the PIN *policy* applies to new PINs, not login.
    pin: str = Field(min_length=1, max_length=64)
    device_label: Optional[str] = Field(default=None, max_length=120)


class OfficerProfile(BaseModel):
    id: uuid.UUID
    officer_code: str
    full_name: str
    role: Role
    is_admin: bool
    is_super_admin: bool
    sees_all_facilities: bool
    must_change_pin: bool
    facility_id: uuid.UUID | None
    facility_code: str | None
    facility_name: str | None

    @classmethod
    def build(cls, officer: Officer, facility: Facility | None) -> OfficerProfile:
        return cls(
            id=officer.id,
            officer_code=officer.officer_code,
            full_name=officer.full_name,
            role=officer.role,
            is_admin=officer.is_admin,
            is_super_admin=officer.is_super_admin,
            sees_all_facilities=officer.sees_all_facilities,
            must_change_pin=officer.must_change_pin,
            facility_id=officer.facility_id,
            facility_code=facility.code if facility else None,
            facility_name=facility.name if facility else None,
        )


class LoginResponse(BaseModel):
    token_type: Literal["bearer"] = "bearer"
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    officer: OfficerProfile


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=256)


class RefreshResponse(BaseModel):
    token_type: Literal["bearer"] = "bearer"
    access_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=256)


class ChangePinRequest(BaseModel):
    current_pin: str = Field(min_length=1, max_length=64)
    # Policy (6-10 digits etc.) is enforced in the service -> weak_pin error.
    new_pin: str = Field(min_length=1, max_length=64)


# ---- pydantic models: admin ----

_CODE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9-]*$"


class CreateFacilityRequest(BaseModel):
    code: str = Field(min_length=2, max_length=32, pattern=_CODE_PATTERN)
    name: str = Field(min_length=2, max_length=200)


class FacilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    code: str
    name: str
    is_active: bool


class CreateOfficerRequest(BaseModel):
    facility_code: str = Field(min_length=2, max_length=32)
    full_name: str = Field(min_length=2, max_length=150)
    role: Role = Role.OFFICER

    @field_validator("role")
    @classmethod
    def _facility_role_only(cls, v: Role) -> Role:
        if v not in FACILITY_ROLES:
            raise ValueError(
                "Admins can only create facility officers or managers.")
        return v


class CreateOfficerResponse(BaseModel):
    officer: OfficerProfile
    # Shown ONCE. Only the hash is stored; it cannot be fetched again.
    temp_pin: str


class ResetPinResponse(BaseModel):
    officer_code: str
    full_name: str
    temp_pin: str


class AdminOfficerOut(OfficerProfile):
    is_active: bool

    @classmethod
    def from_row(cls, officer: Officer, facility: Facility | None) -> AdminOfficerOut:
        base = OfficerProfile.build(officer, facility)
        return cls(**base.model_dump(), is_active=officer.is_active)

# ---- super admin ----


class CreateAdminRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    role: Role
    facility_code: Optional[str] = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def _facility_matches_role(self) -> "CreateAdminRequest":
        needs = self.role in FACILITY_ROLES
        has = bool(self.facility_code and self.facility_code.strip())
        if needs and not has:
            raise ValueError("facility_code is required for this role.")
        if not needs and has:
            raise ValueError("This role is global; leave facility_code empty.")
        return self


class AdminSummary(OfficerProfile):
    is_active: bool

    @classmethod
    def from_officer(cls, officer: Officer, facility: Facility | None) -> "AdminSummary":
        base = OfficerProfile.build(officer, facility)
        return cls(**base.model_dump(), is_active=officer.is_active)


class TempPinResponse(BaseModel):
    officer: AdminSummary
    temp_pin: str  # shown ONCE. Hand it over in person.


# ----- trucks schema -----

class TruckLookupOut(BaseModel):
    truck_id: uuid.UUID
    plate_number: str
    driver_name: str
    driver_phone: Optional[str]
    company: Optional[str]
    # Set when this truck is currently inside (so the app can offer sign-out).
    open_entry_id: Optional[uuid.UUID]


class TruckSignInRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: uuid.UUID  # generated by the client; makes retries idempotent
    plate_number: str = Field(min_length=2, max_length=40)
    driver_name: str = Field(min_length=2, max_length=150)
    driver_phone: Optional[str] = Field(default=None, max_length=32)
    company: Optional[str] = Field(default=None, max_length=200)
    scm_purchased: Optional[Decimal] = Field(
        default=None, ge=0, max_digits=12, decimal_places=2)
    signed_in_at: Optional[datetime] = None  # default: server time
    signature: Optional[str] = Field(default=None, max_length=400_000)
    device_id: Optional[str] = Field(default=None, max_length=64)

    @field_validator("plate_number")
    @classmethod
    def _plate(cls, v: str) -> str:
        plate = normalize_plate(v)
        if not 2 <= len(plate) <= 20:
            raise ValueError("Plate number must be 2-20 letters/digits.")
        return plate

    @field_validator("driver_phone", "company", "device_id")
    @classmethod
    def _blank_to_none(cls, v: Optional[str]) -> Optional[str]:
        return v or None

    @field_validator("signed_in_at")
    @classmethod
    def _tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _require_tz(v)


class TruckSignOutRequest(BaseModel):
    signed_out_at: Optional[datetime] = None  # default: server time
    scm_purchased: Optional[Decimal] = Field(
        default=None, ge=0, max_digits=12, decimal_places=2)

    @field_validator("signed_out_at")
    @classmethod
    def _tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _require_tz(v)


class TruckEntryOut(BaseModel):
    id: uuid.UUID
    truck_id: uuid.UUID
    facility_id: uuid.UUID
    facility_code: str
    plate_number: str
    driver_name: str
    driver_phone: Optional[str]
    company: Optional[str]
    scm_purchased: Optional[Decimal]
    signed_in_at: datetime
    signed_out_at: Optional[datetime]
    signed_in_by: uuid.UUID
    signed_in_by_name: str
    signed_out_by: Optional[uuid.UUID]
    signed_out_by_name: Optional[str]
    device_id: Optional[str]
    has_signature: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row: Any) -> "TruckEntryOut":
        e, facility_code, has_signature, in_name, out_name = row
        return cls(
            id=e.id, truck_id=e.truck_id, facility_id=e.facility_id,
            facility_code=facility_code, plate_number=e.plate_number,
            driver_name=e.driver_name, driver_phone=e.driver_phone,
            company=e.company, scm_purchased=e.scm_purchased,
            signed_in_at=e.signed_in_at, signed_out_at=e.signed_out_at,
            signed_in_by=e.signed_in_by, signed_in_by_name=in_name,
            signed_out_by=e.signed_out_by, signed_out_by_name=out_name,
            device_id=e.device_id, has_signature=bool(has_signature),
            created_at=e.created_at, updated_at=e.updated_at,
        )
