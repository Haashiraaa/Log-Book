

# backend/src/api/schemas.py

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.src.db.orm.tables import Facility, Officer
from backend.src.models import Role, FACILITY_ROLES

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
