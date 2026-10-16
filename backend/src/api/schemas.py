

# backend/src/api/schemas.py


from __future__ import annotations
from backend.src.db.orm.tables import Facility, Officer
from pydantic import BaseModel, Field
from datetime import datetime

import uuid
from dataclasses import dataclass
from backend.src.models import Role
from typing import Literal, Optional

# ---- enum models ----

# ---- dataclass models -----


@dataclass(frozen=True)
class CurrentOfficer:
    officer_id: uuid.UUID
    session_id: uuid.UUID
    facility_id: uuid.UUID | None
    role: Role
    is_admin: bool

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


# ---- pydantic models ----

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
    sees_all_facilities: bool
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
            sees_all_facilities=officer.sees_all_facilities,
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
