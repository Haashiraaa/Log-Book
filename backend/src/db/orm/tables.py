"""
Gate-log database models (SQLAlchemy 2.0 style, PostgreSQL).

Design rules baked in here:

* Every row that belongs to a station carries `facility_id`. The API must set it
  from the logged-in officer's token, NEVER from the request body.
* Entry tables (truck / visitor / staff) use UUID primary keys that the PHONE
  generates, so offline records can never collide and a retried sync push is
  an idempotent upsert, not a duplicate.
* `signed_in_at` / `signed_out_at` are the real-world event times (from the
  phone). `created_at` / `updated_at` are SERVER times and drive sync pulls.
* All timestamps are timezone-aware and stored in UTC. Convert to Lagos time
  (UTC+1) only for display.
* Entries are never deleted. A security log that can lose rows is not a log.
"""

import re
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates

# --------------------------------------------------------------------------
# Base + naming convention (keeps Alembic migrations stable and diffable)
# --------------------------------------------------------------------------

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

ROLE_OFFICER = "officer"
ROLE_CSO = "cso"


def normalize_plate(raw: str) -> str:
    """'abc-123 xy' -> 'ABC123XY'. Typos in separators must not create
    duplicate truck records and break the 'returning truck' lookup."""
    return re.sub(r"[^A-Z0-9]", "", raw.upper())


def normalize_code(raw: str) -> str:
    """Facility / officer / staff codes are case-insensitive for typing."""
    return raw.strip().upper()


# --------------------------------------------------------------------------
# Mixins
# --------------------------------------------------------------------------


class TimestampMixin:
    """Server-side timestamps. `updated_at` is what /sync/pull filters on.

    NOTE: when you upsert with `insert(...).on_conflict_do_update(...)`, set
    `updated_at=func.now()` explicitly in the `set_` dict. Core upserts do not
    reliably trigger the ORM-level `onupdate`.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class EntryMixin:
    """Columns shared by every sign-in / sign-out record.

    No CHECK that signed_out_at >= signed_in_at on purpose: phones working
    offline can have wrong clocks, and rejecting a record at sync time would
    block the guard's whole queue. Validate softly in the app and flag odd
    rows in reports instead.
    """

    facility_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("facilities.id", ondelete="RESTRICT"), nullable=False
    )
    signed_in_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    signed_out_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # PNG bytes. deferred=True so list queries don't drag blobs around.
    signature_in: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True, deferred=True
    )
    signed_in_by: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("officers.id", ondelete="RESTRICT"), nullable=False
    )
    signed_out_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("officers.id", ondelete="RESTRICT"), nullable=True
    )
    device_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


# --------------------------------------------------------------------------
# Facilities, officers, sessions
# --------------------------------------------------------------------------


class Facility(TimestampMixin, Base):
    __tablename__ = "facilities"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g. CNG-BEN-01
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        default=True, server_default=text("true"), nullable=False
    )

    __table_args__ = (UniqueConstraint("code", name="uq_facilities_code"),)

    @validates("code")
    def _normalize_code(self, _key: str, value: str) -> str:
        return normalize_code(value)


class Officer(TimestampMixin, Base):
    """A security officer, or the CSO.

    Login = (facility.code, officer_code, PIN). The pair (facility_id,
    officer_code) is unique, so an officer code only means something inside
    its own facility. The CSO has facility_id NULL and role 'cso'.
    """

    __tablename__ = "officers"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    facility_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("facilities.id", ondelete="RESTRICT"), nullable=True
    )
    officer_code: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g. OFF-014
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    pin_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(16), default=ROLE_OFFICER, server_default=ROLE_OFFICER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        default=True, server_default=text("true"), nullable=False
    )
    failed_pin_attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default=text("0"), nullable=False
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "facility_id", "officer_code", name="uq_officers_facility_id_officer_code"
        ),
        # NULL facility_id rows (the CSO) are "distinct" to Postgres, so the
        # constraint above does not protect them. This partial index does.
        Index(
            "uq_officers_cso_officer_code",
            "officer_code",
            unique=True,
            postgresql_where=text("facility_id IS NULL"),
        ),
        CheckConstraint("role IN ('officer', 'cso')", name="role_valid"),
        CheckConstraint(
            "role = 'cso' OR facility_id IS NOT NULL", name="officer_has_facility"
        ),
    )

    @validates("officer_code")
    def _normalize_code(self, _key: str, value: str) -> str:
        return normalize_code(value)


class OfficerSession(Base):
    """One row per logged-in phone. Store only a HASH of the refresh token.
    Revoking a lost phone = set revoked_at."""

    __tablename__ = "officer_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    officer_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("officers.id", ondelete="CASCADE"), nullable=False
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    device_label: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "refresh_token_hash", name="uq_officer_sessions_refresh_token_hash"
        ),
        Index("ix_officer_sessions_officer_id", "officer_id"),
    )


# --------------------------------------------------------------------------
# Trucks
# --------------------------------------------------------------------------


class Truck(TimestampMixin, Base):
    """Registry of trucks per facility. A returning truck is looked up by
    plate and the guard only CONFIRMS the stored driver details."""

    __tablename__ = "trucks"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    facility_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("facilities.id", ondelete="RESTRICT"), nullable=False
    )
    plate_number: Mapped[str] = mapped_column(String(20), nullable=False)  # normalized
    driver_name: Mapped[str] = mapped_column(String(150), nullable=False)
    driver_phone: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    company: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "facility_id", "plate_number", name="uq_trucks_facility_id_plate_number"
        ),
    )

    @validates("plate_number")
    def _normalize_plate(self, _key: str, value: str) -> str:
        return normalize_plate(value)


class TruckEntry(EntryMixin, TimestampMixin, Base):
    """One visit. Driver/plate/company are SNAPSHOTS: if the registry record
    changes later, the historical log must not."""

    __tablename__ = "truck_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )  # supplied by the phone
    truck_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("trucks.id", ondelete="RESTRICT"), nullable=False
    )
    plate_number: Mapped[str] = mapped_column(String(20), nullable=False)
    driver_name: Mapped[str] = mapped_column(String(150), nullable=False)
    driver_phone: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    company: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    scm_purchased: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(12, 2), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "scm_purchased IS NULL OR scm_purchased >= 0", name="scm_non_negative"
        ),
        Index("ix_truck_entries_facility_signed_in", "facility_id", "signed_in_at"),
        Index("ix_truck_entries_facility_updated", "facility_id", "updated_at"),
        Index("ix_truck_entries_facility_plate", "facility_id", "plate_number"),
        # "Trucks currently inside" stays fast however big the table gets.
        Index(
            "ix_truck_entries_open",
            "facility_id",
            postgresql_where=text("signed_out_at IS NULL"),
        ),
    )

    @validates("plate_number")
    def _normalize_plate(self, _key: str, value: str) -> str:
        return normalize_plate(value)


# --------------------------------------------------------------------------
# Visitors (no registry: visitors rarely repeat, so entries only)
# --------------------------------------------------------------------------


class VisitorEntry(EntryMixin, TimestampMixin, Base):
    __tablename__ = "visitor_entries"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    phone: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    purpose: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    person_visited: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    id_type: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    id_number: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_visitor_entries_facility_signed_in", "facility_id", "signed_in_at"),
        Index("ix_visitor_entries_facility_updated", "facility_id", "updated_at"),
        Index(
            "ix_visitor_entries_open",
            "facility_id",
            postgresql_where=text("signed_out_at IS NULL"),
        ),
    )


# --------------------------------------------------------------------------
# Staff
# --------------------------------------------------------------------------


class Staff(TimestampMixin, Base):
    __tablename__ = "staff"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    facility_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("facilities.id", ondelete="RESTRICT"), nullable=False
    )
    staff_code: Mapped[str] = mapped_column(String(32), nullable=False)
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        default=True, server_default=text("true"), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "facility_id", "staff_code", name="uq_staff_facility_id_staff_code"
        ),
    )

    @validates("staff_code")
    def _normalize_code(self, _key: str, value: str) -> str:
        return normalize_code(value)


class StaffEntry(EntryMixin, TimestampMixin, Base):
    __tablename__ = "staff_entries"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    staff_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staff.id", ondelete="RESTRICT"), nullable=False
    )

    __table_args__ = (
        Index("ix_staff_entries_facility_signed_in", "facility_id", "signed_in_at"),
        Index("ix_staff_entries_facility_updated", "facility_id", "updated_at"),
        Index(
            "ix_staff_entries_open",
            "facility_id",
            postgresql_where=text("signed_out_at IS NULL"),
        ),
    )

