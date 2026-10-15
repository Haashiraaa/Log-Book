

# backend/src/db/orm/_mixins.py

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    Uuid,
    func
)
from sqlalchemy.orm import Mapped, mapped_column


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
