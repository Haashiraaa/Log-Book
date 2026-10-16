

# backend/src/models.py


"""Shared enums (and, later, shared pydantic models).

Rules:
* Enums used by BOTH the DB tables and the API live here: one source of truth.
* Route-specific request/response schemas live in the api package, not here.
* Keep this file free of imports from backend.src.db and backend.src.api,
  so both layers can import it without circular imports.

`is_admin` is deliberately NOT a Role. It is an additive flag on the officers
table (see tables.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from dataclasses import dataclass


# ---- enum models ----

class Role(str, Enum):
    """`str` mixin so values compare equal to plain strings and serialize
    to JSON as 'officer' / 'cso' without extra work."""

    OFFICER = "officer"
    CSO = "cso"


# ----- dataclass models -----
@dataclass(frozen=True)
class AccessClaims:
    officer_id: uuid.UUID
    session_id: uuid.UUID
    expires_at: datetime
