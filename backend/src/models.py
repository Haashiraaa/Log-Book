
# backend/src/models.py

"""Shared enums (and, later, shared pydantic models).

Rules:
* Enums used by BOTH the DB tables and the API live here: one source of truth.
* Route-specific request/response schemas live in the api package, not here.
* Keep this file free of imports from backend.src.db and backend.src.api.

`is_admin` / `is_super_admin` are deliberately NOT roles. They are additive
power flags on the officers table. Roles describe the field job; flags describe
account-management powers.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Role(str, Enum):
    OFFICER = "officer"                    # reads + writes, own facility
    FACILITY_MANAGER = "facility_manager"  # reads, own facility
    CSO = "cso"                            # reads all facilities, read-only


# Facility roles MUST have a facility_id. Global roles have none.
FACILITY_ROLES: frozenset[Role] = frozenset(
    {Role.OFFICER, Role.FACILITY_MANAGER})
GLOBAL_ROLES: frozenset[Role] = frozenset({Role.CSO})

# Auto-issued account codes: PREFIX-001, PREFIX-002 ...
CODE_PREFIX: dict[Role, str] = {
    Role.OFFICER: "OFF",
    Role.FACILITY_MANAGER: "MGR",
    Role.CSO: "CSO",
}

# Fails at import time if someone adds a Role and forgets to classify it.
assert FACILITY_ROLES | GLOBAL_ROLES == set(Role)
assert not (FACILITY_ROLES & GLOBAL_ROLES)
assert set(CODE_PREFIX) == set(Role)


@dataclass(frozen=True)
class AccessClaims:
    officer_id: uuid.UUID
    session_id: uuid.UUID
    expires_at: datetime
