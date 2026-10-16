

# backend/src/db/orm/_helpers.py

# pyright: reportUnusedFunction=false

from __future__ import annotations
import re
from enum import Enum


def normalize_plate(raw: str) -> str:
    """'abc-123 xy' -> 'ABC123XY'. Typos in separators must not create
    duplicate truck records and break the 'returning truck' lookup."""
    return re.sub(r"[^A-Z0-9]", "", raw.upper())


def normalize_code(raw: str) -> str:
    """Facility / officer / staff codes are case-insensitive for typing."""
    return raw.strip().upper()


def enum_values(enum_cls: type[Enum]) -> list[str]:
    """Store the enum VALUES ('officer'), not the member NAMES ('OFFICER')."""
    return [member.value for member in enum_cls]
