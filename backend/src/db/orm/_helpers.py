

# backend/src/db/orm/_helpers.py

from __future__ import annotations
import re


def normalize_plate(raw: str) -> str:
    """'abc-123 xy' -> 'ABC123XY'. Typos in separators must not create
    duplicate truck records and break the 'returning truck' lookup."""
    return re.sub(r"[^A-Z0-9]", "", raw.upper())


def normalize_code(raw: str) -> str:
    """Facility / officer / staff codes are case-insensitive for typing."""
    return raw.strip().upper()
