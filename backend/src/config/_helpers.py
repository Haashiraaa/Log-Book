

# backend/src/config/_helpers.py

# pyright: reportUnusedFunction=false

from __future__ import annotations

import os
from importlib.util import find_spec

from backend.src.exceptions.errors import EnvVariableError


def _normalize_db_url(url: str | None) -> str | None:
    """Railway hands out postgres:// ; SQLAlchemy 2.x rejects that scheme.

    A bare postgresql:// makes SQLAlchemy import psycopg2. If only psycopg v3
    is installed (requirements.txt: psycopg[binary]) that crashes, so pick the
    driver that is actually present.
    """
    if not url:
        return url
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            rest = url[len(prefix):]
            if find_spec("psycopg") and not find_spec("psycopg2"):
                return "postgresql+psycopg://" + rest
            return "postgresql://" + rest
    return url


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise EnvVariableError(
            f"{name} must be an integer, got {raw!r}.") from exc
