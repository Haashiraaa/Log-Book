
# backend/src/config/settings.py

from __future__ import annotations

import os
from dotenv import load_dotenv
from backend.src.exceptions.errors import EnvVariableError

load_dotenv()


def _normalize_db_url(url: str | None) -> str | None:
    """Railway/Heroku hand out postgres:// ; SQLAlchemy 2.x rejects that scheme."""
    if url and url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


class Settings:

    DATABASE_URL = _normalize_db_url(os.getenv('DATABASE_URL'))

    @classmethod
    def _require(cls, name: str) -> str:
        value = getattr(cls, name)
        if not value:
            raise EnvVariableError(
                f"Missing or invalid {name}! Check your .env file.")
        return value

    @classmethod
    def require_database(cls) -> str:
        return cls._require('DATABASE_URL')
