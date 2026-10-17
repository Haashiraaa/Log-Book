

# backend/src/config/settings.py

# pyright: reportPrivateUsage=false

from __future__ import annotations

import os

from dotenv import load_dotenv

from backend.src.config._helpers import _int_env, _normalize_db_url
from backend.src.exceptions.errors import EnvVariableError

load_dotenv()


class Settings:

    DATABASE_URL = _normalize_db_url(os.getenv('DATABASE_URL'))

    CORS_ORIGINS = tuple(
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
        if o.strip()
    )

    # --- auth ---
    JWT_SECRET = os.getenv('JWT_SECRET')
    PIN_PEPPER = os.getenv('PIN_PEPPER')
    JWT_ALGORITHM = "HS256"
    JWT_ISSUER = os.getenv('JWT_ISSUER', 'tetracore-log')
    ACCESS_TOKEN_MINUTES = _int_env('ACCESS_TOKEN_MINUTES', 15)
    REFRESH_TOKEN_DAYS = _int_env('REFRESH_TOKEN_DAYS', 30)
    MAX_PIN_ATTEMPTS = _int_env('MAX_PIN_ATTEMPTS', 5)
    LOCKOUT_MINUTES = _int_env('LOCKOUT_MINUTES', 15)

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

    @classmethod
    def require_jwt_secret(cls) -> str:
        value = cls._require('JWT_SECRET')
        if len(value) < 32:
            raise EnvVariableError(
                "JWT_SECRET must be at least 32 characters. Generate one with: "
                "python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
        return value

    @classmethod
    def require_pin_pepper(cls) -> str:
        value = cls._require('PIN_PEPPER')
        if len(value) < 32:
            raise EnvVariableError(
                "PIN_PEPPER must be at least 32 characters.")
        return value
