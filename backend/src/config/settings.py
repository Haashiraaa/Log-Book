
# backend/src/config/settings.py

import os
from dotenv import load_dotenv
from backend.src.exceptions.errors import EnvVariableError

load_dotenv()


class Settings:

    DATABASE_URL = os.getenv('DATABASE_URL')

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
