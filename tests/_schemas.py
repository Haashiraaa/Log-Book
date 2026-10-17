

# tests/_schemas.py

from __future__ import annotations

import uuid
from typing import NamedTuple, Optional


class Actor(NamedTuple):
    id: uuid.UUID
    code: str
    facility: Optional[str]
    headers: dict[str, str]
