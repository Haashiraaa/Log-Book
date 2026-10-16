

# backend/src/security/tokens.py

"""Access tokens (short-lived JWT) and refresh tokens (opaque, DB-backed).

The access token carries ONLY identity: officer id + session id. Role,
is_admin, is_active and facility are re-read from the DB on every request
(see api/deps.py), so promoting, disabling or revoking takes effect on the very
next request instead of after the token expires.

Refresh tokens are 256-bit random strings. We store only their SHA-256, and
plain SHA-256 is correct here (unlike PINs): the input is high-entropy, so
there is nothing to brute-force.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from backend.src.config.settings import Settings
from backend.src.models import AccessClaims
from backend.src.exceptions.errors import InvalidTokenError, TokenExpiredError

_ACCESS_TYPE = "access"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(
    officer_id: uuid.UUID, session_id: uuid.UUID, now: datetime | None = None
) -> tuple[str, datetime]:
    now = now or utcnow()
    expires_at = now + timedelta(minutes=Settings.ACCESS_TOKEN_MINUTES)
    payload = {
        "iss": Settings.JWT_ISSUER,
        "typ": _ACCESS_TYPE,
        "sub": str(officer_id),
        "sid": str(session_id),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(
        payload, Settings.require_jwt_secret(), algorithm=Settings.JWT_ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> AccessClaims:
    try:
        payload = jwt.decode(
            token,
            Settings.require_jwt_secret(),
            # pin the alg: never trust the header
            algorithms=[Settings.JWT_ALGORITHM],
            issuer=Settings.JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "sid", "iss"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except jwt.PyJWTError as exc:
        raise InvalidTokenError() from exc

    if payload.get("typ") != _ACCESS_TYPE:
        raise InvalidTokenError()
    try:
        return AccessClaims(
            officer_id=uuid.UUID(payload["sub"]),
            session_id=uuid.UUID(payload["sid"]),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        )
    except (ValueError, TypeError) as exc:
        raise InvalidTokenError() from exc


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
