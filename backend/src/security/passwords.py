

# backend/src/security/passwords.py

"""PIN hashing: HMAC-SHA256 with a server-side pepper, then argon2id.

Why the pepper: a 6-digit PIN has only 1,000,000 possibilities. If the DB
leaks, argon2 alone buys you hours, not safety. With the pepper kept OUT of
the database (env var), a dump by itself is useless.

argon2 is deliberately slow and CPU/memory heavy, so call these from plain
`def` route handlers (FastAPI runs those in a threadpool), never from
`async def` handlers, or one login blocks the whole event loop.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from backend.src.config.settings import Settings

PIN_MIN_LENGTH = 6
PIN_MAX_LENGTH = 10

_hasher = PasswordHasher()  # argon2id, argon2-cffi's RFC 9106 low-memory defaults


def _prehash(pin: str) -> str:
    pepper = Settings.require_pin_pepper().encode()
    return hmac.new(pepper, pin.encode(), hashlib.sha256).hexdigest()


def validate_pin_policy(pin: str) -> None:
    """Policy for NEW PINs only (login accepts anything and just fails).
    Raises ValueError with a human-readable reason."""
    if not pin.isascii() or not pin.isdigit():
        raise ValueError("PIN must contain digits only.")
    if not (PIN_MIN_LENGTH <= len(pin) <= PIN_MAX_LENGTH):
        raise ValueError(
            f"PIN must be {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits long.")
    if len(set(pin)) == 1:
        raise ValueError("PIN cannot be a single repeated digit.")
    digits = [int(c) for c in pin]
    steps = {b - a for a, b in zip(digits, digits[1:], strict=False)}
    if steps in ({1}, {-1}):
        raise ValueError("PIN cannot be a straight run like 123456.")


def generate_temp_pin(length: int = 6) -> str:
    """Random numeric PIN that passes validate_pin_policy."""
    while True:
        pin = "".join(secrets.choice("0123456789") for _ in range(length))
        try:
            validate_pin_policy(pin)
        except ValueError:
            continue
        return pin


def hash_pin(pin: str) -> str:
    return _hasher.hash(_prehash(pin))


def verify_pin(pin: str, pin_hash: str) -> bool:
    try:
        return _hasher.verify(pin_hash, _prehash(pin))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(pin_hash: str) -> bool:
    """True when argon2 parameters were raised since this hash was made."""
    return _hasher.check_needs_rehash(pin_hash)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash("tetracore-dummy-pin")


def burn_verify_time(pin: str) -> None:
    """Run a real argon2 verify against a throwaway hash.

    Called when the officer does not exist, so 'no such officer' and 'wrong PIN'
    take the same time and login can't be used to enumerate officer codes.
    """
    verify_pin(pin, _dummy_hash())
