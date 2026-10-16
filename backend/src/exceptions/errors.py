
# backend/src/exceptions/errors.py

from __future__ import annotations


class TetracoreLogError(Exception):
    """Base class for all Tetracore Log errors."""


class EnvVariableError(TetracoreLogError):
    """Raised when an environment variable is missing or invalid."""


# --------------------------------------------------------------------------
# Auth errors. Each carries a machine-readable `code` the phone app can switch
# on (e.g. refresh on token_expired, force re-login on session_revoked).
# The HTTP status mapping lives in the api layer, not here.
# --------------------------------------------------------------------------


class AuthError(TetracoreLogError):
    code = "auth_error"
    message = "Authentication failed."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.message
        super().__init__(self.message)


class InvalidCredentialsError(AuthError):
    """Wrong facility / officer / PIN. Deliberately one message for all three."""
    code = "invalid_credentials"
    message = "Invalid facility code, officer code or PIN."


class AccountLockedError(AuthError):
    code = "account_locked"
    message = "Too many failed attempts. Try again later."

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__()


class TokenExpiredError(AuthError):
    """Access token expired: the client should call /auth/refresh."""
    code = "token_expired"
    message = "Access token expired."


class InvalidTokenError(AuthError):
    code = "invalid_token"
    message = "Invalid or missing token."


class SessionRevokedError(AuthError):
    """Session revoked/expired or officer disabled: the client must log in again."""
    code = "session_revoked"
    message = "Session is no longer valid. Please log in again."


class PermissionDeniedError(AuthError):
    code = "forbidden"
    message = "You do not have permission to do that."
