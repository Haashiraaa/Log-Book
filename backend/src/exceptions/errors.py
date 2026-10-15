
# backend/src/exceptions/errors.py

class TetracoreLogError(Exception):
    """Base class for all Tetracore Log errors."""


class EnvVariableError(TetracoreLogError):
    """Raised when an environment variable is missing or invalid."""
