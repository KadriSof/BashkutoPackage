"""Custom exceptions for bashkuto."""


class BashkutoError(Exception):
    """Base exception for all bashkuto errors."""
    pass


class SecurityError(BashkutoError):
    """Raised when a command fails security checks."""
    pass


class TimeoutError(BashkutoError):
    """Raised when a command exceeds the timeout limit."""
    pass


class BinaryOutputError(BashkutoError):
    """Raised when binary output is detected."""
    pass


class OverflowError(BashkutoError):
    """Raised when output overflow handling fails."""
    pass
