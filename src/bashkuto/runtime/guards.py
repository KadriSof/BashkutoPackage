"""Security guards for Bashkuto - DEPRECATED.

This module is deprecated. Use bashkuto.security.Paragon instead.

Example migration:
    # Old (deprecated):
    from bashkuto.runtime.guards import check_command
    check_command(command)

    # New (recommended):
    from bashkuto.security import Paragon
    paragon = Paragon()
    paragon.check_command(command)
"""

import re
import warnings
from typing import List, Optional

from .exceptions import SecurityError

# Import Paragon for delegation (lazy import to avoid circular dependency)
_Paragon = None


def _get_paragon_class():
    """Lazy import of Paragon to avoid circular dependency."""
    global _Paragon
    if _Paragon is None:
        try:
            from ..security.paragon import Paragon as _P
            _Paragon = _P
        except ImportError:
            _Paragon = None
    return _Paragon


def _emit_deprecation_warning(old_name: str, new_name: str) -> None:
    """Emit a deprecation warning for migrated APIs."""
    warnings.warn(
        f"{old_name} is deprecated and will be removed in a future version. "
        f"Use {new_name} instead.",
        DeprecationWarning,
        stacklevel=3,
    )


# Comprehensive blocked patterns for shell command security
# Used by both guards.py (runtime validation) and tool_registry.py (tool script validation)
# Note: These constants are deprecated. Use Paragon with custom patterns instead.
BLOCKED_PATTERNS = [
    # Root directory deletion
    r"rm\s+(-[rf]+\s+)*(/\s*$|/home|/etc|/usr|/var|/root)",
    r"rm\s+-rf\s+/",
    r"rm\s+-fr\s+/",
    r"rm\s+-rf\s+\*",          # Current directory wipe
    # Home directory deletion
    r"rm\s+(-[rf]+\s+)*~",
    # Dangerous permissions
    r"chmod\s+(-R\s+)?777\s+/",
    # Disk overwriting
    r">\s*/dev/sd[a-z]",
    r"echo\s+.*>\s*/dev/sd[a-z]",
    r"dd\s+.*of=/dev/sd[a-z]",
    r"dd\s+.*of=/dev/",        # Low-level disk writing (broader)
    # System control
    r"\b(shutdown|reboot|poweroff|halt)\b",
    r"shutdown\s+(-h)?\s+now", # Immediate shutdown (legacy)
    r"reboot\s*(-f)?",         # Force reboot (legacy)
    # Remote code execution
    r"curl\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\|\s*(ba)?sh",
    r"curl\s+.*\|\s*bash",
    r"wget\s+.*\|\s*bash",
    r"wget\s+.*-O-.*\|\s*(ba)?sh",  # wget pipe to shell (legacy)
    # Fork bomb
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;",
    r":(){ :|:& };:",  # Fork bomb (legacy substring-style)
    # Filesystem destruction
    r"mkfs",
    r"mkfs\.",                 # Filesystem creation (legacy)
    r"fdisk.*-y",
    r"parted.*mklabel",
]

# Simple substring checks for quick validation (runtime)
# Note: BLOCKED_SUBSTRINGS is deprecated. Use Paragon with custom substrings instead.
BLOCKED_SUBSTRINGS = [
    "rm -rf",
    ":(){ :|:& };:",  # Fork bomb
]


def check_command(
    command: str,
    blocked_substrings: Optional[List[str]] = None,
    blocked_patterns: Optional[List[str]] = None
) -> None:
    """
    Check command against security rules.

    DEPRECATED: Use Paragon.check_command() instead.

    This function delegates to Paragon for backward compatibility.
    New code should use:
        from bashkuto.security import Paragon
        paragon = Paragon()
        paragon.check_command(command)

    Args:
        command: Command string to validate
        blocked_substrings: List of forbidden substrings
        blocked_patterns: List of forbidden regex patterns

    Raises:
        SecurityError: If command matches a blocked pattern
    """
    _emit_deprecation_warning(
        "guards.check_command()",
        "Paragon.check_command()"
    )

    # Use Paragon internally for consistent validation
    ParagonClass = _get_paragon_class()
    if ParagonClass is not None:
        # Create a temporary Paragon instance with the provided parameters
        paragon = ParagonClass(
            blocked_substrings=blocked_substrings,
            blocked_patterns=blocked_patterns,
        )
        paragon.check_command(command)
    else:
        # Fallback to original implementation if Paragon not available
        _check_command_legacy(command, blocked_substrings, blocked_patterns)


def _check_command_legacy(
    command: str,
    blocked_substrings: Optional[List[str]] = None,
    blocked_patterns: Optional[List[str]] = None
) -> None:
    """
    Legacy implementation of check_command (fallback if Paragon unavailable).

    This is the original implementation before Paragon was introduced.
    """
    substrings = blocked_substrings or BLOCKED_SUBSTRINGS
    patterns = blocked_patterns or BLOCKED_PATTERNS

    # Check substring matches
    for substring in substrings:
        if substring in command:
            raise SecurityError(f"Blocked command detected: '{substring}'")

    # Check regex patterns
    for pattern in patterns:
        if re.search(pattern, command):
            raise SecurityError(f"Command matches blocked pattern: '{pattern}'")