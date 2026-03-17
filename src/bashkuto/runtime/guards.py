import re
from typing import List, Optional

from .exceptions import SecurityError


BLOCKED_SUBSTRINGS = [
    "rm -rf",
    ":(){ :|:& };:",  # Fork bomb
]

BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/",           # Root directory deletion
    r"rm\s+-rf\s+\*",          # Current directory wipe
    r"chmod\s+-R\s+777\s+/",   # Dangerous permissions on root
    r">\s*/dev/sd[a-z]",       # Disk overwriting
    r"mkfs\.",                 # Filesystem creation
    r"dd\s+.*of=/dev/",        # Low-level disk writing
    r"shutdown\s+(-h)?\s+now", # Immediate shutdown
    r"reboot\s*(-f)?",         # Force reboot
    r"curl.*\|\s*(ba)?sh",     # Pipe remote script to shell
    r"wget.*-O-.*\|\s*(ba)?sh",# wget pipe to shell
]


def check_command(
    command: str,
    blocked_substrings: Optional[List[str]] = None,
    blocked_patterns: Optional[List[str]] = None
) -> None:
    """
    Check command against security rules.

    Args:
        command: Command string to validate
        blocked_substrings: List of forbidden substrings
        blocked_patterns: List of forbidden regex patterns

    Raises:
        SecurityError: If command matches a blocked pattern
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