import re
from typing import List, Optional

from .exceptions import SecurityError


# Comprehensive blocked patterns for shell command security
# Used by both guards.py (runtime validation) and tool_registry.py (tool script validation)
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