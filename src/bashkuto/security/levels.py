"""Security level configurations for Paragon.

Defines which validation rules are active at each security level.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Type


class SecurityLevel(Enum):
    """Security policy levels for Paragon validation.

    Attributes:
        PERMISSIVE: Minimal security. Only blocks the most dangerous operations.
            Suitable for trusted environments with sandboxed execution.
        BALANCED: Default security level. Blocks known dangerous patterns.
            Recommended for most AI agent workflows.
        STRICT: Maximum security. Aggressively blocks potentially dangerous operations.
            Suitable for untrusted code execution or high-security environments.
    """
    PERMISSIVE = "permissive"
    BALANCED = "balanced"
    STRICT = "strict"


@dataclass
class SecurityLevelConfig:
    """Configuration for a security level.

    Attributes:
        level: The security level this config applies to.
        description: Human-readable description of the security level.
        blocked_substrings: Substrings that are always blocked.
        blocked_patterns: Regex patterns that are always blocked.
        dangerous_commands: Commands that are blocked when used with variables.
        injection_patterns: Code injection patterns to block.
        allow_network: Whether network commands (curl, wget, ssh) are allowed.
        allow_filesystem: Whether filesystem commands (rm, chmod) are allowed.
        allow_system_control: Whether system control (reboot, shutdown) is allowed.
        require_allowlist: Whether an explicit allowlist is required.
        additional_rules: Additional rule classes to apply at this level.
    """
    level: SecurityLevel
    description: str
    blocked_substrings: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    dangerous_commands: List[str] = field(default_factory=list)
    injection_patterns: List[tuple] = field(default_factory=list)
    allow_network: bool = True
    allow_filesystem: bool = True
    allow_system_control: bool = False
    require_allowlist: bool = False
    additional_rules: List[Type] = field(default_factory=list)


# Default injection patterns (used by all levels)
DEFAULT_INJECTION_PATTERNS = [
    (r'\beval\b.*\$', "eval with variable expansion"),
    (r'\bexec\b.*\$', "exec with variable expansion"),
    (r'\bbash\s+(-[a-zA-Z]+\s+)*["\']?\$', "bash with variable (script injection)"),
    (r'\bsh\s+(-[a-zA-Z]+\s+)*["\']?\$', "sh with variable (script injection)"),
    (r'\bsource\b.*\$', "source with variable expansion"),
    (r'\.\s+["\']?\$', "dot-source with variable expansion"),
]

# Default blocked patterns (core dangerous operations)
DEFAULT_BLOCKED_PATTERNS = [
    # Root directory deletion
    r"rm\s+(-[rf]+\s+)*(/\s*$|/home|/etc|/usr|/var|/root)",
    r"rm\s+-rf\s+/",
    r"rm\s+-fr\s+/",
    r"rm\s+-rf\s+\*",
    # Home directory deletion
    r"rm\s+(-[rf]+\s+)*~",
    # Dangerous permissions
    r"chmod\s+(-R\s+)?777\s+/",
    # Disk overwriting
    r">\s*/dev/sd[a-z]",
    r"echo\s+.*>\s*/dev/sd[a-z]",
    r"dd\s+.*of=/dev/sd[a-z]",
    r"dd\s+.*of=/dev/",
    # System control
    r"\b(shutdown|reboot|poweroff|halt)\b",
    r"shutdown\s+(-h)?\s+now",
    r"reboot\s*(-f)?",
    # Remote code execution
    r"curl\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\|\s*(ba)?sh",
    r"curl\s+.*\|\s*bash",
    r"wget\s+.*\|\s*bash",
    r"wget\s+.*-O-.*\|\s*(ba)?sh",
    # Fork bomb
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;",
    r":(){ :|:& };:",
    # Filesystem destruction
    r"mkfs",
    r"mkfs\.",
    r"fdisk.*-y",
    r"parted.*mklabel",
]

# Default blocked substrings
DEFAULT_BLOCKED_SUBSTRINGS = [
    "rm -rf",
    ":(){ :|:& };:",
]


# PERMISSIVE level configuration
# Minimal security - only blocks the absolute most dangerous operations
PERMISSIVE_CONFIG = SecurityLevelConfig(
    level=SecurityLevel.PERMISSIVE,
    description=(
        "Permissive security level. Only blocks the most dangerous operations "
        "like root directory deletion, fork bombs, and disk overwriting. "
        "Suitable for trusted environments with sandboxed execution."
    ),
    blocked_substrings=[
        ":(){ :|:& };:",  # Fork bomb
    ],
    blocked_patterns=[
        r"rm\s+-rf\s+/",  # Root deletion only
        r"dd\s+.*of=/dev/sd[a-z]",  # Disk overwrite
        r">\s*/dev/sd[a-z]",
        r":\(\)\s*\{\s*:\|:&\s*\}\s*;",  # Fork bomb
    ],
    dangerous_commands=[
        "dd", "mkfs", "fdisk", "parted",  # Disk operations only
    ],
    injection_patterns=DEFAULT_INJECTION_PATTERNS,
    allow_network=True,
    allow_filesystem=True,
    allow_system_control=False,
    require_allowlist=False,
)


# BALANCED level configuration (default)
# Blocks known dangerous patterns while allowing normal Unix workflows
BALANCED_CONFIG = SecurityLevelConfig(
    level=SecurityLevel.BALANCED,
    description=(
        "Balanced security level (default). Blocks known dangerous patterns "
        "including system directory deletion, dangerous permissions, remote code "
        "execution, and system control commands. Recommended for most AI agent workflows."
    ),
    blocked_substrings=DEFAULT_BLOCKED_SUBSTRINGS,
    blocked_patterns=DEFAULT_BLOCKED_PATTERNS,
    dangerous_commands=[
        "rm", "chmod", "chown", "dd", "mkfs", "fdisk", "parted",
        "shutdown", "reboot", "poweroff", "halt",
    ],
    injection_patterns=DEFAULT_INJECTION_PATTERNS,
    allow_network=True,  # curl, wget allowed (but not piped to shell)
    allow_filesystem=True,  # rm, chmod allowed (but not with variables on dangerous paths)
    allow_system_control=False,
    require_allowlist=False,
)


# STRICT level configuration
# Maximum security - aggressively blocks potentially dangerous operations
STRICT_CONFIG = SecurityLevelConfig(
    level=SecurityLevel.STRICT,
    description=(
        "Strict security level. Aggressively blocks potentially dangerous operations "
        "including all network commands, filesystem modification with variables, "
        "and code injection patterns. Suitable for untrusted code execution or "
        "high-security environments."
    ),
    blocked_substrings=DEFAULT_BLOCKED_SUBSTRINGS + [
        "curl", "wget",  # Block network commands entirely
        "ssh", "scp", "rsync",  # Block remote access
    ],
    blocked_patterns=DEFAULT_BLOCKED_PATTERNS + [
        # Block any network commands
        r"\b(curl|wget|ssh|scp|rsync)\b",
        # Block any rm with variables
        r"\brm\s+.*\$",
        # Block any chmod with variables
        r"\bchmod\s+.*\$",
    ],
    dangerous_commands=[
        "rm", "chmod", "chown", "dd", "mkfs", "fdisk", "parted",
        "shutdown", "reboot", "poweroff", "halt",
        "curl", "wget", "nc", "netcat", "ssh", "scp", "rsync",
    ],
    injection_patterns=DEFAULT_INJECTION_PATTERNS + [
        (r'\bcurl\b', "curl command (network access)"),
        (r'\bwget\b', "wget command (network access)"),
        (r'\bssh\b', "ssh command (remote access)"),
        (r'\bnc\s', "netcat command (network access)"),
        (r'\bnetcat\b', "netcat command (network access)"),
    ],
    allow_network=False,
    allow_filesystem=False,  # Block filesystem commands with variables
    allow_system_control=False,
    require_allowlist=True,  # Require explicit allowlist
)


# Security level configuration registry
SECURITY_LEVEL_CONFIGS: Dict[SecurityLevel, SecurityLevelConfig] = {
    SecurityLevel.PERMISSIVE: PERMISSIVE_CONFIG,
    SecurityLevel.BALANCED: BALANCED_CONFIG,
    SecurityLevel.STRICT: STRICT_CONFIG,
}


def get_security_config(level: SecurityLevel) -> SecurityLevelConfig:
    """Get the configuration for a security level.

    Args:
        level: The security level to get configuration for.

    Returns:
        SecurityLevelConfig for the specified level.
    """
    return SECURITY_LEVEL_CONFIGS[level]


def get_all_security_levels() -> List[SecurityLevel]:
    """Get all available security levels.

    Returns:
        List of all SecurityLevel values.
    """
    return list(SecurityLevel)


def describe_security_level(level: SecurityLevel) -> str:
    """Get a human-readable description of a security level.

    Args:
        level: The security level to describe.

    Returns:
        Human-readable description string.
    """
    config = get_security_config(level)
    return (
        f"{level.value.upper()} Security Level\n"
        f"{'=' * len(level.value)}\n"
        f"{config.description}\n\n"
        f"Settings:\n"
        f"  - Network commands allowed: {config.allow_network}\n"
        f"  - Filesystem commands allowed: {config.allow_filesystem}\n"
        f"  - System control allowed: {config.allow_system_control}\n"
        f"  - Require allowlist: {config.require_allowlist}\n"
        f"  - Blocked substrings: {len(config.blocked_substrings)}\n"
        f"  - Blocked patterns: {len(config.blocked_patterns)}\n"
        f"  - Dangerous commands: {len(config.dangerous_commands)}"
    )
