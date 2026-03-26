"""Security module for Bashkuto.

Provides Paragon, the centralized security validation engine.

Example usage:
    from bashkuto.security import Paragon, SecurityLevel

    # Create Paragon with default settings
    paragon = Paragon()

    # Validate a command
    try:
        paragon.check_command("rm -rf /home")
    except SecurityError as e:
        print(f"Blocked: {e}")

    # Validate a script
    try:
        paragon.check_script('eval "$1"')
    except SecurityError as e:
        print(f"Blocked: {e}")

    # Custom security level
    paragon_strict = Paragon(security_level=SecurityLevel.STRICT)

    # Custom rules from gallery
    from bashkuto.security.rules import NoNetworkRule, NoFilesystemRule
    paragon_custom = Paragon(custom_rules=[
        NoNetworkRule(),
        NoFilesystemRule(),
    ])

Security Levels:
    - PERMISSIVE: Minimal security, only blocks most dangerous operations
    - BALANCED: Default, blocks known dangerous patterns (recommended)
    - STRICT: Maximum security, aggressively blocks dangerous operations
"""

from .paragon import (
    Paragon,
    SecurityLevel,
    ValidationResult,
    ValidationRule,
    BlockedSubstringRule,
    BlockedPatternRule,
    DangerousCommandRule,
    CodeInjectionRule,
    AllowlistRule,
    ValidationContext,
    check_command,  # Backward compatibility
)

from .levels import (
    get_security_config,
    get_all_security_levels,
    describe_security_level,
    SecurityLevelConfig,
    PERMISSIVE_CONFIG,
    BALANCED_CONFIG,
    STRICT_CONFIG,
)

from .rules import (
    NoNetworkRule,
    NoFilesystemRule,
    NoCodeExecutionRule,
    CommandAllowlistRule,
    NoPrivilegeEscalationRule,
    NoEnvironmentManipulationRule,
    get_readonly_rules,
    get_sandbox_rules,
    get_minimal_rules,
)

__all__ = [
    # Core Paragon
    "Paragon",
    "SecurityLevel",
    "ValidationResult",
    "ValidationRule",
    "ValidationContext",
    # Built-in Rules
    "BlockedSubstringRule",
    "BlockedPatternRule",
    "DangerousCommandRule",
    "CodeInjectionRule",
    "AllowlistRule",
    # Rule Gallery
    "NoNetworkRule",
    "NoFilesystemRule",
    "NoCodeExecutionRule",
    "CommandAllowlistRule",
    "NoPrivilegeEscalationRule",
    "NoEnvironmentManipulationRule",
    # Pre-built Rule Sets
    "get_readonly_rules",
    "get_sandbox_rules",
    "get_minimal_rules",
    # Security Levels
    "get_security_config",
    "get_all_security_levels",
    "describe_security_level",
    "SecurityLevelConfig",
    "PERMISSIVE_CONFIG",
    "BALANCED_CONFIG",
    "STRICT_CONFIG",
    # Backward compatibility
    "check_command",
]
