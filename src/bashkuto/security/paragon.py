"""Paragon - Centralized Security Validation Engine for Bashkuto.

This module provides a unified security validation interface for commands
and scripts, designed for dependency injection into BashRuntime and ToolRegistry.
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from ..runtime.exceptions import SecurityError
from .levels import (
    SecurityLevel,
    get_security_config,
    SECURITY_LEVEL_CONFIGS,
)

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of a security validation check.

    Attributes:
        passed: Whether the validation passed.
        violation_type: Type of violation detected (if any).
        message: Human-readable error message (if failed).
        severity: Severity level - 'error', 'warning', or 'info'.
        rule_name: Name of the rule that produced this result.
    """
    passed: bool = True
    violation_type: Optional[str] = None
    message: Optional[str] = None
    severity: str = "error"
    rule_name: Optional[str] = None

    def to_exception(self) -> SecurityError:
        """Convert failed validation to SecurityError."""
        if self.passed:
            raise ValueError("Cannot create exception for passed validation")
        return SecurityError(self.message or "Security validation failed")


class ValidationRule(ABC):
    """Abstract base class for validation rules.

    Subclasses must implement validate() to check content against a specific
    security rule.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this rule."""
        pass

    @abstractmethod
    def validate(self, content: str, context: Optional[Dict] = None) -> ValidationResult:
        """Validate content against this rule.

        Args:
            content: The command or script content to validate.
            context: Optional context dictionary for additional information.

        Returns:
            ValidationResult indicating pass/fail and details.
        """
        pass


@dataclass
class ValidationContext:
    """Context information for validation.

    Attributes:
        content_type: Type of content - 'command' or 'script'.
        source: Source of the content (e.g., 'user', 'tool', 'agent').
        metadata: Additional metadata for validation rules.
    """
    content_type: str = "command"
    source: str = "user"
    metadata: Dict = field(default_factory=dict)


class BlockedSubstringRule(ValidationRule):
    """Rule: Block commands/scripts containing dangerous substrings."""

    def __init__(self, substrings: Optional[List[str]] = None):
        self._substrings = substrings or []

    @property
    def name(self) -> str:
        return "blocked_substring"

    def validate(self, content: str, context: Optional[Dict] = None) -> ValidationResult:
        for substring in self._substrings:
            if substring in content:
                return ValidationResult(
                    passed=False,
                    violation_type="blocked_substring",
                    message=f"Content contains blocked substring: '{substring}'",
                    rule_name=self.name,
                )
        return ValidationResult(passed=True, rule_name=self.name)


class BlockedPatternRule(ValidationRule):
    """Rule: Block commands/scripts matching dangerous regex patterns."""

    def __init__(self, patterns: Optional[List[str]] = None):
        self._pattern_strings = patterns or []
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self._pattern_strings
        ]

    @property
    def name(self) -> str:
        return "blocked_pattern"

    def validate(self, content: str, context: Optional[Dict] = None) -> ValidationResult:
        for pattern_str, compiled in zip(self._pattern_strings, self._compiled_patterns):
            if compiled.search(content):
                return ValidationResult(
                    passed=False,
                    violation_type="blocked_pattern",
                    message=f"Content matches blocked pattern: '{pattern_str}'",
                    rule_name=self.name,
                )
        return ValidationResult(passed=True, rule_name=self.name)


class DangerousCommandRule(ValidationRule):
    """Rule: Block dangerous commands with variable argument forwarding."""

    def __init__(self, commands: Optional[List[str]] = None):
        self._dangerous_commands = set(commands or [])

    @property
    def name(self) -> str:
        return "dangerous_command"

    def validate(self, content: str, context: Optional[Dict] = None) -> ValidationResult:
        # Pattern matches: cmd ... $@ or $* or $1 or ${1} etc., with optional quotes
        pattern_template = r'\b{}\s+.*?["\']?\$(\{{)?[@*0-9]+(\}})?["\']?'

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for cmd in self._dangerous_commands:
                pattern = pattern_template.format(cmd)
                if re.search(pattern, line):
                    return ValidationResult(
                        passed=False,
                        violation_type="dangerous_command",
                        message=(
                            f"Script contains dangerous command '{cmd}' with variable "
                            f"arguments that could bypass security. Use explicit argument "
                            f"validation instead."
                        ),
                        rule_name=self.name,
                    )
        return ValidationResult(passed=True, rule_name=self.name)


class CodeInjectionRule(ValidationRule):
    """Rule: Block code injection patterns (eval, exec, dynamic execution)."""

    DEFAULT_PATTERNS = [
        (r'\beval\b.*\$', "eval with variable expansion"),
        (r'\bexec\b.*\$', "exec with variable expansion"),
        (r'\bbash\s+(-[a-zA-Z]+\s+)*["\']?\$', "bash with variable (script injection)"),
        (r'\bsh\s+(-[a-zA-Z]+\s+)*["\']?\$', "sh with variable (script injection)"),
        (r'\bsource\b.*\$', "source with variable expansion"),
        (r'\.\s+["\']?\$', "dot-source with variable expansion"),
    ]

    def __init__(self, patterns: Optional[List[tuple]] = None):
        self._patterns = patterns or self.DEFAULT_PATTERNS.copy()

    @property
    def name(self) -> str:
        return "code_injection"

    def validate(self, content: str, context: Optional[Dict] = None) -> ValidationResult:
        for pattern, description in self._patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return ValidationResult(
                    passed=False,
                    violation_type="code_injection",
                    message=(
                        f"Content contains potentially dangerous pattern: {description}. "
                        f"This could allow code injection attacks."
                    ),
                    rule_name=self.name,
                )
        return ValidationResult(passed=True, rule_name=self.name)


class AllowlistRule(ValidationRule):
    """Rule: Enforce command allowlist if configured."""

    def __init__(self, allowlist: Optional[Set[str]] = None):
        self._allowlist = allowlist

    @property
    def name(self) -> str:
        return "allowlist"

    def validate(self, content: str, context: Optional[Dict] = None) -> ValidationResult:
        if self._allowlist is None:
            return ValidationResult(passed=True, rule_name=self.name)

        lines = content.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            tokens = line.split()
            if tokens:
                cmd = tokens[0]
                # Remove leading special chars (pipes, redirects, etc.)
                cmd = re.sub(r"^[|;&<>]+", "", cmd)
                if cmd and cmd not in self._allowlist:
                    return ValidationResult(
                        passed=False,
                        violation_type="allowlist",
                        message=(
                            f"Command '{cmd}' is not in the allowlist. "
                            f"Allowed: {sorted(self._allowlist)}"
                        ),
                        rule_name=self.name,
                    )
        return ValidationResult(passed=True, rule_name=self.name)


class Paragon:
    """
    Centralized security validation engine for Bashkuto.

    Paragon orchestrates multiple validation layers for commands and scripts,
    providing a unified interface for security checks. Designed for dependency
    injection into BashRuntime and ToolRegistry.

    Features:
        - Multi-layer validation (substrings, patterns, injection, allowlist)
        - Configurable security levels (STRICT, BALANCED, PERMISSIVE)
        - Custom rule injection
        - Audit logging with Python logging framework
        - Backward compatible with existing guards.py

    Security Levels:
        - PERMISSIVE: Minimal security, only blocks most dangerous operations
        - BALANCED: Default, blocks known dangerous patterns (recommended)
        - STRICT: Maximum security, aggressively blocks dangerous operations

    Example:
        >>> from bashkuto.security import Paragon, SecurityLevel
        >>> paragon = Paragon(security_level=SecurityLevel.BALANCED)
        >>> result = paragon.validate_command("rm -rf /home")
        >>> if not result.passed:
        ...     raise result.to_exception()

        >>> # With custom rules
        >>> from bashkuto.security import ValidationRule, ValidationResult
        >>> class MyRule(ValidationRule):
        ...     @property
        ...     def name(self): return "my_rule"
        ...     def validate(self, content, context=None):
        ...         return ValidationResult(passed=True)
        >>>
        >>> paragon = Paragon(custom_rules=[MyRule()])
    """

    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.BALANCED,
        custom_rules: Optional[List[ValidationRule]] = None,
        audit_logger: Optional[logging.Logger] = None,
        # Backward compatibility parameters
        blocked_substrings: Optional[List[str]] = None,
        blocked_patterns: Optional[List[str]] = None,
        tool_allowlist: Optional[Set[str]] = None,
        additional_dangerous_commands: Optional[List[str]] = None,
    ):
        """
        Initialize Paragon security engine.

        Args:
            security_level: Security policy level (default: BALANCED).
            custom_rules: List of custom ValidationRule instances.
            audit_logger: Optional logger for audit logging.
                If None, uses module logger. Set to False to disable.
            blocked_substrings: Custom blocked substrings (backward compat).
            blocked_patterns: Custom blocked patterns (backward compat).
            tool_allowlist: Command allowlist (backward compat).
            additional_dangerous_commands: Extra dangerous commands to block.
        """
        self.security_level = security_level
        self._audit_logger = audit_logger if audit_logger is not False else None
        self._rules: List[ValidationRule] = self._init_rules(
            security_level=security_level,
            blocked_substrings=blocked_substrings,
            blocked_patterns=blocked_patterns,
            tool_allowlist=tool_allowlist,
            additional_dangerous_commands=additional_dangerous_commands,
        )

        if custom_rules:
            self._rules.extend(custom_rules)

        self._log_init()

    def _log_init(self) -> None:
        """Log initialization information."""
        if self._audit_logger is not None:
            logger = self._audit_logger if isinstance(self._audit_logger, logging.Logger) else logging.getLogger(__name__)
            logger.info(
                f"Paragon initialized with security level: {self.security_level.value}, "
                f"rules: {self.get_rules()}"
            )

    def _init_rules(
        self,
        security_level: SecurityLevel,
        blocked_substrings: Optional[List[str]] = None,
        blocked_patterns: Optional[List[str]] = None,
        tool_allowlist: Optional[Set[str]] = None,
        additional_dangerous_commands: Optional[List[str]] = None,
    ) -> List[ValidationRule]:
        """Initialize default validation rules based on security level."""
        rules: List[ValidationRule] = []
        config = get_security_config(security_level)

        # Merge custom substrings/patterns with level defaults
        substrings = list(config.blocked_substrings)
        if blocked_substrings:
            substrings.extend(blocked_substrings)

        patterns = list(config.blocked_patterns)
        if blocked_patterns:
            patterns.extend(blocked_patterns)

        # Merge dangerous commands
        dangerous_cmds = list(config.dangerous_commands)
        if additional_dangerous_commands:
            dangerous_cmds.extend(additional_dangerous_commands)

        # Merge injection patterns
        injection_patterns = list(config.injection_patterns)

        # Add level-specific injection patterns (e.g., curl/wget in STRICT)
        if not config.allow_network:
            injection_patterns.extend([
                (r'\bcurl\b', "curl command (network access blocked)"),
                (r'\bwget\b', "wget command (network access blocked)"),
            ])

        # Create rules based on configuration
        if substrings:
            rules.append(BlockedSubstringRule(substrings=substrings))

        if patterns:
            rules.append(BlockedPatternRule(patterns=patterns))

        if dangerous_cmds:
            rules.append(DangerousCommandRule(commands=dangerous_cmds))

        if injection_patterns:
            rules.append(CodeInjectionRule(patterns=injection_patterns))

        # Allowlist rule (required in STRICT mode or if explicitly provided)
        if config.require_allowlist or tool_allowlist is not None:
            rules.append(AllowlistRule(allowlist=tool_allowlist))

        return rules

    def validate_command(
        self,
        command: str,
        context: Optional[Dict] = None,
    ) -> ValidationResult:
        """
        Validate a shell command string.

        Args:
            command: The command string to validate.
            context: Optional context for validation.

        Returns:
            ValidationResult indicating pass/fail and details.

        Raises:
            SecurityError: If validation fails.
        """
        result = self._validate_all(command, context, content_type="command")
        self._audit("command", command, result)

        if not result.passed:
            raise result.to_exception()

        return result

    def validate_script(
        self,
        script: str,
        context: Optional[Dict] = None,
    ) -> ValidationResult:
        """
        Validate a shell script content.

        Args:
            script: The script content to validate.
            context: Optional context for validation.

        Returns:
            ValidationResult indicating pass/fail and details.

        Raises:
            SecurityError: If validation fails.
        """
        result = self._validate_all(script, context, content_type="script")
        self._audit("script", script[:100] + "..." if len(script) > 100 else script, result)

        if not result.passed:
            raise result.to_exception()

        return result

    def check_command(
        self,
        command: str,
        context: Optional[Dict] = None,
    ) -> None:
        """
        Validate command and raise SecurityError if it fails.

        This is a convenience method for backward compatibility with
        the existing check_command() function in guards.py.

        Args:
            command: The command string to validate.
            context: Optional context for validation.

        Raises:
            SecurityError: If validation fails.
        """
        self.validate_command(command, context)

    def check_script(
        self,
        script: str,
        context: Optional[Dict] = None,
    ) -> None:
        """
        Validate script and raise SecurityError if it fails.

        This is a convenience method for backward compatibility.

        Args:
            script: The script content to validate.
            context: Optional context for validation.

        Raises:
            SecurityError: If validation fails.
        """
        self.validate_script(script, context)

    def _validate_all(
        self,
        content: str,
        context: Optional[Dict] = None,
        content_type: str = "command",
    ) -> ValidationResult:
        """Run all validation rules against content."""
        for rule in self._rules:
            result = rule.validate(content, context)
            if not result.passed:
                return result
        return ValidationResult(passed=True)

    def _audit(
        self,
        content_type: str,
        content: str,
        result: ValidationResult,
    ) -> None:
        """Log audit information."""
        if self._audit_logger is None:
            return

        log_level = logging.INFO if result.passed else logging.WARNING
        status = "PASS" if result.passed else f"FAIL ({result.violation_type})"
        msg = f"[{content_type}] {status}: {content[:50]}..." if len(content) > 50 else f"[{content_type}] {status}: {content}"

        if isinstance(self._audit_logger, logging.Logger):
            self._audit_logger.log(log_level, msg)
        else:
            logger.log(log_level, msg)

    def add_rule(self, rule: ValidationRule) -> None:
        """Add a custom validation rule."""
        self._rules.append(rule)

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name.

        Args:
            rule_name: Name of the rule to remove.

        Returns:
            True if rule was removed, False if not found.
        """
        for i, rule in enumerate(self._rules):
            if rule.name == rule_name:
                self._rules.pop(i)
                return True
        return False

    def get_rules(self) -> List[str]:
        """Get list of active rule names."""
        return [rule.name for rule in self._rules]

    def describe(self) -> str:
        """Get a description of the current security configuration.

        Returns:
            Human-readable description string.
        """
        from .levels import describe_security_level
        return describe_security_level(self.security_level)


# Backward compatibility function
def check_command(
    command: str,
    blocked_substrings: Optional[List[str]] = None,
    blocked_patterns: Optional[List[str]] = None,
) -> None:
    """
    Check command against security rules (backward compatible).

    This function maintains backward compatibility with the existing
    check_command() in guards.py. New code should use Paragon directly.

    Args:
        command: Command string to validate.
        blocked_substrings: List of forbidden substrings.
        blocked_patterns: List of forbidden regex patterns.

    Raises:
        SecurityError: If command matches a blocked pattern.
    """
    paragon = Paragon(
        blocked_substrings=blocked_substrings,
        blocked_patterns=blocked_patterns,
    )
    paragon.check_command(command)
