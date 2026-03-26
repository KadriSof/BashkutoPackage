"""Rule Gallery - Pre-built validation rules for common security policies.

This module provides ready-to-use validation rules for specific security concerns.
Import and use with Paragon:

    from bashkuto.security import Paragon
    from bashkuto.security.rules import NoNetworkRule, NoFilesystemRule

    paragon = Paragon(custom_rules=[
        NoNetworkRule(),
        NoFilesystemRule(),
    ])
"""

import re
from typing import List, Optional, Set

from .paragon import ValidationRule, ValidationResult


class NoNetworkRule(ValidationRule):
    """Block all network-related commands.

    Prevents:
    - curl, wget (HTTP downloads)
    - ssh, scp, rsync (remote access)
    - nc, netcat (network connections)
    - ping, traceroute (network probing)
    - Any command with URLs (http://, https://, ftp://)

    Use case: Sandboxed environments where network access should be prevented.
    """

    NETWORK_COMMANDS = [
        "curl", "wget", "ssh", "scp", "rsync",
        "nc", "netcat", "ping", "traceroute",
        "nmap", "telnet", "ftp", "sftp",
    ]

    URL_PATTERNS = [
        r'https?://',
        r'ftp://',
        r'sftp://',
    ]

    def __init__(self, additional_commands: Optional[List[str]] = None):
        self._commands = set(self.NETWORK_COMMANDS)
        if additional_commands:
            self._commands.update(additional_commands)

    @property
    def name(self) -> str:
        return "no_network"

    def validate(self, content: str, context: Optional[dict] = None) -> ValidationResult:
        # Check for network commands
        for cmd in self._commands:
            pattern = rf'\b{cmd}\b'
            if re.search(pattern, content, re.IGNORECASE):
                return ValidationResult(
                    passed=False,
                    violation_type="no_network",
                    message=f"Network command '{cmd}' is not allowed",
                    rule_name=self.name,
                )

        # Check for URLs
        for url_pattern in self.URL_PATTERNS:
            if re.search(url_pattern, content):
                return ValidationResult(
                    passed=False,
                    violation_type="no_network",
                    message=f"URLs are not allowed (detected: {url_pattern})",
                    rule_name=self.name,
                )

        return ValidationResult(passed=True, rule_name=self.name)


class NoFilesystemRule(ValidationRule):
    """Block filesystem modification commands.

    Prevents:
    - rm, rmdir (file/directory deletion)
    - chmod, chown, chgrp (permission changes)
    - mv, cp (file moves/copies with write intent)
    - ln (link creation)
    - touch (file creation)
    - mkdir (directory creation)
    - dd (low-level disk operations)

    Use case: Read-only analysis environments.
    """

    FS_COMMANDS = [
        "rm", "rmdir", "chmod", "chown", "chgrp",
        "mv", "cp", "ln", "touch", "mkdir",
        "dd", "mkfs", "fdisk", "parted",
    ]

    def __init__(
        self,
        additional_commands: Optional[List[str]] = None,
        allow_read_only: bool = True,
    ):
        """
        Initialize NoFilesystemRule.

        Args:
            additional_commands: Extra commands to block.
            allow_read_only: If True, allow read-only commands (cat, ls, etc.)
                even if they're in the blocked list. This is handled by
                checking for write-related flags.
        """
        self._commands = set(self.FS_COMMANDS)
        if additional_commands:
            self._commands.update(additional_commands)
        self._allow_read_only = allow_read_only

    @property
    def name(self) -> str:
        return "no_filesystem"

    def validate(self, content: str, context: Optional[dict] = None) -> ValidationResult:
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for cmd in self._commands:
                # Match command at word boundary
                pattern = rf'\b{cmd}\b'
                if re.search(pattern, line, re.IGNORECASE):
                    # Special handling: allow 'rm' in comments or safe contexts
                    if self._allow_read_only:
                        # Check if it's actually a destructive operation
                        if self._is_safe_usage(cmd, line):
                            continue

                    return ValidationResult(
                        passed=False,
                        violation_type="no_filesystem",
                        message=f"Filesystem command '{cmd}' is not allowed",
                        rule_name=self.name,
                    )

        return ValidationResult(passed=True, rule_name=self.name)

    def _is_safe_usage(self, cmd: str, line: str) -> bool:
        """Check if filesystem command usage is safe (read-only)."""
        # This is a simplified check - in practice, you might want more sophisticated analysis
        safe_patterns = {
            'rm': [],  # rm is never safe in read-only mode
            'chmod': [],
            'mkdir': [],
        }
        # For now, no filesystem command is considered "safe"
        return False


class NoCodeExecutionRule(ValidationRule):
    """Block code execution and dynamic evaluation.

    Prevents:
    - eval (shell evaluation)
    - exec (command execution)
    - $() (command substitution in dangerous contexts)
    - `` (backtick execution)
    - source, . (script sourcing)
    - bash/sh with arguments

    Use case: Preventing arbitrary code execution in untrusted scripts.
    """

    def __init__(self, block_command_substitution: bool = False):
        """
        Initialize NoCodeExecutionRule.

        Args:
            block_command_substitution: If True, block all $() and `` usage.
                Default False as this is very restrictive.
        """
        self._block_substitution = block_command_substitution

    @property
    def name(self) -> str:
        return "no_code_execution"

    def validate(self, content: str, context: Optional[dict] = None) -> ValidationResult:
        # Check for eval/exec
        if re.search(r'\beval\b', content, re.IGNORECASE):
            return ValidationResult(
                passed=False,
                violation_type="no_code_execution",
                message="eval command is not allowed",
                rule_name=self.name,
            )

        if re.search(r'\bexec\b', content, re.IGNORECASE):
            return ValidationResult(
                passed=False,
                violation_type="no_code_execution",
                message="exec command is not allowed",
                rule_name=self.name,
            )

        # Check for script sourcing
        if re.search(r'\bsource\b', content, re.IGNORECASE):
            return ValidationResult(
                passed=False,
                violation_type="no_code_execution",
                message="source command is not allowed",
                rule_name=self.name,
            )

        if re.search(r'^\.\s+', content, re.MULTILINE):
            return ValidationResult(
                passed=False,
                violation_type="no_code_execution",
                message="dot-source (.) command is not allowed",
                rule_name=self.name,
            )

        # Check for bash/sh invocation with script
        if re.search(r'\b(bash|sh)\s+["\']?[^"\']', content):
            return ValidationResult(
                passed=False,
                violation_type="no_code_execution",
                message="bash/sh script invocation is not allowed",
                rule_name=self.name,
            )

        # Check for command substitution if enabled
        if self._block_substitution:
            if re.search(r'\$\([^)]+\)', content):
                return ValidationResult(
                    passed=False,
                    violation_type="no_code_execution",
                    message="Command substitution $() is not allowed",
                    rule_name=self.name,
                )

            if re.search(r'`[^`]+`', content):
                return ValidationResult(
                    passed=False,
                    violation_type="no_code_execution",
                    message="Backtick execution is not allowed",
                    rule_name=self.name,
                )

        return ValidationResult(passed=True, rule_name=self.name)


class CommandAllowlistRule(ValidationRule):
    """Enforce a strict command allowlist.

    Only allows explicitly whitelisted commands. All other commands are blocked.

    Use case: Highly restricted environments where only specific operations
    should be permitted.
    """

    def __init__(
        self,
        allowlist: Set[str],
        allow_pipes: bool = True,
        allow_redirects: bool = True,
    ):
        """
        Initialize CommandAllowlistRule.

        Args:
            allowlist: Set of allowed command names.
            allow_pipes: If True, allow pipe characters (|) between allowed commands.
            allow_redirects: If True, allow redirects (>, >>, <) with allowed commands.
        """
        self._allowlist = allowlist
        self._allow_pipes = allow_pipes
        self._allow_redirects = allow_redirects

    @property
    def name(self) -> str:
        return "command_allowlist"

    def validate(self, content: str, context: Optional[dict] = None) -> ValidationResult:
        lines = content.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Split by pipes if allowed
            if self._allow_pipes:
                segments = line.split("|")
            else:
                segments = [line]

            for segment in segments:
                segment = segment.strip()
                if not segment:
                    continue

                # Handle redirects
                if self._allow_redirects:
                    # Remove redirect portions
                    segment = re.split(r'\s*[<>]+\s*', segment)[0].strip()

                # Get the command (first token)
                tokens = segment.split()
                if not tokens:
                    continue

                cmd = tokens[0]
                # Remove leading special chars
                cmd = re.sub(r"^[|;&<>]+", "", cmd)

                if cmd and cmd not in self._allowlist:
                    return ValidationResult(
                        passed=False,
                        violation_type="command_allowlist",
                        message=f"Command '{cmd}' is not in the allowlist",
                        rule_name=self.name,
                    )

        return ValidationResult(passed=True, rule_name=self.name)


class NoPrivilegeEscalationRule(ValidationRule):
    """Block privilege escalation commands.

    Prevents:
    - sudo (privilege escalation)
    - su (switch user)
    - pkexec (polkit execution)
    - doas (OpenBSD sudo alternative)
    - setuid/setgid operations

    Use case: Preventing privilege escalation in any environment.
    """

    PRIVILEGE_COMMANDS = ["sudo", "su", "pkexec", "doas", "runas"]

    def __init__(self, additional_commands: Optional[List[str]] = None):
        self._commands = set(self.PRIVILEGE_COMMANDS)
        if additional_commands:
            self._commands.update(additional_commands)

    @property
    def name(self) -> str:
        return "no_privilege_escalation"

    def validate(self, content: str, context: Optional[dict] = None) -> ValidationResult:
        for cmd in self._commands:
            pattern = rf'\b{cmd}\b'
            if re.search(pattern, content, re.IGNORECASE):
                return ValidationResult(
                    passed=False,
                    violation_type="no_privilege_escalation",
                    message=f"Privilege escalation command '{cmd}' is not allowed",
                    rule_name=self.name,
                )

        return ValidationResult(passed=True, rule_name=self.name)


class NoEnvironmentManipulationRule(ValidationRule):
    """Block environment manipulation commands.

    Prevents:
    - export (environment variable export)
    - unset (variable unsetting)
    - set (shell options)
    - PATH manipulation

    Use case: Preventing environment-based attacks or configuration changes.
    """

    ENV_COMMANDS = ["export", "unset", "set", "declare", "typeset"]

    def __init__(self, additional_commands: Optional[List[str]] = None):
        self._commands = set(self.ENV_COMMANDS)
        if additional_commands:
            self._commands.update(additional_commands)

    @property
    def name(self) -> str:
        return "no_environment"

    def validate(self, content: str, context: Optional[dict] = None) -> ValidationResult:
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for cmd in self._commands:
                pattern = rf'\b{cmd}\b'
                if re.search(pattern, line):
                    return ValidationResult(
                        passed=False,
                        violation_type="no_environment",
                        message=f"Environment command '{cmd}' is not allowed",
                        rule_name=self.name,
                    )

        return ValidationResult(passed=True, rule_name=self.name)


# Pre-built rule sets for common security policies

def get_readonly_rules() -> List[ValidationRule]:
    """Get rules for read-only operation.

    Returns:
        List of rules that enforce read-only access.
    """
    return [
        NoFilesystemRule(),
        NoEnvironmentManipulationRule(),
    ]


def get_sandbox_rules() -> List[ValidationRule]:
    """Get rules for sandboxed execution.

    Returns:
        List of rules for sandboxed environments.
    """
    return [
        NoNetworkRule(),
        NoFilesystemRule(),
        NoPrivilegeEscalationRule(),
        NoCodeExecutionRule(),
    ]


def get_minimal_rules() -> List[ValidationRule]:
    """Get minimal security rules.

    Returns:
        List of minimal rules that only block the most dangerous operations.
    """
    return [
        NoPrivilegeEscalationRule(),
        NoCodeExecutionRule(block_command_substitution=False),
    ]
