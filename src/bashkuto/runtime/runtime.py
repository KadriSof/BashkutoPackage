"""Bash runtime orchestration."""

import logging

from typing import List, Optional

from .executor import execute, get_default_shell
from .result import CommandResult
from .guards import (
    check_command,
    BLOCKED_SUBSTRINGS,
    BLOCKED_PATTERNS,
)
from .exceptions import BashkutoError
from ..presentation.truncation import OverflowManager
from ..presentation.binary_guard import is_binary


logger = logging.getLogger(__name__)


class BashRuntime:
    """
    Main runtime for executing bash commands safely.

    Provides command execution with security guards, output handling,
    and structured results optimized for AI agents.
    """

    def __init__(
        self,
        shell: Optional[str] = None,
        timeout_sec: Optional[float] = None,
        max_output_chars: int = 8000,
        blocked_substrings: Optional[List[str]] = None,
        blocked_patterns: Optional[List[str]] = None,
        overflow_dir: str = ".bashkuto_overflow",
        overflow_max_age_hours: int = 24,
        overflow_max_size_mb: int = 100,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ):
        """
        Initialize BashRuntime.

        Args:
            shell: Shell executable to use (default: platform default)
            timeout_sec: Command timeout in seconds (None = no timeout)
            max_output_chars: Maximum output characters before truncation
            blocked_substrings: Additional blocked command substrings
            blocked_patterns: Additional blocked regex patterns
            overflow_dir: Directory for overflow files
            overflow_max_age_hours: Max age of overflow files
            overflow_max_size_mb: Max size of overflow directory
            cwd: Working directory for commands
            env: Environment variables for commands
        """
        self.shell = shell if shell is not None else get_default_shell()
        self.timeout_sec = timeout_sec
        self.max_output_chars = max_output_chars
        self.overflow_dir = overflow_dir
        self.cwd = cwd
        self.env = env

        # Combine default and custom blocked commands
        self.blocked_substrings = (
            BLOCKED_SUBSTRINGS + (blocked_substrings or [])
        )
        self.blocked_patterns = (
            BLOCKED_PATTERNS + (blocked_patterns or [])
        )

        # Initialize overflow manager
        self.overflow_manager = OverflowManager(
            overflow_dir=overflow_dir,
            max_age_hours=overflow_max_age_hours,
            max_size_mb=overflow_max_size_mb,
        )

        logger.debug(
            f"BashRuntime initialized: shell={shell}, timeout={timeout_sec}s"
        )

    def run(self, command: str) -> CommandResult:
        """
        Execute a command and return the result.

        Args:
            command: The command string to execute

        Returns:
            CommandResult with output and metadata

        Raises:
            SecurityError: If command fails security checks
            TimeoutError: If command exceeds timeout
            BashkutoError: For other execution errors
        """
        logger.info(f"Executing: {command[:100]}...")

        try:
            # Security check
            check_command(
                command,
                self.blocked_substrings,
                self.blocked_patterns,
            )
            logger.debug("Security check passed")

            # Execute command
            stdout, stderr, code, duration = execute(
                command=command,
                shell=self.shell,
                timeout_sec=self.timeout_sec,
            )
            logger.info(f"Completed: exit_code={code}, duration={duration}ms")

            # Check for binary output
            if is_binary(stdout):
                logger.debug("Binary output detected, suppressing")
                return CommandResult(
                    output="[binary output suppressed]",
                    stderr="",
                    exit_code=code,
                    duration_ms=duration,
                )

            # Decode output
            text_out = stdout.decode("utf-8", errors="replace")
            text_err = stderr.decode("utf-8", errors="replace")

            # Handle overflow
            text_out, truncated, overflow_file = (
                self.overflow_manager.truncate_output(
                    text_out, self.max_output_chars
                )
            )
            if truncated:
                logger.debug(f"Output truncated, saved to: {overflow_file}")

            return CommandResult(
                output=text_out,
                stderr=text_err,
                exit_code=code,
                duration_ms=duration,
                truncated=truncated,
                overflow_file=overflow_file,
            )

        except BashkutoError:
            # Re-raise our custom errors
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise BashkutoError(f"Command execution failed: {e}") from e