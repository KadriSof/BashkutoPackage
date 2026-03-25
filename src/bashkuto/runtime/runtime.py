"""Bash runtime orchestration."""

import logging
import os
import shutil
import shlex

from typing import Dict, List, Optional

from .executor import execute, execute_async, get_default_shell
from .result import CommandResult
from .guards import (
    check_command,
    BLOCKED_SUBSTRINGS,
    BLOCKED_PATTERNS,
)
from .exceptions import BashkutoError, SecurityError
from .tool_registry import ToolRegistry
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
        env: Optional[Dict[str, str]] = None,
        tool_dir: Optional[str] = None,
        tool_blocked_patterns: Optional[List[str]] = None,
        tool_allowlist: Optional[List[str]] = None,
        tool_execution_security: bool = True,
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
            env: Environment variables for commands (replaces os.environ if provided)
                 Note: To extend os.environ, pass os.environ.copy() | your_vars
            tool_dir: Directory for agent-created tools (default: .bashkuto_tools)
            tool_blocked_patterns: Additional blocked patterns for tool scripts
            tool_allowlist: If provided, only allow these commands in tools
            tool_execution_security: If True (default), validate tool invocations
                against security rules. Set to False to allow tools to execute
                unrestricted (only recommended for trusted tools in sandboxed environments).
        """
        self.shell = shell if shell is not None else get_default_shell()
        self.timeout_sec = timeout_sec
        self.max_output_chars = max_output_chars
        self.overflow_dir = overflow_dir
        self.cwd = cwd
        self.env = env or os.environ.copy()

        # Combine default and custom blocked commands
        self.blocked_substrings = (
            BLOCKED_SUBSTRINGS + (blocked_substrings or [])
        )
        self.blocked_patterns = (
            BLOCKED_PATTERNS + (blocked_patterns or [])
        )

        # Tool execution security policy
        self.tool_execution_security = tool_execution_security

        # Initialize overflow manager
        self.overflow_manager = OverflowManager(
            overflow_dir=overflow_dir,
            max_age_hours=overflow_max_age_hours,
            max_size_mb=overflow_max_size_mb,
        )

        # Initialize tool registry
        self.tool_registry = ToolRegistry(
            tool_dir=tool_dir if tool_dir else ".bashkuto_tools",
            blocked_patterns=tool_blocked_patterns,
            tool_allowlist=tool_allowlist,
        )

        self._validate_shell()

        logger.debug(
            f"BashRuntime initialized: shell={self.shell}, timeout={timeout_sec}s, cwd={cwd}, "
            f"tool_execution_security={tool_execution_security}"
        )

    def create_tool(
        self,
        name: str,
        script: str,
        description: str = "",
        created_by: str = "agent",
    ):
        """
        Create a new agent tool.

        Args:
            name: Tool name (will be used as filename without extension)
            script: Shell script content
            description: Optional tool description
            created_by: Creator identifier (default: "agent")

        Returns:
            Path to the created tool script

        Raises:
            SecurityError: If script contains dangerous patterns
            ValueError: If tool name is invalid
        """
        return self.tool_registry.create_tool(
            name=name,
            script=script,
            description=description,
            created_by=created_by,
        )

    def list_tools(self) -> List[str]:
        """List all available tool names."""
        return self.tool_registry.list_tools()

    def tool_exists(self, name: str) -> bool:
        """Check if a tool exists."""
        return self.tool_registry.tool_exists(name)

    def describe_tool(self, name: str):
        """Get full metadata for a tool."""
        return self.tool_registry.describe_tool(name)

    def search_tools(self, query: str) -> List[str]:
        """Search tools by description."""
        return self.tool_registry.search_tools(query)

    def delete_tool(self, name: str) -> bool:
        """Delete a tool."""
        return self.tool_registry.delete_tool(name)

    def export_tools(self, path: str) -> int:
        """Export all tools to a JSON file."""
        return self.tool_registry.export_tools(path)

    def import_tools(self, path: str, overwrite: bool = False) -> int:
        """Import tools from a JSON file."""
        return self.tool_registry.import_tools(path, overwrite=overwrite)

    def clear_all_tools(self) -> int:
        """Delete all tools."""
        return self.tool_registry.clear_all_tools()

    def _resolve_command(self, command: str) -> tuple[Optional[str], List[str]]:
        """
        Resolve command to tool or return None for shell execution.

        Args:
            command: Full command string

        Returns:
            Tuple of (tool_path, args) if tool exists, (None, args) otherwise
        """
        # Parse command into tokens
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Fallback for Windows or malformed commands
            tokens = command.split()

        if not tokens:
            return None, []

        cmd_name = tokens[0]
        args = tokens[1:]

        # Check if it's a tool
        tool_path = self.tool_registry.get_tool_path(cmd_name)
        if tool_path:
            return str(tool_path), args

        return None, args

    def _validate_shell(self) -> None:
        """Verify that the configured shell is available and executable."""
        if not shutil.which(self.shell):
            raise BashkutoError(
                f"Invalid shell: '{self.shell}' was not found or is not executable. "
                "Please provide a valid path to a shell executable (e.g., '/bin/bash' or 'cmd.exe')."
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
            # Resolve command (check for tools first)
            tool_path, args = self._resolve_command(command)

            if tool_path:
                # Tool execution security check
                if self.tool_execution_security:
                    # Validate the original command string against security rules
                    # This prevents tools from being used to bypass security
                    check_command(
                        command,
                        self.blocked_substrings,
                        self.blocked_patterns,
                    )
                    logger.debug("Tool invocation security check passed")

                # Execute tool
                logger.debug(f"Resolved to tool: {tool_path}")
                # Build command: bash <tool_path> <args>
                tool_command = f'bash "{tool_path}"'
                if args:
                    tool_command += " " + " ".join(shlex.quote(arg) for arg in args)

                # Execute the tool
                stdout, stderr, code, duration = execute(
                    command=tool_command,
                    shell=self.shell,
                    timeout_sec=self.timeout_sec,
                    cwd=self.cwd,
                    env=self.env
                )

                # Increment usage count
                tool_name = command.split()[0]
                self.tool_registry.increment_usage(tool_name)

                logger.info(f"Tool completed: exit_code={code}, duration={duration}ms")
                return self._process_result(stdout, stderr, code, duration)

            # Security check for shell commands
            check_command(
                command,
                self.blocked_substrings,
                self.blocked_patterns,
            )
            logger.debug("Security check passed")

            # Execute command via shell
            stdout, stderr, code, duration = execute(
                command=command,
                shell=self.shell,
                timeout_sec=self.timeout_sec,
                cwd=self.cwd,
                env=self.env
            )
            logger.info(f"Completed: exit_code={code}, duration={duration}ms")

            return self._process_result(stdout, stderr, code, duration)

        except BashkutoError:
            # Re-raise our custom errors
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise BashkutoError(f"Command execution failed: {e}") from e

    async def run_async(self, command: str) -> CommandResult:
        """
        Execute a command asynchronously and return the result.

        Args:
            command: The command string to execute

        Returns:
            CommandResult with output and metadata
        """
        logger.info(f"Executing async: {command[:100]}...")

        try:
            # Resolve command (check for tools first)
            tool_path, args = self._resolve_command(command)

            if tool_path:
                # Tool execution security check
                if self.tool_execution_security:
                    # Validate the original command string against security rules
                    # This prevents tools from being used to bypass security
                    check_command(
                        command,
                        self.blocked_substrings,
                        self.blocked_patterns,
                    )
                    logger.debug("Tool invocation security check passed")

                # Execute tool
                logger.debug(f"Resolved to tool: {tool_path}")
                # Build command: bash <tool_path> <args>
                tool_command = f'bash "{tool_path}"'
                if args:
                    tool_command += " " + " ".join(shlex.quote(arg) for arg in args)

                # Execute the tool
                stdout, stderr, code, duration = await execute_async(
                    command=tool_command,
                    shell=self.shell,
                    timeout_sec=self.timeout_sec,
                    cwd=self.cwd,
                    env=self.env
                )

                # Increment usage count
                tool_name = command.split()[0]
                self.tool_registry.increment_usage(tool_name)

                logger.info(f"Tool completed: exit_code={code}, duration={duration}ms")
                return self._process_result(stdout, stderr, code, duration)

            # Security check for shell commands
            check_command(
                command,
                self.blocked_substrings,
                self.blocked_patterns,
            )

            # Execute command via shell
            stdout, stderr, code, duration = await execute_async(
                command=command,
                shell=self.shell,
                timeout_sec=self.timeout_sec,
                cwd=self.cwd,
                env=self.env
            )
            logger.info(f"Async completed: exit_code={code}, duration={duration}ms")

            return self._process_result(stdout, stderr, code, duration)

        except BashkutoError:
            raise
        except Exception as e:
            logger.error(f"Unexpected async error: {e}")
            raise BashkutoError(f"Async command execution failed: {e}") from e

    def _process_result(
        self,
        stdout: bytes,
        stderr: bytes,
        code: int,
        duration: int
    ) -> CommandResult:
        """Common result processing logic."""
        # Decode stderr first for error reporting (even if stdout is binary)
        text_err = stderr.decode("utf-8", errors="replace")

        # Check for binary output
        if is_binary(stdout):
            logger.debug("Binary output detected, suppressing")
            return CommandResult(
                output="[binary output suppressed]",
                stderr=text_err,
                exit_code=code,
                duration_ms=duration,
            )

        # Decode output
        text_out = stdout.decode("utf-8", errors="replace")

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
