"""Agent Interface - convenience functions for quick usage."""

from typing import Optional

from .runtime.runtime import BashRuntime
from .runtime.result import CommandResult
from .runtime.session import BashSession


# Default runtime instance for convenience functions
_default_runtime: Optional[BashRuntime] = None


def get_default_runtime() -> BashRuntime:
    """Get or create the default runtime instance."""
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = BashRuntime()
    return _default_runtime


def set_default_runtime(runtime: BashRuntime) -> None:
    """Set a custom default runtime instance."""
    global _default_runtime
    _default_runtime = runtime


def run(command: str) -> str:
    """
    Execute a command using the default runtime.

    Args:
        command: The command string to execute

    Returns:
        Agent-formatted result string
    """
    runtime = get_default_runtime()
    result = runtime.run(command)
    return result.to_agent_string()


def run_structured(command: str) -> CommandResult:
    """
    Execute a command and return structured result.

    Args:
        command: The command string to execute

    Returns:
        CommandResult with structured data
    """
    runtime = get_default_runtime()
    return runtime.run(command)


async def run_async(command: str) -> CommandResult:
    """
    Execute a command asynchronously and return structured result.

    Args:
        command: The command string to execute

    Returns:
        CommandResult with structured data
    """
    runtime = get_default_runtime()
    return await runtime.run_async(command)
