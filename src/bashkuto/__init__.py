import sys

from .api import run
from .runtime.session import BashSession
from .runtime.runtime import BashRuntime
from .runtime.result import CommandResult
from .runtime.exceptions import (
    BashkutoError,
    SecurityError,
    TimeoutError,
    BinaryOutputError,
    OverflowError,
)
from .presentation.formatter import OutputFormatter, format_result

__all__ = [
    # Main API
    "run",
    "BashSession",
    "BashRuntime",
    "CommandResult",
    # Exceptions
    "BashkutoError",
    "SecurityError",
    "TimeoutError",
    "BinaryOutputError",
    "OverflowError",
    # Formatting
    "OutputFormatter",
    "format_result",
    # CLI
    "main",
]


def main() -> None:
    """CLI entry point for bashkuto."""
    if len(sys.argv) < 2:
        print("Usage: bashkuto <command>")
        print("Execute a bash command and print the result.")
        sys.exit(1)

    command = " ".join(sys.argv[1:])
    try:
        result = run(command)
        print(result)
    except BashkutoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)