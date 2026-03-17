"""Output formatting for AI agent consumption."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..runtime.result import CommandResult


class OutputFormatter:
    """Formats command output for AI agent consumption."""

    def __init__(self, max_context_lines: int = 50):
        """
        Initialize formatter.

        Args:
            max_context_lines: Maximum lines to show before truncation
        """
        self.max_context_lines = max_context_lines

    def format_for_agent(
        self,
        result: "CommandResult",
        include_stderr: bool = True,
        include_metadata: bool = True,
        compact: bool = False
    ) -> str:
        """
        Format command result for optimal LLM consumption.

        Args:
            result: CommandResult to format
            include_stderr: Whether to include stderr output
            include_metadata: Whether to include exit code and duration
            compact: Use compact format (fewer newlines)

        Returns:
            Formatted string optimized for agent context
        """
        lines = []

        # Status indicator
        if result.exit_code != 0:
            lines.append(f"[FAILED] Exit code: {result.exit_code}")
        elif not compact:
            lines.append("[SUCCESS]")

        # Truncation notice
        if result.truncated:
            lines.append(f"[TRUNCATED] Full output: {result.overflow_file}")

        # Main output
        if result.output:
            output_lines = result.output.strip().split("\n")
            if len(output_lines) > self.max_context_lines:
                # Smart truncation: show beginning and end
                keep = self.max_context_lines // 2
                lines.extend(output_lines[:keep])
                lines.append(
                    f"... {len(output_lines) - self.max_context_lines} lines omitted ..."
                )
                lines.extend(output_lines[-keep:])
            else:
                lines.append(result.output.strip())

        # Errors
        if include_stderr and result.stderr:
            lines.append("")
            lines.append("--- STDERR ---")
            lines.append(result.stderr.strip())

        # Metadata
        if include_metadata:
            lines.append("")
            lines.append(f"[Duration: {result.duration_ms}ms]")

        separator = "\n" if not compact else " "
        return separator.join(lines)


def format_result(
    result: "CommandResult",
    max_context_lines: int = 50,
    **kwargs
) -> str:
    """
    Quick formatting with default settings.

    Args:
        result: CommandResult to format
        max_context_lines: Maximum lines to show
        **kwargs: Additional arguments for OutputFormatter

    Returns:
        Formatted string
    """
    formatter = OutputFormatter(max_context_lines=max_context_lines)
    return formatter.format_for_agent(result, **kwargs)
