"""Tests for output formatter."""

from bashkuto.presentation.formatter import OutputFormatter, format_result
from bashkuto.runtime.result import CommandResult


class TestOutputFormatter:
    """Test OutputFormatter class."""

    def test_format_success(self):
        """Should format successful command."""
        result = CommandResult("output", "", 0, 100)
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(result)
        assert "[SUCCESS]" in formatted
        assert "output" in formatted

    def test_format_failure(self):
        """Should format failed command."""
        result = CommandResult("", "error", 1, 100)
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(result)
        assert "[FAILED]" in formatted
        assert "Exit code: 1" in formatted

    def test_format_with_stderr(self):
        """Should include stderr when present."""
        result = CommandResult("out", "stderr message", 0, 100)
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(result)
        assert "--- STDERR ---" in formatted
        assert "stderr message" in formatted

    def test_format_exclude_stderr(self):
        """Should exclude stderr when requested."""
        result = CommandResult("out", "stderr message", 0, 100)
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(
            result, include_stderr=False
        )
        assert "--- STDERR ---" not in formatted
        assert "stderr message" not in formatted

    def test_format_truncated(self):
        """Should show truncation notice."""
        result = CommandResult(
            "out", "", 0, 100,
            truncated=True,
            overflow_file="/tmp/file.txt",
        )
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(result)
        assert "[TRUNCATED]" in formatted
        assert "/tmp/file.txt" in formatted

    def test_format_metadata(self):
        """Should include duration metadata."""
        result = CommandResult("out", "", 0, 150)
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(result)
        assert "[Duration: 150ms]" in formatted

    def test_format_exclude_metadata(self):
        """Should exclude metadata when requested."""
        result = CommandResult("out", "", 0, 150)
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(
            result, include_metadata=False
        )
        assert "[Duration:" not in formatted

    def test_format_compact(self):
        """Should use compact format."""
        result = CommandResult("out", "", 0, 100)
        formatter = OutputFormatter()
        formatted = formatter.format_for_agent(result, compact=True)
        assert "[SUCCESS]" not in formatted  # No success indicator
        assert " " in formatted  # Space-separated

    def test_format_truncation_lines(self):
        """Should truncate long output."""
        long_output = "\n".join([f"line {i}" for i in range(100)])
        result = CommandResult(long_output, "", 0, 100)
        formatter = OutputFormatter(max_context_lines=20)
        formatted = formatter.format_for_agent(result)
        assert "lines omitted" in formatted
        assert "line 0" in formatted  # First lines present
        assert "line 99" in formatted  # Last lines present

    def test_format_no_truncation_short(self):
        """Should not truncate short output."""
        result = CommandResult("short output", "", 0, 100)
        formatter = OutputFormatter(max_context_lines=50)
        formatted = formatter.format_for_agent(result)
        assert "omitted" not in formatted


class TestFormatResult:
    """Test format_result convenience function."""

    def test_format_result_function(self):
        """Should format with defaults."""
        result = CommandResult("out", "", 0, 100)
        formatted = format_result(result)
        assert "[SUCCESS]" in formatted

    def test_format_result_custom_lines(self):
        """Should support custom max lines."""
        long_output = "\n".join([f"line {i}" for i in range(100)])
        result = CommandResult(long_output, "", 0, 100)
        formatted = format_result(result, max_context_lines=10)
        assert "lines omitted" in formatted
