"""Tests for CommandResult."""

import json

from bashkuto.runtime.result import CommandResult


class TestCommandResult:
    """Test CommandResult dataclass."""

    def test_basic_creation(self):
        """Should create result with basic fields."""
        result = CommandResult(
            output="hello",
            stderr="",
            exit_code=0,
            duration_ms=100,
        )
        assert result.output == "hello"
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.duration_ms == 100
        assert result.truncated is False
        assert result.overflow_file is None

    def test_success_property(self):
        """Success should be true for exit code 0."""
        result_success = CommandResult("out", "", 0, 100)
        result_failure = CommandResult("out", "", 1, 100)
        assert result_success.success is True
        assert result_failure.success is False

    def test_to_agent_string(self):
        """Should format output for agents."""
        result = CommandResult("output", "error", 0, 100)
        agent_str = result.to_agent_string()
        assert "output" in agent_str
        assert "error" in agent_str
        assert "[exit:0 | 100ms]" in agent_str

    def test_to_agent_string_no_stderr(self):
        """Should omit stderr when empty."""
        result = CommandResult("output", "", 0, 100)
        agent_str = result.to_agent_string()
        assert "[stderr]" not in agent_str

    def test_to_dict(self):
        """Should convert to dictionary."""
        result = CommandResult(
            output="out",
            stderr="err",
            exit_code=0,
            duration_ms=100,
            truncated=True,
            overflow_file="/tmp/file.txt",
        )
        d = result.to_dict()
        assert d["stdout"] == "out"
        assert d["stderr"] == "err"
        assert d["exit_code"] == 0
        assert d["duration_ms"] == 100
        assert d["truncated"] is True
        assert d["overflow_file"] == "/tmp/file.txt"

    def test_to_json(self):
        """Should convert to JSON string."""
        result = CommandResult("out", "err", 0, 100)
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["stdout"] == "out"
        assert parsed["stderr"] == "err"
        assert parsed["exit_code"] == 0
        assert parsed["duration_ms"] == 100

    def test_to_json_indent(self):
        """Should support custom indent."""
        result = CommandResult("out", "err", 0, 100)
        json_str = result.to_json(indent=4)
        assert "    " in json_str  # 4-space indent

    def test_full_result_workflow(self):
        """Test complete result with all fields."""
        result = CommandResult(
            output="command output\nwith multiple lines",
            stderr="warning: something",
            exit_code=0,
            duration_ms=250,
            truncated=True,
            overflow_file=".bashkuto_overflow/cmd_abc123.txt",
        )
        assert result.success is True
        assert result.truncated is True
        assert "command output" in result.to_agent_string()
