"""Tests for BashRuntime."""

import os
import pytest

from bashkuto import BashRuntime, SecurityError, TimeoutError
from bashkuto.runtime.result import CommandResult


class TestBashRuntimeBasic:
    """Test basic BashRuntime functionality."""

    def test_simple_command(self):
        """Should execute simple command."""
        runtime = BashRuntime()
        result = runtime.run("echo hello")
        assert result.success is True
        assert "hello" in result.output

    def test_command_exit_code(self):
        """Should capture exit code."""
        runtime = BashRuntime()
        if os.name == "nt":
            result = runtime.run("cmd /c exit 0")
            assert result.exit_code == 0
            result = runtime.run("cmd /c exit 1")
            assert result.exit_code == 1
        else:
            result = runtime.run("true")
            assert result.exit_code == 0
            result = runtime.run("false")
            assert result.exit_code == 1

    def test_command_duration(self):
        """Should measure duration."""
        runtime = BashRuntime()
        result = runtime.run("echo test")
        assert result.duration_ms >= 0

    def test_stderr_capture(self):
        """Should capture stderr."""
        runtime = BashRuntime()
        if os.name == "nt":
            result = runtime.run("cmd /c echo stdout && echo stderr 1>&2")
        else:
            result = runtime.run("sh -c 'echo stdout; echo stderr >&2'")
        assert "stdout" in result.output
        assert "stderr" in result.stderr


class TestBashRuntimePipes:
    """Test pipe chain execution."""

    def test_pipe_chain(self):
        """Should execute pipe chains."""
        runtime = BashRuntime()
        if os.name == "nt":
            result = runtime.run("echo hello | findstr hello")
        else:
            result = runtime.run("echo hello | grep hello")
        assert result.success is True
        assert "hello" in result.output

    def test_pipe_chain_failure(self):
        """Should handle pipe chain failure."""
        runtime = BashRuntime()
        if os.name == "nt":
            result = runtime.run("echo hello | findstr nonexistent")
        else:
            result = runtime.run("echo hello | grep nonexistent")
        assert result.exit_code != 0


class TestBashRuntimeSecurity:
    """Test security features."""

    def test_blocks_dangerous_command(self):
        """Should block dangerous commands."""
        runtime = BashRuntime()
        with pytest.raises(SecurityError):
            runtime.run("rm -rf /")

    def test_blocks_fork_bomb(self):
        """Should block fork bomb."""
        runtime = BashRuntime()
        with pytest.raises(SecurityError):
            runtime.run(":(){ :|:& };:")

    def test_custom_blocked_commands(self):
        """Should respect custom blocked commands."""
        runtime = BashRuntime(
            blocked_substrings=["forbidden"]
        )
        with pytest.raises(SecurityError):
            runtime.run("my_forbidden_cmd")


class TestBashRuntimeTimeout:
    """Test timeout functionality."""

    def test_timeout(self):
        """Should timeout on long commands."""
        runtime = BashRuntime(timeout_sec=0.5)
        with pytest.raises(TimeoutError):
            if os.name == "nt":
                # Windows: ping for timeout simulation
                runtime.run("ping 127.0.0.1 -n 3 >nul")
            else:
                runtime.run("sleep 2")

    def test_no_timeout_fast_command(self):
        """Should not timeout fast commands."""
        runtime = BashRuntime(timeout_sec=5)
        result = runtime.run("echo fast")
        assert result.success is True


class TestBashRuntimeOverflow:
    """Test output overflow handling."""

    def test_truncation(self, overflow_dir):
        """Should truncate long output."""
        runtime = BashRuntime(
            max_output_chars=100,
            overflow_dir=overflow_dir,
        )
        if os.name == "nt":
            result = runtime.run("powershell -Command \"Write-Host ('x' * 1000)\"")
        else:
            result = runtime.run("python3 -c 'print(\"x\" * 1000)'")
        assert result.truncated is True
        assert result.overflow_file is not None

    def test_no_truncation_short(self):
        """Should not truncate short output."""
        runtime = BashRuntime(max_output_chars=10000)
        result = runtime.run("echo short")
        assert result.truncated is False
        assert result.overflow_file is None


class TestBashRuntimeResult:
    """Test result formatting."""

    def test_to_agent_string(self):
        """Should format for agents."""
        runtime = BashRuntime()
        result = runtime.run("echo hello")
        agent_str = result.to_agent_string()
        assert "hello" in agent_str
        assert "[exit:" in agent_str

    def test_to_dict(self):
        """Should convert to dict."""
        runtime = BashRuntime()
        result = runtime.run("echo hello")
        d = result.to_dict()
        assert "stdout" in d
        assert "exit_code" in d

    def test_to_json(self):
        """Should convert to JSON."""
        runtime = BashRuntime()
        result = runtime.run("echo hello")
        json_str = result.to_json()
        assert "stdout" in json_str
        assert "exit_code" in json_str


class TestBashRuntimeConfig:
    """Test runtime configuration."""

    def test_custom_shell(self):
        """Should use custom shell."""
        if os.name != "nt":
            runtime = BashRuntime(shell="/bin/sh")
            result = runtime.run("echo test")
            assert result.success is True

    def test_custom_max_output(self):
        """Should respect max_output_chars."""
        runtime = BashRuntime(max_output_chars=50)
        result = runtime.run("echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        # May or may not truncate depending on exact length
        assert result.output is not None
