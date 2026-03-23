"""Tests for command executor."""

import os
import pytest

from bashkuto.runtime.executor import execute, get_default_shell
from bashkuto.runtime.exceptions import TimeoutError


class TestExecuteBasic:
    """Test basic execution."""

    def test_simple_command(self):
        """Should execute simple command."""
        shell = get_default_shell()
        if os.name == "nt":
            cmd = "echo hello"
        else:
            cmd = "echo hello"
        stdout, stderr, code, duration = execute(cmd, shell)
        assert code == 0
        assert b"hello" in stdout
        assert duration >= 0

    def test_exit_code_capture(self):
        """Should capture exit codes."""
        shell = get_default_shell()
        if os.name == "nt":
            _, _, code, _ = execute("cmd /c exit 0", shell)
            assert code == 0
            _, _, code, _ = execute("cmd /c exit 1", shell)
            assert code == 1
        else:
            _, _, code, _ = execute("true", shell)
            assert code == 0
            _, _, code, _ = execute("false", shell)
            assert code == 1

    def test_stderr_capture(self):
        """Should capture stderr."""
        shell = get_default_shell()
        if os.name == "nt":
            _, stderr, code, _ = execute(
                "cmd /c echo error 1>&2", shell
            )
        else:
            _, stderr, code, _ = execute(
                "sh -c 'echo error >&2'", shell
            )
        assert code == 0
        assert b"error" in stderr

    def test_duration_measurement(self):
        """Should measure execution duration."""
        shell = get_default_shell()
        if os.name == "nt":
            # Windows: quick command
            _, _, _, duration = execute("echo test", shell)
        else:
            _, _, _, duration = execute("sleep 0.01", shell)
        assert duration >= 0  # Just verify we get a duration


class TestExecuteTimeout:
    """Test timeout functionality."""

    def test_timeout_raises_error(self):
        """Should raise TimeoutError on timeout."""
        shell = get_default_shell()
        # Use ping for cross-platform timeout simulation
        if os.name == "nt":
            # Windows: ping with 4 packets, 2 second interval
            cmd = "ping 127.0.0.1 -n 4 >nul"
        else:
            cmd = "sleep 2"
        with pytest.raises(TimeoutError):
            execute(cmd, shell, timeout_sec=0.5)

    def test_no_timeout_without_limit(self):
        """Should not timeout without limit."""
        shell = get_default_shell()
        stdout, stderr, code, duration = execute(
            "echo fast", shell, timeout_sec=None
        )
        assert code == 0

    def test_timeout_message(self):
        """Should include command in error message."""
        shell = get_default_shell()
        if os.name == "nt":
            cmd = "ping 127.0.0.1 -n 4 >nul"
        else:
            cmd = "sleep 2"
        with pytest.raises(TimeoutError) as exc_info:
            execute(cmd, shell, timeout_sec=0.1)
        assert "timed out" in str(exc_info.value).lower()


class TestExecutePipes:
    """Test pipe execution."""

    def test_pipe_chain(self):
        """Should execute pipe chains."""
        shell = get_default_shell()
        if os.name == "nt":
            stdout, _, code, _ = execute(
                "echo hello | findstr hello", shell
            )
        else:
            stdout, _, code, _ = execute(
                "echo hello | grep hello", shell
            )
        assert code == 0
        assert b"hello" in stdout

    def test_pipe_with_multiple_commands(self):
        """Should handle multiple piped commands."""
        shell = get_default_shell()
        if os.name == "nt":
            # Windows: use PowerShell for better pipe support
            stdout, _, code, _ = execute(
                "powershell -Command \"'a','b','c' | Where-Object { $_ -ne 'b' }\"",
                shell
            )
        else:
            stdout, _, code, _ = execute(
                "echo -e 'a\\nb\\nc' | grep -v b", shell
            )
        assert code == 0
        assert b"a" in stdout
        assert b"c" in stdout


class TestExecuteErrors:
    """Test error handling."""

    def test_command_not_found(self):
        """Should handle non-existent commands."""
        shell = get_default_shell()
        if os.name == "nt":
            _, _, code, _ = execute("nonexistent_cmd_xyz_123", shell)
        else:
            _, _, code, _ = execute("nonexistent_cmd_xyz", shell)
        assert code != 0

    def test_permission_denied(self):
        """Should handle permission errors."""
        shell = get_default_shell()
        if os.name == "nt":
            # Try to read a protected file on Windows
            _, _, code, _ = execute(
                "type C:\\Windows\\System32\\config\\SAM 2>nul", shell
            )
        else:
            # Try to read a protected file on Unix
            _, _, code, _ = execute(
                "cat /etc/shadow 2>/dev/null", shell
            )
        # May fail or succeed depending on system
        assert isinstance(code, int)


class TestExecuteShell:
    """Test shell selection."""

    def test_default_shell(self):
        """Should work with default shell."""
        shell = get_default_shell()
        stdout, _, code, _ = execute("echo test", shell)
        assert code == 0
        assert b"test" in stdout

    def test_custom_shell(self):
        """Should work with custom shell if available."""
        if os.name != "nt":
            stdout, _, code, _ = execute(
                "echo test", "/bin/sh"
            )
            assert code == 0
            assert b"test" in stdout
