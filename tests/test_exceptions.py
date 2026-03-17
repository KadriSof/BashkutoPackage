"""Tests for exceptions."""

import pytest

from bashkuto import (
    BashkutoError,
    SecurityError,
    TimeoutError,
    BinaryOutputError,
    OverflowError,
)


class TestExceptionHierarchy:
    """Test exception class hierarchy."""

    def test_security_error_subclass(self):
        """SecurityError should be subclass of BashkutoError."""
        assert issubclass(SecurityError, BashkutoError)

    def test_timeout_error_subclass(self):
        """TimeoutError should be subclass of BashkutoError."""
        assert issubclass(TimeoutError, BashkutoError)

    def test_binary_output_error_subclass(self):
        """BinaryOutputError should be subclass of BashkutoError."""
        assert issubclass(BinaryOutputError, BashkutoError)

    def test_overflow_error_subclass(self):
        """OverflowError should be subclass of BashkutoError."""
        assert issubclass(OverflowError, BashkutoError)


class TestExceptionInstances:
    """Test exception instances."""

    def test_security_error_message(self):
        """SecurityError should have descriptive message."""
        try:
            raise SecurityError("Test blocked command")
        except SecurityError as e:
            assert "Test blocked command" in str(e)

    def test_timeout_error_message(self):
        """TimeoutError should have descriptive message."""
        try:
            raise TimeoutError("Command timed out after 30s")
        except TimeoutError as e:
            assert "timed out" in str(e).lower()

    def test_catch_as_bashkuto_error(self):
        """Should catch specific errors as BashkutoError."""
        try:
            raise SecurityError("test")
        except BashkutoError as e:
            assert isinstance(e, SecurityError)

        try:
            raise TimeoutError("test")
        except BashkutoError as e:
            assert isinstance(e, TimeoutError)


class TestExceptionUsage:
    """Test exception usage in context."""

    def test_security_error_in_runtime(self):
        """Runtime should raise SecurityError for blocked commands."""
        from bashkuto import BashRuntime

        runtime = BashRuntime()
        with pytest.raises(SecurityError):
            runtime.run("rm -rf /")

    def test_timeout_error_in_runtime(self):
        """Runtime should raise TimeoutError on timeout."""
        from bashkuto import BashRuntime

        runtime = BashRuntime(timeout_sec=0.1)
        with pytest.raises(TimeoutError):
            runtime.run("sleep 1")
