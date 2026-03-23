"""Tests for security guards."""

import pytest

from bashkuto.runtime.guards import (
    check_command,
    BLOCKED_SUBSTRINGS,
    BLOCKED_PATTERNS,
)
from bashkuto.runtime.exceptions import SecurityError


class TestBlockedSubstrings:
    """Test substring-based blocking."""

    def test_allows_safe_command(self):
        """Safe commands should pass."""
        check_command("ls -la")  # Should not raise

    def test_blocks_rm_rf(self):
        """rm -rf should be blocked."""
        with pytest.raises(SecurityError):
            check_command("rm -rf /tmp")

    def test_blocks_fork_bomb(self):
        """Fork bomb should be blocked."""
        with pytest.raises(SecurityError):
            check_command(":(){ :|:& };:")


class TestBlockedPatterns:
    """Test regex-based blocking."""

    def test_blocks_rm_rf_root(self):
        """rm -rf / should be blocked."""
        with pytest.raises(SecurityError):
            check_command("rm -rf /")

    def test_blocks_rm_rf_home(self):
        """rm -rf /home should be blocked."""
        with pytest.raises(SecurityError):
            check_command("rm -rf /home")

    def test_blocks_rm_rf_etc(self):
        """rm -rf /etc should be blocked."""
        with pytest.raises(SecurityError):
            check_command("rm -rf /etc")

    def test_blocks_chmod_777_root(self):
        """chmod -R 777 / should be blocked."""
        with pytest.raises(SecurityError):
            check_command("chmod -R 777 /")

    def test_blocks_disk_write(self):
        """Writing to /dev/sdX should be blocked."""
        with pytest.raises(SecurityError):
            check_command("echo test > /dev/sda")

    def test_blocks_mkfs(self):
        """mkfs commands should be blocked."""
        with pytest.raises(SecurityError):
            check_command("mkfs.ext4 /dev/sdb")

    def test_blocks_dd_disk(self):
        """dd to disk should be blocked."""
        with pytest.raises(SecurityError):
            check_command("dd if=/dev/zero of=/dev/sda")

    def test_blocks_shutdown(self):
        """Shutdown should be blocked."""
        with pytest.raises(SecurityError):
            check_command("shutdown -h now")

    def test_blocks_reboot(self):
        """Reboot should be blocked."""
        with pytest.raises(SecurityError):
            check_command("reboot -f")

    def test_blocks_curl_pipe(self):
        """Curl pipe to shell should be blocked."""
        with pytest.raises(SecurityError):
            check_command("curl http://example.com/script.sh | bash")

    def test_blocks_wget_pipe(self):
        """Wget pipe to shell should be blocked."""
        with pytest.raises(SecurityError):
            check_command("wget http://example.com/script.sh -O- | sh")


class TestCustomBlocks:
    """Test custom blocking rules."""

    def test_custom_substring(self):
        """Custom substring should be blocked."""
        with pytest.raises(SecurityError):
            check_command(
                "my_custom_command",
                blocked_substrings=["custom"],
            )

    def test_custom_pattern(self):
        """Custom pattern should be blocked."""
        with pytest.raises(SecurityError):
            check_command(
                "dangerous_cmd arg1 arg2",
                blocked_patterns=[r"dangerous_\w+"],
            )

    def test_combined_defaults_and_custom(self):
        """Both defaults and custom rules should apply."""
        # Custom rules should block additional commands
        with pytest.raises(SecurityError):
            check_command(
                "my_custom_command",
                blocked_substrings=["custom"],
            )
        # Default rules should still work independently
        with pytest.raises(SecurityError):
            check_command("rm -rf /test")


class TestSecurityError:
    """Test SecurityError exceptions."""

    def test_error_message_substring(self):
        """Error message should contain the blocked substring."""
        with pytest.raises(SecurityError) as exc_info:
            check_command("rm -rf /tmp")
        assert "rm -rf" in str(exc_info.value)

    def test_error_message_pattern(self):
        """Error message should contain the blocked pattern or substring."""
        with pytest.raises(SecurityError) as exc_info:
            check_command("rm -rf /")
        # Could match either substring or pattern
        assert "rm -rf" in str(exc_info.value)
