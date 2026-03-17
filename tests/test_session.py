"""Tests for BashSession."""

import os
import pytest
from pathlib import Path

from bashkuto.runtime.session import BashSession
from bashkuto.runtime.result import CommandResult


class TestBashSession:
    """Test persistent session management."""

    def test_initialization(self):
        """Should initialize with defaults."""
        session = BashSession()
        assert session.cwd == os.getcwd()
        assert session.env is not None

    def test_explicit_change_dir(self, tmp_path):
        """Should change directory explicitly."""
        session = BashSession()
        target = tmp_path / "subdir"
        target.mkdir()
        
        session.change_dir(str(target))
        assert session.cwd == str(target.resolve())

    def test_implicit_change_dir(self, tmp_path):
        """Should track directory changes via cd command."""
        session = BashSession()
        target = tmp_path / "implicit"
        target.mkdir()
        
        # We need to use absolute path for reliable test
        abs_target = str(target.resolve())
        
        # Test command wrapper behavior
        if os.name == "nt":
            cmd = f"cd {abs_target}"
        else:
            cmd = f"cd {abs_target}"
            
        result = session.run(cmd)
        
        assert result.exit_code == 0
        assert session.cwd == abs_target

    def test_env_persistence(self):
        """Should persist environment variables."""
        session = BashSession()
        session.update_env({"TEST_VAR": "persistent_value"})
        
        if os.name == "nt":
            result = session.run("echo %TEST_VAR%")
        else:
            result = session.run("echo $TEST_VAR")
            
        assert "persistent_value" in result.output

    @pytest.mark.asyncio
    async def test_async_session(self, tmp_path):
        """Should support async execution with state."""
        session = BashSession()
        target = tmp_path / "async_dir"
        target.mkdir()
        abs_target = str(target.resolve())
        
        if os.name == "nt":
            cmd = f"cd {abs_target}"
        else:
            cmd = f"cd {abs_target}"

        result = await session.run_async(cmd)
        
        assert result.exit_code == 0
        assert session.cwd == abs_target


class TestBashSessionEdgeCases:
    """Test edge cases for session."""

    def test_cd_failure(self):
        """Should handle cd failure gracefully."""
        session = BashSession()
        original_cwd = session.cwd
        
        # Try to cd to non-existent directory
        result = session.run("cd /nonexistent/path")
        
        # Exit code should be non-zero (from cd)
        assert result.exit_code != 0
        # CWD should be unchanged
        assert session.cwd == original_cwd

    def test_complex_command(self, tmp_path):
        """Should handle complex commands."""
        session = BashSession()
        target = tmp_path / "complex"
        target.mkdir()
        abs_target = str(target.resolve())
        
        if os.name != "nt":
            # "cd target && echo in_target"
            result = session.run(f"cd {abs_target} && echo in_target")
            assert "in_target" in result.output
            assert session.cwd == abs_target
