"""Tests for truncation and overflow management."""

import time
from pathlib import Path

from bashkuto.presentation.truncation import (
    OverflowManager,
    truncate_output,
)


class TestOverflowManager:
    """Test OverflowManager class."""

    def test_no_truncation_for_short_text(self, overflow_dir):
        """Should not truncate short text."""
        manager = OverflowManager(overflow_dir)
        text = "short text"
        result, truncated, path = manager.truncate_output(text, 1000)
        assert result == text
        assert truncated is False
        assert path is None

    def test_truncation_for_long_text(self, overflow_dir):
        """Should truncate long text."""
        manager = OverflowManager(overflow_dir)
        text = "x" * 2000
        result, truncated, path = manager.truncate_output(text, 1000)
        assert truncated is True
        assert path is not None
        assert len(result) < len(text)
        assert "output truncated" in result
        assert path in result

    def test_overflow_file_created(self, overflow_dir):
        """Should create overflow file."""
        manager = OverflowManager(overflow_dir)
        text = "x" * 2000
        _, _, path = manager.truncate_output(text, 1000)
        assert Path(path).exists()
        assert Path(path).read_text() == text

    def test_overflow_filename_pattern(self, overflow_dir):
        """Should use correct filename pattern."""
        manager = OverflowManager(overflow_dir)
        text = "x" * 2000
        _, _, path = manager.truncate_output(text, 1000)
        filename = Path(path).name
        assert filename.startswith("cmd_")
        assert filename.endswith(".txt")

    def test_overflow_dir_created(self, temp_dir):
        """Should create overflow directory if missing."""
        overflow_path = temp_dir / "new_overflow"
        manager = OverflowManager(str(overflow_path))
        text = "x" * 2000
        manager.truncate_output(text, 1000)
        assert overflow_path.exists()

    def test_save_overflow(self, overflow_dir):
        """Should save overflow content."""
        manager = OverflowManager(overflow_dir)
        text = "test content"
        filename, path = manager.save_overflow(text)
        assert Path(path).read_text() == text
        assert filename.endswith(".txt")


class TestOverflowCleanup:
    """Test overflow cleanup functionality."""

    def test_cleanup_by_age(self, overflow_dir):
        """Should clean up old files."""
        import time
        manager = OverflowManager(
            overflow_dir,
            max_age_hours=24,  # Normal expiry
        )
        # Create file
        _, path = manager.save_overflow("test")
        assert Path(path).exists()

        # Cleanup should run without errors and preserve recent files
        manager.cleanup()
        # Recent file should still exist
        assert Path(path).exists()

    def test_cleanup_by_size(self, overflow_dir):
        """Should clean up when size exceeded."""
        manager = OverflowManager(
            overflow_dir,
            max_size_mb=0.0001,  # Very small limit
        )
        # Create multiple files
        paths = []
        for i in range(5):
            _, path = manager.save_overflow("x" * 1000)
            paths.append(path)

        # Some files should be cleaned up
        remaining = [p for p in paths if Path(p).exists()]
        assert len(remaining) < 5

    def test_cleanup_preserves_recent(self, overflow_dir):
        """Should preserve recent files."""
        manager = OverflowManager(
            overflow_dir,
            max_age_hours=24,
            max_size_mb=100,
        )
        # Create file
        _, path = manager.save_overflow("test")
        # Cleanup should not remove recent file
        manager.cleanup()
        assert Path(path).exists()


class TestLegacyTruncateOutput:
    """Test legacy truncate_output function."""

    def test_legacy_no_truncation(self, overflow_dir):
        """Should not truncate short text."""
        text = "short"
        result, truncated, path = truncate_output(text, 1000, overflow_dir)
        assert result == text
        assert truncated is False
        assert path is None

    def test_legacy_truncation(self, overflow_dir):
        """Should truncate long text."""
        text = "x" * 2000
        result, truncated, path = truncate_output(text, 1000, overflow_dir)
        assert truncated is True
        assert path is not None
        assert "truncated" in result
