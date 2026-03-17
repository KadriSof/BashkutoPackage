"""Tests for filesystem utilities."""

from pathlib import Path

from bashkuto.utils.filesystem import (
    ensure_dir,
    safe_write,
    safe_read,
    file_size_mb,
    directory_size_mb,
)


class TestEnsureDir:
    """Test ensure_dir function."""

    def test_create_new_directory(self, temp_dir):
        """Should create new directory."""
        new_dir = temp_dir / "new_folder"
        result = ensure_dir(str(new_dir))
        assert result.exists()
        assert result.is_dir()

    def test_existing_directory(self, temp_dir):
        """Should not fail for existing directory."""
        result = ensure_dir(str(temp_dir))
        assert result.exists()

    def test_create_nested_directories(self, temp_dir):
        """Should create nested directories."""
        nested = temp_dir / "a" / "b" / "c"
        result = ensure_dir(str(nested))
        assert result.exists()
        assert result.parent.exists()


class TestSafeWrite:
    """Test safe_write function."""

    def test_write_file(self, temp_dir):
        """Should write file content."""
        path = temp_dir / "test.txt"
        safe_write(path, "hello world")
        assert path.read_text() == "hello world"

    def test_create_parent_dirs(self, temp_dir):
        """Should create parent directories."""
        path = temp_dir / "subdir" / "test.txt"
        safe_write(path, "content")
        assert path.read_text() == "content"

    def test_overwrite_file(self, temp_dir):
        """Should overwrite existing file."""
        path = temp_dir / "test.txt"
        safe_write(path, "first")
        safe_write(path, "second")
        assert path.read_text() == "second"


class TestSafeRead:
    """Test safe_read function."""

    def test_read_existing_file(self, temp_dir):
        """Should read existing file."""
        path = temp_dir / "test.txt"
        path.write_text("content")
        result = safe_read(path)
        assert result == "content"

    def test_read_nonexistent_default(self, temp_dir):
        """Should return default for missing file."""
        path = temp_dir / "missing.txt"
        result = safe_read(path, default="default")
        assert result == "default"

    def test_read_nonexistent_none(self, temp_dir):
        """Should return None for missing file."""
        path = temp_dir / "missing.txt"
        result = safe_read(path)
        assert result is None


class TestFileSize:
    """Test file_size_mb function."""

    def test_file_size_calculation(self, temp_dir):
        """Should calculate file size correctly."""
        path = temp_dir / "test.txt"
        # Write 1 KB
        path.write_text("x" * 1024)
        size = file_size_mb(path)
        assert abs(size - 0.001) < 0.0001  # ~1 KB in MB

    def test_nonexistent_file_size(self, temp_dir):
        """Should return 0 for missing file."""
        path = temp_dir / "missing.txt"
        size = file_size_mb(path)
        assert size == 0.0


class TestDirectorySize:
    """Test directory_size_mb function."""

    def test_directory_size_calculation(self, temp_dir):
        """Should calculate directory size."""
        # Create files totaling ~3 KB
        for i in range(3):
            path = temp_dir / f"file{i}.txt"
            path.write_text("x" * 1024)

        size = directory_size_mb(temp_dir)
        assert abs(size - 0.003) < 0.0001  # ~3 KB in MB

    def test_empty_directory(self, temp_dir):
        """Should return 0 for empty directory."""
        size = directory_size_mb(temp_dir)
        assert size == 0.0

    def test_nonexistent_directory(self, temp_dir):
        """Should return 0 for missing directory."""
        path = temp_dir / "missing"
        size = directory_size_mb(path)
        assert size == 0.0

    def test_directory_with_pattern(self, temp_dir):
        """Should filter by pattern."""
        # Create mixed files
        (temp_dir / "test.txt").write_text("x" * 1024)
        (temp_dir / "test.log").write_text("y" * 1024)

        # Only count .txt files
        size = directory_size_mb(temp_dir, pattern="*.txt")
        assert abs(size - 0.001) < 0.0001
