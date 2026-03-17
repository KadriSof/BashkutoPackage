"""Filesystem utilities for bashkuto."""

from pathlib import Path
from typing import Optional


def ensure_dir(path: str) -> Path:
    """
    Create directory if it doesn't exist.

    Args:
        path: Directory path to create

    Returns:
        Path object for the directory
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def safe_write(path: Path, content: str) -> None:
    """
    Write content to file safely.

    Args:
        path: File path to write to
        content: Text content to write
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def safe_read(path: Path, default: Optional[str] = None) -> Optional[str]:
    """
    Read file content safely.

    Args:
        path: File path to read from
        default: Default value if file doesn't exist

    Returns:
        File content or default value
    """
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def file_size_mb(path: Path) -> float:
    """
    Get file size in megabytes.

    Args:
        path: File path

    Returns:
        File size in MB
    """
    if not path.exists():
        return 0.0
    return path.stat().st_size / (1024 * 1024)


def directory_size_mb(path: Path, pattern: str = "*") -> float:
    """
    Get total size of files in directory matching pattern.

    Args:
        path: Directory path
        pattern: Glob pattern for files

    Returns:
        Total size in MB
    """
    if not path.exists():
        return 0.0
    return sum(f.stat().st_size for f in path.glob(pattern)) / (1024 * 1024)
