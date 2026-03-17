"""Output truncation and overflow management."""

import time
import uuid
from pathlib import Path
from typing import Optional, Tuple


class OverflowManager:
    """Manages overflow file lifecycle."""

    def __init__(
        self,
        overflow_dir: str,
        max_age_hours: int = 24,
        max_size_mb: int = 100
    ):
        """
        Initialize overflow manager.

        Args:
            overflow_dir: Directory to store overflow files
            max_age_hours: Maximum age of files before cleanup
            max_size_mb: Maximum total size of overflow directory
        """
        self.overflow_dir = Path(overflow_dir)
        self.max_age_hours = max_age_hours
        self.max_size_mb = max_size_mb

    def save_overflow(self, text: str) -> Tuple[str, str]:
        """
        Save overflow content to file.

        Args:
            text: Full output text to save

        Returns:
            Tuple of (filename, absolute_path)
        """
        self.overflow_dir.mkdir(parents=True, exist_ok=True)

        filename = f"cmd_{uuid.uuid4().hex[:12]}.txt"
        path = self.overflow_dir / filename
        path.write_text(text, encoding="utf-8")

        # Cleanup after saving
        self.cleanup()

        return filename, str(path)

    def truncate_output(
        self,
        text: str,
        max_chars: int
    ) -> Tuple[str, bool, Optional[str]]:
        """
        Truncate output if it exceeds max_chars.

        Args:
            text: Output text to potentially truncate
            max_chars: Maximum characters before truncation

        Returns:
            Tuple of (text, truncated_flag, overflow_file_path)
        """
        if len(text) <= max_chars:
            return text, False, None

        _, path = self.save_overflow(text)

        truncated = text[:max_chars]
        truncated += "\n\n--- output truncated ---"
        truncated += f"\nFull output: {path}"

        return truncated, True, path

    def cleanup(self):
        """Remove old files based on age and size."""
        if not self.overflow_dir.exists():
            return

        self._cleanup_by_age()
        self._cleanup_by_size()

    def _cleanup_by_age(self):
        """Remove files older than max_age_hours."""
        cutoff = time.time() - (self.max_age_hours * 3600)

        for file in self.overflow_dir.glob("cmd_*.txt"):
            if file.stat().st_mtime < cutoff:
                file.unlink()

    def _cleanup_by_size(self):
        """Remove oldest files if directory exceeds size limit."""
        try:
            files = sorted(
                self.overflow_dir.glob("cmd_*.txt"),
                key=lambda f: f.stat().st_mtime
            )
        except OSError:
            return

        total_size_mb = sum(f.stat().st_size for f in files) / (1024 * 1024)

        while files and total_size_mb > self.max_size_mb:
            oldest = files.pop(0)
            try:
                oldest.unlink()
                total_size_mb = sum(
                    f.stat().st_size for f in files
                ) / (1024 * 1024)
            except OSError:
                break


# Legacy function for backward compatibility
def truncate_output(
    text: str,
    max_chars: int,
    overflow_dir: str
) -> Tuple[str, bool, Optional[str]]:
    """
    Truncate output if it exceeds max_chars (legacy function).

    Args:
        text: Output text to potentially truncate
        max_chars: Maximum characters before truncation
        overflow_dir: Directory to store overflow files

    Returns:
        Tuple of (text, truncated_flag, overflow_file_path)
    """
    manager = OverflowManager(overflow_dir)
    return manager.truncate_output(text, max_chars)