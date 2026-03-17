import json
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class CommandResult:
    """Result of a command execution."""

    output: str
    stderr: str
    exit_code: int
    duration_ms: int
    truncated: bool = False
    overflow_file: Optional[str] = None

    def to_agent_string(self) -> str:
        """Format output for agent consumption (legacy format)."""
        parts = []

        if self.output:
            parts.append(self.output)

        if self.stderr:
            parts.append(f"[stderr]\n{self.stderr}")

        footer = f"[exit:{self.exit_code} | {self.duration_ms}ms]"
        parts.append(footer)

        return "\n".join(parts)

    def to_dict(self) -> dict:
        """Convert to dictionary for structured access."""
        return {
            "stdout": self.output,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "overflow_file": self.overflow_file,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self.exit_code == 0