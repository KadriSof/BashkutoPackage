from dataclasses import dataclass
from typing import Optional


@dataclass
class CommandResult:
    output: str
    stderr: str
    exit_code: int
    duration_ms: int
    truncated: bool = False
    overflow_file: Optional[str] = None

    def to_agent_string(self) -> str:
        parts = []

        if self.output:
            parts.append(self.output)

        if self.stderr:
            parts.append(f"[stderr]\n{self.stderr}")

        footer = f"[exit:{self.exit_code} | {self.duration_ms}ms]"
        parts.append(footer)

        return "\n".join(parts)