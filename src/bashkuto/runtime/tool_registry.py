"""Tool Registry for managing agent-created shell tools."""

import json
import os
import re
import stat
from pathlib import Path
from typing import Dict, List, Optional, Set

from .exceptions import SecurityError

# Primary security imports from Paragon
from ..security import (
    Paragon,
    BlockedPatternRule,
    BlockedSubstringRule,
)

# Backward compatibility: import from guards.py (deprecated)
from .guards import BLOCKED_PATTERNS, BLOCKED_SUBSTRINGS


class ToolRegistry:
    """
    Manages agent-created shell tools.

    Tools are stored as executable shell scripts in a dedicated directory.
    Each tool can have associated metadata stored in a JSON file.

    Supports optional Paragon security engine via dependency injection.
    If no Paragon instance is provided, falls back to built-in validation.
    """

    def __init__(
        self,
        tool_dir: str = ".bashkuto_tools",
        blocked_patterns: Optional[List[str]] = None,
        tool_allowlist: Optional[List[str]] = None,
        allowlist_mode: str = "permissive",
        paragon: Optional["Paragon"] = None,
    ):
        """
        Initialize ToolRegistry.

        Args:
            tool_dir: Directory to store tools (default: .bashkuto_tools)
            blocked_patterns: Additional regex patterns to block in scripts
            tool_allowlist: If provided, only allow these commands in tools.
                Note: This checks the first command of each line only. Shell
                metacharacters (pipes, redirects, etc.) are still allowed to
                enable natural Unix workflows. Security relies primarily on
                BLOCKED_PATTERNS and BLOCKED_SUBSTRINGS for dangerous commands.
            allowlist_mode: Deprecated. Kept for API compatibility.
                All modes now behave as "permissive" to enable AI agent workflows.
                Security is enforced via BLOCKED_PATTERNS/SUBSTRINGS instead.
            paragon: Optional Paragon security engine for validation.
                If provided, Paragon's validate_script() will be used.
                If None, falls back to built-in _validate_script().
        """
        self.tool_dir = Path(tool_dir).resolve()
        self._blocked_patterns: List[str] = (
            BLOCKED_PATTERNS + (blocked_patterns or [])
        )
        self._compiled_patterns: List[re.Pattern] = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self._blocked_patterns
        ]
        self._tool_allowlist: Optional[Set[str]] = (
            set(tool_allowlist) if tool_allowlist else None
        )
        self._allowlist_mode: str = allowlist_mode  # Deprecated, kept for compatibility
        self._paragon: Optional["Paragon"] = paragon

        # Auto-create tool directory
        self._ensure_tool_dir()

    def _ensure_tool_dir(self) -> None:
        """Create tool directory if it doesn't exist."""
        self.tool_dir.mkdir(parents=True, exist_ok=True)
        # Ensure directory is not world-writable on Unix systems
        if os.name != "nt":
            mode = self.tool_dir.stat().st_mode
            self.tool_dir.chmod(mode & ~stat.S_IWOTH)

    def _validate_script(self, script: str) -> None:
        """
        Validate script for dangerous patterns.

        If Paragon is configured via dependency injection, delegates to
        Paragon's validate_script(). Otherwise, uses built-in validation.

        Args:
            script: The shell script content to validate

        Raises:
            SecurityError: If script contains dangerous patterns
        """
        # Use Paragon if configured
        if self._paragon is not None:
            self._paragon.validate_script(script)
            return

        # Fall back to built-in validation
        self._check_blocked_substrings(script)
        self._check_blocked_patterns(script)
        self._check_dangerous_command_patterns(script)
        self._check_code_injection_patterns(script)
        self._check_allowlist(script)

    @staticmethod
    def _check_blocked_substrings(script: str) -> None:
        """Check script for blocked substrings."""
        for substring in BLOCKED_SUBSTRINGS:
            if substring in script:
                raise SecurityError(
                    f"Script contains blocked substring: '{substring}'"
                )

    def _check_blocked_patterns(self, script: str) -> None:
        """Check script for blocked regex patterns."""
        for pattern, compiled in zip(self._blocked_patterns, self._compiled_patterns):
            if compiled.search(script):
                raise SecurityError(
                    f"Script contains blocked pattern: '{pattern}'"
                )

    @staticmethod
    def _check_dangerous_command_patterns(script: str) -> None:
        """Check for dangerous commands with variable argument forwarding."""
        dangerous_commands = [
            "rm", "chmod", "chown", "dd", "mkfs", "fdisk", "parted",
            "shutdown", "reboot", "poweroff", "halt", "curl", "wget",
            "nc", "netcat", "ssh", "scp", "rsync"
        ]

        for line in script.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for cmd in dangerous_commands:
                pattern = rf'\b{cmd}\s+.*?["\']?\$(\{{)?[@*0-9]+(\}})?["\']?'
                if re.search(pattern, line):
                    raise SecurityError(
                        f"Script contains dangerous command '{cmd}' with variable "
                        f"arguments that could bypass security. Use explicit argument "
                        f"validation instead."
                    )

    @staticmethod
    def _check_code_injection_patterns(script: str) -> None:
        """Check for code injection patterns (eval, exec, dynamic execution)."""
        injection_patterns = [
            (r'\beval\b.*\$', "eval with variable expansion"),
            (r'\bexec\b.*\$', "exec with variable expansion"),
            (r'\bbash\s+(-[a-zA-Z]+\s+)*["\']?\$', "bash with variable (script injection)"),
            (r'\bsh\s+(-[a-zA-Z]+\s+)*["\']?\$', "sh with variable (script injection)"),
            (r'\bsource\b.*\$', "source with variable expansion"),
            (r'\.\s+["\']?\$', "dot-source with variable expansion"),
        ]
        for pattern, description in injection_patterns:
            if re.search(pattern, script, re.IGNORECASE):
                raise SecurityError(
                    f"Script contains potentially dangerous pattern: {description}. "
                    f"This could allow code injection attacks."
                )

    def _check_allowlist(self, script: str) -> None:
        """Check script commands against allowlist if configured."""
        if self._tool_allowlist is None:
            return

        lines = script.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            tokens = line.split()
            if tokens:
                cmd = tokens[0]
                cmd = re.sub(r"^[|;&<>]+", "", cmd)
                if cmd and cmd not in self._tool_allowlist:
                    raise SecurityError(
                        f"Command '{cmd}' is not in the allowlist. "
                        f"Allowed: {sorted(self._tool_allowlist)}"
                    )

    def create_tool(
        self,
        name: str,
        script: str,
        description: str = "",
        created_by: str = "agent",
    ) -> Path:
        """
        Create a new tool.
        
        Args:
            name: Tool name (will be used as filename without extension)
            script: Shell script content
            description: Optional tool description
            created_by: Creator identifier (default: "agent")
            
        Returns:
            Path to the created tool script
            
        Raises:
            SecurityError: If script contains dangerous patterns
            ValueError: If tool name is invalid
        """
        # Validate tool name
        if not name:
            raise ValueError("Tool name cannot be empty")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", name):
            raise ValueError(
                f"Invalid tool name '{name}'. Must start with letter and contain "
                "only letters, numbers, underscores, and hyphens."
            )
        
        # Validate script content
        self._validate_script(script)
        
        # Ensure script starts with shebang or is a valid shell script
        script_content = script.strip()
        if not script_content.startswith("#!"):
            script_content = "#!/bin/bash\n" + script_content
        
        # Create tool script path
        tool_path = self.tool_dir / f"{name}.sh"
        metadata_path = self.tool_dir / f"{name}.json"
        
        # Write script atomically
        tool_path.write_text(script_content, encoding="utf-8")
        
        # Make executable (chmod 0o755)
        if os.name != "nt":
            current_mode = tool_path.stat().st_mode
            tool_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        # Create metadata
        import datetime
        metadata = {
            "name": name,
            "description": description,
            "created_by": created_by,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "usage_count": 0,
            "last_used": None,
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        
        return tool_path

    def tool_exists(self, name: str) -> bool:
        """Check if a tool exists."""
        tool_path = self.tool_dir / f"{name}.sh"
        return tool_path.exists() and tool_path.is_file()

    def get_tool_path(self, name: str) -> Optional[Path]:
        """
        Get the path to a tool script if it exists.
        
        Args:
            name: Tool name
            
        Returns:
            Path to tool script or None if not found
        """
        tool_path = self.tool_dir / f"{name}.sh"
        if tool_path.exists() and tool_path.is_file():
            return tool_path
        return None

    def get_script(self, name: str) -> Optional[str]:
        """
        Get the script content for a tool.
        
        Args:
            name: Tool name
            
        Returns:
            Script content or None if tool doesn't exist
        """
        tool_path = self.get_tool_path(name)
        if tool_path:
            return tool_path.read_text(encoding="utf-8")
        return None

    def delete_tool(self, name: str) -> bool:
        """
        Delete a tool.
        
        Args:
            name: Tool name
            
        Returns:
            True if tool was deleted, False if it didn't exist
        """
        tool_path = self.tool_dir / f"{name}.sh"
        metadata_path = self.tool_dir / f"{name}.json"
        
        deleted = False
        if tool_path.exists():
            tool_path.unlink()
            deleted = True
        
        if metadata_path.exists():
            metadata_path.unlink()
        
        return deleted

    def list_tools(self) -> List[str]:
        """
        List all available tool names.
        
        Returns:
            List of tool names (without .sh extension)
        """
        if not self.tool_dir.exists():
            return []
        
        tools = []
        for path in self.tool_dir.glob("*.sh"):
            if path.is_file():
                tools.append(path.stem)
        
        return sorted(tools)

    def describe_tool(self, name: str) -> Optional[Dict]:
        """
        Get full metadata for a tool.
        
        Args:
            name: Tool name
            
        Returns:
            Tool metadata dict or None if tool doesn't exist
        """
        metadata_path = self.tool_dir / f"{name}.json"
        if not metadata_path.exists():
            return None
        
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            # Include script content
            metadata["script"] = self.get_script(name)
            return metadata
        except (json.JSONDecodeError, IOError):
            return None

    def search_tools(self, query: str) -> List[str]:
        """
        Search tools by description.
        
        Args:
            query: Search query (substring match)
            
        Returns:
            List of matching tool names
        """
        matching = []
        query_lower = query.lower()
        
        for name in self.list_tools():
            metadata = self.describe_tool(name)
            if metadata:
                description = metadata.get("description", "").lower()
                if query_lower in description or query_lower in name.lower():
                    matching.append(name)
        
        return sorted(matching)

    def add_blocked_pattern(self, pattern: str) -> None:
        """
        Add a custom blocked pattern.
        
        Args:
            pattern: Regex pattern to block
        """
        if pattern not in self._blocked_patterns:
            self._blocked_patterns.append(pattern)
            self._compiled_patterns.append(
                re.compile(pattern, re.IGNORECASE)
            )

    def remove_blocked_pattern(self, pattern: str) -> bool:
        """
        Remove a blocked pattern.
        
        Args:
            pattern: Regex pattern to remove
            
        Returns:
            True if pattern was removed, False if not found
        """
        if pattern in self._blocked_patterns:
            idx = self._blocked_patterns.index(pattern)
            self._blocked_patterns.pop(idx)
            self._compiled_patterns.pop(idx)
            return True
        return False

    def increment_usage(self, name: str) -> None:
        """
        Increment usage count for a tool.
        
        Args:
            name: Tool name
        """
        metadata_path = self.tool_dir / f"{name}.json"
        if not metadata_path.exists():
            return
        
        try:
            import datetime
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["usage_count"] = metadata.get("usage_count", 0) + 1
            metadata["last_used"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            metadata_path.write_text(
                json.dumps(metadata, indent=2), encoding="utf-8"
            )
        except (json.JSONDecodeError, IOError):
            pass  # Ignore metadata update errors

    def export_tools(self, path: str) -> int:
        """
        Export all tools to a JSON file.
        
        Args:
            path: Path to export file
            
        Returns:
            Number of tools exported
        """
        export_path = Path(path)
        tools_data = {}
        
        for name in self.list_tools():
            metadata = self.describe_tool(name)
            if metadata:
                tools_data[name] = metadata
        
        export_path.write_text(
            json.dumps(tools_data, indent=2),
            encoding="utf-8"
        )
        
        return len(tools_data)

    def import_tools(self, path: str, overwrite: bool = False) -> int:
        """
        Import tools from a JSON file.
        
        Args:
            path: Path to import file
            overwrite: Whether to overwrite existing tools
            
        Returns:
            Number of tools imported
        """
        import_path = Path(path)
        if not import_path.exists():
            raise FileNotFoundError(f"Import file not found: {path}")
        
        tools_data = json.loads(import_path.read_text(encoding="utf-8"))
        imported = 0
        
        for name, data in tools_data.items():
            if not overwrite and self.tool_exists(name):
                continue
            
            script = data.get("script", "")
            description = data.get("description", "")
            created_by = data.get("created_by", "imported")
            
            try:
                self.create_tool(
                    name=name,
                    script=script,
                    description=description,
                    created_by=created_by,
                )
                imported += 1
            except (SecurityError, ValueError):
                # Skip tools that fail validation
                pass
        
        return imported

    def clear_all_tools(self) -> int:
        """
        Delete all tools.
        
        Returns:
            Number of tools deleted
        """
        count = 0
        for name in self.list_tools():
            if self.delete_tool(name):
                count += 1
        return count
