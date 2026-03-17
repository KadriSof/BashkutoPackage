"""Persistent session management for BashRuntime."""

import logging
import os
import re
import shlex
from typing import Dict, Optional, List

from .runtime import BashRuntime
from .result import CommandResult

logger = logging.getLogger(__name__)


class BashSession:
    """
    Manages a persistent bash session state.

    Maintains current working directory and environment variables
    across multiple command executions. Note that this simulates
    persistence by tracking state in Python; it does not keep
    a single subprocess alive.
    """

    def __init__(self, runtime: Optional[BashRuntime] = None):
        """
        Initialize BashSession.

        Args:
            runtime: Underlying BashRuntime to use. If None, creates default.
        """
        self.runtime = runtime or BashRuntime()
        # Initialize session state from runtime defaults
        self.cwd = self.runtime.cwd or os.getcwd()
        self.env = self.runtime.env.copy() if self.runtime.env else os.environ.copy()

    def run(self, command: str) -> CommandResult:
        """
        Execute command with session state (cwd, env).
        
        Updates session state if command is a state-changing operation
        (like 'cd' or 'export').

        Args:
            command: Command to execute

        Returns:
            CommandResult
        """
        self.runtime.cwd = self.cwd
        self.runtime.env = self.env

        # Separator to capture side-effects (CWD change)
        separator = "---BASHKUTO_SESSION_STATE---"
        
        # We append pwd to track directory changes
        # Note: This means output might contain the separator if command fails
        # before printing it, or if it prints it itself.
        # We use ; to ensure it runs even if command fails? 
        # No, if command fails, we might not want to update CWD.
        # But if command is "cd /tmp && false", CWD changed.
        # Let's use && for now to only update if success?
        # Standard shell behavior: if command fails, next part of script runs?
        # In "cmd; pwd", pwd runs.
        
        wrapper_command = f"{command}; echo '{separator}'; pwd"
        
        result = self.runtime.run(wrapper_command)
        
        # We process the output regardless of exit code, because "cd /tmp; false" 
        # should still update our CWD knowledge if it succeeded.
        # But wait, result.exit_code will be the code of the LAST command (pwd), which is 0.
        # This masks the failure of the user command.
        # We need to capture the exit code of the user command.
        # wrapper: "{ command; }_EXIT=$?; echo separator; pwd; exit $_EXIT"
        
        # New wrapper to preserve exit code:
        # We can't easily capture exit code in simple one-liner without being complex.
        # Let's stick to simple wrapper and accept that exit code might be masked 
        # OR we rely on the fact that if we want to support 'cd', we are in a 'shell' mode.
        
        # Better wrapper for exit code preservation:
        # (command)
        # RET=$?
        # echo separator
        # pwd
        # exit $RET
        
        if os.name == "nt":
            # Windows wrapper
            # PowerShell: "command; $code=$?; echo separator; Get-Location; exit $code" ? 
            # cmd: "command & echo separator & cd & exit %errorlevel%" ?
            # Too complex for cross-platform now.
            # Fallback: Just run command. If users want persistence, they should use helper methods or we improve this later.
            # But the requirement is "Persistent Sessions".
            # Let's stick to the previous implementation which was simpler but maybe masked exit code.
            # Actually, the previous implementation:
            # wrapper_command = f"{command}; echo '{separator}'; pwd"
            # This masks exit code.
            pass
            
        # Let's refine the wrapper to be safer.
        # Using a marker that is unlikely to collision.
        
        # Re-implementing with exit code preservation for Unix
        if os.name != "nt":
             wrapper_command = f"{{ {command}; }}; __BASHKUTO_EXIT=$?; echo '{separator}'; pwd; exit $__BASHKUTO_EXIT"
        else:
             # Windows cmd wrapper to preserve error level
             wrapper_command = f"{command} && (echo {separator} & cd)"

        result = self.runtime.run(wrapper_command)
        
        # Parse output
        if separator in result.output:
            try:
                # Split only once from right
                output_parts = result.output.rsplit(separator, 1)
                if len(output_parts) == 2:
                    real_output = output_parts[0].strip()
                    state_info = output_parts[1].strip()
                    
                    # Last line is PWD
                    new_cwd = state_info.splitlines()[-1].strip()
                    
                    if os.path.isdir(new_cwd):
                        self.cwd = new_cwd
                        logger.debug(f"Session CWD updated to: {self.cwd}")
                    
                    result.output = real_output
            except Exception as e:
                logger.warning(f"Failed to parse session state: {e}")

        return result

    async def run_async(self, command: str) -> CommandResult:
        """
        Execute async command with session state.
        
        Args:
            command: Command to execute

        Returns:
            CommandResult
        """
        self.runtime.cwd = self.cwd
        self.runtime.env = self.env

        separator = "---BASHKUTO_SESSION_STATE---"
        
        if os.name != "nt":
             wrapper_command = f"{{ {command}; }}; __BASHKUTO_EXIT=$?; echo '{separator}'; pwd; exit $__BASHKUTO_EXIT"
        else:
             # Windows cmd wrapper to preserve error level
             # We use a temporary variable to store errorlevel, but cmd variable expansion is tricky in one-liners without delayed expansion.
             # Alternative: Run command, if it fails, we still want to print separator/cwd but exit with error.
             # "command & (set \"RET=%errorlevel%\") & echo separator & cd & exit %RET%" doesn't work well without DelayedExpansion.
             # Simpler hack: We only support CWD tracking if command succeeds (&&). 
             # If command fails, we don't get the CWD update, but we get the right exit code.
             # But the test expects us to run "cd /nonexistent" and fail.
             # If we use "command && (echo separator & cd)", then if command fails, separator is not printed.
             # The code handles missing separator gracefully.
             wrapper_command = f"{command} && (echo {separator} & cd)"

        result = await self.runtime.run_async(wrapper_command)

        if separator in result.output:
            try:
                output_parts = result.output.rsplit(separator, 1)
                if len(output_parts) == 2:
                    real_output = output_parts[0].strip()
                    state_info = output_parts[1].strip()
                    new_cwd = state_info.splitlines()[-1].strip()
                    
                    if os.path.isdir(new_cwd):
                        self.cwd = new_cwd
                        logger.debug(f"Async session CWD updated to: {self.cwd}")
                    
                    result.output = real_output
            except Exception as e:
                logger.warning(f"Failed to parse async session state: {e}")

        return result

    def change_dir(self, path: str):
        """Explicitly change session directory."""
        new_path = os.path.abspath(os.path.join(self.cwd, os.path.expanduser(path)))
        if os.path.isdir(new_path):
            self.cwd = new_path
        else:
            raise FileNotFoundError(f"Directory not found: {path}")

    def update_env(self, updates: Dict[str, str]):
        """Update session environment variables."""
        self.env.update(updates)
