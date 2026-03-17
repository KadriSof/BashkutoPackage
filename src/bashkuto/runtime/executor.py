import subprocess
import time
import os
from typing import Optional, Tuple

from .exceptions import TimeoutError


def get_default_shell() -> str:
    """Get the default shell for the current platform."""
    if os.name == "nt":
        # Windows: use cmd.exe or PowerShell
        return os.environ.get("COMSPEC", "cmd.exe")
    else:
        # Unix-like: use bash or sh
        return "/bin/bash"


def execute(
    command: str,
    shell: Optional[str] = None,
    timeout_sec: Optional[float] = None
) -> Tuple[bytes, bytes, int, int]:
    """
    Execute a command in a subprocess.

    Args:
        command: The command string to execute
        shell: The shell executable to use (default: platform default)
        timeout_sec: Optional timeout in seconds

    Returns:
        Tuple of (stdout, stderr, returncode, duration_ms)

    Raises:
        TimeoutError: If command exceeds timeout_sec
    """
    if shell is None:
        shell = get_default_shell()

    start = time.time()

    process = subprocess.Popen(
        command,
        shell=True,
        executable=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        stdout, stderr = process.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()  # Clean up
        raise TimeoutError(
            f"Command timed out after {timeout_sec}s: {command[:50]}..."
        )

    duration = int((time.time() - start) * 1000)

    return stdout, stderr, process.returncode, duration