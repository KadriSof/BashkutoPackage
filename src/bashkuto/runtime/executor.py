import asyncio
import logging
import os
import subprocess
import time
from typing import Dict, Optional, Tuple

from .exceptions import TimeoutError

logger = logging.getLogger(__name__)


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
    timeout_sec: Optional[float] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[bytes, bytes, int, int]:
    """
    Execute a command in a subprocess.

    Args:
        command: The command string to execute
        shell: The shell executable to use (default: platform default)
        timeout_sec: Optional timeout in seconds
        cwd: Working directory for the command
        env: Environment variables for the command

    Returns:
        Tuple of (stdout, stderr, returncode, duration_ms)

    Raises:
        TimeoutError: If command exceeds timeout_sec
    """
    if shell is None:
        shell = get_default_shell()

    start = time.time()
    
    logger.debug(f"Starting process: {command[:50]}... (shell={shell}, cwd={cwd})")

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            executable=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

        stdout, stderr = process.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out after {timeout_sec}s: {command[:50]}...")
        process.kill()
        stdout, stderr = process.communicate()
        raise TimeoutError(
            f"Command timed out after {timeout_sec}s: {command[:50]}..."
        )
    except Exception as e:
        logger.error(f"Process execution failed: {e}")
        raise

    duration = int((time.time() - start) * 1000)

    return stdout, stderr, process.returncode, duration


async def execute_async(
    command: str,
    shell: Optional[str] = None,
    timeout_sec: Optional[float] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[bytes, bytes, int, int]:
    """
    Execute a command asynchronously.

    Args:
        command: The command string to execute
        shell: The shell executable to use (default: platform default)
        timeout_sec: Optional timeout in seconds
        cwd: Working directory for the command
        env: Environment variables for the command

    Returns:
        Tuple of (stdout, stderr, returncode, duration_ms)

    Raises:
        TimeoutError: If command exceeds timeout_sec
    """
    if shell is None:
        shell = get_default_shell()

    start = time.time()
    
    logger.debug(f"Starting async process: {command[:50]}... (shell={shell}, cwd={cwd})")

    try:
        # Use asyncio.create_subprocess_shell for shell execution
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            executable=shell,
            cwd=cwd,
            env=env,
        )

        try:
            if timeout_sec:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout_sec
                )
            else:
                stdout, stderr = await process.communicate()
        except asyncio.TimeoutError:
            logger.warning(f"Async command timed out after {timeout_sec}s: {command[:50]}...")
            try:
                process.kill()
                # Wait for process to terminate to clean up zombies
                await process.wait() 
            except Exception as e:
                logger.warning(f"Failed to kill timed-out process: {e}")
            raise TimeoutError(
                f"Command timed out after {timeout_sec}s: {command[:50]}..."
            )

    except Exception as e:
        logger.error(f"Async process execution failed: {e}")
        raise

    duration = int((time.time() - start) * 1000)
    
    # Return code can be None if process was killed but wait() hasn't returned yet, 
    # but communicate() usually handles this. If killed via timeout, returncode might be -SIGKILL
    returncode = process.returncode if process.returncode is not None else -1

    return stdout, stderr, returncode, duration
