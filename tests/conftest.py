"""Pytest fixtures for bashkuto tests."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    dirpath = tempfile.mkdtemp()
    yield Path(dirpath)
    shutil.rmtree(dirpath)


@pytest.fixture
def overflow_dir(temp_dir):
    """Create a temporary overflow directory."""
    path = temp_dir / "overflow"
    path.mkdir()
    yield str(path)


@pytest.fixture
def sample_command():
    """Sample safe command for testing."""
    return "echo hello"


@pytest.fixture
def sample_output():
    """Expected output for sample command."""
    if os.name == "nt":
        return "hello\r\n"
    return "hello\n"
