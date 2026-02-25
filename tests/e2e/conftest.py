"""E2E test configuration — skip if not root (DTrace requires sudo)."""

import os
import subprocess
import pytest

PROGRAMS_DIR = os.path.join(os.path.dirname(__file__), 'programs')


def pytest_collection_modifyitems(config, items):
    """Skip E2E tests if not running as root."""
    if os.geteuid() != 0:
        skip = pytest.mark.skip(reason="E2E tests require sudo (DTrace needs root)")
        e2e_dir = os.path.dirname(__file__)
        for item in items:
            if str(item.fspath).startswith(e2e_dir):
                item.add_marker(skip)


@pytest.fixture(scope='session')
def compile_programs():
    """Ensure test C programs are compiled."""
    result = subprocess.run(['make', '-C', PROGRAMS_DIR], capture_output=True, text=True)
    assert result.returncode == 0, f"Compilation failed: {result.stderr}"
    return PROGRAMS_DIR
