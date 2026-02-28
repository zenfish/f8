"""E2E test configuration — skip if not root or no C compiler."""

import os
import shutil
import subprocess
import pytest

PROGRAMS_DIR = os.path.join(os.path.dirname(__file__), 'programs')

# Check for C compiler availability at collection time
HAS_CC = bool(shutil.which('cc') or shutil.which('gcc') or shutil.which('clang'))


def pytest_collection_modifyitems(config, items):
    """Skip E2E tests if not running as root or no C compiler."""
    e2e_dir = os.path.dirname(__file__)
    for item in items:
        if not str(item.fspath).startswith(e2e_dir):
            continue
        if os.geteuid() != 0:
            item.add_marker(pytest.mark.skip(
                reason="E2E tests require sudo (DTrace needs root)"))
        elif not HAS_CC:
            item.add_marker(pytest.mark.skip(
                reason="No C compiler found (cc/gcc/clang) — cannot build test programs"))


@pytest.fixture(scope='session')
def compile_programs():
    """Ensure test C programs are compiled. Skip if no compiler."""
    if not HAS_CC:
        pytest.skip("No C compiler found (cc/gcc/clang)")
    result = subprocess.run(['make', '-C', PROGRAMS_DIR], capture_output=True, text=True)
    assert result.returncode == 0, f"Compilation failed: {result.stderr}"
    return PROGRAMS_DIR
