"""
Shared pytest fixtures for mactrace test suite.

This conftest.py ensures that the mactrace project root is on sys.path
so that mactrace_lib, mactrace_categories, etc. can be imported by tests.
"""

import os
import sys
import json
import tempfile
import pytest

# Add mactrace project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


@pytest.fixture
def project_root():
    """Path to mactrace project root."""
    return PROJECT_ROOT


@pytest.fixture
def fixtures_dir():
    """Path to test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def syscalls_json_path():
    """Path to syscalls.json."""
    return os.path.join(PROJECT_ROOT, 'syscalls.json')


@pytest.fixture
def syscalls_data(syscalls_json_path):
    """Parsed contents of syscalls.json."""
    with open(syscalls_json_path) as f:
        return json.load(f)


@pytest.fixture
def temp_dir():
    """Temporary directory for test outputs, cleaned up after test."""
    with tempfile.TemporaryDirectory(prefix='mactrace_test_') as d:
        yield d


@pytest.fixture
def temp_config(temp_dir):
    """
    Create a temporary mactrace config file.
    
    Returns a function that writes config content and returns the path.
    Usage:
        def test_foo(temp_config):
            config_path = temp_config("MACTRACE_HOME=~/mactrace\\nMACTRACE_OUTPUT=~/output")
    """
    def _write_config(content):
        config_dir = os.path.join(temp_dir, '.mactrace')
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, 'config')
        with open(config_path, 'w') as f:
            f.write(content)
        return config_path
    
    return _write_config


@pytest.fixture
def simple_trace():
    """Minimal valid trace JSON for testing."""
    return {
        "command": ["cat", "/etc/passwd"],
        "target_pid": 1234,
        "exit_code": 0,
        "duration_ms": 15.3,
        "start_time": "2026-02-24T10:00:00",
        "events": [
            {
                "timestamp_us": 1000,
                "pid": 1234,
                "syscall": "open",
                "return_value": 3,
                "errno": 0,
                "args": {
                    "path": "/etc/passwd",
                    "flags": "O_RDONLY",
                    "flags_raw": 0
                }
            },
            {
                "timestamp_us": 2000,
                "pid": 1234,
                "syscall": "read",
                "return_value": 512,
                "errno": 0,
                "args": {
                    "fd": 3,
                    "count": 4096,
                    "data": "726f6f743a783a303a303a726f6f74"
                }
            },
            {
                "timestamp_us": 3000,
                "pid": 1234,
                "syscall": "write",
                "return_value": 512,
                "errno": 0,
                "args": {
                    "fd": 1,
                    "count": 512
                }
            },
            {
                "timestamp_us": 4000,
                "pid": 1234,
                "syscall": "close",
                "return_value": 0,
                "errno": 0,
                "args": {
                    "fd": 3
                }
            }
        ],
        "pids_traced": [1234]
    }


@pytest.fixture
def fork_exec_trace():
    """Trace with fork/exec/wait — tests process tree reconstruction."""
    return {
        "command": ["sh", "-c", "echo hello"],
        "target_pid": 100,
        "exit_code": 0,
        "duration_ms": 25.0,
        "start_time": "2026-02-24T10:00:00",
        "events": [
            {
                "timestamp_us": 1000,
                "pid": 100,
                "syscall": "fork",
                "return_value": 101,
                "errno": 0,
                "args": {}
            },
            {
                "timestamp_us": 2000,
                "pid": 101,
                "syscall": "execve",
                "return_value": 0,
                "errno": 0,
                "args": {"path": "/bin/echo"}
            },
            {
                "timestamp_us": 3000,
                "pid": 101,
                "syscall": "write",
                "return_value": 6,
                "errno": 0,
                "args": {"fd": 1, "count": 6}
            },
            {
                "timestamp_us": 4000,
                "pid": 101,
                "syscall": "exit",
                "return_value": 0,
                "errno": 0,
                "args": {}
            },
            {
                "timestamp_us": 5000,
                "pid": 100,
                "syscall": "wait4",
                "return_value": 101,
                "errno": 0,
                "args": {}
            }
        ],
        "process_tree": {"101": 100},
        "pids_traced": [100, 101]
    }


@pytest.fixture
def error_trace():
    """Trace with various error conditions."""
    return {
        "command": ["cat", "/nonexistent"],
        "target_pid": 500,
        "exit_code": 1,
        "duration_ms": 5.0,
        "start_time": "2026-02-24T10:00:00",
        "events": [
            {
                "timestamp_us": 1000,
                "pid": 500,
                "syscall": "open",
                "return_value": -1,
                "errno": 2,
                "args": {
                    "path": "/nonexistent",
                    "errno_name": "ENOENT"
                }
            },
            {
                "timestamp_us": 2000,
                "pid": 500,
                "syscall": "connect",
                "return_value": -1,
                "errno": 111,
                "args": {
                    "fd": 3,
                    "display": "127.0.0.1:9999",
                    "errno_name": "ECONNREFUSED"
                }
            }
        ],
        "pids_traced": [500]
    }
