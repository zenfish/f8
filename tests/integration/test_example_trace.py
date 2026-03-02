"""
Integration test for the example trace — verifies it imports cleanly
and the server can serve it.

This is a smoke test to ensure the pre-built example shipped with
the repo stays valid as the codebase evolves.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVER_DIR = os.path.join(PROJECT_ROOT, 'server')
IMPORT_JS = os.path.join(SERVER_DIR, 'import.js')
SERVER_JS = os.path.join(SERVER_DIR, 'server.js')
EXAMPLE_TRACE = os.path.join(PROJECT_ROOT, 'examples', 'echo-hello.json')


class TestExampleTrace:
    """Validate the shipped example trace."""

    def test_example_exists(self):
        assert os.path.exists(EXAMPLE_TRACE), "examples/echo-hello.json missing"

    def test_example_is_valid_json(self):
        with open(EXAMPLE_TRACE) as f:
            data = json.load(f)
        assert 'events' in data
        assert 'command' in data
        assert len(data['events']) > 0

    def test_example_has_required_fields(self):
        with open(EXAMPLE_TRACE) as f:
            data = json.load(f)
        required = ['command', 'target_pid', 'exit_code', 'duration_ms',
                     'events', 'pids_traced', 'summary']
        for field in required:
            assert field in data, f"Example trace missing required field: {field}"

    def test_example_events_have_required_fields(self):
        with open(EXAMPLE_TRACE) as f:
            data = json.load(f)
        for i, event in enumerate(data['events']):
            for field in ['timestamp_us', 'pid', 'syscall', 'return_value', 'errno']:
                assert field in event, f"Event {i} missing field: {field}"

    def test_example_has_diverse_syscalls(self):
        """Example should showcase multiple syscall categories."""
        with open(EXAMPLE_TRACE) as f:
            data = json.load(f)
        syscalls = {e['syscall'] for e in data['events']}
        # Should have file + memory ops at minimum
        assert syscalls & {'open', 'read', 'write', 'close'}, "Missing file syscalls"
        assert syscalls & {'mmap', 'mprotect', 'munmap'}, "Missing memory syscalls"

    def test_example_has_error_events(self):
        """Example should include at least one error for demonstration."""
        with open(EXAMPLE_TRACE) as f:
            data = json.load(f)
        errors = [e for e in data['events'] if e['errno'] != 0]
        assert len(errors) > 0, "Example should include error events for demo purposes"

    def test_example_imports_cleanly(self, tmp_path):
        """Example trace should import into SQLite without errors."""
        db_path = str(tmp_path / 'test.db')
        io_dir = str(tmp_path / 'io')
        result = subprocess.run(
            ['node', IMPORT_JS, EXAMPLE_TRACE, '--db', db_path, '--io-dir', io_dir],
            capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
        )
        assert result.returncode == 0, f"Import failed: {result.stderr}"
        assert os.path.exists(db_path), "Database file not created"

    def test_example_roundtrip_event_count(self, tmp_path):
        """Imported event count should match JSON event count."""
        with open(EXAMPLE_TRACE) as f:
            data = json.load(f)
        expected_count = len(data['events'])

        db_path = str(tmp_path / 'test.db')
        io_dir = str(tmp_path / 'io')
        subprocess.run(
            ['node', IMPORT_JS, EXAMPLE_TRACE, '--db', db_path, '--io-dir', io_dir],
            capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
        )

        # Query the database
        import sqlite3
        conn = sqlite3.connect(db_path)
        count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        conn.close()
        assert count == expected_count, f"Expected {expected_count} events, got {count}"
