"""
Tests for mactrace_data — trace data management CLI.

Tests the list, info, delete, and stats subcommands against a fixture database.
"""

import json
import os
import subprocess
import sys
import tempfile
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MACTRACE_DATA = os.path.join(PROJECT_ROOT, 'mactrace_data')
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'fixtures', 'traces')
SERVER_DIR = os.path.join(PROJECT_ROOT, 'server')
IMPORT_JS = os.path.join(SERVER_DIR, 'import.js')


@pytest.fixture
def test_db(tmp_path):
    """Create a test database with an imported fixture trace."""
    db_path = str(tmp_path / 'test.db')
    json_file = os.path.join(FIXTURES_DIR, 'simple_echo.json')
    io_dir = os.path.join(FIXTURES_DIR, 'simple_echo')

    result = subprocess.run(
        ['node', IMPORT_JS, json_file, '--db', db_path, '--io-dir', io_dir],
        capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
    )
    assert result.returncode == 0, f"Import failed: {result.stderr}"
    return db_path


def run_data(args, db_path, timeout=15):
    """Run mactrace_data with given args and return result."""
    env = os.environ.copy()
    env['MACTRACE_DB'] = db_path
    return subprocess.run(
        [sys.executable, MACTRACE_DATA] + args,
        capture_output=True, text=True, env=env, timeout=timeout
    )


class TestDataList:
    def test_list_basic(self, test_db):
        result = run_data(['list'], test_db)
        assert result.returncode == 0
        assert 'echo' in result.stdout.lower() or 'cat' in result.stdout.lower() or '#' in result.stdout

    def test_list_json(self, test_db):
        result = run_data(['list', '-j'], test_db)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_db_list(self, test_db):
        result = run_data(['db', 'list'], test_db)
        assert result.returncode == 0

    def test_db_list_json(self, test_db):
        result = run_data(['db', 'list', '-j'], test_db)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)


class TestDataInfo:
    def test_info_by_id(self, test_db):
        # Get the ID first
        result = run_data(['db', 'list', '-j'], test_db)
        data = json.loads(result.stdout)
        if data:
            trace_id = str(data[0]['id'])
            result = run_data(['db', 'info', trace_id], test_db)
            assert result.returncode == 0, f"info failed: {result.stderr}"

    def test_db_info(self, test_db):
        result = run_data(['db', 'list', '-j'], test_db)
        data = json.loads(result.stdout)
        if data:
            trace_id = str(data[0]['id'])
            result = run_data(['db', 'info', trace_id], test_db)
            assert result.returncode == 0


class TestDataStats:
    def test_db_stats(self, test_db):
        result = run_data(['db', 'stats'], test_db)
        assert result.returncode == 0
        # Should mention traces, events, or size
        out = result.stdout.lower()
        assert 'trace' in out or 'event' in out or 'size' in out or 'row' in out

    def test_db_vacuum(self, test_db):
        result = run_data(['db', 'vacuum'], test_db, timeout=30)
        assert result.returncode == 0


class TestDataDelete:
    def test_delete_by_id(self, test_db):
        # Get the ID
        result = run_data(['db', 'list', '-j'], test_db)
        data = json.loads(result.stdout)
        if data:
            trace_id = str(data[0]['id'])
            result = run_data(['db', 'delete', '-f', trace_id], test_db)
            assert result.returncode == 0
            # Verify it's gone
            result = run_data(['db', 'list', '-j'], test_db)
            remaining = json.loads(result.stdout)
            assert len(remaining) < len(data)

    def test_delete_nonexistent(self, test_db):
        result = run_data(['db', 'delete', '-f', '99999'], test_db)
        # Should handle gracefully (not crash)
        assert result.returncode in (0, 1)


class TestDataHelp:
    def test_help(self, test_db):
        result = run_data(['--help'], test_db)
        assert result.returncode == 0
        assert 'usage' in result.stdout.lower() or 'mactrace_data' in result.stdout.lower()

    def test_db_help(self, test_db):
        result = run_data(['db', '--help'], test_db)
        assert result.returncode == 0


class TestDataErrors:
    def test_no_db(self, tmp_path):
        """Should handle missing database gracefully."""
        db_path = str(tmp_path / 'nonexistent.db')
        result = run_data(['list'], db_path)
        # Should not crash
        assert result.returncode in (0, 1)

    def test_bad_subcommand(self, test_db):
        result = run_data(['nonexistent_command'], test_db)
        assert result.returncode != 0
