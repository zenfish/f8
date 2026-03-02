"""
Integration tests for the import pipeline: JSON → SQLite → query.

Tests that traces imported via f8_import produce correct database
contents: event counts, categories, targets, process tree, error tracking.
Uses golden fixture files and a real SQLite database.
"""

import os
import sys
import json
import tempfile
import subprocess
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'fixtures', 'traces')
SERVER_DIR = os.path.join(PROJECT_ROOT, 'server')
IMPORT_JS = os.path.join(SERVER_DIR, 'import.js')


def import_trace(json_path, db_path):
    """Run f8_import on a JSON file, return subprocess result."""
    result = subprocess.run(
        ['node', IMPORT_JS, json_path, '--db', db_path],
        capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
    )
    return result


def query_db(db_path, sql, params=None):
    """Query the test database using better-sqlite3 via Node subprocess."""
    script = f"""
    import Database from 'better-sqlite3';
    const db = new Database({json.dumps(db_path)}, {{readonly: true}});
    const rows = db.prepare({json.dumps(sql)}).all({','.join(json.dumps(p) for p in (params or []))});
    console.log(JSON.stringify(rows));
    db.close();
    """
    result = subprocess.run(
        ['node', '--input-type=module', '-e', script],
        capture_output=True, text=True, cwd=SERVER_DIR, timeout=10
    )
    if result.returncode != 0:
        raise RuntimeError(f"DB query failed: {result.stderr}")
    return json.loads(result.stdout)


class TestImportSimpleEcho:
    """Import simple_echo.json and verify database contents."""

    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path):
        self.db_path = str(tmp_path / 'test.db')
        self.json_path = os.path.join(FIXTURES_DIR, 'simple_echo.json')
        result = import_trace(self.json_path, self.db_path)
        assert result.returncode == 0, f"Import failed: {result.stderr}"

    def test_trace_created(self):
        traces = query_db(self.db_path, 'SELECT * FROM traces')
        assert len(traces) == 1
        assert traces[0]['name'] == 'simple_echo'
        assert traces[0]['target_pid'] == 10000
        assert traces[0]['exit_code'] == 0
        assert traces[0]['event_count'] == 5

    def test_correct_event_count(self):
        events = query_db(self.db_path, 'SELECT COUNT(*) as count FROM events')
        assert events[0]['count'] == 5

    def test_categories_assigned(self):
        cats = query_db(self.db_path,
            'SELECT category, COUNT(*) as count FROM events GROUP BY category ORDER BY category')
        cat_map = {r['category']: r['count'] for r in cats}
        assert cat_map.get('file', 0) >= 2  # open + close + write
        assert cat_map.get('memory', 0) >= 1  # mmap
        assert cat_map.get('process', 0) >= 1  # exit

    def test_targets_extracted(self):
        """open should have /usr/lib/libSystem.B.dylib as target."""
        opens = query_db(self.db_path,
            "SELECT target FROM events WHERE syscall = 'open'")
        assert len(opens) >= 1
        assert any('/usr/lib/libSystem.B.dylib' in (r['target'] or '') for r in opens)

    def test_io_data_captured(self):
        """write event should have raw data captured."""
        writes = query_db(self.db_path,
            "SELECT data_raw FROM events WHERE syscall = 'write' AND data_raw IS NOT NULL")
        assert len(writes) >= 1
        assert writes[0]['data_raw'] == '68656c6c6f20776f726c640a'

    def test_timestamps_are_positive(self):
        """All timestamps should be non-negative."""
        events = query_db(self.db_path,
            'SELECT MIN(timestamp_us) as min_ts, MAX(timestamp_us) as max_ts FROM events')
        assert events[0]['min_ts'] >= 0
        assert events[0]['max_ts'] > events[0]['min_ts']


class TestImportForkExecPipeline:
    """Import fork_exec_pipeline.json — tests process tree reconstruction."""

    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path):
        self.db_path = str(tmp_path / 'test.db')
        self.json_path = os.path.join(FIXTURES_DIR, 'fork_exec_pipeline.json')
        result = import_trace(self.json_path, self.db_path)
        assert result.returncode == 0, f"Import failed: {result.stderr}"

    def test_correct_event_count(self):
        events = query_db(self.db_path, 'SELECT COUNT(*) as count FROM events')
        assert events[0]['count'] == 12

    def test_multiple_pids(self):
        """Should have events from 3 different PIDs."""
        pids = query_db(self.db_path, 'SELECT DISTINCT pid FROM events ORDER BY pid')
        pid_values = [r['pid'] for r in pids]
        assert 20000 in pid_values
        assert 20001 in pid_values
        assert 20002 in pid_values

    def test_process_tree_imported(self):
        """Processes table should have parent→child relationships."""
        procs = query_db(self.db_path,
            'SELECT pid, parent_pid, exec_path FROM processes ORDER BY pid')
        proc_map = {r['pid']: r for r in procs}
        # Child 20001 has parent 20000 and exec /bin/echo
        assert proc_map.get(20001, {}).get('parent_pid') == 20000
        assert '/bin/echo' in (proc_map.get(20001, {}).get('exec_path') or '')
        # Child 20002 has parent 20000 and exec /usr/bin/wc
        assert proc_map.get(20002, {}).get('parent_pid') == 20000
        assert '/usr/bin/wc' in (proc_map.get(20002, {}).get('exec_path') or '')

    def test_fork_and_exec_events_present(self):
        """Should have fork and execve syscall events."""
        forks = query_db(self.db_path,
            "SELECT COUNT(*) as count FROM events WHERE syscall = 'fork'")
        assert forks[0]['count'] == 2
        execs = query_db(self.db_path,
            "SELECT COUNT(*) as count FROM events WHERE syscall = 'execve'")
        assert execs[0]['count'] == 2

    def test_category_distribution(self):
        """Process-related syscalls should be categorized correctly."""
        cats = query_db(self.db_path,
            "SELECT category, COUNT(*) as count FROM events WHERE syscall IN ('fork','execve','exit','wait4') GROUP BY category")
        # All of these should be 'process'
        for row in cats:
            assert row['category'] == 'process', \
                f"Syscall in wrong category: {row}"


class TestImportNetworkWithErrors:
    """Import network_with_errors.json — tests error handling and network categorization."""

    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path):
        self.db_path = str(tmp_path / 'test.db')
        self.json_path = os.path.join(FIXTURES_DIR, 'network_with_errors.json')
        result = import_trace(self.json_path, self.db_path)
        assert result.returncode == 0, f"Import failed: {result.stderr}"

    def test_error_events_preserved(self):
        """Events with non-zero errno should be imported correctly."""
        errors = query_db(self.db_path,
            'SELECT syscall, errno, errno_name FROM events WHERE errno != 0 ORDER BY seq')
        assert len(errors) == 3
        errnos = {r['errno_name'] for r in errors}
        assert 'ECONNREFUSED' in errnos
        assert 'ENOENT' in errnos
        assert 'EACCES' in errnos

    def test_negative_return_values(self):
        """Failed syscalls should have return_value = -1."""
        failed = query_db(self.db_path,
            'SELECT return_value FROM events WHERE errno != 0')
        for row in failed:
            assert row['return_value'] == -1

    def test_network_category(self):
        """socket and connect should be categorized as 'network'."""
        net = query_db(self.db_path,
            "SELECT syscall, category FROM events WHERE syscall IN ('socket', 'connect')")
        for row in net:
            assert row['category'] == 'network'

    def test_network_target_extracted(self):
        """connect event should have 127.0.0.1:9999 as target."""
        connects = query_db(self.db_path,
            "SELECT target FROM events WHERE syscall = 'connect'")
        assert len(connects) == 1
        assert '127.0.0.1:9999' in connects[0]['target']

    def test_exit_code_preserved(self):
        """Trace exit code should be 7 (curl connection refused)."""
        traces = query_db(self.db_path, 'SELECT exit_code FROM traces')
        assert traces[0]['exit_code'] == 7


class TestImportIdempotence:
    """Importing the same trace twice should create two separate traces."""

    def test_double_import(self, tmp_path):
        db_path = str(tmp_path / 'test.db')
        json_path = os.path.join(FIXTURES_DIR, 'simple_echo.json')
        
        r1 = import_trace(json_path, db_path)
        assert r1.returncode == 0
        r2 = import_trace(json_path, db_path)
        assert r2.returncode == 0
        
        traces = query_db(db_path, 'SELECT COUNT(*) as count FROM traces')
        assert traces[0]['count'] == 2
        
        events = query_db(db_path, 'SELECT COUNT(*) as count FROM events')
        assert events[0]['count'] == 10  # 5 events × 2 imports




class TestImportIovecWritev:
    """Import trace with iov_buffers and verify roundtrip through the DB."""

    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path):
        self.db_path = str(tmp_path / 'test.db')
        self.json_path = os.path.join(FIXTURES_DIR, 'iovec_writev.json')
        result = import_trace(self.json_path, self.db_path)
        assert result.returncode == 0, f"Import failed: {result.stderr}"

    def test_trace_created(self):
        traces = query_db(self.db_path, "SELECT * FROM traces")
        assert len(traces) == 1
        assert traces[0]['name'] == 'iovec_writev'

    def test_correct_event_count(self):
        events = query_db(self.db_path, "SELECT COUNT(*) as count FROM events")
        assert events[0]['count'] == 7

    def test_writev_events_imported(self):
        """writev events should be imported with correct syscall and return value."""
        events = query_db(self.db_path,
            "SELECT * FROM events WHERE syscall = 'writev' ORDER BY timestamp_us")
        assert len(events) == 2, "Expected 2 writev events"
        assert events[0]['return_value'] == 12
        assert events[1]['return_value'] == 12

    def test_readv_event_imported(self):
        """readv event should be imported."""
        events = query_db(self.db_path,
            "SELECT * FROM events WHERE syscall = 'readv'")
        assert len(events) == 1
        assert events[0]['return_value'] == 12

    def test_writev_details_has_iovcnt(self):
        """Details column should include iovcnt for writev."""
        events = query_db(self.db_path,
            "SELECT details FROM events WHERE syscall = 'writev' ORDER BY timestamp_us")
        assert 'iovcnt=3' in (events[0]['details'] or ''), \
            f"Expected iovcnt=3 in details, got: {events[0]['details']}"

    def test_truncated_writev_shows_captured_count(self):
        """Truncated writev (iovcnt=6, 4 captured) should note that in details."""
        events = query_db(self.db_path,
            "SELECT details FROM events WHERE syscall = 'writev' ORDER BY timestamp_us")
        # Second writev has iovcnt=6 with only 4 captured
        assert 'iovcnt=6' in (events[1]['details'] or ''), \
            f"Expected iovcnt=6, got: {events[1]['details']}"
        assert '4 captured' in (events[1]['details'] or ''), \
            f"Expected '4 captured' note, got: {events[1]['details']}"

    def test_writev_data_raw_has_concatenated_hex(self):
        """data_raw should have concatenated iov buffer hex data."""
        events = query_db(self.db_path,
            "SELECT data_raw FROM events WHERE syscall = 'writev' ORDER BY timestamp_us")
        raw = events[0]['data_raw'] or ''
        # HEAD(48454144) + BODY(424f4459) + TAIL(5441494c) = concatenated
        assert '48454144' in raw, "Expected HEAD hex in data_raw"
        assert '424f4459' in raw, "Expected BODY hex in data_raw"
        assert '5441494c' in raw, "Expected TAIL hex in data_raw"

    def test_writev_marked_as_io(self):
        """writev events should have has_io=1."""
        events = query_db(self.db_path,
            "SELECT has_io FROM events WHERE syscall = 'writev'")
        for e in events:
            assert e['has_io'] == 1, "writev should be marked as I/O"

    def test_readv_marked_as_io(self):
        """readv events should have has_io=1."""
        events = query_db(self.db_path,
            "SELECT has_io FROM events WHERE syscall = 'readv'")
        assert events[0]['has_io'] == 1, "readv should be marked as I/O"
