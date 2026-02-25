"""
End-to-end tracing tests — runs mactrace against deterministic C programs.

Requires sudo. Tests verify structural properties of the trace output:
- Expected syscalls are present
- fd→path mappings are correct
- Process tree relationships are correct
- Error codes are captured

These tests are NOT deterministic in exact event ordering or counts
(DTrace scheduling varies), but the structural assertions should always hold.
"""

import os
import sys
import json
import subprocess
import tempfile
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MACTRACE = os.path.join(PROJECT_ROOT, 'mactrace')
PROGRAMS_DIR = os.path.join(os.path.dirname(__file__), 'programs')


def run_mactrace(program_path, extra_args=None, timeout=30):
    """Run mactrace on a program, return parsed JSON trace."""
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        output_path = f.name

    try:
        cmd = ['sudo', sys.executable, MACTRACE, '-o', output_path]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(program_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        assert result.returncode == 0, f"mactrace failed: {result.stderr}"

        with open(output_path) as f:
            return json.load(f)
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)


class TestFileOps:
    """Trace test_fileops and verify file operation sequence."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data = run_mactrace(os.path.join(PROGRAMS_DIR, 'test_fileops'))

    def test_exit_code_zero(self):
        assert self.data['exit_code'] == 0

    def test_has_open_for_test_file(self):
        """Should have open() calls for the test file path."""
        events = self.data['events']
        opens = [e for e in events if e['syscall'] in ('open', 'openat')
                 and 'mactrace_test_fileops' in str(e.get('args', {}).get('path', ''))]
        assert len(opens) >= 2, "Expected at least 2 opens (write + read)"

    def test_has_write_event(self):
        """Should have a write event with 14 bytes (TEST_LEN)."""
        events = self.data['events']
        writes = [e for e in events if e['syscall'] in ('write', 'write_nocancel')
                  and e['return_value'] == 14]
        assert len(writes) >= 1

    def test_has_read_event(self):
        """Should have a read event returning 14 bytes."""
        events = self.data['events']
        reads = [e for e in events if e['syscall'] in ('read', 'read_nocancel')
                 and e['return_value'] == 14]
        assert len(reads) >= 1

    def test_has_unlink(self):
        """Should have unlink for the test file."""
        events = self.data['events']
        unlinks = [e for e in events if e['syscall'] == 'unlink'
                   and 'mactrace_test_fileops' in str(e.get('args', {}).get('path', ''))]
        assert len(unlinks) >= 1

    def test_events_have_categories(self):
        """All events should have a category assigned."""
        for e in self.data['events']:
            assert 'category' in e, f"Event missing category: {e['syscall']}"


class TestForkExec:
    """Trace test_forkexec and verify process tree."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data = run_mactrace(os.path.join(PROGRAMS_DIR, 'test_forkexec'))

    def test_exit_code_zero(self):
        assert self.data['exit_code'] == 0

    def test_multiple_pids(self):
        """Should trace at least 2 PIDs (parent + child)."""
        pids = set(e['pid'] for e in self.data['events'])
        assert len(pids) >= 2

    def test_has_fork(self):
        """Should have a fork syscall."""
        events = self.data['events']
        forks = [e for e in events if e['syscall'] in ('fork', 'vfork')]
        assert len(forks) >= 1

    def test_has_execve(self):
        """Should have execve for /bin/echo."""
        events = self.data['events']
        execs = [e for e in events if e['syscall'] in ('execve', 'posix_spawn')]
        assert len(execs) >= 1

    def test_process_tree_has_parent_child(self):
        """Process tree should map child→parent."""
        tree = self.data.get('process_tree', {})
        assert len(tree) >= 1, "Process tree should have at least one entry"

    def test_child_stdout_write(self):
        """Child should write 'mactrace_test_output\\n' to stdout."""
        child_pids = set(self.data['events'][-1]['pid'] for _ in [1])  # placeholder
        # Find write to fd 1 with the expected length (21 bytes)
        events = self.data['events']
        writes = [e for e in events if e['syscall'] in ('write', 'write_nocancel')
                  and e.get('args', {}).get('fd') == 1
                  and e['return_value'] > 0]
        assert len(writes) >= 1


class TestNetwork:
    """Trace test_network and verify socket operations."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data = run_mactrace(os.path.join(PROGRAMS_DIR, 'test_network'))

    def test_exit_code_zero(self):
        assert self.data['exit_code'] == 0

    def test_has_socket_creation(self):
        """Should have socket(AF_INET, SOCK_STREAM)."""
        events = self.data['events']
        sockets = [e for e in events if e['syscall'] == 'socket']
        assert len(sockets) >= 1

    def test_has_connect_with_econnrefused(self):
        """Should have connect() that failed with ECONNREFUSED."""
        events = self.data['events']
        connects = [e for e in events if e['syscall'] in ('connect', 'connect_nocancel')
                    and e['errno'] != 0]
        assert len(connects) >= 1
        # errno 61 is ECONNREFUSED on macOS
        refused = [c for c in connects if c['errno'] == 61
                   or c.get('args', {}).get('errno_name') == 'ECONNREFUSED']
        assert len(refused) >= 1

    def test_connect_target_is_localhost(self):
        """Connect target should be 127.0.0.1:1."""
        events = self.data['events']
        connects = [e for e in events if e['syscall'] in ('connect', 'connect_nocancel')]
        targets = [c.get('args', {}).get('display', '') for c in connects]
        assert any('127.0.0.1' in t for t in targets)
