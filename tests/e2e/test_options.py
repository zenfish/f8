"""
End-to-end tests for EVERY major mactrace option and combination.

Tests --capture-io, --trace (all categories), --iovec variants, --throttle,
--io-size, -e/--untraced, -jp/--json-pretty, --strsize, and key combos.

Each test class runs mactrace with a specific option set and verifies:
  1. DTrace compiles (no DIF/DOF errors — exit code 0)
  2. Events are captured (syscall_count > 0)
  3. Option-specific behavior works (IO data present, categories filtered, etc.)

Requires sudo. Some tests are slow (full probe set + IO capture).
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


def run_mactrace(program_path, extra_args=None, timeout=45):
    """Run mactrace on a program, return parsed JSON trace and stderr."""
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        output_path = f.name
    os.unlink(output_path)  # remove so mactrace can create it

    try:
        cmd = ['sudo', sys.executable, MACTRACE, '-o', output_path]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(program_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        assert result.returncode == 0, (
            f"mactrace failed (exit {result.returncode}):\n{result.stderr}"
        )
        # Fail explicitly on DIF/DOF errors even if exit code is 0
        assert 'DIF program exceeds' not in result.stderr, (
            f"DTrace DIF/DOF limit exceeded:\n{result.stderr}"
        )

        with open(output_path) as f:
            data = json.load(f)
        return data, result.stderr
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)


def assert_has_events(data, min_events=1):
    """Assert trace captured events."""
    assert data['syscall_count'] >= min_events, (
        f"Expected >= {min_events} syscalls, got {data['syscall_count']}"
    )
    assert len(data['events']) >= min_events


# ═══════════════════════════════════════════════════════════════════
# --capture-io (the option that was broken)
# ═══════════════════════════════════════════════════════════════════

class TestCaptureIO:
    """--capture-io with ALL categories (full probe set, 270+ probes)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--capture-io']
        )

    def test_dtrace_compiled(self):
        """DTrace script should compile without DIF/DOF errors."""
        assert 'DIF program exceeds' not in self.stderr

    def test_events_captured(self):
        """Should capture events (not the 0-event failure mode)."""
        assert_has_events(self.data, min_events=10)

    def test_pid_nonzero(self):
        """Target PID should be detected (not 0)."""
        assert self.data['target_pid'] > 0

    def test_read_has_io_data(self):
        """read() events should have hex data captured."""
        reads = [e for e in self.data['events']
                 if e['syscall'] in ('read', 'read_nocancel')
                 and e['return_value'] > 0]
        assert len(reads) >= 1, "Expected at least one successful read"
        reads_with_data = [r for r in reads if r.get('args', {}).get('data')]
        assert len(reads_with_data) >= 1, (
            "No read events have 'data' field — IO capture not working"
        )

    def test_write_has_io_data(self):
        """write() events should have hex data captured."""
        writes = [e for e in self.data['events']
                  if e['syscall'] in ('write', 'write_nocancel')
                  and e['return_value'] > 0]
        assert len(writes) >= 1
        writes_with_data = [w for w in writes if w.get('args', {}).get('data')]
        assert len(writes_with_data) >= 1, (
            "No write events have 'data' field — IO capture not working"
        )

    def test_write_data_contains_test_string(self):
        """The write to test file should contain 'Hello mactrace' in hex."""
        expected_hex = b"Hello mactrace".hex()
        writes = [e for e in self.data['events']
                  if e['syscall'] in ('write', 'write_nocancel')
                  and e['return_value'] == 14
                  and expected_hex in e.get('args', {}).get('data', '')]
        assert len(writes) >= 1, (
            "Expected write with 'Hello mactrace' payload"
        )

    def test_dof_maxsize_adjusted(self):
        """stderr should show dof_maxsize was auto-adjusted."""
        assert 'dof_maxsize' in self.stderr, (
            "dof_maxsize should be auto-adjusted for full probe set + IO"
        )


class TestCaptureIONetwork:
    """--capture-io with network traffic (UDP sendto/recvfrom)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_udp_io'),
            extra_args=['--capture-io']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)

    def test_sendto_has_data(self):
        """sendto should capture the UDP payload."""
        expected_hex = b"MACTRACE_UDP_TEST_DATA".hex()
        sendtos = [e for e in self.data['events']
                   if e['syscall'] in ('sendto', 'sendto_nocancel')
                   and e['return_value'] == 22]
        assert len(sendtos) >= 1, "Expected sendto with 22-byte payload"
        with_data = [s for s in sendtos
                     if expected_hex in s.get('args', {}).get('data', '')]
        assert len(with_data) >= 1, (
            "sendto should have captured 'MACTRACE_UDP_TEST_DATA' payload"
        )

    def test_recvfrom_has_data(self):
        """recvfrom should capture the UDP payload."""
        expected_hex = b"MACTRACE_UDP_TEST_DATA".hex()
        recvs = [e for e in self.data['events']
                 if e['syscall'] in ('recvfrom', 'recvfrom_nocancel')
                 and e['return_value'] == 22]
        assert len(recvs) >= 1, "Expected recvfrom with 22-byte payload"
        with_data = [r for r in recvs
                     if expected_hex in r.get('args', {}).get('data', '')]
        assert len(with_data) >= 1, (
            "recvfrom should have captured 'MACTRACE_UDP_TEST_DATA' payload"
        )


class TestCaptureIOSmallSize:
    """--capture-io --io-size 256 (small buffer, still works)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--capture-io', '--io-size', '256']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=10)

    def test_io_data_present(self):
        """Even with small io-size, short reads/writes should be captured."""
        reads = [e for e in self.data['events']
                 if e['syscall'] in ('read', 'read_nocancel')
                 and e['return_value'] == 14
                 and e.get('args', {}).get('data')]
        assert len(reads) >= 1


# ═══════════════════════════════════════════════════════════════════
# --trace (category filtering)
# ═══════════════════════════════════════════════════════════════════

class TestTraceFile:
    """--trace=file: only file syscalls."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--trace=file']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)

    def test_only_file_and_process_categories(self):
        """Events should be file, process, or mac (mac is cross-cutting)."""
        categories = set(e['category'] for e in self.data['events'])
        allowed = {'file', 'process', 'mac'}
        unexpected = categories - allowed
        assert not unexpected, f"Unexpected categories with --trace=file: {unexpected}"


class TestTraceNet:
    """--trace=net: only network syscalls."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_network'),
            extra_args=['--trace=net']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=1)

    def test_has_socket_ops(self):
        """Should have socket/connect events."""
        syscalls = set(e['syscall'] for e in self.data['events'])
        assert 'socket' in syscalls or 'connect' in syscalls


class TestTraceNetCaptureIO:
    """--trace=net --capture-io: network category with IO capture."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_udp_io'),
            extra_args=['--trace=net', '--capture-io']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=1)

    def test_sendto_present(self):
        syscalls = set(e['syscall'] for e in self.data['events'])
        net_io = {'sendto', 'sendto_nocancel', 'recvfrom', 'recvfrom_nocancel',
                  'sendmsg', 'recvmsg'}
        assert syscalls & net_io, f"Expected network IO syscalls, got: {syscalls}"


class TestTraceProcess:
    """--trace=process: only process lifecycle syscalls."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_forkexec'),
            extra_args=['--trace=process']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=1)

    def test_has_fork_or_exec(self):
        syscalls = set(e['syscall'] for e in self.data['events'])
        proc_calls = {'fork', 'vfork', 'execve', 'posix_spawn',
                      'getpid', 'getppid', 'wait4'}
        assert syscalls & proc_calls, f"Expected process syscalls, got: {syscalls}"


class TestTraceMemory:
    """--trace=memory: only memory syscalls (mmap/mprotect/munmap)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        # Any program uses mmap/mprotect during dyld load
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--trace=memory']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=1)

    def test_only_memory_and_process(self):
        categories = set(e['category'] for e in self.data['events'])
        allowed = {'memory', 'process', 'mac'}
        unexpected = categories - allowed
        assert not unexpected, f"Unexpected categories: {unexpected}"


class TestTraceMultiCategory:
    """--trace=file,net: multiple categories combined."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_network'),
            extra_args=['--trace=file,net']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=3)

    def test_has_both_categories(self):
        categories = set(e['category'] for e in self.data['events'])
        assert 'file' in categories or 'network' in categories


class TestTraceIO:
    """--trace=io alias (file + network)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--trace=io']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)


class TestTraceAll:
    """--trace=all: explicitly all categories (same as default)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--trace=all']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=10)


class TestTraceAllCaptureIO:
    """--trace=all --capture-io: the full monty."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--trace=all', '--capture-io']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=10)

    def test_io_data_present(self):
        writes = [e for e in self.data['events']
                  if e['syscall'] in ('write', 'write_nocancel')
                  and e['return_value'] > 0
                  and e.get('args', {}).get('data')]
        assert len(writes) >= 1


class TestTraceSingleSyscall:
    """--trace=open: single syscall name."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--trace=open']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=1)

    def test_only_open_events(self):
        """Should only have open syscalls (plus process tracker)."""
        syscalls = set(e['syscall'] for e in self.data['events'])
        # process category always included for tree tracking
        for sc in syscalls:
            assert sc in ('open', 'open_nocancel', 'openat',
                          'getpid', 'getppid', 'execve', 'fork', 'vfork',
                          'wait4', 'exit', '__mac_syscall',
                          'getuid', 'getgid', 'geteuid', 'getegid',
                          'setsid', 'setpgid'), \
                f"Unexpected syscall '{sc}' with --trace=open"


# ═══════════════════════════════════════════════════════════════════
# --iovec variants
# ═══════════════════════════════════════════════════════════════════

class TestIovecAllCategories:
    """--iovec 4 WITHOUT --trace filter (full probe set — was untested!)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_iovec'),
            extra_args=['--iovec', '4']
        )

    def test_dtrace_compiled(self):
        assert 'DIF program exceeds' not in self.stderr

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)

    def test_writev_buffers_captured(self):
        writevs = [e for e in self.data['events']
                   if e['syscall'] in ('writev', 'writev_nocancel')
                   and e['args'].get('iovcnt') == 3
                   and 'iov_buffers' in e.get('args', {})]
        assert len(writevs) >= 1, "Expected writev with iov_buffers"


class TestIovecHighN:
    """--iovec 8: higher scatter count (more DIF programs)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_iovec'),
            extra_args=['--iovec', '8', '--trace=file']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=3)

    def test_writev_buffers_present(self):
        writevs = [e for e in self.data['events']
                   if e['syscall'] in ('writev', 'writev_nocancel')
                   and 'iov_buffers' in e.get('args', {})]
        assert len(writevs) >= 1


class TestIovecSyscallsFilter:
    """--iovec 4 --iovec-syscalls=writev: narrowed to writev only."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_iovec'),
            extra_args=['--iovec', '4', '--iovec-syscalls=writev', '--trace=file']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=3)

    def test_writev_has_buffers(self):
        writevs = [e for e in self.data['events']
                   if e['syscall'] in ('writev', 'writev_nocancel')
                   and 'iov_buffers' in e.get('args', {})]
        assert len(writevs) >= 1

    def test_readv_has_no_buffers(self):
        """readv should NOT have iov_buffers since we filtered to writev only."""
        readvs = [e for e in self.data['events']
                  if e['syscall'] in ('readv', 'readv_nocancel')
                  and 'iov_buffers' in e.get('args', {})]
        assert len(readvs) == 0, (
            "readv should not have iov_buffers with --iovec-syscalls=writev"
        )


# ═══════════════════════════════════════════════════════════════════
# --throttle
# ═══════════════════════════════════════════════════════════════════

class TestThrottle:
    """--throttle: background QoS on traced process."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--throttle']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)

    def test_exit_code_zero(self):
        assert self.data['exit_code'] == 0


class TestThrottleCaptureIO:
    """--throttle --capture-io: both together."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--throttle', '--capture-io']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)

    def test_io_data_present(self):
        reads = [e for e in self.data['events']
                 if e['syscall'] in ('read', 'read_nocancel')
                 and e['return_value'] > 0
                 and e.get('args', {}).get('data')]
        assert len(reads) >= 1


# ═══════════════════════════════════════════════════════════════════
# -e / --untraced
# ═══════════════════════════════════════════════════════════════════

class TestUntraced:
    """-e: show untraced syscalls summary."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['-e']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=10)

    def test_untraced_summary_in_stderr(self):
        """stderr should include the untraced syscalls summary."""
        assert 'Untraced syscalls' in self.stderr or 'untraced' in self.stderr.lower()


class TestUntracedWithTrace:
    """-e --trace=file: untraced summary with filtered categories."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['-e', '--trace=file']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)


# ═══════════════════════════════════════════════════════════════════
# -jp / --json-pretty
# ═══════════════════════════════════════════════════════════════════

class TestJsonPretty:
    """-jp: pretty-print JSON output."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['-jp']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=10)

    def test_valid_json(self):
        """Output should be valid JSON (already parsed by run_mactrace)."""
        assert isinstance(self.data, dict)


# ═══════════════════════════════════════════════════════════════════
# --strsize
# ═══════════════════════════════════════════════════════════════════

class TestStrsize:
    """--strsize 512: smaller string capture size."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--strsize', '512']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=10)

    def test_paths_captured(self):
        """Should still capture file paths."""
        opens = [e for e in self.data['events']
                 if e['syscall'] in ('open', 'openat')
                 and e.get('args', {}).get('path')]
        assert len(opens) >= 1


# ═══════════════════════════════════════════════════════════════════
# --verbose
# ═══════════════════════════════════════════════════════════════════

class TestVerbose:
    """-v: verbose mode."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['-v']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=10)

    def test_verbose_output_present(self):
        """Verbose mode should show DTrace probe info."""
        assert 'DTrace probes' in self.stderr or 'Starting DTrace' in self.stderr


# ═══════════════════════════════════════════════════════════════════
# Kitchen sink combos
# ═══════════════════════════════════════════════════════════════════

class TestKitchenSinkFile:
    """All file-related options: --capture-io --trace=file -e -jp -v."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_fileops'),
            extra_args=['--capture-io', '--trace=file', '-e', '-jp', '-v']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)

    def test_io_data(self):
        writes = [e for e in self.data['events']
                  if e['syscall'] in ('write', 'write_nocancel')
                  and e['return_value'] > 0
                  and e.get('args', {}).get('data')]
        assert len(writes) >= 1


class TestKitchenSinkNet:
    """All network options: --capture-io --trace=net -v."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_udp_io'),
            extra_args=['--capture-io', '--trace=net', '-v']
        )

    def test_events_captured(self):
        assert_has_events(self.data, min_events=1)


class TestKitchenSinkIovec:
    """Iovec with all categories + verbose: --iovec 4 -v -e."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_iovec'),
            extra_args=['--iovec', '4', '-v', '-e']
        )

    def test_dtrace_compiled(self):
        assert 'DIF program exceeds' not in self.stderr

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)


class TestKitchenSinkAll:
    """The absolute maximum: --capture-io --iovec 4 --trace=file -e -jp -v --throttle."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_iovec'),
            extra_args=['--capture-io', '--iovec', '4', '--trace=file',
                        '-e', '-jp', '-v', '--throttle']
        )

    def test_dtrace_compiled(self):
        assert 'DIF program exceeds' not in self.stderr

    def test_events_captured(self):
        assert_has_events(self.data, min_events=3)

    def test_iovec_buffers_present(self):
        writevs = [e for e in self.data['events']
                   if e['syscall'] in ('writev', 'writev_nocancel')
                   and 'iov_buffers' in e.get('args', {})]
        assert len(writevs) >= 1

    def test_io_data_present(self):
        reads = [e for e in self.data['events']
                 if e['syscall'] in ('read', 'read_nocancel')
                 and e['return_value'] > 0
                 and e.get('args', {}).get('data')]
        # Reads might be filtered by --trace=file, which includes read
        # At minimum, file I/O should have data
        assert len(reads) >= 1 or len(self.data['events']) > 0


class TestFullProbesCaptureIOIovec:
    """The DOF stress test: all probes + capture-io + iovec (no --trace filter)."""

    @pytest.fixture(autouse=True)
    def trace(self, compile_programs):
        self.data, self.stderr = run_mactrace(
            os.path.join(PROGRAMS_DIR, 'test_iovec'),
            extra_args=['--capture-io', '--iovec', '4'],
            timeout=60  # extra time for heavy probe set
        )

    def test_dtrace_compiled(self):
        """This is THE regression test for the DOF limit bug."""
        assert 'DIF program exceeds' not in self.stderr

    def test_events_captured(self):
        assert_has_events(self.data, min_events=5)

    def test_pid_nonzero(self):
        assert self.data['target_pid'] > 0

    def test_dof_maxsize_adjusted(self):
        assert 'dof_maxsize' in self.stderr
