"""
Tests for DTrace parser handling of malformed, garbled, and edge-case input.

DTrace under heavy load drops events, produces partial lines, and
interleaves output from multiple CPUs. The parser must handle all of
this without crashing or producing corrupt data.
"""

import os
import sys
import importlib.util
import importlib.machinery
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
spec = importlib.util.spec_from_loader(
    'mactrace_mod',
    importlib.machinery.SourceFileLoader('mactrace_mod', os.path.join(PROJECT_ROOT, 'mactrace'))
)
mactrace_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mactrace_mod)
MacTrace = mactrace_mod.MacTrace

BASE_TS = 1000000


def make_tracer():
    t = MacTrace(verbose=False)
    t.start_timestamp = BASE_TS
    return t


# ============================================================================
# Truncated / Partial Lines
# ============================================================================

class TestTruncatedLines:
    """Lines that got cut off mid-output (DTrace buffer overflow)."""

    def test_syscall_missing_all_args(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL", BASE_TS)
        assert len(t.events) == 0

    def test_syscall_missing_most_args(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234", BASE_TS)
        assert len(t.events) == 0

    def test_syscall_missing_return_value(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234 1 open", BASE_TS)
        # May or may not parse — shouldn't crash
        # Don't assert on events, just verify no exception

    def test_child_missing_timestamp(self):
        t = make_tracer()
        t._parse_line("MACTRACE_CHILD 200 100", BASE_TS)
        # Missing timestamp — shouldn't crash

    def test_fork_child_missing_fields(self):
        t = make_tracer()
        t._parse_line("MACTRACE_FORK_CHILD 100", BASE_TS)
        t._parse_line("MACTRACE_FORK_CHILD 100 200", BASE_TS)
        t._parse_line("MACTRACE_FORK_CHILD 100 200 1", BASE_TS)

    def test_exit_missing_fields(self):
        t = make_tracer()
        t._parse_line("MACTRACE_EXIT 200", BASE_TS)
        t._parse_line("MACTRACE_EXIT 200 100", BASE_TS)

    def test_start_missing_timestamp(self):
        t = make_tracer()
        t._parse_line("MACTRACE_START 1234", BASE_TS)
        assert 1234 in t.pids_traced

    def test_end_empty(self):
        t = make_tracer()
        t._parse_line("MACTRACE_END", BASE_TS)


# ============================================================================
# Garbled / Interleaved Output
# ============================================================================

class TestGarbledOutput:
    """Lines corrupted by CPU interleaving or buffer issues."""

    def test_non_numeric_pid(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL abc 1 open 3 0 2000000", BASE_TS)
        # Should not crash — garbled PID

    def test_non_numeric_timestamp(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234 1 open 3 0 notanumber", BASE_TS)

    def test_negative_pid(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL -1 1 open 3 0 2000000", BASE_TS)

    def test_extremely_large_pid(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 99999999999 1 open 3 0 2000000", BASE_TS)

    def test_empty_syscall_name(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234 1  3 0 2000000", BASE_TS)

    def test_binary_garbage(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL \x00\x01\x02 1 open 3 0 2000000", BASE_TS)

    def test_very_long_line(self):
        t = make_tracer()
        long_path = "/a" * 10000
        t._parse_line(f'MACTRACE_SYSCALL 1234 1 open 3 0 2000000 "{long_path}" 0x0 0644', BASE_TS)

    def test_interleaved_partial_lines(self):
        """Two lines merged together by buffer race."""
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234 1 open 3 0 2000000MACTRACE_SYSCALL 5678 1 close 0 0 3000000", BASE_TS)
        # Should not crash — may parse first event or skip both

    def test_unicode_in_path(self):
        t = make_tracer()
        t._parse_line('MACTRACE_SYSCALL 1234 1 open 3 0 2000000 "/tmp/日本語/файл" 0x0 0644', BASE_TS)

    def test_newlines_in_quoted_path(self):
        t = make_tracer()
        t._parse_line('MACTRACE_SYSCALL 1234 1 open 3 0 2000000 "/tmp/file\\nwith\\nnewlines" 0x0 0644', BASE_TS)


# ============================================================================
# DTrace Drop / Diagnostic Lines
# ============================================================================

class TestDtraceDrops:
    """Lines that DTrace itself emits about drops and errors."""

    def test_dtrace_warning_ignored(self):
        t = make_tracer()
        t._parse_line("dtrace: 15 drops on CPU 0", BASE_TS)
        assert len(t.events) == 0

    def test_dtrace_error_ignored(self):
        t = make_tracer()
        t._parse_line("dtrace: error on enabled probe ID 5: invalid address", BASE_TS)
        assert len(t.events) == 0

    def test_dtrace_scratch_error_ignored(self):
        t = make_tracer()
        t._parse_line("dtrace: 1 dynamic variable drop", BASE_TS)
        assert len(t.events) == 0

    def test_blank_lines_ignored(self):
        t = make_tracer()
        for line in ["", "  ", "\t", "\n", "   \t  \n  "]:
            t._parse_line(line, BASE_TS)
        assert len(t.events) == 0


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases:
    """Valid but unusual inputs."""

    def test_pid_zero(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 0 0 open 3 0 2000000", BASE_TS)
        # PID 0 is kernel — unusual but technically valid

    def test_very_large_return_value(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234 1 mmap 140735340871680 0 2000000", BASE_TS)
        # mmap returns addresses that look like very large numbers

    def test_negative_return_value(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234 1 open -1 2 2000000", BASE_TS)
        if t.events:
            assert t.events[0].return_value == -1

    def test_zero_timestamp(self):
        t = make_tracer()
        t._parse_line("MACTRACE_SYSCALL 1234 1 open 3 0 0", BASE_TS)

    def test_allsyscall_zero_count(self):
        t = make_tracer()
        t._parse_line("MACTRACE_ALLSYSCALL some_call 0", BASE_TS)
        assert t.all_syscall_counts.get('some_call') == 0

    def test_rapid_fork_exit_sequence(self):
        """Simulate rapid fork/exit — 50 children in quick succession."""
        t = make_tracer()
        for i in range(50):
            child = 1000 + i
            ts = 2000000 + i * 100
            t._parse_line(f"MACTRACE_FORK_CHILD 999 {child} 1 {ts}", BASE_TS)
            t._parse_line(f"MACTRACE_EXIT {child} 999 0 {ts + 50}", BASE_TS)
        assert len(t.pids_traced) >= 50
        assert len(t.process_events) >= 100  # 50 forks + 50 exits
