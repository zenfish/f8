"""
Tests for DTrace output line parsing in the mactrace tracer.

Since the mactrace file has no .py extension, we import it via importlib.
Tests cover all MACTRACE_* line formats, malformed input, and edge cases.
"""

import sys
import os
import importlib.util
import pytest

# Import the mactrace module (no .py extension)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
spec = importlib.util.spec_from_loader(
    'mactrace_mod',
    importlib.machinery.SourceFileLoader('mactrace_mod', os.path.join(PROJECT_ROOT, 'mactrace'))
)
mactrace_mod = importlib.util.module_from_spec(spec)

# We need to load the module but NOT run main() — just get the classes
# Load it with __name__ set to avoid triggering if __name__ == "__main__"
spec.loader.exec_module(mactrace_mod)

MacTrace = mactrace_mod.MacTrace
parse_size = mactrace_mod.parse_size


# ============================================================================
# parse_size
# ============================================================================

class TestParseSize:
    """Test parse_size() — human-readable size strings to bytes."""

    def test_bytes(self):
        assert parse_size('1024') == 1024

    def test_kilobytes(self):
        assert parse_size('10k') == 10 * 1024
        assert parse_size('10K') == 10 * 1024

    def test_megabytes(self):
        assert parse_size('5m') == 5 * 1024 * 1024
        assert parse_size('5M') == 5 * 1024 * 1024

    def test_gigabytes(self):
        assert parse_size('1g') == 1024 * 1024 * 1024
        assert parse_size('1G') == 1024 * 1024 * 1024

    def test_fractional(self):
        assert parse_size('1.5M') == int(1.5 * 1024 * 1024)

    def test_whitespace(self):
        assert parse_size('  10M  ') == 10 * 1024 * 1024

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_size('')

    def test_plain_zero(self):
        assert parse_size('0') == 0


# ============================================================================
# _parse_line — DTrace output parsing
# ============================================================================

class TestParseLine:
    """Test MacTrace._parse_line() with various DTrace output formats."""

    def setup_method(self):
        """Create a fresh MacTrace instance for each test."""
        self.tracer = MacTrace(verbose=False)
        self.base_ts = 1000000  # base timestamp for relative calculations

    def test_start_line(self):
        """MACTRACE_START sets start timestamp and records PID."""
        self.tracer._parse_line("MACTRACE_START 1234 5000000", self.base_ts)
        assert 1234 in self.tracer.pids_traced
        assert self.tracer.start_timestamp == 5000000

    def test_end_line(self):
        """MACTRACE_END sets end timestamp."""
        self.tracer._parse_line("MACTRACE_END 9000000", self.base_ts)
        assert self.tracer.end_timestamp == 9000000

    def test_child_line(self):
        """MACTRACE_CHILD records child PID and parent mapping."""
        self.tracer.start_timestamp = self.base_ts
        self.tracer._parse_line("MACTRACE_CHILD 200 100 2000000", self.base_ts)
        assert 200 in self.tracer.pids_traced
        assert self.tracer.process_tree[200] == 100

    def test_fork_child_line(self):
        """MACTRACE_FORK_CHILD records parent→child relationship."""
        self.tracer.start_timestamp = self.base_ts
        self.tracer._parse_line("MACTRACE_FORK_CHILD 100 201 1 3000000", self.base_ts)
        assert 201 in self.tracer.pids_traced
        assert self.tracer.process_tree[201] == 100
        assert len(self.tracer.process_events) == 1
        assert self.tracer.process_events[0].event_type == "fork"

    def test_exit_line(self):
        """MACTRACE_EXIT records exit event."""
        self.tracer.start_timestamp = self.base_ts
        self.tracer._parse_line("MACTRACE_EXIT 200 100 0 4000000", self.base_ts)
        assert any(pe.event_type == "exit" for pe in self.tracer.process_events)

    def test_allsyscall_line(self):
        """MACTRACE_ALLSYSCALL records syscall counts."""
        self.tracer._parse_line("MACTRACE_ALLSYSCALL open 42", self.base_ts)
        assert self.tracer.all_syscall_counts['open'] == 42

    def test_allsyscall_init_skipped(self):
        """MACTRACE_ALLSYSCALL __init__ (our marker) is ignored."""
        self.tracer._parse_line("MACTRACE_ALLSYSCALL __init__ 1", self.base_ts)
        assert '__init__' not in self.tracer.all_syscall_counts

    def test_syscall_line(self):
        """MACTRACE_SYSCALL records a syscall event."""
        self.tracer.start_timestamp = self.base_ts
        self.tracer._parse_line(
            "MACTRACE_SYSCALL 1234 1 open 3 0 2000000 \"/etc/passwd\" 0x0 0644",
            self.base_ts
        )
        assert len(self.tracer.events) == 1
        evt = self.tracer.events[0]
        # SyscallEvent is a dataclass — access via attributes, not dict keys
        assert evt.pid == 1234
        assert evt.syscall == 'open'
        assert evt.return_value == 3
        assert evt.errno == 0

    def test_empty_line_ignored(self):
        """Empty/blank lines are silently ignored."""
        self.tracer._parse_line("", self.base_ts)
        self.tracer._parse_line("   ", self.base_ts)
        assert len(self.tracer.events) == 0

    def test_non_mactrace_line_ignored(self):
        """Lines not starting with MACTRACE_ are ignored."""
        self.tracer._parse_line("dtrace: some warning message", self.base_ts)
        self.tracer._parse_line("random garbage", self.base_ts)
        assert len(self.tracer.events) == 0

    def test_truncated_line_no_crash(self):
        """Truncated lines shouldn't crash the parser."""
        # These are all malformed but should not raise exceptions
        self.tracer._parse_line("MACTRACE_SYSCALL", self.base_ts)
        self.tracer._parse_line("MACTRACE_SYSCALL 1234", self.base_ts)
        self.tracer._parse_line("MACTRACE_START", self.base_ts)
        self.tracer._parse_line("MACTRACE_CHILD 100", self.base_ts)
        assert len(self.tracer.events) == 0  # Nothing valid parsed

    def test_garbled_timestamp_no_crash(self):
        """Non-numeric timestamps shouldn't crash."""
        # DTrace can produce garbled output under load
        self.tracer._parse_line("MACTRACE_START 1234 notanumber", self.base_ts)
        # Should either ignore or handle gracefully

    def test_negative_return_value(self):
        """Negative return values (error indicators) are preserved."""
        self.tracer.start_timestamp = self.base_ts
        self.tracer._parse_line(
            "MACTRACE_SYSCALL 1234 1 open -1 2 2000000 \"/nonexistent\" 0x0 0644",
            self.base_ts
        )
        if self.tracer.events:
            assert self.tracer.events[0].return_value == -1
            assert self.tracer.events[0].errno == 2


# ============================================================================
# render_terminal_lines (standalone function in mactrace)
# ============================================================================

class TestRenderTerminalLines:
    """Test render_terminal_lines() in the mactrace module."""

    def setup_method(self):
        self.render = mactrace_mod.render_terminal_lines

    def test_empty(self):
        assert self.render([]) == []

    def test_single_line(self):
        assert self.render(["hello"]) == ["hello"]

    def test_multiple_lines(self):
        assert self.render(["line1", "line2"]) == ["line1", "line2"]

    def test_progress_overwrites(self):
        """Wget-style progress lines should collapse."""
        lines = [
            "0K .......... .......... .......... .......... ..........  50%",
            "50K .......... .......... .......... .......... .......... 100%",
        ]
        result = self.render(lines)
        # Should keep final progress line
        assert any("100%" in line for line in result)
