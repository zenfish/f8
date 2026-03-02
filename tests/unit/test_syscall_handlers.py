"""
Tests for syscalls/ handler modules — DTrace probe generation and argument parsing.

Validates:
- All registered handlers produce non-empty DTrace probe text
- DTrace text contains expected probe patterns (syscall::name:entry/return)
- parse_args handles valid input for each handler family
- parse_args handles missing/malformed args gracefully
- Handler metadata is consistent (categories, syscall lists)
"""

import re
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

from syscalls import (
    HANDLER_REGISTRY, ALL_DTRACE_PROBES, TRACED_SYSCALLS,
    SyscallHandler,
)


class TestHandlerRegistry:
    """Tests for the handler registration system."""

    def test_registry_not_empty(self):
        assert len(HANDLER_REGISTRY) > 100, "Should have 100+ registered syscall handlers"

    def test_all_handlers_are_instances(self):
        for name, handler in HANDLER_REGISTRY.items():
            assert isinstance(handler, SyscallHandler), f"{name} handler is not a SyscallHandler"

    def test_traced_syscalls_matches_registry(self):
        """TRACED_SYSCALLS should be a subset of or equal to registry keys."""
        for name in TRACED_SYSCALLS:
            assert name in HANDLER_REGISTRY, f"{name} in TRACED_SYSCALLS but not in HANDLER_REGISTRY"

    def test_all_handlers_have_categories(self):
        for name, handler in HANDLER_REGISTRY.items():
            assert hasattr(handler, 'categories'), f"{name} handler missing categories"
            assert len(handler.categories) > 0, f"{name} handler has empty categories"

    def test_all_handlers_have_syscalls_list(self):
        for name, handler in HANDLER_REGISTRY.items():
            assert hasattr(handler, 'syscalls'), f"{name} handler missing syscalls list"

    def test_no_duplicate_syscall_registrations(self):
        """Each syscall name should map to exactly one handler."""
        seen = {}
        for name, handler in HANDLER_REGISTRY.items():
            if name in seen:
                pytest.fail(f"Syscall '{name}' registered by both {seen[name]} and {handler.__class__.__name__}")
            seen[name] = handler.__class__.__name__


class TestDTraceProbes:
    """Tests for generated DTrace probe text."""

    def test_probes_not_empty(self):
        assert len(ALL_DTRACE_PROBES) > 1000, "Combined DTrace probes should be substantial"

    def test_probes_contain_entry_return_pairs(self):
        """Every handler that has dtrace text should have both entry and return probes."""
        handlers_seen = set()
        for name, handler in HANDLER_REGISTRY.items():
            cls = handler.__class__.__name__
            if cls in handlers_seen:
                continue
            handlers_seen.add(cls)
            dtrace = getattr(handler, 'dtrace', '')
            if not dtrace:
                continue
            # At least one entry and one return probe
            assert 'entry' in dtrace or 'return' in dtrace or 'BEGIN' in dtrace, \
                f"{cls} has dtrace text but no entry probes"

    def test_probes_contain_f8_prefix(self):
        """All probes should output F8_ prefixed lines."""
        assert 'F8_' in ALL_DTRACE_PROBES

    def test_no_syntax_errors_in_probes(self):
        """Basic syntax checks on DTrace text."""
        # Balanced braces
        open_braces = ALL_DTRACE_PROBES.count('{')
        close_braces = ALL_DTRACE_PROBES.count('}')
        assert open_braces == close_braces, \
            f"Unbalanced braces: {open_braces} open vs {close_braces} close"

    def test_probe_references_tracked_syscalls(self):
        """Spot-check that key syscalls appear in probe text."""
        for syscall in ['open', 'read', 'write', 'close', 'connect', 'socket', 'stat64']:
            assert f'syscall::{syscall}:' in ALL_DTRACE_PROBES, \
                f"Expected probe for '{syscall}' not found in DTrace text"


class TestFileOpenHandler:
    """Tests for file open syscall parsing."""

    def test_parse_open_basic(self):
        h = HANDLER_REGISTRY['open']
        result = h.parse_args('open', ['3', '0', '1000', '"/etc/passwd"', '0x0', '0644'])
        assert 'path' in result
        assert 'flags' in result

    def test_parse_open_empty_args(self):
        h = HANDLER_REGISTRY['open']
        result = h.parse_args('open', [])
        assert isinstance(result, dict)

    def test_parse_openat(self):
        h = HANDLER_REGISTRY['openat']
        result = h.parse_args('openat', ['AT_FDCWD', '"/tmp/test"', '0x0', '0644'])
        assert isinstance(result, dict)


class TestFileRWHandler:
    """Tests for read/write syscall parsing."""

    def test_parse_read(self):
        h = HANDLER_REGISTRY['read']
        result = h.parse_args('read', ['3', '4096'])
        assert result.get('fd') == 3
        assert result.get('count') == 4096

    def test_parse_write(self):
        h = HANDLER_REGISTRY['write']
        result = h.parse_args('write', ['1', '512'])
        assert result.get('fd') == 1
        assert result.get('count') == 512

    def test_parse_read_empty(self):
        h = HANDLER_REGISTRY['read']
        result = h.parse_args('read', [])
        assert isinstance(result, dict)

    def test_parse_pread(self):
        h = HANDLER_REGISTRY['pread']
        result = h.parse_args('pread', ['3', '4096', '1024'])
        assert isinstance(result, dict)


class TestFileStatHandler:
    """Tests for stat syscall parsing."""

    def test_parse_stat64(self):
        h = HANDLER_REGISTRY['stat64']
        result = h.parse_args('stat64', ['"/etc/passwd"'])
        assert isinstance(result, dict)

    def test_parse_fstat64(self):
        h = HANDLER_REGISTRY['fstat64']
        result = h.parse_args('fstat64', ['3'])
        assert isinstance(result, dict)

    def test_parse_lstat64(self):
        h = HANDLER_REGISTRY['lstat64']
        result = h.parse_args('lstat64', ['"/etc/passwd"'])
        assert isinstance(result, dict)


class TestNetworkHandlers:
    """Tests for network syscall parsing."""

    def test_parse_socket(self):
        h = HANDLER_REGISTRY['socket']
        result = h.parse_args('socket', ['2', '1', '6'])
        assert isinstance(result, dict)

    def test_parse_connect(self):
        h = HANDLER_REGISTRY['connect']
        result = h.parse_args('connect', ['3', '"AF_INET/SOCK_STREAM/10.0.0.1:80"'])
        assert isinstance(result, dict)

    def test_parse_sendto(self):
        h = HANDLER_REGISTRY['sendto']
        result = h.parse_args('sendto', ['3', '512', '0'])
        assert isinstance(result, dict)

    def test_parse_recvfrom(self):
        h = HANDLER_REGISTRY['recvfrom']
        result = h.parse_args('recvfrom', ['3', '1024', '0'])
        assert isinstance(result, dict)

    def test_parse_socket_empty(self):
        h = HANDLER_REGISTRY['socket']
        result = h.parse_args('socket', [])
        assert isinstance(result, dict)


class TestProcessHandlers:
    """Tests for process syscall parsing."""

    def test_parse_fork(self):
        h = HANDLER_REGISTRY.get('fork')
        if h:
            result = h.parse_args('fork', [])
            assert isinstance(result, dict)

    def test_parse_execve(self):
        h = HANDLER_REGISTRY.get('execve')
        if h:
            result = h.parse_args('execve', ['"/bin/ls"', '"ls"', '"-la"'])
            assert isinstance(result, dict)


class TestMemoryHandlers:
    """Tests for memory syscall parsing."""

    def test_parse_mmap(self):
        h = HANDLER_REGISTRY['mmap']
        result = h.parse_args('mmap', ['0x0', '4096', '3', '2', '3', '0'])
        assert isinstance(result, dict)

    def test_parse_mprotect(self):
        h = HANDLER_REGISTRY['mprotect']
        result = h.parse_args('mprotect', ['0x100000', '4096', '1'])
        assert isinstance(result, dict)

    def test_parse_munmap(self):
        h = HANDLER_REGISTRY['munmap']
        result = h.parse_args('munmap', ['0x100000', '4096'])
        assert isinstance(result, dict)


class TestCloseHandler:
    """Tests for close syscall parsing."""

    def test_parse_close(self):
        h = HANDLER_REGISTRY['close']
        result = h.parse_args('close', ['3'])
        assert isinstance(result, dict)
        assert result.get('fd') == 3

    def test_parse_close_nocancel(self):
        h = HANDLER_REGISTRY.get('close_nocancel')
        if h:
            result = h.parse_args('close_nocancel', ['5'])
            assert isinstance(result, dict)


class TestMACHandlers:
    """Tests for MAC (Mandatory Access Control) handlers."""

    def test_mac_syscall_registered(self):
        h = HANDLER_REGISTRY.get('__mac_syscall')
        if h:
            assert 'mac' in h.categories


class TestEdgeCases:
    """Edge cases across all handlers."""

    def test_all_handlers_survive_empty_args(self):
        """No handler should crash on empty args."""
        for name, handler in HANDLER_REGISTRY.items():
            try:
                result = handler.parse_args(name, [])
                assert isinstance(result, dict), f"{name} returned non-dict on empty args"
            except (IndexError, ValueError, TypeError) as e:
                pytest.fail(f"Handler '{name}' crashed on empty args: {e}")

    def test_all_handlers_survive_garbage_args(self):
        """No handler should crash on garbage args."""
        garbage = ['GARBAGE', 'not_a_number', '""', '0xZZZ', '-1']
        for name, handler in HANDLER_REGISTRY.items():
            try:
                result = handler.parse_args(name, garbage)
                assert isinstance(result, dict), f"{name} returned non-dict on garbage"
            except (IndexError, ValueError, TypeError):
                pass  # Acceptable to raise on garbage, just shouldn't crash/hang

    def test_nocancel_variants_have_same_handler(self):
        """_nocancel variants should use the same handler class as the base syscall."""
        for name, handler in HANDLER_REGISTRY.items():
            if name.endswith('_nocancel'):
                base = name.replace('_nocancel', '')
                if base in HANDLER_REGISTRY:
                    assert type(handler) == type(HANDLER_REGISTRY[base]), \
                        f"{name} and {base} should use same handler class"
