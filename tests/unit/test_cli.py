"""
CLI argument parsing tests for mactrace and mactrace_data.

Tests that all documented flags, subcommands, and option combinations
parse correctly without hitting argparse errors. Uses subprocess to
invoke the actual CLI entry points.
"""

import json
import os
import re
import subprocess
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MACTRACE = os.path.join(PROJECT_ROOT, 'mactrace')
MACTRACE_DATA = os.path.join(PROJECT_ROOT, 'mactrace_data')


def run_cli(cmd, args, timeout=10, expect_exit=None):
    """Run a CLI command and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, cmd] + args,
        capture_output=True, text=True, timeout=timeout
    )
    if expect_exit is not None:
        assert result.returncode == expect_exit, \
            f"Expected exit {expect_exit}, got {result.returncode}\n" \
            f"stdout: {result.stdout[:500]}\nstderr: {result.stderr[:500]}"
    return result.returncode, result.stdout, result.stderr


# =============================================================================
# mactrace CLI tests
# =============================================================================

class TestMactraceHelp:
    """Basic help and flag recognition."""

    def test_help_exits_zero(self):
        run_cli(MACTRACE, ['--help'], expect_exit=0)

    def test_help_contains_examples(self):
        _, stdout, _ = run_cli(MACTRACE, ['--help'], expect_exit=0)
        assert 'Examples:' in stdout
        assert '--trace=net' in stdout

    def test_help_contains_output_naming(self):
        _, stdout, _ = run_cli(MACTRACE, ['--help'], expect_exit=0)
        assert 'Output naming:' in stdout
        assert 'seconds-since-1970' in stdout

    def test_no_args_shows_help(self):
        """No command and no -p should print help, not crash."""
        code, stdout, stderr = run_cli(MACTRACE, [])
        # Should show help (exit 1) or usage, not a traceback
        assert code != 0
        assert 'Traceback' not in stderr


class TestMactraceIovecSyscalls:
    """--iovec-syscalls flag parsing."""

    def test_bare_iovec_syscalls_shows_help(self):
        """Bare --iovec-syscalls (no argument) should show help, not error."""
        code, stdout, stderr = run_cli(MACTRACE, ['--iovec-syscalls'])
        assert code == 0, f"Expected exit 0, got {code}\nstderr: {stderr}"
        assert 'Vectored I/O syscalls' in stdout
        assert 'readv' in stdout
        assert 'writev' in stdout

    def test_iovec_syscalls_help_explicit(self):
        """--iovec-syscalls=help should show the reference table."""
        code, stdout, _ = run_cli(MACTRACE, ['--iovec-syscalls=help'])
        assert code == 0
        assert 'Vectored I/O syscalls' in stdout
        assert 'DIF programs' in stdout

    def test_iovec_syscalls_help_space(self):
        """--iovec-syscalls help (space-separated) should also work."""
        code, stdout, _ = run_cli(MACTRACE, ['--iovec-syscalls', 'help'])
        assert code == 0
        assert 'Vectored I/O syscalls' in stdout


class TestMactraceTraceHelp:
    """--trace help flag parsing."""

    def test_trace_help_exits_zero(self):
        code, stdout, _ = run_cli(MACTRACE, ['--trace', 'help'])
        assert code == 0
        assert 'Categories' in stdout or 'category' in stdout.lower()

    def test_trace_help_equals(self):
        code, stdout, _ = run_cli(MACTRACE, ['--trace=help'])
        assert code == 0


class TestMactraceOutputNaming:
    """Output filename epoch injection logic."""

    def test_bare_name_gets_epoch(self):
        """'-o make' should become 'make.EPOCH.json'."""
        # We can't easily test this without running as root, but we can
        # test the logic by checking the error message (file doesn't exist
        # is fine — it means the name was resolved)
        code, _, stderr = run_cli(MACTRACE, ['-o', 'make', 'true'])
        # Will fail with "requires root" — but should NOT fail with argparse error
        assert 'error: unrecognized' not in stderr
        assert 'expected one argument' not in stderr

    def test_json_extension_preserved(self):
        """'-o make.json' should keep exact name (no epoch)."""
        code, _, stderr = run_cli(MACTRACE, ['-o', 'make.json', 'true'])
        assert 'error: unrecognized' not in stderr
        assert 'expected one argument' not in stderr




class TestMactraceDynamicMax:
    """DIF auto-sizing: -d flag and help text."""

    def test_help_shows_current_difo(self):
        """Help text for -d should show 'currently: NNNNN', not a hardcoded default."""
        _, stdout, _ = run_cli(MACTRACE, ['--help'], expect_exit=0)
        assert 'currently:' in stdout, "Expected 'currently: NNNNN' in -d help text"
        # argparse wraps long lines, normalize whitespace
        assert 'overrides automatic DIF' in ' '.join(stdout.split())

    def test_help_mentions_auto_adjust(self):
        """Description should mention automatic DIF adjustment."""
        _, stdout, _ = run_cli(MACTRACE, ['--help'], expect_exit=0)
        assert 'automatically adjusted' in stdout

# =============================================================================
# mactrace_data CLI tests
# =============================================================================

class TestMactraceDataHelp:
    """Basic help and subcommand recognition."""

    def test_help_exits_zero(self):
        run_cli(MACTRACE_DATA, ['--help'], expect_exit=0)

    def test_no_args_shows_help(self):
        code, stdout, _ = run_cli(MACTRACE_DATA, [])
        # Should show help, not crash
        assert 'mactrace_data' in stdout or 'usage' in stdout.lower()

    def test_help_shows_all_subcommands(self):
        _, stdout, _ = run_cli(MACTRACE_DATA, ['--help'], expect_exit=0)
        for cmd in ['list', 'info', 'delete', 'db', 'files', 'config']:
            assert cmd in stdout, f"Missing subcommand '{cmd}' in help"


class TestMactraceDataConfig:
    """config subcommand."""

    def test_config_runs(self):
        code, stdout, _ = run_cli(MACTRACE_DATA, ['config'])
        assert code == 0
        assert 'Config file:' in stdout
        assert 'Database:' in stdout
        assert 'Traces dir:' in stdout

    def test_config_alias_cfg(self):
        code, stdout, _ = run_cli(MACTRACE_DATA, ['cfg'])
        assert code == 0
        assert 'Config file:' in stdout


class TestMactraceDataList:
    """list subcommand."""

    def test_list_runs(self):
        code, stdout, _ = run_cli(MACTRACE_DATA, ['list'])
        assert code == 0
        # Should have header or "No traces"
        assert '#' in stdout or 'No traces' in stdout

    def test_list_alias_ls(self):
        code, _, _ = run_cli(MACTRACE_DATA, ['ls'])
        assert code == 0

    def test_list_with_nonexistent_db(self):
        """--db pointing to nonexistent file should handle gracefully."""
        code, stdout, stderr = run_cli(MACTRACE_DATA, ['--db', '/tmp/nonexistent.db', 'list'])
        # Should not crash with traceback
        assert 'Traceback' not in stderr


class TestMactraceDataDelete:
    """delete subcommand argument parsing."""

    def test_delete_force_long(self):
        """'delete --all --force' should parse without error."""
        # Use nonexistent DB/traces so it doesn't scan real (slow) volumes
        code, stdout, stderr = run_cli(MACTRACE_DATA,
            ['--db', '/tmp/nonexistent.db', '-t', '/tmp/nonexistent_traces', 'delete', '--all', '--force'])
        assert 'unrecognized arguments' not in stderr, \
            f"--force not recognized: {stderr}"

    def test_delete_force_short(self):
        """'delete --all -f' should parse without error."""
        code, stdout, stderr = run_cli(MACTRACE_DATA,
            ['--db', '/tmp/nonexistent.db', '-t', '/tmp/nonexistent_traces', 'delete', '--all', '-f'])
        assert 'unrecognized arguments' not in stderr

    def test_delete_by_number_force(self):
        """'delete 1 --force' should parse."""
        code, stdout, stderr = run_cli(MACTRACE_DATA,
            ['--db', '/tmp/nonexistent.db', '-t', '/tmp/nonexistent_traces', 'delete', '1', '--force'])
        assert 'unrecognized arguments' not in stderr

    def test_delete_multiple_numbers(self):
        """'delete 1 2 3' should parse."""
        code, stdout, stderr = run_cli(MACTRACE_DATA,
            ['--db', '/tmp/nonexistent.db', '-t', '/tmp/nonexistent_traces', 'delete', '1', '2', '3'])
        assert 'unrecognized arguments' not in stderr

    def test_delete_no_args_errors(self):
        """'delete' with no IDs and no --all should error."""
        code, stdout, stderr = run_cli(MACTRACE_DATA, ['delete'])
        assert code != 0

    def test_delete_all_no_force_prompts(self):
        """'delete --all' without --force should prompt (and EOF → cancel)."""
        code, stdout, stderr = run_cli(MACTRACE_DATA, ['delete', '--all'])
        # Will try to prompt, get EOF, and cancel or error — but NOT argparse error
        assert 'unrecognized arguments' not in stderr


class TestMactraceDataDbSubcommand:
    """db subcommand and its sub-subcommands."""

    def test_db_help(self):
        code, stdout, _ = run_cli(MACTRACE_DATA, ['db', '--help'])
        assert code == 0
        assert 'list' in stdout

    def test_db_list(self):
        code, stdout, stderr = run_cli(MACTRACE_DATA, ['db', 'list'])
        assert 'unrecognized' not in stderr

    def test_db_list_json(self):
        code, stdout, stderr = run_cli(MACTRACE_DATA, ['db', 'list', '--json'])
        assert 'unrecognized' not in stderr

    def test_db_stats(self):
        code, stdout, stderr = run_cli(MACTRACE_DATA, ['db', 'stats'])
        assert 'unrecognized' not in stderr

    def test_db_delete_force(self):
        """'db delete 1 --force' should parse."""
        code, _, stderr = run_cli(MACTRACE_DATA, ['db', 'delete', '1', '--force'])
        assert 'unrecognized arguments' not in stderr

    def test_db_delete_short_force(self):
        """'db delete 1 -f' should parse."""
        code, _, stderr = run_cli(MACTRACE_DATA, ['db', 'delete', '1', '-f'])
        assert 'unrecognized arguments' not in stderr

    def test_db_vacuum(self):
        code, _, stderr = run_cli(MACTRACE_DATA, ['--db', '/tmp/nonexistent.db', 'db', 'vacuum'])
        # Nonexistent DB → error, but not an argparse error
        assert 'unrecognized' not in stderr

    def test_db_info(self):
        code, _, stderr = run_cli(MACTRACE_DATA, ['db', 'info', '1'])
        assert 'unrecognized' not in stderr


class TestMactraceDataFilesSubcommand:
    """files subcommand and its sub-subcommands."""

    def test_files_help(self):
        code, stdout, _ = run_cli(MACTRACE_DATA, ['files', '--help'])
        assert code == 0

    def test_files_list(self):
        code, _, stderr = run_cli(MACTRACE_DATA, ['files', 'list'])
        assert 'unrecognized' not in stderr

    def test_files_list_json(self):
        code, _, stderr = run_cli(MACTRACE_DATA, ['files', 'list', '--json'])
        assert 'unrecognized' not in stderr

    def test_files_delete_force(self):
        """'files delete 1 --force' should parse."""
        code, _, stderr = run_cli(MACTRACE_DATA, ['files', 'delete', '1', '--force'])
        assert 'unrecognized arguments' not in stderr

    def test_files_delete_short_force(self):
        """'files delete 1 -f' should parse."""
        code, _, stderr = run_cli(MACTRACE_DATA, ['files', 'delete', '1', '-f'])
        assert 'unrecognized arguments' not in stderr


class TestMactraceDataVerbose:
    """Global flags work with subcommands."""

    def test_verbose_with_list(self):
        code, _, stderr = run_cli(MACTRACE_DATA, ['-v', 'list'])
        assert code == 0
        assert 'Database:' in stderr

    def test_verbose_with_config(self):
        code, stdout, _ = run_cli(MACTRACE_DATA, ['-v', 'config'])
        assert code == 0
