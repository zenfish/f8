"""
Tests for mactrace_lib.py — shared utility functions.

Covers: format_bytes, format_duration, sanitize_filename, extract_raw_bytes,
        python_hexdump, render_terminal, file classification, config parsing.
"""

import os
import re
import tempfile
import pytest

from mactrace_lib import (
    format_bytes, format_bytes_short, format_duration,
    sanitize_filename, truncate_path,
    extract_raw_bytes, python_hexdump, render_terminal,
    is_config_file, is_library, is_startup_file,
    get_mactrace_config, get_config_value, resolve_input_path,
)


# ============================================================================
# format_bytes
# ============================================================================

class TestFormatBytes:
    """Test format_bytes() — long form with units."""

    def test_zero(self):
        assert format_bytes(0) == "0 B"

    def test_small(self):
        assert format_bytes(1) == "1 B"
        assert format_bytes(100) == "100 B"
        assert format_bytes(1023) == "1023 B"

    def test_kilobytes(self):
        result = format_bytes(1024)
        assert "1.0" in result and "KB" in result

    def test_megabytes(self):
        result = format_bytes(1024 * 1024)
        assert "1.0" in result and "MB" in result

    def test_gigabytes(self):
        result = format_bytes(1024 * 1024 * 1024)
        assert "1.0" in result and "GB" in result

    def test_intermediate_values(self):
        """512 KB, 1.5 MB, etc."""
        result = format_bytes(512 * 1024)
        assert "512" in result or "0.5" in result

    def test_large_values(self):
        """Multi-GB values."""
        result = format_bytes(10 * 1024 * 1024 * 1024)
        assert "10" in result and "GB" in result


class TestFormatBytesShort:
    """Test format_bytes_short() — compact form."""

    def test_zero(self):
        assert format_bytes_short(0) == "0"

    def test_small(self):
        assert format_bytes_short(100) == "100"

    def test_kilobytes(self):
        assert format_bytes_short(1024) == "1.0K"

    def test_megabytes(self):
        assert format_bytes_short(1048576) == "1.0M"


# ============================================================================
# format_duration
# ============================================================================

class TestFormatDuration:
    """Test format_duration()."""

    def test_microseconds(self):
        result = format_duration(0.5)
        assert "µs" in result or "us" in result

    def test_milliseconds(self):
        result = format_duration(15.3)
        assert "ms" in result

    def test_seconds(self):
        result = format_duration(1500)
        assert "s" in result

    def test_minutes(self):
        result = format_duration(120000)
        assert "min" in result

    def test_zero(self):
        result = format_duration(0)
        assert "µs" in result or "0" in result


# ============================================================================
# sanitize_filename
# ============================================================================

class TestSanitizeFilename:
    """Test sanitize_filename()."""

    def test_simple_name(self):
        assert sanitize_filename("hello") == "hello"

    def test_empty_string(self):
        assert sanitize_filename("") == "unknown"

    def test_none(self):
        assert sanitize_filename(None) == "unknown"

    def test_slashes(self):
        result = sanitize_filename("/foo/bar/baz")
        assert "/" not in result

    def test_special_characters(self):
        result = sanitize_filename('hello:world<test>?*"|')
        assert all(c not in result for c in ':*?"<>|')

    def test_leading_dots_removed(self):
        result = sanitize_filename("..hidden")
        assert not result.startswith('.')

    def test_leading_underscores_removed(self):
        result = sanitize_filename("__private")
        assert not result.startswith('_')

    def test_multiple_underscores_collapsed(self):
        result = sanitize_filename("foo___bar")
        assert "__" not in result

    def test_truncation(self):
        long_name = "a" * 200
        result = sanitize_filename(long_name)
        assert len(result) <= 60

    def test_custom_max_len(self):
        result = sanitize_filename("abcdefghij", max_len=5)
        assert len(result) <= 5

    def test_spaces_replaced(self):
        result = sanitize_filename("hello world")
        assert " " not in result

    def test_path_with_extension(self):
        result = sanitize_filename("/usr/bin/python3.11")
        assert "/" not in result
        assert "python3.11" in result or "python3_11" in result

    def test_socket_address(self):
        """Socket addresses like '127.0.0.1:8080' should sanitize cleanly."""
        result = sanitize_filename("127.0.0.1:8080")
        assert result  # Not empty/unknown
        assert "/" not in result


# ============================================================================
# truncate_path
# ============================================================================

class TestTruncatePath:
    """Test truncate_path()."""

    def test_short_path_unchanged(self):
        assert truncate_path("/usr/bin/foo") == "/usr/bin/foo"

    def test_long_path_truncated(self):
        long_path = "/very/deeply/nested" * 20
        result = truncate_path(long_path, max_len=50)
        assert len(result) <= 55  # Allow slight overshoot due to " ... "
        assert "..." in result

    def test_preserves_start_and_end(self):
        path = "/start/" + "x" * 200 + "/end.txt"
        result = truncate_path(path, max_len=40)
        assert result.startswith("/start")
        assert result.endswith("end.txt") or "..." in result


# ============================================================================
# extract_raw_bytes
# ============================================================================

class TestExtractRawBytes:
    """Test extract_raw_bytes() — converts various data formats to bytes."""

    def test_none(self):
        assert extract_raw_bytes(None) == b''

    def test_bytes_passthrough(self):
        data = b'\x00\x01\x02'
        assert extract_raw_bytes(data) == data

    def test_hex_string(self):
        assert extract_raw_bytes("48656c6c6f") == b'Hello'

    def test_hex_string_uppercase(self):
        assert extract_raw_bytes("48454C4C4F") == b'HELLO'

    def test_hex_string_single_byte(self):
        assert extract_raw_bytes("41") == b'A'

    def test_escape_newline(self):
        assert extract_raw_bytes("\\n") == b'\n'

    def test_escape_tab(self):
        assert extract_raw_bytes("\\t") == b'\t'

    def test_escape_cr(self):
        assert extract_raw_bytes("\\r") == b'\r'

    def test_escape_backslash(self):
        assert extract_raw_bytes("\\\\") == b'\\'

    def test_escape_hex(self):
        assert extract_raw_bytes("\\x41") == b'A'
        assert extract_raw_bytes("\\x00") == b'\x00'
        assert extract_raw_bytes("\\xff") == b'\xff'

    def test_escape_octal(self):
        assert extract_raw_bytes("\\101") == b'A'  # 0o101 = 65 = 'A'
        assert extract_raw_bytes("\\000") == b'\x00'

    def test_escape_null(self):
        assert extract_raw_bytes("\\0") == b'\x00'

    def test_mixed_content(self):
        """Plain text with escape sequences mixed in."""
        result = extract_raw_bytes("Hello\\nWorld")
        assert result == b'Hello\nWorld'

    def test_list_of_bytes(self):
        assert extract_raw_bytes([72, 101, 108, 108, 111]) == b'Hello'

    def test_empty_string(self):
        assert extract_raw_bytes("") == b''

    def test_plain_text(self):
        """Non-hex, non-escape text passes through as UTF-8."""
        result = extract_raw_bytes("hello world")
        assert result == b'hello world'

    def test_odd_length_hex_not_treated_as_hex(self):
        """Odd-length all-hex strings shouldn't be treated as hex."""
        result = extract_raw_bytes("abc")  # 3 chars, odd
        # Should be treated as text, not hex
        assert result == b'abc'


# ============================================================================
# python_hexdump
# ============================================================================

class TestPythonHexdump:
    """Test python_hexdump() — pure Python hexdump -C equivalent."""

    def test_empty(self):
        result = python_hexdump(b'')
        assert b'00000000' in result

    def test_single_byte(self):
        result = python_hexdump(b'A')
        assert b'41' in result
        assert b'|A|' in result

    def test_hello_world(self):
        result = python_hexdump(b'Hello, World!')
        lines = result.decode('ascii').strip().split('\n')
        assert len(lines) == 2  # One data line + offset trailer
        assert '48 65 6c 6c 6f' in lines[0]
        assert '|Hello, World!|' in lines[0]

    def test_16_byte_boundary(self):
        """Exactly 16 bytes should produce one data line."""
        data = b'0123456789abcdef'
        result = python_hexdump(data)
        lines = result.decode('ascii').strip().split('\n')
        assert len(lines) == 2  # Data + trailer
        assert '|0123456789abcdef|' in lines[0]

    def test_multi_line(self):
        """More than 16 bytes produces multiple lines."""
        data = b'A' * 32
        result = python_hexdump(data)
        lines = result.decode('ascii').strip().split('\n')
        assert len(lines) == 3  # Two data lines + trailer

    def test_non_printable_as_dots(self):
        """Non-printable bytes show as dots in ASCII column."""
        data = bytes(range(16))
        result = python_hexdump(data)
        # Bytes 0-31 are non-printable, should show as dots
        assert b'|................|' in result

    def test_offset_format(self):
        """Offsets should be 8-digit hex."""
        data = b'A' * 17
        result = python_hexdump(data).decode('ascii')
        assert '00000000' in result
        assert '00000010' in result

    def test_ends_with_offset_trailer(self):
        """Output ends with the total size as offset."""
        data = b'Hello'
        result = python_hexdump(data).decode('ascii').strip()
        last_line = result.split('\n')[-1]
        assert last_line.strip() == '00000005'


# ============================================================================
# render_terminal
# ============================================================================

class TestRenderTerminal:
    """Test render_terminal() — simulates terminal rendering."""

    def test_plain_text(self):
        result = render_terminal(b'Hello World')
        assert result == b'Hello World'

    def test_newlines(self):
        result = render_terminal(b'line1\nline2\nline3')
        assert b'line1\nline2\nline3' == result

    def test_cr_overwrites(self):
        """Carriage return should overwrite the current line."""
        result = render_terminal(b'old text\rnew')
        assert result == b'new text'

    def test_backspace(self):
        result = render_terminal(b'abc\x08d')
        assert result == b'abd'

    def test_tab_expansion(self):
        result = render_terminal(b'a\tb')
        assert b'a' in result and b'b' in result
        # Tab should expand to 8-char boundary
        assert len(result) >= 9  # 'a' + 7 spaces + 'b'

    def test_ansi_escape_stripped(self):
        """ANSI color codes should be removed."""
        result = render_terminal(b'\x1b[31mred text\x1b[0m')
        assert result == b'red text'
        assert b'\x1b' not in result

    def test_empty_input(self):
        result = render_terminal(b'')
        assert result == b''

    def test_progress_bar_cr(self):
        """Progress bar pattern: repeated CR-overwrite keeps only final version."""
        data = b'Progress: 10%\rProgress: 50%\rProgress: 100%'
        result = render_terminal(data)
        assert b'100%' in result


# ============================================================================
# File Classification
# ============================================================================

class TestFileClassification:
    """Test is_config_file, is_library, is_startup_file."""

    def test_config_files(self):
        assert is_config_file('/etc/resolv.conf')
        assert is_config_file('/home/user/.bashrc')
        assert is_config_file('/home/user/.config/foo')
        assert is_config_file('/path/to/settings.yaml')
        assert is_config_file('/path/to/app.conf')
        assert is_config_file('/path/to/something.plist')

    def test_not_config_files(self):
        assert not is_config_file('/usr/bin/python3')
        assert not is_config_file('/tmp/data.bin')
        assert not is_config_file('/home/user/document.txt')

    def test_libraries(self):
        assert is_library('/usr/lib/libc.dylib')
        assert is_library('/usr/lib/libSystem.B.dylib')
        assert is_library('/System/Library/Frameworks/Security.framework/Security')
        assert is_library('/usr/lib/system/libsystem_kernel.dylib')

    def test_not_libraries(self):
        assert not is_library('/usr/bin/python3')
        assert not is_library('/tmp/data.txt')
        assert not is_library('/home/user/test.py')

    def test_startup_files(self):
        assert is_startup_file('/usr/lib/dyld')
        assert is_startup_file('/usr/lib/libSystem.B.dylib')
        assert is_startup_file('/dev/null')
        assert is_startup_file('/dev/urandom')

    def test_not_startup_files(self):
        assert not is_startup_file('/etc/passwd')
        assert not is_startup_file('/usr/bin/ls')
        assert not is_startup_file('/tmp/test.txt')


# ============================================================================
# Config Parsing
# ============================================================================

class TestConfigParsing:
    """Test config file parsing. Uses temp files to avoid touching real config."""

    def test_resolve_input_path_absolute(self):
        """Absolute paths are returned as-is."""
        assert resolve_input_path('/tmp/foo.json') == '/tmp/foo.json'

    def test_resolve_input_path_explicit_relative(self):
        """Paths starting with ./ or ../ are returned as-is."""
        assert resolve_input_path('./foo.json') == './foo.json'
        assert resolve_input_path('../foo.json') == '../foo.json'

    def test_resolve_input_path_stdin(self):
        """Stdin marker '-' is returned as-is."""
        assert resolve_input_path('-') == '-'

    def test_resolve_input_path_empty(self):
        """Empty/None paths returned as-is."""
        assert resolve_input_path('') == ''
        assert resolve_input_path(None) is None
