#!/usr/bin/env python3
"""
mactrace_lib.py - Shared utilities for mactrace tools.

Extracted from mactrace_analyze.py and mactrace_timeline.py to eliminate
code duplication. All mactrace Python tools should import from here.
"""

import os
import sys
sys.dont_write_bytecode = True
import re
import pwd


# =============================================================================
# Configuration
# =============================================================================

def get_mactrace_config() -> dict:
    """
    Read mactrace config file, supporting variable expansion.
    Config is at ~/.mactrace/config (using SUDO_USER's home if running as root).
    
    Returns dict of config values with variables expanded.
    """
    config = {}
    
    # Determine whose home directory to use
    sudo_user = os.environ.get('SUDO_USER')
    if sudo_user and os.geteuid() == 0:
        try:
            home = pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            home = os.path.expanduser('~')
    else:
        home = os.path.expanduser('~')
    
    config_path = os.path.join(home, '.mactrace', 'config')
    
    if not os.path.exists(config_path):
        return config
    
    try:
        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                    
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Expand ~ to home directory (of sudo caller, not root)
                if '~' in value:
                    value = value.replace('~', home)
                
                # Expand $VAR and ${VAR} references (from config or environment)
                def expand_var(match):
                    var_name = match.group(1) or match.group(2)
                    # First check our config (allows forward references within file)
                    if var_name in config:
                        return config[var_name]
                    # Then check environment
                    return os.environ.get(var_name, match.group(0))
                
                value = re.sub(r'\$\{(\w+)\}|\$(\w+)', expand_var, value)
                config[key] = value
                
    except (IOError, OSError):
        pass
    
    return config


def get_config_value(key: str, default: str = None) -> str:
    """Get a config value, checking env vars first, then config file."""
    # Environment takes precedence
    env_val = os.environ.get(key)
    if env_val:
        return env_val
    
    # Then config file
    config = get_mactrace_config()
    return config.get(key, default)


def resolve_input_path(path: str) -> str:
    """
    Resolve input file path using MACTRACE_OUTPUT if path is relative.
    
    Returns the resolved path (which may or may not exist).
    """
    if not path or path == '-':
        return path
    
    # Absolute paths or explicit relative (./) used as-is
    if os.path.isabs(path) or path.startswith('./') or path.startswith('../'):
        return path
    
    # If file exists in current directory, use it
    if os.path.exists(path):
        return path
    
    # Try MACTRACE_OUTPUT directory
    output_dir = get_config_value('MACTRACE_OUTPUT')
    if output_dir:
        resolved = os.path.join(output_dir, path)
        return resolved
    
    return path


# =============================================================================
# Formatting
# =============================================================================

def format_bytes(n: int) -> str:
    """Format bytes in human-readable form."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    else:
        return f"{n / (1024 * 1024 * 1024):.2f} GB"


def format_bytes_short(n: int) -> str:
    """Format bytes with short suffixes (K, M, G) — no spaces."""
    if n < 1024:
        return f"{n}"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f}K"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f}M"
    else:
        return f"{n / (1024 * 1024 * 1024):.2f}G"


def format_duration(ms: float) -> str:
    """Format duration in human-readable form."""
    if ms < 1:
        return f"{ms * 1000:.1f} µs"
    elif ms < 1000:
        return f"{ms:.1f} ms"
    elif ms < 60000:
        return f"{ms / 1000:.2f} s"
    else:
        return f"{ms / 60000:.1f} min"


def format_timestamp(ts: str) -> str:
    """Format ISO timestamp to shorter form."""
    from datetime import datetime
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M:%S.%f")[:-3]
    except (ValueError, TypeError):
        return str(ts)


# =============================================================================
# File Classification
# =============================================================================

CONFIG_FILE_PATTERNS = [
    r'\..*rc$',
    r'\.config/',
    r'\.local/',
    r'/etc/',
    r'\.plist$',
    r'\.conf$',
    r'\.cfg$',
    r'\.ini$',
    r'\.yaml$',
    r'\.yml$',
    r'preferences\.plist$',
]

LIBRARY_PATTERNS = [
    r'\.dylib$',
    r'\.so(\.\d+)*$',
    r'/lib/',
    r'/usr/lib/',
    r'/System/Library/',
    r'/Library/Frameworks/',
]

STARTUP_PATTERNS = [
    r'/usr/lib/dyld$',
    r'libSystem',
    r'libc\+\+',
    r'libdyld',
    r'/dev/null$',
    r'/dev/urandom$',
    r'/dev/random$',
]


def is_config_file(path: str) -> bool:
    """Check if a path looks like a configuration file."""
    for pattern in CONFIG_FILE_PATTERNS:
        if re.search(pattern, path):
            return True
    return False


def is_library(path: str) -> bool:
    """Check if a path looks like a shared library."""
    for pattern in LIBRARY_PATTERNS:
        if re.search(pattern, path):
            return True
    return False


def is_startup_file(path: str) -> bool:
    """Check if a path is a startup-related file."""
    if is_library(path):
        return True
    for pattern in STARTUP_PATTERNS:
        if re.search(pattern, path):
            return True
    return False


# =============================================================================
# Text Processing
# =============================================================================

MAX_PATH_DISPLAY = 120

def truncate_path(path: str, max_len: int = MAX_PATH_DISPLAY) -> str:
    """Truncate long paths, keeping start and end visible."""
    if len(path) <= max_len:
        return path
    keep = (max_len - 5) // 2
    return path[:keep] + " ... " + path[-keep:]


def sanitize_filename(s: str, max_len: int = 60) -> str:
    """Sanitize a string for use in a filename."""
    if not s:
        return "unknown"
    
    # Replace problematic chars
    s = s.replace('/', '_').replace('\\', '_')
    s = s.replace(':', '_').replace('*', '_')
    s = s.replace('?', '_').replace('"', '_')
    s = s.replace('<', '_').replace('>', '_')
    s = s.replace('|', '_').replace(' ', '_')
    s = s.replace('\n', '_').replace('\r', '_')
    
    # Remove leading underscores/dots
    s = s.lstrip('_.')
    
    # Collapse multiple underscores
    while '__' in s:
        s = s.replace('__', '_')
    
    # Truncate
    if len(s) > max_len:
        s = s[:max_len]
    
    return s.rstrip('_') or "unknown"


def python_hexdump(data: bytes) -> bytes:
    """Pure Python replacement for hexdump -C. No subprocess fork needed."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk[:8])
        if len(chunk) > 8:
            hex_part += '  ' + ' '.join(f'{b:02x}' for b in chunk[8:])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{offset:08x}  {hex_part:<48s}  |{ascii_part}|')
    lines.append(f'{len(data):08x}')
    return '\n'.join(lines).encode('ascii') + b'\n'


def render_terminal(data: bytes, width: int = 80) -> bytes:
    """
    Render terminal data as it would appear on screen.
    
    Processes CR, LF, backspace, tab, and ANSI escape sequences.
    """
    # Strip ANSI escapes
    cleaned = bytearray()
    i = 0
    
    while i < len(data):
        if data[i] == 0x1b and i + 1 < len(data):
            next_byte = data[i + 1]
            if next_byte == ord('['):
                # CSI sequence
                i += 2
                while i < len(data) and 0x20 <= data[i] <= 0x3F:
                    i += 1
                if i < len(data) and 0x40 <= data[i] <= 0x7E:
                    i += 1
                continue
            elif next_byte == ord(']'):
                # OSC sequence
                i += 2
                while i < len(data):
                    if data[i] == 0x07:
                        i += 1
                        break
                    if data[i] == 0x1b and i + 1 < len(data) and data[i + 1] == ord('\\'):
                        i += 2
                        break
                    i += 1
                continue
            else:
                i += 2
                continue
        elif data[i] >= 0x20 or data[i] in (0x08, 0x09, 0x0a, 0x0d):
            cleaned.append(data[i])
            i += 1
        else:
            i += 1
    
    # Simulate terminal with cursor tracking
    lines = [[]]
    row = 0
    col = 0
    
    for byte in cleaned:
        if byte == 0x0d:  # CR
            col = 0
        elif byte == 0x0a:  # LF
            row += 1
            col = 0
            while len(lines) <= row:
                lines.append([])
        elif byte == 0x08:  # BS
            if col > 0:
                col -= 1
        elif byte == 0x09:  # TAB
            col = ((col // 8) + 1) * 8
        elif byte >= 0x20:
            while len(lines) <= row:
                lines.append([])
            while len(lines[row]) <= col:
                lines[row].append(ord(' '))
            lines[row][col] = byte
            col += 1
    
    # Build output
    result = bytearray()
    for i, line in enumerate(lines):
        line_bytes = bytes(line).rstrip(b' ')
        result.extend(line_bytes)
        if i < len(lines) - 1:
            result.append(0x0a)
    
    return bytes(result).strip(b'\n')


def extract_raw_bytes(data) -> bytes:
    """
    Extract raw bytes from data representation.
    
    Handles:
    - Raw bytes
    - Hex strings (e.g., "48656c6c6f")
    - Strings with escape sequences (\\n, \\xNN, etc.)
    - Base64 encoded data
    """
    if data is None:
        return b''
    
    if isinstance(data, bytes):
        return data
    
    if isinstance(data, list):
        try:
            return bytes(data)
        except (TypeError, ValueError):
            pass
    
    if not isinstance(data, str):
        return str(data).encode('utf-8', errors='replace')
    
    # Try hex string first (common in trace output)
    if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) % 2 == 0 and len(data) > 0:
        try:
            return bytes.fromhex(data)
        except ValueError:
            pass
    
    # Handle escape sequences
    result = bytearray()
    i = 0
    
    while i < len(data):
        if data[i] == '\\' and i + 1 < len(data):
            next_char = data[i + 1]
            
            if next_char == 'n':
                result.append(ord('\n'))
                i += 2
            elif next_char == 'r':
                result.append(ord('\r'))
                i += 2
            elif next_char == 't':
                result.append(ord('\t'))
                i += 2
            elif next_char == '\\':
                result.append(ord('\\'))
                i += 2
            elif next_char == '"':
                result.append(ord('"'))
                i += 2
            elif next_char == '0' and i + 2 < len(data) and not data[i + 2].isdigit():
                result.append(0)
                i += 2
            elif next_char == 'x' and i + 3 < len(data):
                try:
                    hex_val = int(data[i + 2:i + 4], 16)
                    result.append(hex_val)
                    i += 4
                except ValueError:
                    result.append(ord(data[i]))
                    i += 1
            elif next_char.isdigit():
                # Octal escape
                octal = ''
                j = i + 1
                while j < len(data) and j < i + 4 and data[j].isdigit() and data[j] in '01234567':
                    octal += data[j]
                    j += 1
                if octal:
                    try:
                        result.append(int(octal, 8) & 0xFF)
                        i = j
                    except ValueError:
                        result.append(ord(data[i]))
                        i += 1
                else:
                    result.append(ord(data[i]))
                    i += 1
            else:
                result.append(ord(data[i]))
                i += 1
        else:
            result.append(ord(data[i]))
            i += 1
    
    return bytes(result)
