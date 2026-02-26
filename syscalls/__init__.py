"""
syscalls — Modular syscall handler framework for mactrace.

Each handler module in this package defines DTrace probes and Python
parsers for a family of related syscalls.  The main tracer auto-discovers
all handlers at import time and builds:

  HANDLER_REGISTRY   — {syscall_name: handler_instance}
  ALL_DTRACE_PROBES  — concatenated D-language probe text
  TRACED_SYSCALLS    — set of all syscall names with rich argument capture

Usage in the main tracer:

    from syscalls import HANDLER_REGISTRY, ALL_DTRACE_PROBES, TRACED_SYSCALLS

    # Build DTrace script
    dtrace_script = DTRACE_HEADER + ALL_DTRACE_PROBES + DTRACE_FOOTER

    # Parse syscall arguments
    handler = HANDLER_REGISTRY.get(syscall_name)
    if handler:
        args = handler.parse_args(syscall_name, tokens)
"""

import importlib
import os
import pkgutil
import sys
sys.dont_write_bytecode = True


class SyscallHandler:
    """Base class for syscall handler modules.

    Subclass this and decorate with @register to add a new syscall family.
    At minimum, provide:
      - syscalls:   list of syscall names this handler covers
      - dtrace:     D-language probe text (entry + return probes)
      - parse_args: method to parse MACTRACE_SYSCALL argument tokens

    Optionally:
      - update_fd_info:  update fd tracking after this syscall
      - parse_sockaddr:  parse MACTRACE_SOCKADDR data for this syscall
    """

    # List of syscall names this handler covers
    syscalls = []

    # D-language probe text — concatenated into the DTrace script.
    # Use the TRACED predicate, self-> for thread-local vars, and
    # MACTRACE_SYSCALL output format.  See existing handlers for examples.
    dtrace = ""

    # ── Helpers available to all handlers ────────────────────────────

    @staticmethod
    def clean_str(s):
        """Strip surrounding quotes from a DTrace string argument."""
        if s and len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            return s[1:-1]
        return s

    @staticmethod
    def parse_int(s, base=0):
        """Parse an integer, handling 0x hex and octal prefixes gracefully."""
        try:
            if isinstance(s, int):
                return s
            s = s.strip()
            if s.startswith("0x") or s.startswith("-0x"):
                return int(s, 16)
            if s.startswith("0") and len(s) > 1 and s[1:].isdigit():
                return int(s, 8)
            return int(s)
        except (ValueError, AttributeError):
            return 0

    @staticmethod
    def parse_hex(s):
        """Parse a hex string (with or without 0x prefix)."""
        try:
            s = s.strip()
            if s.startswith("0x"):
                return int(s, 16)
            # If it contains hex letters, parse as hex
            if any(c in s for c in 'abcdefABCDEF'):
                return int(s, 16)
            return int(s)
        except (ValueError, AttributeError):
            return 0

    # ── Methods to override in subclasses ────────────────────────────

    def parse_args(self, syscall, args):
        """Parse MACTRACE_SYSCALL argument tokens into a dict.

        Args:
            syscall: the syscall name (e.g. "open", "openat")
            args:    list of string tokens after pid/tid/name/retval/errno/ts

        Returns:
            dict of parsed arguments (keys are arg names like "path", "fd", etc.)
        """
        return {}

    def update_fd_info(self, event, fd_tracker):
        """Update fd tracking state after this syscall.

        Override if this syscall creates, modifies, or closes file descriptors.

        Args:
            event:      SyscallEvent with parsed args
            fd_tracker: object with set_file(), set_socket(), remove() methods
        """
        pass

    def parse_sockaddr(self, syscall, parts, base_timestamp, tracer):
        """Parse a MACTRACE_SOCKADDR line for this syscall.

        Override for syscalls that capture socket addresses (connect, bind,
        accept, sendto, recvfrom, getpeername, getsockname).

        Returns:
            SyscallEvent or None
        """
        return None


# ── Handler registry ────────────────────────────────────────────────

# Maps syscall name → handler instance
HANDLER_REGISTRY = {}

# Set of all syscall names with rich tracing (DTrace probes + parsers)
TRACED_SYSCALLS = set()

# Concatenated D-language probe text from all handlers
ALL_DTRACE_PROBES = ""

# All registered handler instances (for iteration)
_ALL_HANDLERS = []


def register(cls):
    """Class decorator — registers a SyscallHandler subclass.

    Usage:
        @register
        class OpenHandler(SyscallHandler):
            syscalls = ["open", "open_nocancel"]
            ...
    """
    instance = cls()
    _ALL_HANDLERS.append(instance)
    for name in cls.syscalls:
        if name in HANDLER_REGISTRY:
            raise ValueError(
                f"Syscall '{name}' registered by both "
                f"{type(HANDLER_REGISTRY[name]).__name__} and {cls.__name__}"
            )
        HANDLER_REGISTRY[name] = instance
        TRACED_SYSCALLS.add(name)
    return cls


def _discover_handlers():
    """Import all modules in this package to trigger @register decorators."""
    global ALL_DTRACE_PROBES
    pkg_dir = os.path.dirname(__file__)
    for importer, modname, ispkg in pkgutil.iter_modules([pkg_dir]):
        if modname.startswith('_'):
            continue  # Skip _constants, __init__, etc.
        importlib.import_module(f'.{modname}', package=__name__)
    # Build the concatenated DTrace probe text
    parts = []
    for handler in _ALL_HANDLERS:
        if handler.dtrace:
            parts.append(handler.dtrace)
    ALL_DTRACE_PROBES = "\n".join(parts)


# Auto-discover on import
_discover_handlers()
