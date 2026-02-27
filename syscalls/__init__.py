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


# ── Category metadata for --trace filtering ─────────────────────────

CATEGORY_DESCRIPTIONS = {
    'file': 'File system operations: open, read, write, stat, link, chmod, directory ops',
    'network': 'Socket and network I/O: connect, send/recv, DNS, socket options, '
               'plus Apple NECP network policy (routing, VPN, per-app rules)',
    'process': 'Process lifecycle and identity: fork, exec, exit, wait, getpid/uid, '
               'plus MAC framework policy checks (__mac_syscall)',
    'memory': 'Virtual memory: mmap, mprotect, munmap',
    'signal': 'Signal delivery and handling: kill, sigaction, sigprocmask',
    'mac': 'Apple Mandatory Access Control framework: __mac_syscall (Sandbox, AMFI), '
           '__mac_get/set for file, process, and fd labels. Cross-cutting security '
           'policy layer — also included in process category',
    'poll': 'Event multiplexing: select, poll, kqueue/kevent',
}

CATEGORY_ALIASES = {
    'net': ['network'],
    'fs': ['file'],
    'io': ['file', 'network'],
    'xio': ['file', 'network', 'process'],
    'exec': ['process'],
    'all': None,  # sentinel — means all handlers
}


def get_category_info():
    """Return dict of category → {description, syscalls, handlers} from live registry."""
    from collections import defaultdict
    info = {}
    cat_syscalls = defaultdict(set)
    cat_handlers = defaultdict(set)
    
    for syscall_name, handler in HANDLER_REGISTRY.items():
        handler_name = type(handler).__name__
        for cat in handler.categories:
            cat_syscalls[cat].add(syscall_name)
            cat_handlers[cat].add(handler_name)
    
    for cat in sorted(cat_syscalls.keys()):
        info[cat] = {
            'description': CATEGORY_DESCRIPTIONS.get(cat, '(no description)'),
            'syscalls': sorted(cat_syscalls[cat]),
            'handlers': sorted(cat_handlers[cat]),
        }
    return info


def resolve_trace_spec(spec: str):
    """Parse a --trace spec string into categories and individual syscalls.

    Tokens are interpreted as:
      1. Category alias (e.g. 'net' → network)
      2. Known category id (e.g. 'file', 'network', 'signal')
      3. Individual syscall name (e.g. 'connect', 'sendto')

    Args:
        spec: comma-separated names, e.g. "net,mmap,execve"

    Returns:
        (categories: frozenset|None, syscalls: frozenset|None)
        categories=None AND syscalls=None means "all handlers"
    """
    tokens = [t.strip().lower() for t in spec.split(',') if t.strip()]
    if not tokens or 'all' in tokens:
        return None, None  # all handlers

    # Collect all known category ids from handlers
    known_categories = set()
    for h in _ALL_HANDLERS:
        known_categories.update(getattr(h, 'categories', []))

    categories = set()
    syscalls = set()

    for token in tokens:
        if token in CATEGORY_ALIASES:
            expanded = CATEGORY_ALIASES[token]
            if expanded is None:
                return None, None
            categories.update(expanded)
        elif token in known_categories:
            categories.add(token)
        elif token in HANDLER_REGISTRY:
            # It's a known syscall name
            syscalls.add(token)
        else:
            # Unknown — treat as potential syscall (will just not match anything)
            syscalls.add(token)

    return (frozenset(categories) if categories else None,
            frozenset(syscalls) if syscalls else None)


def resolve_trace_categories(spec: str):
    """Parse a --trace spec string into a set of category names.

    Backward-compatible wrapper around resolve_trace_spec.
    Individual syscall tokens are resolved to their handler's categories.

    Args:
        spec: comma-separated category names/aliases, e.g. "net,process"

    Returns:
        frozenset of category names, or None meaning "all"
    """
    cats, syscalls = resolve_trace_spec(spec)
    if cats is None and syscalls is None:
        return None
    result = set(cats) if cats else set()
    # Add categories for individual syscalls
    if syscalls:
        for sc in syscalls:
            handler = HANDLER_REGISTRY.get(sc)
            if handler:
                result.update(getattr(handler, 'categories', []))
    return frozenset(result) if result else None


def _filter_handlers(categories, syscalls=None):
    """Return handlers matching the given categories and/or individual syscalls.

    Args:
        categories: frozenset of category names, or None for all.
        syscalls: frozenset of individual syscall names, or None.

    Returns:
        list of handler instances
    """
    if categories is None and syscalls is None:
        return list(_ALL_HANDLERS)
    
    result = []
    seen = set()
    
    # Add handlers matching categories
    if categories:
        for h in _ALL_HANDLERS:
            if any(c in categories for c in getattr(h, 'categories', [])):
                if id(h) not in seen:
                    result.append(h)
                    seen.add(id(h))
    
    # Add handlers for individual syscalls
    if syscalls:
        for sc in syscalls:
            handler = HANDLER_REGISTRY.get(sc)
            if handler and id(handler) not in seen:
                result.append(handler)
                seen.add(id(handler))
    
    return result


def get_dtrace_probes(categories=None, syscalls=None):
    """Return concatenated DTrace probe text for the given categories/syscalls.

    When individual syscalls are specified, the *entire handler* that owns
    those syscalls is loaded (DTrace clause granularity = handler, not syscall).

    Args:
        categories: frozenset of category names, or None for all.
        syscalls: frozenset of individual syscall names, or None.

    Returns:
        str of D-language probe text
    """
    parts = []
    for handler in _filter_handlers(categories, syscalls):
        if handler.dtrace:
            parts.append(handler.dtrace)
    return "\n".join(parts)


def get_handler_registry(categories=None, syscalls=None):
    """Return {syscall_name: handler} for the given categories/syscalls.

    Args:
        categories: frozenset of category names, or None for all.
        syscalls: frozenset of individual syscall names, or None.

    Returns:
        dict mapping syscall name to handler instance
    """
    if categories is None and syscalls is None:
        return dict(HANDLER_REGISTRY)
    handlers = _filter_handlers(categories, syscalls)
    handler_set = set(id(h) for h in handlers)
    return {name: h for name, h in HANDLER_REGISTRY.items()
            if id(h) in handler_set}


def get_active_categories(categories=None):
    """Return the set of category names that are active.

    Args:
        categories: frozenset of category names, or None for all.

    Returns:
        sorted list of category name strings
    """
    if categories is None:
        cats = set()
        for h in _ALL_HANDLERS:
            cats.update(getattr(h, 'categories', []))
        return sorted(cats)
    return sorted(categories)



def count_dif_programs(dtrace_text: str) -> int:
    """Count the number of DIF programs (probe clauses) in a DTrace script.

    Each syscall:: probe reference creates a DIF program. This is an
    approximation — combined probe specs (entry,return on one line) count
    as one clause but produce two DIF programs.

    Args:
        dtrace_text: D-language script text

    Returns:
        Estimated number of DIF programs
    """
    import re
    # Count individual syscall:: references (each is a DIF program)
    return len(re.findall(r'syscall::\w+', dtrace_text))


# Auto-discover on import
_discover_handlers()
