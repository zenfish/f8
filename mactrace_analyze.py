#!/usr/bin/env python3
"""
Analyze mactrace JSON output to show what happened during execution.

Reads JSON from mactrace and produces a human-readable summary
including file access, network activity, process lifecycle, and errors.

Usage:
    ./mactrace_analyze.py trace.json
    ./mactrace -o - /bin/ls | ./mactrace_analyze.py -

    # Filter by syscall category
    ./mactrace_analyze.py trace.json --category file
    ./mactrace_analyze.py trace.json --category network

    # Show only errors
    ./mactrace_analyze.py trace.json --errors-only

    # Output JSON summary instead of text
    ./mactrace_analyze.py trace.json --json
"""

import sys
import json
import argparse
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from datetime import datetime


# ============================================================================
# Utility Functions
# ============================================================================

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
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M:%S.%f")[:-3]
    except (ValueError, TypeError):
        return str(ts)


# File classification patterns
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


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class FileAccess:
    """Track file access patterns."""
    path: str
    opened: bool = False
    read: bool = False
    written: bool = False
    stat: bool = False
    closed: bool = False
    error: Optional[str] = None
    bytes_read: int = 0
    bytes_written: int = 0
    pids: Set[int] = field(default_factory=set)
    is_config: bool = False
    is_library: bool = False
    is_startup: bool = False


@dataclass
class NetworkConnection:
    """Track network connections."""
    fd: int
    family: str = "unknown"  # AF_INET, AF_INET6, AF_UNIX
    sock_type: str = "unknown"  # SOCK_STREAM, SOCK_DGRAM
    local_addr: Optional[str] = None
    remote_addr: Optional[str] = None
    connected: bool = False
    bytes_sent: int = 0
    bytes_recv: int = 0
    pid: Optional[int] = None


@dataclass
class ProcessInfo:
    """Track process lifecycle."""
    pid: int
    parent_pid: Optional[int] = None
    exec_path: Optional[str] = None
    exit_code: Optional[int] = None
    fork_time: Optional[int] = None
    exec_time: Optional[int] = None
    exit_time: Optional[int] = None


# ============================================================================
# Analyzer Class
# ============================================================================

class MacTraceAnalyzer:
    """Analyze mactrace JSON output."""
    
    # Syscall categories
    FILE_SYSCALLS = {
        'open', 'open_nocancel', 'openat', 'openat_nocancel',
        'close', 'close_nocancel',
        'read', 'read_nocancel', 'pread', 'pread_nocancel',
        'write', 'write_nocancel', 'pwrite', 'pwrite_nocancel',
        'stat64', 'lstat64', 'fstat64', 'fstatat64',
        'access', 'faccessat',
        'unlink', 'rename', 'mkdir', 'rmdir', 'chdir', 'fchdir',
        'chmod', 'fchmod', 'truncate', 'ftruncate',
        'link', 'symlink', 'readlink',
        'dup', 'dup2', 'fcntl', 'fcntl_nocancel',
        'fsync', 'fsync_nocancel',
        'getdirentries64', 'getattrlistbulk',
    }
    
    NETWORK_SYSCALLS = {
        'socket', 'connect', 'connect_nocancel',
        'bind', 'listen', 'accept', 'accept_nocancel',
        'sendto', 'sendto_nocancel', 'recvfrom', 'recvfrom_nocancel',
        'shutdown', 'setsockopt', 'getsockopt',
    }
    
    PROCESS_SYSCALLS = {
        'fork', 'execve', 'posix_spawn', 'exit',
        'wait4', 'wait4_nocancel',
        'kill', 'getpid', 'getppid',
    }
    
    MEMORY_SYSCALLS = {
        'mmap', 'munmap', 'mprotect',
    }
    
    SIGNAL_SYSCALLS = {
        'sigaction', 'sigprocmask', 'kill',
    }

    def __init__(self):
        self.trace_data: Dict[str, Any] = {}
        self.files: Dict[str, FileAccess] = {}
        self.fd_to_path: Dict[int, Dict[int, str]] = defaultdict(dict)  # pid -> {fd -> path}
        self.sockets: Dict[int, Dict[int, NetworkConnection]] = defaultdict(dict)  # pid -> {fd -> conn}
        self.processes: Dict[int, ProcessInfo] = {}
        self.errors: List[Dict[str, Any]] = []
        self.syscall_counts: Dict[str, int] = defaultdict(int)
        self.category_counts: Dict[str, int] = defaultdict(int)
        
    def load(self, filepath: str) -> None:
        """Load trace data from file or stdin."""
        if filepath == '-':
            self.trace_data = json.load(sys.stdin)
        else:
            with open(filepath, 'r') as f:
                self.trace_data = json.load(f)
                
    def analyze(self) -> None:
        """Analyze the loaded trace data."""
        # Initialize root process
        target_pid = self.trace_data.get('target_pid', 0)
        if target_pid:
            self.processes[target_pid] = ProcessInfo(
                pid=target_pid,
                exec_path=self.trace_data.get('command', [None])[0] if self.trace_data.get('command') else None
            )
        
        # Process tree
        for child_str, parent in self.trace_data.get('process_tree', {}).items():
            child = int(child_str)
            if child not in self.processes:
                self.processes[child] = ProcessInfo(pid=child)
            self.processes[child].parent_pid = parent
            
        # Process events
        for event in self.trace_data.get('process_events', []):
            self._process_event(event)
            
        # Syscall events
        for event in self.trace_data.get('events', []):
            self._process_syscall(event)
            
    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process a process lifecycle event."""
        event_type = event.get('event_type', '')
        pid = event.get('pid', 0)
        details = event.get('details', {})
        
        if pid not in self.processes:
            self.processes[pid] = ProcessInfo(pid=pid)
        proc = self.processes[pid]
        
        if event_type in ('fork', 'child_detected'):
            proc.parent_pid = details.get('parent_pid')
            proc.fork_time = event.get('timestamp_us')
            
        elif event_type == 'exec':
            proc.exec_path = details.get('path')
            proc.exec_time = event.get('timestamp_us')
            
        elif event_type == 'exit':
            proc.exit_code = details.get('exit_code')
            proc.exit_time = event.get('timestamp_us')
            
    def _process_syscall(self, event: Dict[str, Any]) -> None:
        """Process a syscall event."""
        syscall = event.get('syscall', '')
        pid = event.get('pid', 0)
        args = event.get('args', {})
        retval = event.get('return_value', 0)
        errno = event.get('errno', 0)
        
        # Count syscalls
        self.syscall_counts[syscall] += 1
        
        # Categorize
        if syscall in self.FILE_SYSCALLS:
            self.category_counts['file'] += 1
        elif syscall in self.NETWORK_SYSCALLS:
            self.category_counts['network'] += 1
        elif syscall in self.PROCESS_SYSCALLS:
            self.category_counts['process'] += 1
        elif syscall in self.MEMORY_SYSCALLS:
            self.category_counts['memory'] += 1
        elif syscall in self.SIGNAL_SYSCALLS:
            self.category_counts['signal'] += 1
        else:
            self.category_counts['other'] += 1
            
        # Track errors
        if errno != 0:
            error_name = args.get('errno_name', f'errno={errno}')
            self.errors.append({
                'syscall': syscall,
                'pid': pid,
                'errno': errno,
                'errno_name': error_name,
                'args': args,
            })
            
        # Handle specific syscalls
        if syscall in ('open', 'open_nocancel', 'openat', 'openat_nocancel'):
            self._handle_open(pid, syscall, args, retval, errno)
        elif syscall in ('close', 'close_nocancel'):
            self._handle_close(pid, args, retval)
        elif syscall in ('read', 'read_nocancel', 'pread', 'pread_nocancel'):
            self._handle_read(pid, args, retval)
        elif syscall in ('write', 'write_nocancel', 'pwrite', 'pwrite_nocancel'):
            self._handle_write(pid, args, retval)
        elif syscall in ('stat64', 'lstat64', 'fstat64', 'fstatat64', 'access', 'faccessat'):
            self._handle_stat(pid, syscall, args, errno)
        elif syscall == 'socket':
            self._handle_socket(pid, args, retval)
        elif syscall in ('connect', 'connect_nocancel'):
            self._handle_connect(pid, args, retval, errno)
        elif syscall in ('bind',):
            self._handle_bind(pid, args, retval)
        elif syscall in ('sendto', 'sendto_nocancel'):
            self._handle_send(pid, args, retval)
        elif syscall in ('recvfrom', 'recvfrom_nocancel'):
            self._handle_recv(pid, args, retval)
            
    def _handle_open(self, pid: int, syscall: str, args: Dict, retval: int, errno: int) -> None:
        """Handle open/openat syscalls."""
        path = args.get('path', '')
        if not path:
            return
            
        if path not in self.files:
            self.files[path] = FileAccess(
                path=path,
                is_config=is_config_file(path),
                is_library=is_library(path),
                is_startup=is_startup_file(path),
            )
            
        fa = self.files[path]
        fa.pids.add(pid)
        
        if errno == 0 and retval >= 0:
            fa.opened = True
            self.fd_to_path[pid][retval] = path
            
            # Check flags for read/write intent
            flags = args.get('flags', '')
            if isinstance(flags, str):
                if 'O_WRONLY' in flags or 'O_RDWR' in flags:
                    fa.written = True
                if 'O_RDONLY' in flags or 'O_RDWR' in flags:
                    fa.read = True
        else:
            fa.error = args.get('errno_name', f'errno={errno}')
            
    def _handle_close(self, pid: int, args: Dict, retval: int) -> None:
        """Handle close syscalls."""
        fd = args.get('fd')
        if fd is not None and fd in self.fd_to_path.get(pid, {}):
            path = self.fd_to_path[pid].pop(fd)
            if path in self.files:
                self.files[path].closed = True
                
    def _handle_read(self, pid: int, args: Dict, retval: int) -> None:
        """Handle read syscalls."""
        fd = args.get('fd')
        if fd is not None and retval > 0:
            path = self.fd_to_path.get(pid, {}).get(fd)
            if path and path in self.files:
                self.files[path].read = True
                self.files[path].bytes_read += retval
                
    def _handle_write(self, pid: int, args: Dict, retval: int) -> None:
        """Handle write syscalls."""
        fd = args.get('fd')
        if fd is not None and retval > 0:
            path = self.fd_to_path.get(pid, {}).get(fd)
            if path and path in self.files:
                self.files[path].written = True
                self.files[path].bytes_written += retval
                
    def _handle_stat(self, pid: int, syscall: str, args: Dict, errno: int) -> None:
        """Handle stat/access syscalls."""
        path = args.get('path', '')
        if not path:
            # fstat64 uses fd instead
            return
            
        if path not in self.files:
            self.files[path] = FileAccess(
                path=path,
                is_config=is_config_file(path),
                is_library=is_library(path),
                is_startup=is_startup_file(path),
            )
            
        fa = self.files[path]
        fa.pids.add(pid)
        fa.stat = True
        
        if errno != 0:
            fa.error = args.get('errno_name', f'errno={errno}')
            
    def _handle_socket(self, pid: int, args: Dict, retval: int) -> None:
        """Handle socket syscalls."""
        if retval < 0:
            return
            
        domain = args.get('domain', 'unknown')
        sock_type = args.get('type', 'unknown')
        
        conn = NetworkConnection(
            fd=retval,
            family=domain,
            sock_type=sock_type,
            pid=pid,
        )
        self.sockets[pid][retval] = conn
        
    def _handle_connect(self, pid: int, args: Dict, retval: int, errno: int) -> None:
        """Handle connect syscalls."""
        fd = args.get('fd')
        if fd is None:
            return
            
        if fd in self.sockets.get(pid, {}):
            conn = self.sockets[pid][fd]
            if errno == 0 or errno == 36:  # EINPROGRESS
                conn.connected = True
                
    def _handle_bind(self, pid: int, args: Dict, retval: int) -> None:
        """Handle bind syscalls."""
        fd = args.get('fd')
        if fd is None:
            return
            
        if fd in self.sockets.get(pid, {}):
            conn = self.sockets[pid][fd]
            # TODO: parse address when available
            
    def _handle_send(self, pid: int, args: Dict, retval: int) -> None:
        """Handle sendto syscalls."""
        fd = args.get('fd')
        if fd is not None and retval > 0:
            if fd in self.sockets.get(pid, {}):
                self.sockets[pid][fd].bytes_sent += retval
                
    def _handle_recv(self, pid: int, args: Dict, retval: int) -> None:
        """Handle recvfrom syscalls."""
        fd = args.get('fd')
        if fd is not None and retval > 0:
            if fd in self.sockets.get(pid, {}):
                self.sockets[pid][fd].bytes_recv += retval

    # ========================================================================
    # Output Methods
    # ========================================================================
    
    def print_summary(self, category: Optional[str] = None, 
                      errors_only: bool = False,
                      hide_startup: bool = False) -> None:
        """Print human-readable summary."""
        
        print("=" * 70)
        print("MACTRACE ANALYSIS")
        print("=" * 70)
        
        # Basic info
        cmd = self.trace_data.get('command', [])
        print(f"\nCommand: {' '.join(cmd)}")
        print(f"Duration: {format_duration(self.trace_data.get('duration_ms', 0))}")
        print(f"Target PID: {self.trace_data.get('target_pid', 'unknown')}")
        print(f"Exit code: {self.trace_data.get('exit_code', 'unknown')}")
        print(f"Processes traced: {len(self.trace_data.get('pids_traced', []))}")
        print(f"Total syscalls: {self.trace_data.get('syscall_count', 0)}")
        
        # Category breakdown
        print("\n--- Syscall Categories ---")
        for cat in ['file', 'network', 'process', 'memory', 'signal', 'other']:
            count = self.category_counts.get(cat, 0)
            if count > 0:
                print(f"  {cat:12} {count:6}")
                
        if not errors_only:
            # Top syscalls
            print("\n--- Top Syscalls ---")
            sorted_syscalls = sorted(self.syscall_counts.items(), key=lambda x: -x[1])[:15]
            for syscall, count in sorted_syscalls:
                print(f"  {syscall:24} {count:6}")
                
        # File access (unless filtering to other category)
        if (category is None or category == 'file') and not errors_only:
            self._print_file_summary(hide_startup)
            
        # Network activity
        if (category is None or category == 'network') and not errors_only:
            self._print_network_summary()
            
        # Process tree
        if (category is None or category == 'process') and not errors_only:
            self._print_process_summary()
            
        # Errors
        if self.errors:
            self._print_errors()
            
    def _print_file_summary(self, hide_startup: bool = False) -> None:
        """Print file access summary."""
        # Separate files by type
        regular_files = []
        config_files = []
        library_files = []
        
        for path, fa in self.files.items():
            if hide_startup and fa.is_startup:
                continue
            if fa.is_library:
                library_files.append(fa)
            elif fa.is_config:
                config_files.append(fa)
            else:
                regular_files.append(fa)
                
        if regular_files:
            print("\n--- Files Accessed ---")
            for fa in sorted(regular_files, key=lambda x: x.path):
                flags = []
                if fa.read: flags.append('R')
                if fa.written: flags.append('W')
                if fa.stat and not fa.opened: flags.append('S')
                if fa.error: flags.append(f'E:{fa.error}')
                
                io_info = ""
                if fa.bytes_read > 0 or fa.bytes_written > 0:
                    parts = []
                    if fa.bytes_read > 0:
                        parts.append(f"read {format_bytes(fa.bytes_read)}")
                    if fa.bytes_written > 0:
                        parts.append(f"wrote {format_bytes(fa.bytes_written)}")
                    io_info = f" ({', '.join(parts)})"
                    
                print(f"  [{','.join(flags):5}] {fa.path}{io_info}")
                
        if config_files:
            print("\n--- Config Files ---")
            for fa in sorted(config_files, key=lambda x: x.path):
                flags = []
                if fa.read: flags.append('R')
                if fa.written: flags.append('W')
                if fa.stat and not fa.opened: flags.append('S')
                if fa.error: flags.append('E')
                print(f"  [{','.join(flags):5}] {fa.path}")
                
        if library_files and not hide_startup:
            print(f"\n--- Libraries ({len(library_files)} loaded) ---")
            # Just show count and first few
            for fa in sorted(library_files, key=lambda x: x.path)[:5]:
                print(f"  {fa.path}")
            if len(library_files) > 5:
                print(f"  ... and {len(library_files) - 5} more")
                
    def _print_network_summary(self) -> None:
        """Print network activity summary."""
        all_sockets = []
        for pid, sockets in self.sockets.items():
            for fd, conn in sockets.items():
                all_sockets.append(conn)
                
        if not all_sockets:
            return
            
        print("\n--- Network Activity ---")
        for conn in all_sockets:
            status = "connected" if conn.connected else "created"
            io_info = ""
            if conn.bytes_sent > 0 or conn.bytes_recv > 0:
                parts = []
                if conn.bytes_sent > 0:
                    parts.append(f"sent {format_bytes(conn.bytes_sent)}")
                if conn.bytes_recv > 0:
                    parts.append(f"recv {format_bytes(conn.bytes_recv)}")
                io_info = f" ({', '.join(parts)})"
                
            print(f"  fd={conn.fd} {conn.family}/{conn.sock_type} [{status}]{io_info}")
            
    def _print_process_summary(self) -> None:
        """Print process tree summary."""
        if len(self.processes) <= 1:
            return
            
        print("\n--- Process Tree ---")
        
        # Find root processes (no parent or parent not in trace)
        roots = []
        for pid, proc in self.processes.items():
            if proc.parent_pid is None or proc.parent_pid not in self.processes:
                roots.append(pid)
                
        def print_tree(pid: int, indent: int = 0):
            proc = self.processes.get(pid)
            if not proc:
                return
                
            prefix = "  " * indent
            path = proc.exec_path or "(unknown)"
            exit_info = f" -> exit({proc.exit_code})" if proc.exit_code is not None else ""
            print(f"{prefix}[{pid}] {path}{exit_info}")
            
            # Find children
            for child_pid, child_proc in self.processes.items():
                if child_proc.parent_pid == pid:
                    print_tree(child_pid, indent + 1)
                    
        for root in sorted(roots):
            print_tree(root)
            
    def _print_errors(self) -> None:
        """Print error summary."""
        print(f"\n--- Errors ({len(self.errors)} total) ---")
        
        # Group by error type
        by_errno = defaultdict(list)
        for err in self.errors:
            key = (err['syscall'], err['errno_name'])
            by_errno[key].append(err)
            
        for (syscall, errno_name), errs in sorted(by_errno.items()):
            print(f"  {syscall}: {errno_name} ({len(errs)}x)")
            # Show first example
            if errs:
                args = errs[0].get('args', {})
                if 'path' in args:
                    print(f"    e.g., path={args['path']}")
                    
    def to_json(self) -> Dict[str, Any]:
        """Return analysis as JSON-serializable dict."""
        return {
            'command': self.trace_data.get('command'),
            'duration_ms': self.trace_data.get('duration_ms'),
            'target_pid': self.trace_data.get('target_pid'),
            'exit_code': self.trace_data.get('exit_code'),
            'syscall_count': self.trace_data.get('syscall_count'),
            'category_counts': dict(self.category_counts),
            'syscall_counts': dict(self.syscall_counts),
            'files': {
                path: {
                    'opened': fa.opened,
                    'read': fa.read,
                    'written': fa.written,
                    'stat': fa.stat,
                    'error': fa.error,
                    'bytes_read': fa.bytes_read,
                    'bytes_written': fa.bytes_written,
                    'is_config': fa.is_config,
                    'is_library': fa.is_library,
                }
                for path, fa in self.files.items()
            },
            'network': [
                {
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.sock_type,
                    'connected': conn.connected,
                    'bytes_sent': conn.bytes_sent,
                    'bytes_recv': conn.bytes_recv,
                    'pid': conn.pid,
                }
                for sockets in self.sockets.values()
                for conn in sockets.values()
            ],
            'processes': {
                pid: {
                    'parent_pid': proc.parent_pid,
                    'exec_path': proc.exec_path,
                    'exit_code': proc.exit_code,
                }
                for pid, proc in self.processes.items()
            },
            'errors': self.errors,
        }


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Analyze mactrace JSON output',
        epilog='Reads JSON from mactrace and produces analysis summary.'
    )
    parser.add_argument('file', help='mactrace JSON file (use - for stdin)')
    parser.add_argument('-c', '--category', choices=['file', 'network', 'process', 'memory'],
                        help='Filter to specific syscall category')
    parser.add_argument('--errors-only', action='store_true',
                        help='Only show errors')
    parser.add_argument('--hide-startup', action='store_true',
                        help='Hide startup/library files')
    parser.add_argument('--json', action='store_true',
                        help='Output JSON instead of text')
    
    args = parser.parse_args()
    
    analyzer = MacTraceAnalyzer()
    
    try:
        analyzer.load(args.file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
        
    analyzer.analyze()
    
    if args.json:
        print(json.dumps(analyzer.to_json(), indent=2))
    else:
        analyzer.print_summary(
            category=args.category,
            errors_only=args.errors_only,
            hide_startup=args.hide_startup,
        )


if __name__ == '__main__':
    main()
