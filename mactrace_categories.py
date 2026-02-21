#!/usr/bin/env python3
"""
mactrace_categories.py - Syscall category definitions

This file defines the mapping of syscalls to categories.
Edit this file to add new syscalls or adjust categorization.

Categories are used for:
- Filtering in analysis and timeline views
- Color coding in visualizations
- Grouping in summaries

To add a new syscall:
1. Find the appropriate category
2. Add the syscall name to that category's set
3. All tools (mactrace, mactrace_analyze, mactrace_timeline) will pick it up
"""

# =============================================================================
# SYSCALL CATEGORIES
# =============================================================================
# Each category maps to a set of syscall names.
# A syscall should only appear in ONE category.
# Unknown syscalls default to 'other'.

SYSCALL_CATEGORIES = {
    # -------------------------------------------------------------------------
    # FILE - File system operations
    # -------------------------------------------------------------------------
    'file': {
        # Open/close
        'open', 'open_nocancel', 'openat', 'openat_nocancel',
        'close', 'close_nocancel',
        
        # Read/write
        'read', 'read_nocancel', 'pread', 'pread_nocancel',
        'write', 'write_nocancel', 'pwrite', 'pwrite_nocancel',
        'readv', 'writev', 'preadv', 'pwritev',
        
        # Stat/access
        'stat', 'stat64', 'lstat', 'lstat64', 'fstat', 'fstat64', 'fstatat64',
        'access', 'faccessat',
        'statfs', 'statfs64', 'fstatfs', 'fstatfs64',
        
        # Directory operations
        'mkdir', 'mkdirat', 'rmdir',
        'chdir', 'fchdir', 'getcwd',
        'getdirentries', 'getdirentries64', 'getattrlistbulk',
        
        # File manipulation
        'unlink', 'unlinkat', 'rename', 'renameat', 'renamex_np',
        'link', 'linkat', 'symlink', 'symlinkat', 'readlink', 'readlinkat',
        'truncate', 'ftruncate',
        
        # Permissions
        'chmod', 'fchmod', 'fchmodat',
        'chown', 'fchown', 'lchown', 'fchownat',
        'chflags', 'fchflags',
        
        # Extended attributes
        'getxattr', 'fgetxattr', 'setxattr', 'fsetxattr',
        'listxattr', 'flistxattr', 'removexattr', 'fremovexattr',
        
        # File descriptors
        'dup', 'dup2', 'dup3',
        'fcntl', 'fcntl_nocancel',
        'ioctl',
        
        # Sync
        'fsync', 'fsync_nocancel', 'fdatasync',
        'sync',
        
        # Other file ops
        'umask', 'pathconf', 'fpathconf',
        'getattrlist', 'setattrlist', 'fgetattrlist', 'fsetattrlist',
        'exchangedata', 'searchfs',
    },
    
    # -------------------------------------------------------------------------
    # NETWORK - Network/socket operations
    # -------------------------------------------------------------------------
    'network': {
        # Socket creation
        'socket', 'socketpair',
        
        # Connection
        'connect', 'connect_nocancel',
        'bind', 'listen',
        'accept', 'accept_nocancel',
        
        # Data transfer
        'send', 'sendto', 'sendto_nocancel', 'sendmsg', 'sendmsg_nocancel',
        'recv', 'recvfrom', 'recvfrom_nocancel', 'recvmsg', 'recvmsg_nocancel',
        
        # Socket options
        'setsockopt', 'getsockopt',
        'shutdown',
        
        # Socket info
        'getpeername', 'getsockname',
        'gethostuuid',
    },
    
    # -------------------------------------------------------------------------
    # NECP - Network Extension Control Policy (macOS)
    # -------------------------------------------------------------------------
    'necp': {
        'necp_open',
        'necp_client_action',
        'necp_session_open',
        'necp_session_action',
        'necp_match_policy',
    },
    
    # -------------------------------------------------------------------------
    # PROCESS - Process lifecycle and info
    # -------------------------------------------------------------------------
    'process': {
        # Creation/execution
        'fork', 'vfork',
        'execve', 'posix_spawn',
        '__mac_execve',
        
        # Exit/wait
        'exit', '_exit',
        'wait4', 'wait4_nocancel', 'waitpid', 'waitid',
        
        # Process info
        'getpid', 'getppid', 'getpgid', 'getsid',
        'setpgid', 'setsid',
        
        # User/group IDs
        'getuid', 'geteuid', 'getgid', 'getegid',
        'setuid', 'seteuid', 'setgid', 'setegid',
        'setreuid', 'setregid',
        'getgroups', 'setgroups',
        
        # Resource limits
        'getrlimit', 'setrlimit',
        'getrusage',
        
        # Priority
        'getpriority', 'setpriority',
        'nice',
    },
    
    # -------------------------------------------------------------------------
    # MEMORY - Memory management
    # -------------------------------------------------------------------------
    'memory': {
        'mmap', 'munmap', 'mprotect',
        'madvise', 'mincore', 'mlock', 'munlock',
        'msync',
        'mremap',
        'brk', 'sbrk',
    },
    
    # -------------------------------------------------------------------------
    # SIGNAL - Signal handling
    # -------------------------------------------------------------------------
    'signal': {
        'sigaction', 'sigprocmask', 'sigsuspend', 'sigpending',
        'sigwait', 'sigtimedwait',
        'sigaltstack',
        'sigreturn',
        'kill', 'killpg',
        'pthread_kill',
    },
    
    # -------------------------------------------------------------------------
    # MAC - Mandatory Access Control (macOS security framework)
    # -------------------------------------------------------------------------
    'mac': {
        '__mac_syscall',
        '__mac_get_file', '__mac_set_file',
        '__mac_get_link', '__mac_set_link',
        '__mac_get_proc', '__mac_set_proc',
        '__mac_get_fd', '__mac_set_fd',
        '__mac_get_pid',
        '__mac_get_lcid', '__mac_get_lctx',
        '__mac_set_lctx',
    },
    
    # -------------------------------------------------------------------------
    # IPC - Inter-process communication
    # -------------------------------------------------------------------------
    'ipc': {
        # Pipes
        'pipe', 'pipe2',
        
        # Shared memory
        'shm_open', 'shm_unlink',
        'shmget', 'shmat', 'shmdt', 'shmctl',
        
        # Semaphores
        'sem_open', 'sem_close', 'sem_unlink',
        'sem_wait', 'sem_trywait', 'sem_post',
        'semget', 'semop', 'semctl',
        
        # Message queues
        'msgget', 'msgsnd', 'msgrcv', 'msgctl',
        
        # Mach IPC (macOS)
        'mach_msg', 'mach_msg_overwrite',
    },
    
    # -------------------------------------------------------------------------
    # POLL - Event waiting/polling
    # -------------------------------------------------------------------------
    'poll': {
        'select', 'select_nocancel',
        'pselect', 'pselect_nocancel',
        'poll', 'poll_nocancel',
        'ppoll',
        'kevent', 'kevent64', 'kevent_qos', 'kevent_id',
        'kqueue',
    },
    
    # -------------------------------------------------------------------------
    # TIME - Time and timers
    # -------------------------------------------------------------------------
    'time': {
        'gettimeofday', 'settimeofday',
        'clock_gettime', 'clock_settime', 'clock_getres',
        'nanosleep',
        'getitimer', 'setitimer',
        'timer_create', 'timer_delete', 'timer_settime', 'timer_gettime',
    },
    
    # -------------------------------------------------------------------------
    # THREAD - Thread operations
    # -------------------------------------------------------------------------
    'thread': {
        'pthread_create', 'pthread_exit', 'pthread_join',
        'pthread_mutex_lock', 'pthread_mutex_unlock',
        'pthread_cond_wait', 'pthread_cond_signal',
        'bsdthread_create', 'bsdthread_terminate',
        'bsdthread_register',
        'thread_selfid',
        'workq_kernreturn', 'workq_open',
    },
}

# =============================================================================
# CATEGORY COLORS (for visualization)
# =============================================================================
# Colors from ColorBrewer PiYG (pink-green diverging) palette
# https://colorbrewer2.org/#type=diverging&scheme=PiYG&n=10

CATEGORY_COLORS = {
    'file':     '#276419',  # dark green - most common, anchoring
    'network':  '#4d9221',  # green
    'necp':     '#7fbc41',  # medium green
    'process':  '#b8e186',  # light green
    'memory':   '#e6f5d0',  # pale green
    'signal':   '#fde0ef',  # pale pink
    'mac':      '#f1b6da',  # light pink
    'ipc':      '#de77ae',  # medium pink
    'poll':     '#c51b7d',  # pink
    'time':     '#8e0152',  # dark pink/magenta
    'thread':   '#762a83',  # purple (from PRGn for extra category)
    'other':    '#878787',  # neutral gray
}

# =============================================================================
# CATEGORY DISPLAY ORDER
# =============================================================================

CATEGORY_ORDER = [
    'file', 'network', 'necp', 'process', 'memory', 
    'signal', 'mac', 'ipc', 'poll', 'time', 'thread', 'other'
]

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Build reverse lookup: syscall -> category
_SYSCALL_TO_CATEGORY = {}
for _cat, _syscalls in SYSCALL_CATEGORIES.items():
    for _syscall in _syscalls:
        _SYSCALL_TO_CATEGORY[_syscall] = _cat


def get_category(syscall: str) -> str:
    """
    Get the category for a syscall.
    
    Args:
        syscall: The syscall name (e.g., 'open', 'socket', '__mac_get_file')
        
    Returns:
        Category name (e.g., 'file', 'network', 'mac') or 'other' if unknown.
    """
    return _SYSCALL_TO_CATEGORY.get(syscall, 'other')


def get_color(category: str) -> str:
    """
    Get the color for a category.
    
    Args:
        category: The category name
        
    Returns:
        Hex color string (e.g., '#276419')
    """
    return CATEGORY_COLORS.get(category, CATEGORY_COLORS['other'])


def get_text_color(category: str) -> str:
    """
    Get appropriate text color (black or white) for a category background.
    
    Uses relative luminance to determine contrast.
    
    Args:
        category: The category name
        
    Returns:
        '#000000' (black) for light backgrounds, '#ffffff' (white) for dark
    """
    bg_color = get_color(category).lstrip('#')
    r, g, b = int(bg_color[0:2], 16), int(bg_color[2:4], 16), int(bg_color[4:6], 16)
    # Relative luminance formula (simplified)
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
    return '#000000' if luminance > 0.5 else '#ffffff'


def get_categories_for_display() -> list:
    """
    Get list of categories in display order.
    
    Returns:
        List of category names in preferred display order.
    """
    return CATEGORY_ORDER.copy()


# =============================================================================
# MAIN - Print category summary when run directly
# =============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Display mactrace syscall categories and their mappings.',
        epilog='This file also serves as a Python module imported by other mactrace tools.'
    )
    parser.add_argument('-a', '--all', action='store_true',
                        help='Show all syscalls (default: first 5 per category)')
    args = parser.parse_args()
    
    print("mactrace syscall categories\n")
    print(f"{'Category':<12} {'Count':>6}  Syscalls")
    print("-" * 70)
    
    for cat in CATEGORY_ORDER:
        if cat in SYSCALL_CATEGORIES:
            syscalls = sorted(SYSCALL_CATEGORIES[cat])
            if args.all:
                # Show all syscalls, wrapped
                syscall_str = ', '.join(syscalls)
            else:
                # Show first 5 with count of remaining
                preview = ', '.join(syscalls[:5])
                if len(syscalls) > 5:
                    preview += f', ... (+{len(syscalls) - 5} more)'
                syscall_str = preview
            print(f"{cat:<12} {len(syscalls):>6}  {syscall_str}")
    
    total = sum(len(s) for s in SYSCALL_CATEGORIES.values())
    print("-" * 70)
    print(f"{'Total':<12} {total:>6}")
