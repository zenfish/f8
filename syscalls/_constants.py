"""
Shared constants and flag-parsing helpers for syscall handlers.

All symbolic name tables (errnos, open flags, socket domains, mmap flags,
etc.) live here so handlers can import what they need without pulling in
the entire tracer.
"""

# ── Errno names ─────────────────────────────────────────────────────

ERRNO_NAMES = {
    0: "OK",
    1: "EPERM",
    2: "ENOENT",
    3: "ESRCH",
    4: "EINTR",
    5: "EIO",
    9: "EBADF",
    11: "EAGAIN",
    12: "ENOMEM",
    13: "EACCES",
    14: "EFAULT",
    17: "EEXIST",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    23: "ENFILE",
    24: "EMFILE",
    28: "ENOSPC",
    30: "EROFS",
    36: "ENAMETOOLONG",
    54: "ECONNRESET",
    60: "ETIMEDOUT",
    61: "ECONNREFUSED",
}

# ── Open flags (macOS) ──────────────────────────────────────────────

def parse_open_flags(flags):
    """Convert open() flags bitmask to symbolic string."""
    parts = []
    base = flags & 0x3
    if base == 0:
        parts.append("O_RDONLY")
    elif base == 1:
        parts.append("O_WRONLY")
    elif base == 2:
        parts.append("O_RDWR")

    if flags & 0x0200:
        parts.append("O_CREAT")
    if flags & 0x0400:
        parts.append("O_TRUNC")
    if flags & 0x0008:
        parts.append("O_APPEND")
    if flags & 0x0004:
        parts.append("O_NONBLOCK")
    if flags & 0x0100:
        parts.append("O_CLOEXEC")

    return "|".join(parts) if parts else f"0x{flags:x}"

# ── Socket domains ──────────────────────────────────────────────────

AF_NAMES = {
    0: "AF_UNSPEC",
    1: "AF_UNIX",
    2: "AF_INET",
    30: "AF_INET6",
    31: "AF_SYSTEM",
}

# ── Socket types ────────────────────────────────────────────────────

SOCK_NAMES = {
    1: "SOCK_STREAM",
    2: "SOCK_DGRAM",
    3: "SOCK_RAW",
}

# ── mmap / mprotect protection flags ────────────────────────────────

PROT_FLAGS = {
    0x00: "PROT_NONE",
    0x01: "PROT_READ",
    0x02: "PROT_WRITE",
    0x04: "PROT_EXEC",
}

def parse_prot_flags(prot):
    """Convert mmap/mprotect protection bits to symbolic string."""
    if prot == 0:
        return "PROT_NONE"
    parts = []
    for bit, name in sorted(PROT_FLAGS.items()):
        if bit != 0 and (prot & bit):
            parts.append(name)
    return "|".join(parts) if parts else f"0x{prot:x}"

# ── mmap flags (macOS) ──────────────────────────────────────────────

MAP_FLAGS = {
    0x0001: "MAP_SHARED",
    0x0002: "MAP_PRIVATE",
    0x0010: "MAP_FIXED",
    0x1000: "MAP_ANON",
    0x0800: "MAP_NORESERVE",
    0x2000: "MAP_RESILIENT_CODESIGN",
    0x4000: "MAP_RESILIENT_MEDIA",
}

def parse_mmap_flags(flags):
    """Convert mmap flags bitmask to symbolic string."""
    parts = []
    remaining = flags
    for bit, name in sorted(MAP_FLAGS.items()):
        if flags & bit:
            parts.append(name)
            remaining &= ~bit
    if remaining:
        parts.append(f"0x{remaining:x}")
    return "|".join(parts) if parts else "0x0"

# ── shutdown() how values ───────────────────────────────────────────

SHUT_NAMES = {
    0: "SHUT_RD",
    1: "SHUT_WR",
    2: "SHUT_RDWR",
}

# ── Socket option levels ────────────────────────────────────────────

SOL_NAMES = {
    0xffff: "SOL_SOCKET",
    0: "IPPROTO_IP",
    6: "IPPROTO_TCP",
    17: "IPPROTO_UDP",
    41: "IPPROTO_IPV6",
}

# ── SOL_SOCKET option names ─────────────────────────────────────────

SO_NAMES = {
    0x0004: "SO_REUSEADDR",
    0x0008: "SO_KEEPALIVE",
    0x0080: "SO_LINGER",
    0x0100: "SO_OOBINLINE",
    0x1001: "SO_SNDBUF",
    0x1002: "SO_RCVBUF",
    0x1005: "SO_SNDTIMEO",
    0x1006: "SO_RCVTIMEO",
    0x1022: "SO_TIMESTAMP",
    0x1100: "SO_NOSIGPIPE",
    0x1104: "SO_NOAPNFALLBK",
}

def parse_sockopt_level(level):
    """Convert setsockopt/getsockopt level to name."""
    return SOL_NAMES.get(level, f"SOL_{level}")

def parse_sockopt_name(level, optname):
    """Convert setsockopt/getsockopt option name to symbolic string."""
    if level == 0xffff:  # SOL_SOCKET
        return SO_NAMES.get(optname, f"SO_0x{optname:x}")
    return f"0x{optname:x}"

# ── Signal names ────────────────────────────────────────────────────

SIGNAL_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
    5: "SIGTRAP", 6: "SIGABRT", 7: "SIGEMT", 8: "SIGFPE",
    9: "SIGKILL", 10: "SIGBUS", 11: "SIGSEGV", 12: "SIGSYS",
    13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 16: "SIGURG",
    17: "SIGSTOP", 18: "SIGTSTP", 19: "SIGCONT", 20: "SIGCHLD",
    21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGIO", 24: "SIGXCPU",
    25: "SIGXFSZ", 26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH",
    29: "SIGINFO", 30: "SIGUSR1", 31: "SIGUSR2",
}

def signal_name(sig):
    """Convert signal number to name."""
    return SIGNAL_NAMES.get(sig, f"SIG{sig}")

# ── fcntl commands (macOS) ──────────────────────────────────────────

FCNTL_NAMES = {
    0: "F_DUPFD",
    1: "F_GETFD",
    2: "F_SETFD",
    3: "F_GETFL",
    4: "F_SETFL",
    6: "F_SETLK",
    7: "F_SETLKW",
    8: "F_GETLK",
}

def parse_fcntl_cmd(cmd):
    """Convert fcntl command to name."""
    return FCNTL_NAMES.get(cmd, f"F_{cmd}")
