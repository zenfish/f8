# mactrace

An strace-like utility for macOS using DTrace. Traces system calls for a command and all its children, outputting structured JSON suitable for timeline analysis.

## Requirements

- macOS (tested on 15.7.3 Sequoia)
- SIP disabled (or at least dtrace restrictions disabled) for full tracing
- Python 3.8+
- Root privileges (DTrace requires sudo)

## Usage

```bash
# Basic usage - outputs JSON to stdout
sudo ./mactrace ls -la

# Write to file with pretty printing
sudo ./mactrace -o trace.json -p ls -la

# With timeout (seconds)
sudo ./mactrace -t 10 ./long_running_command

# Verbose mode (shows DTrace activity on stderr)
sudo ./mactrace -v -o trace.json ./my_program
```

## Output Format

The output is JSON with the following structure:

```json
{
  "command": ["ls", "-la"],
  "start_time": "2026-02-04T19:10:00.000000",
  "end_time": "2026-02-04T19:10:00.500000",
  "duration_ms": 500.0,
  "target_pid": 12345,
  "pids_traced": [12345, 12346, 12347],
  "process_tree": {
    "12346": 12345,
    "12347": 12346
  },
  "syscall_count": 150,
  "events": [
    {
      "timestamp_us": 0,
      "pid": 12345,
      "tid": 12345,
      "syscall": "open",
      "return_value": 3,
      "errno": 0,
      "args": {
        "path": "/etc/passwd",
        "flags": "O_RDONLY",
        "flags_raw": 0,
        "mode": "0644",
        "errno_name": "OK"
      }
    }
  ],
  "process_events": [
    {
      "timestamp_us": 1000,
      "event_type": "process_create",
      "pid": 12345,
      "tid": 12345,
      "child_pid": 12346,
      "parent_pid": 12345
    },
    {
      "timestamp_us": 1500,
      "event_type": "exec",
      "pid": 12346,
      "tid": 12346,
      "path": "/bin/ls",
      "parent_pid": 12345
    },
    {
      "timestamp_us": 50000,
      "event_type": "exit",
      "pid": 12346,
      "tid": 12346,
      "exit_code": 0,
      "parent_pid": 12345
    }
  ],
  "summary": {
    "open": 15,
    "read": 42,
    "write": 10,
    "close": 15
  }
}
```

## Traced Syscalls

### File Operations
- open, openat, close, read, pread, write, pwrite
- stat64, lstat64, fstat64, access
- unlink, rename, mkdir, rmdir, chdir
- chmod, fchmod, chown, truncate, ftruncate
- link, symlink, readlink
- fsync, dup, dup2, fcntl, ioctl
- getdirentries64, getattrlist, setattrlist
- getxattr, setxattr, listxattr, removexattr

### Network Operations
- socket, connect, bind, listen, accept
- sendto, recvfrom, sendmsg, recvmsg
- shutdown, setsockopt, getsockopt
- socketpair, getpeername, getsockname

### Process Operations
- fork, execve, posix_spawn
- exit, wait4, kill, pipe
- getpid, getppid, getuid, geteuid, getgid, getegid
- setuid, setgid

### Memory Operations
- mmap, munmap, mprotect

### Signal Operations
- sigaction, sigprocmask

### Other
- select, poll, kevent, kqueue
- gettimeofday, clock_gettime

## Process Tracking

mactrace comprehensively tracks all process lifecycle events:

### Process Creation
- `proc:::create` — Catches process creation before child runs (most reliable)
- `proc:::fork` — Backup fork tracking
- `syscall::fork:return` — Syscall-level fork with return values (note: vfork not available on modern macOS)
- `syscall::posix_spawn` — macOS preferred process spawning

### Execution
- `proc:::exec` — Exec attempt (before success/failure known)
- `proc:::exec-success` — Successful exec with new executable path
- `proc:::exec-failure` — Failed exec with errno
- `syscall::execve` — Syscall-level exec

### Exit & Signals
- `proc:::exit` — Process termination with exit code
- `proc:::signal-send` — Signal sent to tracked process
- `proc:::signal-handle` — Signal received by tracked process

### Process Tree
The `process_tree` field maps each child PID to its parent PID, making it easy to reconstruct the full process hierarchy:

```json
"process_tree": {
  "12346": 12345,   // 12346's parent is 12345
  "12347": 12346    // 12347's parent is 12346
}
```

### Process Event Types
The `process_events` array contains these event types:
- `process_create` — New process created (from parent's perspective)
- `fork` — Fork completed (from child's perspective)
- `exec_attempt` — Exec attempted
- `exec` — Exec succeeded
- `exec_fail` — Exec failed
- `exit` — Process exited
- `signal_send` — Signal sent
- `signal_handle` — Signal handled

## Limitations

1. **Requires root**: DTrace needs elevated privileges
2. **SIP**: System Integrity Protection can restrict what can be traced. Disable for full coverage.
3. **Timestamps**: Per-syscall timestamps use sequence numbers; actual wall-clock times come from process events
4. **Some syscall args**: Complex arguments (like socket addresses) aren't fully decoded yet
5. **Short-lived processes**: Very fast programs might complete before DTrace fully attaches

## Timeline Analysis

The JSON output is designed for timeline analysis. You can:

1. Sort `events` by `timestamp_us` for temporal ordering
2. Use `process_events` to track process creation/termination
3. Filter by `pid` to isolate specific processes
4. Use `summary` for quick syscall frequency analysis

Example jq queries:

```bash
# Count syscalls by type
jq '.summary' trace.json

# Get all file opens
jq '.events[] | select(.syscall == "open") | .args.path' trace.json

# Get network activity
jq '.events[] | select(.syscall | test("socket|connect|send|recv"))' trace.json

# Get events for a specific PID
jq --arg pid "12346" '.events[] | select(.pid == ($pid | tonumber))' trace.json
```

## Future Improvements

- [ ] Socket address decoding (IP/port extraction)
- [ ] More granular timestamps per syscall
- [ ] Output filtering options (file-only, network-only, etc.)
- [ ] Timeline visualization tool
- [ ] Data content capture for read/write (with size limits)

## License

MIT
