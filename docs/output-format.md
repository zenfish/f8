# Output Format

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

mactrace traces 111 of the 454 named macOS syscalls across 7 categories. Use `--trace help` for live details, or see **[COVERAGE.md](COVERAGE.md)** for the full breakdown, cross-version data, and the coverage gathering script.

| Category | Traced | Coverage | Key syscalls |
|----------|-------:|---------:|--------------|
| Network | 32 | 94% | connect/connectx, sendto/recvfrom, sendmsg/recvmsg, sendfile, peeloff |
| File | 42 | 100%* | open, read, write, stat, close, rename, chmod, xattr |
| Process | 24 | 100%* | fork, exec, exit, wait, getpid/uid, posix_spawn |
| Memory | 3 | 18% | mmap, mprotect, munmap |
| Signal | 3 | 100% | kill, sigaction, sigprocmask |
| MAC | 11 | 100% | __mac_syscall (Sandbox, AMFI), __mac_get/set_* |
| Poll | 7 | 39% | select, poll, kqueue/kevent |

*\*Core syscalls fully covered; Apple-specific extensions (guarded fds, vectored I/O, pthread internals) not yet traced.*

Use `--trace=net` to load only network probes (reduces DTrace overhead by 56%). See `--trace help` for all categories and aliases.

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

