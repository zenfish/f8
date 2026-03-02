# Syscall Coverage

f8 traces a subset of the macOS syscall table. This document tracks what we cover, what we don't, and how coverage varies across OS versions.

## Current Coverage

**Tested on:** macOS 15.7.3 (Sequoia, build 24G419), Apple Silicon (arm64)  
**Kernel:** Darwin 24.6.0 (xnu-11417.140.6)  
**DTrace syscall probes:** 558 total (454 named, 104 unnamed tombstones)

| Category | Traced | Available | Coverage | Notes |
|----------|-------:|----------:|---------:|-------|
| Network | 32 | 34 | **94%** | Socket I/O, connect/connectx, DNS, NECP, sendfile, peeloff |
| File | 42 | 42¹ | **100%**¹ | Core file ops; many Apple extensions untraced |
| Process | 24 | 24¹ | **100%**¹ | Core lifecycle; pthread/psynch internals untraced |
| Memory | 3 | 17 | **18%** | Core mmap/mprotect; SysV shm, madvise untraced |
| Signal | 3 | 3 | **100%** | kill, sigaction, sigprocmask |
| MAC | 11 | 11 | **100%** | Mandatory Access Control (__mac_syscall, etc.) |
| Poll/Event | 7 | 18 | **39%** | select/poll/kqueue; aio_* untraced |
| **Total** | **111** | **454** | **24%** | |

¹ Coverage % depends on how broadly you define the category. f8 covers 100% of the *core* file and process syscalls (open, read, write, stat, fork, exec, exit, etc.) but macOS has many extended/Apple-specific variants (guarded file descriptors, vectored I/O, xattr, pthread internals) that aren't traced. The "Available" column above counts only syscalls in f8's own category definitions.

### What's Not Traced (and Why)

**Deliberately excluded** — these are internal plumbing, rarely interesting for tracing:
- **pthread/psynch** (12 syscalls) — Mutex, rwlock, condvar kernel primitives. High frequency, low signal.
- **bsdthread** (4) — Thread pool management. Internal to libdispatch.
- **Audit** (9) — BSM audit framework. Rarely used in practice.
- **Skywalk/Channel** (8) — Apple's kernel networking framework internals.
- **kdebug** (4) — Kernel debug/trace facilities. Meta.
- **SysV IPC** (9) — semaphore/message/shared memory. Mostly legacy.
- **Coalition** (5) — Process coalition management. Scheduler internals.

**Worth adding eventually:**
- `readv`/`writev` (+ `preadv`/`pwritev`) — Vectored I/O. Used by databases.
- `kevent_qos`/`kevent_id` — Modern kqueue variants. Used by libdispatch.
- `madvise` — Memory advisory. Useful for understanding app memory behavior.
- `waitid` — Modern wait variant. Increasingly used.
- `getattrlist`/`setattrlist` — Apple's bulk attribute operations.

### Network Coverage Detail

32 of 34 network-related syscalls (94%):

```
Traced:                          Not traced:
  accept, accept_nocancel          disconnectx
  bind                             necp_match_policy
  connect, connect_nocancel        peeloff
  connectx                         pid_shutdown_sockets
  getpeername                      socket_delegate
  getsockname
  getsockopt
  listen
  necp_client_action, necp_open
  necp_session_action, necp_session_open
  recvfrom, recvfrom_nocancel
  recvmsg, recvmsg_nocancel
  recvmsg_x
  sendfile
  sendmsg, sendmsg_nocancel
  sendmsg_x
  sendto, sendto_nocancel
  setsockopt
  shutdown
  socket, socket_delegate, socketpair
```

### The 104 Unnamed Syscalls

DTrace lists 104 syscalls as `#N` (by number, no name). These are **tombstones** — dead syscalls that macOS inherited from BSD but later replaced or removed. The syscall number is preserved for ABI stability, but the implementation is `nosys()` (returns ENOSYS). They include:

- **86 "old" BSD relics** — `#8 old creat`, `#19 old lseek`, `#71 old mmap`, `#99 old accept`, `#101 old send`, `#102 old recv`, `#206-212 old AppleTalk` (7 dead AT* calls), etc.
- **2 reserved** — `#63` (internal), `#213` (reserved for AppleTalk)
- **2 conditionally compiled** — `#164 funmount`, `#435 pid_hibernate` (iOS only)
- **14 empty slots** — `nosys()` with no explanation

These never fire and are excluded from coverage calculations.

## Gathering Data for Your OS Version

Run the coverage script to dump your system's syscall table:

```bash
sudo ./scripts/syscall-coverage.sh scripts/coverage-data/my-system.json
```

This produces a JSON file with:
- OS version, build, kernel version, architecture
- All named syscall probes
- All unnamed (tombstone) syscall numbers
- `kern.dtrace.difo_maxsize` value

### Comparing Across Versions

Coverage data files live in `scripts/coverage-data/`. To compare two OS versions:

```bash
# What syscalls were added?
diff <(jq -r '.syscalls.named[]' old.json) <(jq -r '.syscalls.named[]' new.json)

# Quick summary
jq '.os.version, .counts' scripts/coverage-data/*.json
```

### Available Data

| File | macOS | Build | Arch | Named | Unnamed | Total |
|------|-------|-------|------|------:|--------:|------:|
| `macos-15.7.3-arm64.json` | 15.7.3 | 24G419 | arm64 | 454 | 104 | 558 |

*Contributions welcome — run the script on other macOS versions and submit the JSON.*

## DTrace DIF Budget

macOS DTrace has a compiled bytecode size limit per probe (`kern.dtrace.difo_maxsize`, default 256KB). f8's full probe set uses ~82% of this budget. The `--trace` flag lets you load only the categories you need:

```
--trace=net           111 probes  ~44% of budget
--trace=fs            124 probes  ~50%
--trace=exec           40 probes  ~16%
--trace=io            189 probes  ~76%
Default (all)         216 probes  ~86%
```

Use `-d` to temporarily double the DIF budget (sets `kern.dtrace.difo_maxsize=524288`, restored on exit).

## Category Reference

Use `f8 --trace help` for live category info, or `--trace help <name>` for details:

```
$ f8 --trace help
Trace categories (7 categories, 111 traced syscalls):

  file           42 syscalls  File system operations: open, read, write, stat, link, chmod, directory ops
  mac            11 syscalls  Apple Mandatory Access Control framework
  memory          3 syscalls  Virtual memory: mmap, mprotect, munmap
  network        32 syscalls  Socket and network I/O: connect, send/recv, DNS, NECP, sendfile
  poll            7 syscalls  Event multiplexing: select, poll, kqueue/kevent
  process        24 syscalls  Process lifecycle and identity: fork, exec, exit, wait, getpid/uid
  signal          3 syscalls  Signal delivery and handling: kill, sigaction, sigprocmask

$ f8 --trace help network
  network
  ───────
  32 syscalls:
    accept, accept_nocancel, bind, connect, connect_nocancel, connectx, disconnectx,
    getpeername, getsockname, getsockopt, listen, necp_client_action,
    necp_open, necp_session_action, necp_session_open, recvfrom,
    recvfrom_nocancel, recvmsg, recvmsg_nocancel, recvmsg_x, sendfile,
    sendmsg, sendmsg_nocancel, sendmsg_x, sendto, sendto_nocancel,
    setsockopt, shutdown, socket, socket_delegate, socketpair
```

## Complete Syscall Reference

Every syscall f8 traces, what it does, and what fields appear in the JSON output.
Syscalls marked with `_nocancel` are non-cancellable variants (identical semantics, won't be
interrupted by thread cancellation). The `-c` flag enables I/O data capture (raw bytes in hex).

**All syscalls also capture:** return value, errno (with symbolic name), timestamp, PID, TID.

#### File Operations (48 syscalls)

| Syscall | What it does | What we capture |
|---------|-------------|-----------------|
| `access` | Check file access permissions | path, mode (R_OK etc.) |
| `chdir` | Change working directory | path |
| `chmod` | Change file permissions | path, mode |
| `close`\[`_nocancel`\] | Close file descriptor | fd |
| `dup` | Duplicate fd | old fd → new fd (return value) |
| `dup2` | Duplicate fd to specific number | old fd, new fd |
| `faccessat` | Check access relative to dirfd | dirfd, path, mode, flags |
| `fchdir` | Change working directory by fd | fd |
| `fchmod` | Change fd permissions | fd, mode |
| `fcntl`\[`_nocancel`\] | File descriptor control | fd, command (F_GETFL etc.) |
| `fstat64` | Get file status by fd | fd |
| `fstatat64` | Get file status relative to dirfd | dirfd, path, flags |
| `fsync`\[`_nocancel`\] | Flush fd to disk | fd |
| `ftruncate` | Truncate file by fd | fd, length |
| `getattrlistbulk` | Bulk read directory attributes | dirfd, buffer size |
| `getdirentries64` | Read directory entries | fd, byte count |
| `ioctl` | Device I/O control | fd, request code |
| `link` | Create hard link | source path, link path |
| `lstat64` | Get symlink status by path | path |
| `mkdir` | Create directory | path, mode |
| `open`\[`_nocancel`\] | Open file or device | path, flags (O_RDONLY etc.), mode |
| `openat`\[`_nocancel`\] | Open file relative to directory fd | dirfd, path, flags, mode |
| `pread`\[`_nocancel`\] | Read at offset | fd, byte count, offset |
| `pwrite`\[`_nocancel`\] | Write at offset | fd, byte count, offset |
| `pwritev` | Vectored write at offset | fd, iov count, offset |
| `readv`\[`_nocancel`\] | Vectored read (scatter) | fd, iov count |
| `writev`\[`_nocancel`\] | Vectored write (gather) | fd, iov count |
| `preadv` | Vectored read at offset | fd, iov count, offset |
| `read`\[`_nocancel`\] | Read from fd | fd, byte count; +data with `-c` |
| `readlink` | Read symbolic link target | path, target buffer |
| `rename` | Rename/move file | old path, new path |
| `rmdir` | Remove directory | path |
| `stat64` | Get file status by path | path |
| `symlink` | Create symbolic link | target, link path |
| `truncate` | Truncate file by path | path, length |
| `unlink` | Delete file | path |
| `write`\[`_nocancel`\] | Write to fd | fd, byte count; +data with `-c` |

#### Network (32 syscalls)

| Syscall | What it does | What we capture |
|---------|-------------|-----------------|
| `accept`\[`_nocancel`\] | Accept incoming connection | fd, peer sockaddr (family, address, port) |
| `bind` | Bind socket to address | fd, sockaddr (family, address, port) |
| `connect`\[`_nocancel`\] | Connect socket to address | fd, sockaddr (family, address, port) |
| `connectx` | Extended connect (multipath TCP) | fd, destination sockaddr from sa_endpoints_t |
| `disconnectx` | Close a connectx association | fd, association ID, connection ID |
| `getpeername` | Get remote socket address | fd, sockaddr |
| `getsockname` | Get local socket address | fd, sockaddr |
| `getsockopt` | Get socket option | fd, level, option name |
| `listen` | Listen for connections | fd, backlog |
| `necp_client_action` | NECP client policy action | fd, action code |
| `necp_open` | Open NECP policy session | flags |
| `necp_session_action` | NECP session action | fd, action code |
| `necp_session_open` | Open NECP session | flags |
| `peeloff` | SCTP: separate stream into new socket | fd, association ID, new socket fd (return) |
| `recvfrom`\[`_nocancel`\] | Receive datagram with source | fd, byte count, flags, source sockaddr; +data with `-c` |
| `recvmsg`\[`_nocancel`\] | Receive message (scatter/gather) | fd, flags, source sockaddr (if present); +data with `-c` |
| `recvmsg_x` | Batch receive multiple messages | fd, message count, flags, total bytes |
| `sendfile` | Zero-copy file→socket transfer | file_fd, socket_fd, offset, bytes_sent, flags |
| `sendmsg`\[`_nocancel`\] | Send message (scatter/gather) | fd, flags, dest sockaddr (if present); +data with `-c` |
| `sendmsg_x` | Batch send multiple messages | fd, message count, flags, total bytes |
| `sendto`\[`_nocancel`\] | Send datagram to address | fd, byte count, flags, dest sockaddr; +data with `-c` |
| `setsockopt` | Set socket option | fd, level, option name (SO_REUSEADDR etc.) |
| `shutdown` | Shutdown socket half | fd, how (SHUT_RD/WR/RDWR) |
| `socket` | Create socket | domain (AF_INET etc.), type (SOCK_STREAM etc.), protocol |
| `socket_delegate` | Create socket in another process | domain, type, protocol, target_pid |
| `socketpair` | Create connected socket pair | domain, type, protocol |

#### MAC Framework (11 syscalls)

| Syscall | What it does | What we capture |
|---------|-------------|-----------------|
| `__mac_execve` | Execute with MAC label | path |
| `__mac_get_fd` | Get MAC label for fd | fd |
| `__mac_get_file` | Get MAC label for file | path |
| `__mac_get_link` | Get MAC label for symlink | path |
| `__mac_get_pid` | Get MAC label for process | target PID |
| `__mac_get_proc` | Get MAC label for current process | (none) |
| `__mac_set_fd` | Set MAC label for fd | fd |
| `__mac_set_file` | Set MAC label for file | path |
| `__mac_set_link` | Set MAC label for symlink | path |
| `__mac_set_proc` | Set MAC label for current process | (none) |
| `__mac_syscall` | MAC framework policy check | policy name (Sandbox, AMFI, etc.), call number |

#### Process (13 syscalls)

| Syscall | What it does | What we capture |
|---------|-------------|-----------------|
| `execve` | Execute program | path |
| `exit` | Terminate process | exit code |
| `fork` | Create child process | child PID (return value) |
| `getegid` | Get effective group ID | EGID (return value) |
| `geteuid` | Get effective user ID | EUID (return value) |
| `getgid` | Get group ID | GID (return value) |
| `getpid` | Get process ID | PID (return value) |
| `getppid` | Get parent process ID | parent PID (return value) |
| `getuid` | Get user ID | UID (return value) |
| `pipe` | Create pipe | read fd, write fd |
| `posix_spawn` | Spawn new process | path |
| `wait4`\[`_nocancel`\] | Wait for child process | target PID, options |

#### Memory (3 syscalls)

| Syscall | What it does | What we capture |
|---------|-------------|-----------------|
| `mmap` | Map memory (file or anonymous) | address, length, protection, flags, fd, offset |
| `mprotect` | Change memory protection | address, length, protection flags |
| `munmap` | Unmap memory region | address, length |

#### Signals (3 syscalls)

| Syscall | What it does | What we capture |
|---------|-------------|-----------------|
| `kill` | Send signal to process | target PID, signal number and name |
| `sigaction` | Set signal handler | signal number and name |
| `sigprocmask` | Block/unblock signals | how (SIG_BLOCK etc.) |

#### Poll / Events (7 syscalls)

| Syscall | What it does | What we capture |
|---------|-------------|-----------------|
| `kevent` | Register/wait for kernel events | kqueue fd, change count, event count |
| `kevent64` | Register/wait for 64-bit kernel events | kqueue fd, change count, event count |
| `kqueue` | Create kernel event queue | kqueue fd (return value) |
| `poll`\[`_nocancel`\] | Wait for fd events | nfds, timeout |
| `select`\[`_nocancel`\] | Wait for fd readiness | nfds, timeout |
