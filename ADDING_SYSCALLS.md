# Adding a System Call to mactrace

This guide walks through adding a new system call, using `renameat` as a worked example.

## Overview

There are two levels of syscall support in mactrace:

1. **Basic tracking** — the syscall is counted, categorized, and appears in traces with its return value. This only requires editing `syscalls.json`.

2. **Rich argument capture** — the syscall's arguments (paths, file descriptors, flags, etc.) are decoded and stored. This requires creating a handler file in `syscalls/` (or adding to an existing one).

Most syscalls only need level 1. Level 2 is for syscalls where the arguments matter (file paths, network addresses, buffer contents).

---

## Level 1: Basic Tracking (category + counting only)

**What you get:** The syscall appears in traces with its name, PID, timestamp, return value, and errno. It's assigned to a category with the correct color in all tools (Python analysis, web timeline, import).

**What you edit:** One file.

### Step 1: Add to `syscalls.json`

Find the appropriate category and add the syscall name to its `syscalls` array:

```json
{
  "id": "file",
  "label": "File",
  "description": "File system operations ...",
  "color": "#276419",
  "textColor": "#ffffff",
  "syscalls": [
    "open",
    "close",
    "read",
    "renameat",       ← add it here
    "renameat_nocancel",
    ...
  ]
}
```

**Rules:**
- Use the exact kernel syscall name (lowercase, as shown by `dtrace -ln 'syscall:::entry'`)
- If the syscall has a `_nocancel` variant, add both
- Array order doesn't matter for functionality, but group related calls together for readability
- One syscall can only belong to one category

**That's it.** All tools read `syscalls.json` at runtime:
- `mactrace_categories.py` → Python analysis tools
- `server/import.js` → database importer
- `server/server.js` → web API

The generic DTrace probe (`syscall:::entry` / `syscall:::return`) already captures every syscall. Adding it to `syscalls.json` just tells the tools what category to assign.

### Step 2: Verify

```bash
# Check the JSON is valid and the syscall is recognized
python3 mactrace_categories.py --verify

# Check it maps correctly
python3 -c "from mactrace_categories import get_category; print(get_category('renameat'))"
# Should print: file

# Run the unit tests
make test-unit
```

### Step 3: Test with a real trace

```bash
# Trace a command that uses the syscall
sudo mactrace -o test.json -jp mv /tmp/test1 /tmp/test2

# Check it appears
python3 -c "
import json
with open('test.json') as f:
    data = json.load(f)
for e in data['events']:
    if 'renameat' in e['syscall']:
        print(f\"{e['syscall']} → {e['return_value']}\")
"
```

---

## Level 2: Rich Argument Capture

**What you get:** In addition to basic tracking, the syscall's arguments are decoded and stored as structured data (paths, flags, file descriptors, etc.).

**What you edit:** Two files — one handler in `syscalls/`, and `syscalls.json` for the category.

### Architecture Overview

The `syscalls/` directory contains a modular handler framework:

```
syscalls/
├── __init__.py        # SyscallHandler base class, @register decorator, auto-discovery
├── _constants.py      # Shared flag tables (AF_NAMES, O_FLAGS, PROT_FLAGS, etc.)
├── file_open.py       # open, openat (+ _nocancel)
├── file_rw.py         # read, write, pread, pwrite (+ _nocancel)
├── file_close.py      # close (+ _nocancel)
├── file_stat.py       # stat64, lstat64, fstat64, fstatat64, access, faccessat
├── file_dir.py        # chdir, fchdir, mkdir, rmdir, getdirentries64, getattrlistbulk
├── file_link.py       # unlink, rename, link, symlink, readlink
├── file_perm.py       # chmod, fchmod, truncate, ftruncate
├── file_fd.py         # dup, dup2, fcntl, ioctl, fsync
├── net_socket.py      # socket, socketpair, listen, shutdown, setsockopt, getsockopt
├── net_connect.py     # connect, bind, accept (with sockaddr)
├── net_io.py          # sendto, recvfrom, sendmsg, recvmsg
├── net_peer.py        # getpeername, getsockname
├── net_necp.py        # necp_open, necp_client_action, necp_session_*
├── process.py         # fork, execve, posix_spawn, exit, wait4
├── memory.py          # mmap, munmap, mprotect
├── signal.py          # kill, sigaction, sigprocmask
├── mac.py             # __mac_syscall, __mac_get/set_file/proc/fd/etc.
├── poll.py            # select, poll, kevent, kevent64, kqueue
└── info.py            # getpid, getuid, etc.
```

Each handler provides:
- **`syscalls`** — list of syscall names it covers
- **`dtrace`** — D-language probe text (entry + return)
- **`parse_args()`** — parse MACTRACE_SYSCALL argument tokens into a dict
- **`update_fd_info()`** (optional) — update fd tracking after this syscall

### Step 1: Add to `syscalls.json` (same as Level 1)

### Step 2: Create or extend a handler file

**Option A: Add to an existing handler** (when the new syscall is in the same family):

Open the appropriate handler file (e.g., `syscalls/file_link.py` for `renameat`) and:
1. Add the syscall name to the `syscalls` list
2. Add DTrace probes to the `dtrace` string
3. Add a parsing branch to `parse_args()`

**Option B: Create a new handler** (for a new syscall family):

Create a new file in `syscalls/` — it will be auto-discovered at import time.

Here's the full example for `renameat` added to `file_link.py`:

```python
"""File link/rename syscalls."""

from . import SyscallHandler, register


@register
class FileLinkHandler(SyscallHandler):
    syscalls = [
        "unlink", "rename", "link", "symlink", "readlink",
        "renameat",          # ← add here
    ]

    dtrace = r'''
/* existing probes ... */

/* renameat - rename file relative to directory fd */
syscall::renameat:entry
/TRACED/
{
    self->renameat_fromfd = arg0;
    self->renameat_from = copyinstr(arg1);
    self->renameat_tofd = arg2;
    self->renameat_to = copyinstr(arg3);
    self->renameat_ts = walltimestamp/1000;
}

syscall::renameat:return
/TRACED && self->renameat_from != NULL/
{
    printf("MACTRACE_SYSCALL %d %d renameat %d %d %d %d \"%s\" %d \"%s\"\n",
        pid, tid, (int)arg1, errno, self->renameat_ts,
        self->renameat_fromfd, self->renameat_from,
        self->renameat_tofd, self->renameat_to);
    self->renameat_from = NULL;
}
'''

    def parse_args(self, syscall, args):
        result = {}
        if syscall == "renameat":
            if len(args) >= 1:
                result["fromfd"] = self.parse_int(args[0])
            if len(args) >= 2:
                result["oldpath"] = self.clean_str(args[1])
            if len(args) >= 3:
                result["tofd"] = self.parse_int(args[2])
            if len(args) >= 4:
                result["newpath"] = self.clean_str(args[3])
        # ... existing branches for rename, unlink, etc.
        return result
```

**Key patterns:**

DTrace probes:
- Use `TRACED` predicate (not `tracked[pid]` — the header defines `TRACED`)
- Use `self->` for thread-local storage between entry and return
- Always null-check in return probe and clean up `self->` variables
- The output format is: `MACTRACE_SYSCALL <pid> <tid> <name> <retval> <errno> <timestamp> [args...]`
- String arguments use `copyinstr()` and are quoted in output

Python parser:
- Use `self.clean_str()` to strip quotes from string arguments
- Use `self.parse_int()` for integers (handles 0x hex gracefully)
- Handle missing fields gracefully (DTrace output can be truncated)
- Return a dict of named arguments

### Step 3: (Optional) Add fd tracking

If the syscall creates, modifies, or closes file descriptors, override `update_fd_info()`:

```python
    def update_fd_info(self, event, fd_tracker):
        """Track fd state changes.

        fd_tracker methods:
          set_file(pid, fd, path)    — record fd as a file
          set_socket(pid, fd, desc)  — record fd as a socket
          mark_socket(pid, fd)       — mark fd as socket (no desc change)
          remove(pid, fd)            — remove fd tracking on close
        """
        if event.return_value >= 0 and "path" in event.args:
            fd_tracker.set_file(event.pid, event.return_value, event.args["path"])
```

### Step 4: Test

```bash
# Run the full test suite (204 tests)
python3 -m pytest tests/ -v --tb=short

# Quick import check
python3 -c "
from syscalls import HANDLER_REGISTRY, TRACED_SYSCALLS
print('renameat' in HANDLER_REGISTRY)  # True
print('renameat' in TRACED_SYSCALLS)   # True
print(HANDLER_REGISTRY['renameat'].parse_args('renameat', ['3', '\"old\"', '4', '\"new\"']))
"

# Test with a real trace
sudo mactrace -o rename_test.json -jp python3 -c "import os; os.rename('/tmp/mt_a', '/tmp/mt_b')"
```

### Step 5: Write a unit test

Add a test in `tests/unit/test_parse_dtrace.py`:

```python
def test_renameat_line(self, tracer):
    """Parse a renameat syscall with from/to paths."""
    line = 'MACTRACE_SYSCALL 100 100 renameat 0 0 1000000 3 "/tmp/old" 4 "/tmp/new"'
    tracer._parse_line(line, 0)
    assert len(tracer.events) == 1
    evt = tracer.events[0]
    assert evt.syscall == 'renameat'
    assert evt.args['oldpath'] == '/tmp/old'
    assert evt.args['newpath'] == '/tmp/new'
    assert evt.args['fromfd'] == 3
    assert evt.args['tofd'] == 4
```

---

## Shared Constants

If your handler needs flag tables (e.g., socket families, open flags), import from `_constants.py`:

```python
from ._constants import AF_NAMES, parse_open_flags, parse_prot_flags
```

Available constants and helpers:
- `ERRNO_NAMES` — errno number → name
- `AF_NAMES` — address family number → name
- `SOCK_NAMES` — socket type number → name
- `SHUT_NAMES` — shutdown how → name
- `SIGNAL_NAMES` — signal number → name
- `FCNTL_NAMES` — fcntl cmd → name
- `SOL_NAMES`, `SO_NAMES` — socket option level/name → string
- `PROT_FLAGS`, `MAP_FLAGS` — mmap protection/mapping flag bits
- `parse_open_flags(flags)` → human-readable string
- `parse_prot_flags(prot)` → human-readable string
- `parse_mmap_flags(flags)` → human-readable string
- `parse_sockopt_level(level)` → string
- `parse_sockopt_name(level, optname)` → string
- `signal_name(sig)` → string

To add a new constant table, add it to `_constants.py` and it's immediately available to all handlers.

---

## Checklist

### Level 1 (basic tracking)
- [ ] Added syscall name to the right category in `syscalls.json`
- [ ] Added `_nocancel` variant if it exists
- [ ] `python3 mactrace_categories.py --verify` passes
- [ ] `python3 -m pytest tests/ -v --tb=short` passes

### Level 2 (rich arguments)
- [ ] Everything from Level 1
- [ ] Added/extended handler in `syscalls/` with DTrace probes + parse_args
- [ ] Handler auto-discovered (check: `python3 -c "from syscalls import HANDLER_REGISTRY; print('newsyscall' in HANDLER_REGISTRY)"`)
- [ ] Added `update_fd_info()` if syscall affects file descriptors
- [ ] Added unit test in `tests/unit/test_parse_dtrace.py`
- [ ] Tested with a real trace (`sudo mactrace ...`)
- [ ] All 204+ tests still pass

---

## Finding syscall names

```bash
# List all available syscalls on this system
sudo dtrace -ln 'syscall:::entry' | awk '{print $NF}' | sort -u

# Check if a specific syscall exists
sudo dtrace -ln 'syscall::renameat:entry'

# See which syscalls mactrace doesn't track yet
sudo mactrace -e -o /dev/null echo hello
# The -e flag reports untraced syscalls at the end
```

## Reference

- **`syscalls.json`** — Single source of truth for syscall→category mappings. All tools read this.
- **`syscalls/`** — Handler package with DTrace probes and Python parsers.
- **`syscalls/__init__.py`** — Framework: `SyscallHandler`, `@register`, `HANDLER_REGISTRY`, `ALL_DTRACE_PROBES`, `TRACED_SYSCALLS`.
- **`syscalls/_constants.py`** — Shared flag/enum tables and parsing helpers.
- **`mactrace`** — Main tracer. DTrace header + handler probes assembled at import time. Parser dispatches to handlers.
- **`mactrace_categories.py`** — Loads `syscalls.json`, provides `get_category()`, `get_color()`, etc.
- **`tests/unit/test_parse_dtrace.py`** — Unit tests for line parsing.
- **`tests/unit/test_categories.py`** — Tests for `syscalls.json` integrity and category lookups.
