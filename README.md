# mactrace

An strace-like utility for macOS using DTrace. Traces system calls for a command and all its children, outputting structured JSON suitable for timeline analysis.

## Requirements

- macOS (tested on 15.7.3 Sequoia)
- SIP disabled (or at least dtrace restrictions disabled) for full tracing
- Python 3.8+
- Root privileges (DTrace requires sudo)

## Environment Variables

Set these to run mactrace from anywhere:

| Variable | Default | Description |
|----------|---------|-------------|
| `MACTRACE_HOME` | `$HOME/.mactrace` | Base directory for all mactrace data |
| `MACTRACE_DB` | `$MACTRACE_HOME/mactrace.db` | SQLite database for timeline server |
| `MACTRACE_OUTPUT` | `.` (cwd) | Where to save/read JSON trace files |
| `MACTRACE_PORT` | `3000` | Default port for timeline server |
| `MACTRACE_USER` | (none) | Default user to run traced programs as |

Add to your shell config:

```bash
# Add to PATH
export PATH="$HOME/phd/src/mactrace:$PATH"

# Create config file (works without sudo -E)
mkdir -p ~/.mactrace ~/traces
cat > ~/.mactrace/config << 'EOF'
MACTRACE_HOME=~/.mactrace
MACTRACE_OUTPUT=~/traces
MACTRACE_DB=$MACTRACE_HOME/mactrace.db
EOF
```

Now you can run from anywhere and outputs go to `~/traces/`. Traced programs automatically run as the sudo caller (not root).

The config file is read using `SUDO_USER`, so it works even though sudo resets environment variables. See [ENVIRONMENT.md](ENVIRONMENT.md) for full config file syntax (supports `~`, `$VAR` expansion, comments).

## Path Resolution

All mactrace tools use consistent path resolution:

- **Absolute paths** (`/path/to/file`) → used as-is
- **Explicit relative** (`./file`, `../file`) → used as-is
- **Simple filename** (`file.json`) → prefixed with appropriate env var

```bash
# With MACTRACE_OUTPUT="$HOME/traces":
sudo mactrace -o myapp.json ./myapp   # Writes to ~/traces/myapp.json
sudo mactrace -o ./myapp.json ./myapp # Writes to ./myapp.json (explicit)

# With MACTRACE_OUTPUT set, import finds the file:
mactrace-import myapp.json            # Reads from ~/traces/myapp.json
```

See [ENVIRONMENT.md](ENVIRONMENT.md) for full details.

## Usage

```bash
# Basic usage - outputs JSON to stdout
sudo ./mactrace ls -la

# Write to file with pretty printing
sudo ./mactrace -o trace.json -p ls -la

# Run traced program as a specific user (not root)
sudo ./mactrace -u zen -o trace.json ./myapp
sudo ./mactrace -u 501 -o trace.json ./myapp  # By UID

# With timeout (seconds)
sudo ./mactrace -t 10 ./long_running_command

# Verbose mode (shows DTrace activity on stderr)
sudo ./mactrace -v -o trace.json ./my_program

# Show untraced syscalls (detect gaps in coverage)
sudo ./mactrace -e -o trace.json ./my_program

# Capture I/O data (read/write buffer contents)
sudo ./mactrace --capture-io -o trace.json ./my_program

# Adjust buffer sizes for heavy tracing
sudo ./mactrace --capture-io --strsize 65536 --io-size 65536 -o trace.json ./my_program
```

### Running as a Non-Root User

**By default, mactrace automatically detects who ran sudo and runs the traced program as that user.** This avoids common issues:
- Files created by the traced program are owned by you, not root
- The program behaves the same as when run normally
- Programs that refuse to run as root work correctly

```bash
# Automatic: if you're 'zen' running sudo, the traced program runs as 'zen'
sudo ./mactrace -o trace.json ./myapp

# Explicit user (overrides auto-detection)
sudo ./mactrace -u testuser -o trace.json ./myapp

# Run as root explicitly
sudo ./mactrace -u root -o trace.json ./myapp
```

User selection priority:
1. `-u`/`--user` flag
2. `MACTRACE_USER` env var
3. `SUDO_USER` (auto-detected)
4. root (fallback)

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

## I/O Metadata Tracking

The `--capture-io` flag emits `MACTRACE_IO` events for read/write/send/recv syscalls:

```bash
sudo ./mactrace --capture-io -o trace.json /bin/cat /etc/passwd
```

### What It Captures

**Metadata only** - syscall name, fd, and byte count:
```
MACTRACE_IO 12345 12345 read 3 1024
MACTRACE_IO 12345 12345 write 1 512
```

**Note:** DTrace cannot practically capture actual buffer contents for variable-length I/O. 
For full buffer capture, use `strace` on Linux or reconstruct from file/network captures.

### DTrace Buffer Options

| Flag | Default | Description |
|------|---------|-------------|
| `--capture-io` / `-d` | off | Emit MACTRACE_IO events |
| `--strsize` | 16384 | DTrace strsize - max string size |
| `--bufsize` | 256m | DTrace bufsize - trace buffer size |
| `--dynvarsize` | 128m | DTrace dynvarsize - dynamic variable space |

### Analyzer I/O Support

The analyzer tracks I/O bytes from syscall return values (not buffer contents):

```bash
# Show network activity with byte counts (from read/write on socket fds)
./mactrace-analyze trace.json
# Output: fd=6 AF_INET/SOCK_STREAM [connected] (sent 1.9 KB, recv 1.8 MB)
```

## Detecting Untraced Syscalls

Use `-e`/`--untraced` to identify syscalls your traced process makes that aren't explicitly captured:

```bash
sudo ./mactrace -e -o trace.json /bin/ls
# Output includes:
# --- Untraced syscalls ---
#   getattrlistbulk: 2
#   fstatat64: 1
```

This helps identify gaps in coverage. Untraced syscalls are still *counted* (via a catch-all DTrace probe), just not decoded with detailed arguments.

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

## Analysis Tools

### mactrace-analyze

Analyze trace output to get a human-readable summary:

```bash
# Basic analysis
./mactrace-analyze trace.json

# Filter by category
./mactrace-analyze trace.json --category file
./mactrace-analyze trace.json --category network

# Show only errors
./mactrace-analyze trace.json --errors-only

# Hide startup/library files
./mactrace-analyze trace.json --hide-startup

# Output JSON for further processing
./mactrace-analyze trace.json --json

# Extract I/O data to files (requires --capture-io during trace)
./mactrace-analyze trace.json --save-io ./io_output
./mactrace-analyze trace.json --save-io ./io_output --hexdump --render-terminal
```

Output includes:
- Syscall category breakdown (file/network/process/memory/signal)
- Top syscalls by frequency
- Files accessed with R/W/S flags
- Network connections
- Process tree
- Error summary
- I/O data extraction (with `--save-io`)

### mactrace-timeline

Generate an interactive HTML timeline:

```bash
./mactrace-timeline trace.json -o timeline.html
```

Features:
- Sortable/searchable DataTables interface
- Color-coded syscall categories
- Filter buttons (All/File/Network/Process/Memory/Errors)
- fd→path tracking for file operations
- Error highlighting

## Timeline Server

The `server/` directory contains a web-based timeline viewer:

```bash
# Import trace into SQLite database
mactrace-import trace.json --db mactrace.db

# Start the web server
mactrace-server --db mactrace.db
# Opens at http://localhost:3000
```

Set `MACTRACE_DB` and `MACTRACE_PORT` environment variables to avoid repeating flags.

### Import Options

| Flag | Default | Description |
|------|---------|-------------|
| `--db <path>` | `mactrace.db` | SQLite database file |
| `--io-dir <path>` | `<trace_name>/` | Directory for I/O binary files |

The importer automatically:
- Creates `.bin` files from captured I/O data (`args.data` in JSON)
- Creates `.meta.json` files with chunk offset information
- Generates hexdump files on-the-fly via the server

### Server Options

| Flag | Default | Description |
|------|---------|-------------|
| `--db <path>` | `$MACTRACE_DB` or `mactrace.db` | SQLite database file |
| `--port <port>` | `$MACTRACE_PORT` or `3000` | Server port |

### Web UI Features

- **Timeline view**: Sortable event list with category filtering
- **Hexdump viewer**: Click `[+]` on I/O events to view captured data
- **Search**: Filter events by syscall, target, or details
- **Process filtering**: View events for specific PIDs

### Database Management

```bash
mactrace-db list              # List all imported traces
mactrace-db info <id>         # Show details for a trace
mactrace-db delete <id>       # Delete a trace
mactrace-db vacuum            # Compact the database
mactrace-db stats             # Show database statistics
```

### FTS5 Note

The import may show:
```
Note: FTS5 not available, search will use LIKE
```

This is informational. **FTS5** (Full-Text Search 5) is a SQLite extension for fast text search. The server uses **sql.js** (WebAssembly SQLite), which doesn't include FTS5 by default.

**Impact:** Search still works via `LIKE '%term%'` queries. For ~100K events this is fine. For millions of events, search would be slower.

**If you need FTS5:** Use native SQLite with FTS5 compiled in, or a sql.js build with FTS5 enabled (larger WASM file).

## Future Improvements

- [ ] Socket address decoding (IP/port extraction)
- [ ] More granular timestamps per syscall
- [ ] Output filtering options (file-only, network-only, etc.)
- [x] Timeline visualization tool (mactrace-timeline)
- [x] Data content capture for read/write (`--capture-io`)
- [x] Web-based timeline server with hexdump viewer

## License

MIT
