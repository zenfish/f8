# mactrace

An strace-like system call tracer for macOS using DTrace. Traces every syscall for a command and all its child processes, producing structured JSON for analysis and an interactive web-based timeline viewer.

![Trace list](docs/screenshot-traces.png)
*Trace list — each imported trace shows the command, event count, duration, and exit code.*

![Timeline view](docs/screenshot-timeline.png)
*Timeline detail — color-coded syscalls with category filtering, I/O tracking, and process tree.*

## Installation

### Prerequisites

- macOS (tested on 15.3 Sequoia)
- Python 3.8+
- Node.js 18+ (for the web server)
- Root privileges (DTrace requires sudo)
- SIP dtrace restrictions disabled (see [Troubleshooting](#troubleshooting))

### Setup

```bash
# Clone or copy to your preferred location
cd ~/src
git clone <repo-url> mactrace
cd mactrace

# Run the installer (installs deps, creates config, sets up PATH)
./install.sh
```

The installer does three things:
1. **`npm install`** in `server/` — installs better-sqlite3 for the web server
2. **Creates `~/.mactrace/config`** — sets `MACTRACE_OUTPUT=~/traces` so traces have a consistent home. All tools read this config automatically, even through `sudo` (uses `SUDO_USER` to find your home directory). See [ENVIRONMENT.md](ENVIRONMENT.md) for full config syntax.
3. **Adds tools to PATH** — symlinks to `/usr/local/bin`, or prints the `export PATH=...` line if that's not writable

### Manual Setup (if you prefer)

```bash
cd server && npm install && cd ..                      # Node.js deps
mkdir -p ~/.mactrace ~/traces                          # Directories
echo 'MACTRACE_OUTPUT=~/traces' > ~/.mactrace/config   # Config
export PATH="$PWD:$PATH"                               # PATH
```

### Verify Installation

```bash
# Should print usage info
sudo mactrace --help

# Quick test — trace the 'echo' command
sudo mactrace -o test.json -jp echo hello
```

## Quick Start

### 1. Trace a command

```bash
sudo mactrace -o trace.json -jp ls -la /tmp
```

This runs `ls -la /tmp` under DTrace, captures every syscall (open, read, write, stat, etc.), and writes structured JSON to `trace.json`. The `-j` flag enables JSON output, `-p` pretty-prints it.

### 2. Analyze the trace (text summary)

```bash
./mactrace_analyze trace.json
```

Sample output:
```
=== mactrace Analysis ===
Command: ls -la /tmp
Duration: 12.3ms
Total syscalls: 87
PIDs traced: 1

--- Category Breakdown ---
  file      : 52  (59.8%)
  memory    : 18  (20.7%)
  process   :  9  (10.3%)
  other     :  8  ( 9.2%)

--- Top Syscalls ---
  stat64          : 15
  open            : 12
  read            :  9
  close           :  8
  mmap            :  7

--- Files Accessed ---
  /tmp                          R
  /usr/lib/dyld                 R
  /dev/dtracehelper             RS

--- Errors ---
  stat64("/tmp/.X11-unix")      ENOENT (2)
```

### 3. View in the web timeline

```bash
# Import into the database
mactrace_import trace.json

# Start the server
mactrace_server
# → http://localhost:3000
```

Select a trace from the dropdown to see the interactive timeline with:
- Color-coded syscall categories (file, network, process, memory, IPC, signal)
- Click-to-expand I/O hexdump viewer
- Category filter buttons and text search
- Process tree visualization
- Per-syscall timing and return values

### 4. Trace everything a program does

```bash
# Capture I/O data (read/write buffer contents)
sudo mactrace --capture-io -o trace.json ./my_program

# Attach to a running process
sudo mactrace -p 12345 -o trace.json -t 30

# Trace with larger buffers for busy programs
sudo mactrace --capture-io --strsize 65536 -o trace.json ./my_program
```

## Requirements

- macOS (tested on 15.3 Sequoia)
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

## Output Naming

Output filenames automatically include a Unix epoch timestamp to prevent collisions:

```bash
sudo mactrace -o make ./configure      # → make.1740000000.json
sudo mactrace -o make.json ./configure # → make.1740000000.json
sudo mactrace -o make ./configure      # → make.1740000001.json (no collision)
```

The import and `mactrace_data` tools strip the epoch suffix for display:
`make.1740000000.json` shows as **make** in listings and the web UI.

## Path Resolution

All mactrace tools use consistent path resolution:

- **Absolute paths** (`/path/to/file`) → used as-is
- **Explicit relative** (`./file`, `../file`) → used as-is
- **Simple filename** (`make`) → prefixed with `$MACTRACE_OUTPUT`, epoch appended

```bash
# With MACTRACE_OUTPUT="$HOME/traces":
sudo mactrace -o make ./configure     # Writes to ~/traces/make.1740000000.json
sudo mactrace -o ./make ./configure   # Writes to ./make.1740000000.json (explicit)

# Import and mactrace_data handle timestamped names transparently:
mactrace_import make.1740000000.json  # Reads from ~/traces/make.1740000000.json
mactrace_data list                    # Shows as "make"
```

See [ENVIRONMENT.md](ENVIRONMENT.md) for full details.

## Usage

```bash
# Basic usage - outputs JSON to stdout
sudo ./mactrace ls -la

# Write to file with pretty printing
sudo ./mactrace -o trace.json -jp ls -la

# Attach to a running process by PID (like strace -p)
sudo ./mactrace -p 12345
sudo ./mactrace -p 12345 -o trace.json -t 30   # with output file and 30s timeout

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
./mactrace_analyze trace.json
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

## Tools Overview

| Tool | Purpose |
|------|---------|
| `mactrace` | Core tracer — runs a command under DTrace, captures all syscalls to JSON |
| `mactrace_analyze` | Text-based analysis — category breakdown, top syscalls, files, errors, I/O extraction |
| `mactrace_timeline` | Generates a standalone HTML timeline (no server needed) |
| `mactrace_import` | Imports JSON traces into SQLite for the web server |
| `mactrace_server` | Starts the web-based timeline viewer |
| `mactrace_db` | Database management — list, info, delete, vacuum, stats |
| `mactrace_run_all.sh` | Batch tracer — runs a command with all analysis tools in one shot |

## Analysis Tools (Detail)

### mactrace_analyze

Analyze trace output to get a human-readable summary:

```bash
# Basic analysis
./mactrace_analyze trace.json

# Filter by category
./mactrace_analyze trace.json --category file
./mactrace_analyze trace.json --category network

# Show only errors
./mactrace_analyze trace.json --errors-only

# Hide startup/library files
./mactrace_analyze trace.json --hide-startup

# Output JSON for further processing
./mactrace_analyze trace.json --json

# Extract I/O data to files (requires --capture-io during trace)
./mactrace_analyze trace.json --save-io ./io_output
./mactrace_analyze trace.json --save-io ./io_output --hexdump --render-terminal
```

Output includes:
- Syscall category breakdown (file/network/process/memory/signal)
- Top syscalls by frequency
- Files accessed with R/W/S flags
- Network connections
- Process tree
- Error summary
- I/O data extraction (with `--save-io`)

### mactrace_timeline

Generate an interactive HTML timeline:

```bash
./mactrace_timeline trace.json -o timeline.html
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
mactrace_import trace.json --db mactrace.db

# Start the web server
mactrace_server --db mactrace.db
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
mactrace_db list              # List all imported traces
mactrace_db info <id>         # Show details for a trace
mactrace_db delete <id>       # Delete a trace
mactrace_db vacuum            # Compact the database
mactrace_db stats             # Show database statistics
```

## Troubleshooting

### "dtrace: system integrity protection is on, some features will not be available"

DTrace on modern macOS is restricted by SIP. To get full tracing:

1. Reboot into Recovery Mode (hold Cmd+R on Intel, power button on Apple Silicon)
2. Open Terminal from Utilities menu
3. Run: `csrutil enable --without dtrace`
4. Reboot

**Note:** This only disables SIP's dtrace restrictions, not SIP itself. To re-enable: `csrutil enable` from Recovery Mode.

### "dtrace: failed to initialize dtrace: DTrace requires additional privileges"

DTrace requires root. Always run mactrace with `sudo`:
```bash
sudo mactrace -o trace.json ./my_program
```

### Drops: "dtrace: N dynamic variable drops" or missing events

DTrace has fixed-size buffers. If your traced program is very busy, increase buffer sizes:
```bash
sudo mactrace --bufsize 512m --dynvarsize 512m -o trace.json ./my_program
```

For I/O capture, also increase string/data sizes:
```bash
sudo mactrace --capture-io --strsize 65536 --io-size 65536 -o trace.json ./my_program
```

### Server won't start / "Cannot find module 'better-sqlite3'"

Install Node.js dependencies:
```bash
cd server && npm install
```

### Empty or missing trace output

- Check that the traced program actually ran (look for exit code in the JSON)
- Try `-v` (verbose) to see DTrace activity on stderr
- Use `-e` to detect untraced syscalls that mactrace doesn't cover yet
- Some programs behave differently under sudo — use `-u yourname` to run as yourself

### Import shows "0 events imported"

The JSON file might be empty or malformed. Check it:
```bash
python3 -c "import json; d=json.load(open('trace.json')); print(f'{len(d.get(\"events\",[]))} events')"
```

## Adding Syscalls

See **[ADDING_SYSCALLS.md](ADDING_SYSCALLS.md)** for a step-by-step guide to adding new system calls. There are two levels:

- **Level 1 (basic):** Add one line to `syscalls.json` — the syscall gets counted, categorized, and colored in all tools. Takes 30 seconds.
- **Level 2 (rich):** Add DTrace probes + a Python parser to capture and decode arguments (paths, fds, flags). Takes 15-30 minutes.

## Future Improvements

- [ ] Socket address decoding (IP/port extraction)
- [ ] More granular timestamps per syscall
- [ ] Output filtering options (file-only, network-only, etc.)
- [x] Timeline visualization tool (mactrace_timeline)
- [x] Data content capture for read/write (`--capture-io`)
- [x] Web-based timeline server with hexdump viewer

## Testing

mactrace has a comprehensive test suite covering unit tests, integration tests, cross-language consistency checks, and end-to-end tracing.

### Quick Start

```bash
make test          # Run all tests (no root needed)
make test-unit     # Unit tests only (~0.3s)
make test-cov      # With coverage report
make test-e2e      # E2E tests (requires sudo)
make verify        # Quick category validation
```

### Test Structure

```
tests/
├── conftest.py                    # Shared fixtures (traces, temp dirs, configs)
├── unit/
│   ├── test_categories.py         # syscalls.json integrity, lookups, colors (35 tests)
│   ├── test_lib.py                # mactrace_lib shared utilities (76 tests)
│   ├── test_parse_dtrace.py       # DTrace output parsing, all event types (24 tests)
│   └── test_parse_malformed.py    # Bad input: truncated, garbled, drops (29 tests)
├── consistency/
│   └── test_cross_language.py     # Python ↔ JS category/color parity (8 tests)
├── integration/
│   ├── test_import_roundtrip.py   # JSON → import.js → SQLite → verify (16 tests)
│   └── test_server_api.py         # Server API endpoints (16 tests)
├── e2e/
│   └── test_tracing.py            # Real DTrace runs against C programs (16 tests, needs sudo)
└── fixtures/
    ├── traces/                    # Golden JSON trace files
    ├── configs/                   # Test config files
    └── dtrace_output/             # Raw DTrace output samples
```

### What's Tested

- **Unit (164 tests):** Format functions, path resolution, hex dump rendering, terminal escape processing, file classification, config parsing, syscall category lookups, JSON schema integrity, DTrace line parsing for all `MACTRACE_*` event types, malformed/truncated input handling, DTrace drop/warning messages
- **Consistency (8 tests):** Python `mactrace_categories.py` and JS `import.js`/`server.js` produce identical category mappings, colors, and text colors from the shared `syscalls.json`
- **Integration (32 tests):** Import roundtrip (JSON → SQLite → query), server API endpoints (traces, events, process-tree, categories), pagination, filtering, search, error handling
- **E2E (16 tests):** Deterministic C programs traced with real DTrace. Tests file ops, fork/exec, and network syscalls. Requires `sudo` and SIP dtrace restrictions disabled.

### Dependencies

```bash
pip install pytest pytest-cov       # Python test runner
cd server && npm install             # better-sqlite3 for integration/consistency tests
```

### Coverage

```bash
make test-cov
# Current: mactrace_categories.py 56%, mactrace_lib.py 68%
# (Unit tests only; integration tests not instrumented for Python coverage)
```

## License

MIT

## Vectored I/O Capture (`--iovec`)

### What This Is

Some programs don't write data in one shot — they scatter it across multiple buffers and
write them all at once. An HTTP server might write the headers from one buffer and the body
from another in a single `writev()` call. Databases do this constantly.

Without `--iovec`, mactrace traces these calls but only captures metadata (fd, byte count,
number of buffers). With `--iovec`, it captures the **actual contents** of each buffer.

### How Many Buffers?

`--iovec N` tells mactrace how many scattered buffers to capture per call. The question is:
what should N be?

Here's what real software actually does:

| What you're tracing | Typical buffers per call | Suggested N |
|---------------------|-------------------------:|------------:|
| HTTP servers (nginx, Apache) | 2–4 | 4 |
| Databases (PostgreSQL, MySQL) | 2–8 | 8 |
| Logging frameworks | 2–3 | 4 |
| Network protocol stacks | 2–6 | 8 |
| `printf`/stdio | 1–3 | 4 |

**If you're not sure, use `--iovec 4`.** That covers the vast majority of real-world code.
If you see truncated captures in the output (the syscall metadata says 6 buffers but you only
got 4), bump it up. The kernel limit is 1024, but virtually nothing uses more than 8.

### Usage

```bash
# Capture scattered buffers (up to 4 per call)
sudo mactrace --iovec 4 -o trace.json ./my_server

# More headroom for database workloads
sudo mactrace --iovec 8 --trace=file -o trace.json ./my_database

# Only capture writev buffers (not readv/preadv/pwritev) — lightest option
sudo mactrace --iovec 8 --iovec-syscalls=writev -o trace.json ./my_program
```

`--iovec` implies `-c` (IO capture). You don't need to specify both.

### Output Format

Each buffer is emitted as a separate event with its position in the scatter list:

```
MACTRACE_IOV <pid> <tid> <syscall> <fd> <index>/<total> <bytes> <hex_data>
```

So a `writev` with 3 buffers produces 3 `MACTRACE_IOV` lines (`0/3`, `1/3`, `2/3`),
letting the parser reconstruct the full write in order.

### The Cost: DIF Budget

Here's where the trade-off lives. DTrace compiles each probe clause into a DIF program,
and there's a hard ceiling (~250 at default settings, scales with `-d`).

Capturing scattered buffers requires **unrolling** — DTrace has no loops, so each buffer
slot is a separate compiled clause. The cost formula:

```
DIF cost = (number of syscall variants) × N × 4 programs per slot
```

mactrace has 6 vectored I/O syscall variants under the hood (readv, writev, preadv, pwritev,
plus _nocancel versions of readv and writev). Using `--iovec-syscalls` reduces the variant count.

| --iovec N | All variants (6) | writev only (2) | writev+readv (4) |
|-----------|------------------:|-----------------:|------------------:|
| 2 | 48 | 16 | 32 |
| 4 | 96 | 32 | 64 |
| 8 | 192 | 64 | 128 |
| 16 | 384 | 128 | 256 |

For context, current mactrace usage:

| Configuration | DIF programs | % of budget |
|---------------|------------:|------------:|
| `--trace=file` | 136 | 54% |
| `--trace=all` | 234 | 93% |

So `--iovec 4` with `--trace=file` adds 96 → total 232 (93%). Fits.
But `--iovec 8` with `--trace=all` adds 192 → total 426 (170%). Doesn't fit.

**When you exceed the budget**, mactrace will tell you and suggest fixes:
- Narrow your trace: `--trace=file` instead of `--trace=all`
- Restrict iovec syscalls: `--iovec-syscalls=writev`
- Raise the ceiling: `-d 524288` (doubles the budget to ~500)
- Lower N: `--iovec 4` instead of `--iovec 8`

### `--iovec-syscalls` (power user)

By default, `--iovec` captures buffers for all vectored I/O syscalls. If you know you only
care about writes (or only reads), you can restrict it:

```bash
# Only writev (2 variants instead of 6 — 3× cheaper)
--iovec-syscalls=writev

# writev + readv (4 variants)
--iovec-syscalls=writev,readv

# Just pwritev (1 variant — cheapest possible)
--iovec-syscalls=pwritev
```

Valid values: `readv`, `writev`, `preadv`, `pwritev`. The `_nocancel` variants are
included automatically when you name the base syscall.
