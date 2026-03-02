# mactrace

An strace-like system call tracer for macOS using DTrace. Traces every syscall for a command and all its child processes, producing structured JSON for analysis and an interactive web-based timeline viewer.

![Trace list](docs/screenshot-traces.png)
*Trace list — each imported trace shows the command, event count, duration, and exit code.*

![Timeline view](docs/screenshot-timeline.png)
*Timeline detail — color-coded syscalls with category filtering, I/O tracking, and process tree.*

> **⚠️ Requires SIP DTrace restrictions to be disabled.** Check with `csrutil status`. See [Troubleshooting](#troubleshooting) if you need to change this.

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


### Try Without Tracing

Want to see the web UI before disabling SIP? Import the included example trace:

```bash
mactrace_import examples/echo-hello.json
mactrace_server
# → http://localhost:3000
```

## Quick Start

> **New to mactrace?** See [TUTORIAL.md](TUTORIAL.md) for a guided walkthrough using `mactrace_run_all.sh` and `mactrace_open`.
> **DNS analysis?** See [DNS.md](DNS.md) for how mactrace detects and classifies DNS resolution paths.

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


## Tools

| Tool | What it does |
|------|-------------|
| `mactrace` | Core tracer — runs a command under DTrace, captures syscalls to JSON |
| `mactrace_run_all.sh` | **One-shot pipeline:** trace → analyze → import → serve |
| `mactrace_server` | Start the web-based timeline viewer |
| `mactrace_open` | Trace macOS .app bundles (Steam, Safari, etc.) |
| `mactrace_analyze` | CLI text analysis — syscall breakdown, files, errors, I/O extraction |
| `mactrace_timeline` | Generate a standalone HTML timeline (no server needed) |
| `mactrace_data` | Manage traces — list, info, delete, vacuum, stats |
| `mactrace_import` | Import JSON traces into SQLite for the web server |

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

### Tracing macOS .app bundles (Steam, Safari, etc.)

Running `mactrace open /Applications/Steam.app` only traces the `open` command itself — not Steam. The `open` command is a thin launcher that asks macOS Launch Services to start the app, then exits. mactrace traces `open`, which finishes in a few seconds, while Steam continues running as a completely separate process.

**Use `mactrace_open` instead:**

```bash
# See what binary the app actually runs:
mactrace_open --list /Applications/Steam.app

# Trace it:
mactrace_open /Applications/Steam.app

# Full pipeline (trace + analyze + import + server):
mactrace_open --run-all /Applications/Steam.app

# Pass flags to the app:
mactrace_open /Applications/Steam.app -- --no-browser
```

`mactrace_open` reads the app's `Info.plist` to find the real executable (`CFBundleExecutable`), then runs mactrace against that binary directly.

**Note:** Some apps spawn additional helper processes after launch. mactrace traces the main process and its direct children, but helpers launched via XPC or Launch Services won't be captured.

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


## Documentation

| Document | Contents |
|----------|----------|
| [TUTORIAL.md](TUTORIAL.md) | Guided walkthrough with `mactrace_run_all.sh` |
| [docs/usage.md](docs/usage.md) | Full CLI usage, environment variables, path resolution |
| [docs/output-format.md](docs/output-format.md) | JSON output schema, process tracking, traced syscalls |
| [docs/io-capture.md](docs/io-capture.md) | I/O data capture, vectored I/O (`--iovec`), DIF budget |
| [docs/analysis.md](docs/analysis.md) | Analysis tools, timeline server, jq recipes |
| [docs/testing.md](docs/testing.md) | Test suite structure, running tests, coverage |
| [ENVIRONMENT.md](ENVIRONMENT.md) | Config file syntax, `~`/`$VAR` expansion, `SUDO_USER` handling |
| [ADDING_SYSCALLS.md](ADDING_SYSCALLS.md) | Step-by-step guide to adding new syscall handlers |
| [COVERAGE.md](COVERAGE.md) | Syscall coverage breakdown by category and macOS version |
| [DNS.md](DNS.md) | How mactrace detects and classifies DNS resolution paths |

## License

MIT
