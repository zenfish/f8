# f8 Tutorial

A quick walkthrough using `f8_run_all.sh` — the one-command pipeline that traces, analyzes, imports, and launches the web viewer.

## Prerequisites

1. Run `make install` (one-time setup — installs deps, creates config, sets PATH)
2. [Disable SIP's DTrace restrictions](README.md#troubleshooting) if you haven't already

## Your First Trace

```bash
f8_run_all.sh ls
```

That's it. This will:

1. **Trace** `ls` with full syscall capture + I/O data (`--capture-io`)
2. **Analyze** the trace — extract I/O files, generate hexdumps and terminal renders
3. **Import** into the SQLite database
4. **Launch** the web server at http://localhost:3000

You'll see output like:

```
starting f8 run, using "ls" as base to use in run.... going to be tracing:

    ls

kern.dtrace.difo_maxsize: 262144 → 393216 (auto-adjusted for 272 probes)
kern.dtrace.dof_maxsize: 524288 → 3407872 (auto-adjusted for 272 probes)
--- Trace summary ---
PID: 12345, Exit code: 0
Syscalls: 234, Processes: 1
Duration: 7338.8ms

... saving i/o

=== f8 Analysis ===
Command: ls
Duration: 7338.8ms
Total syscalls: 234
...
```

Open http://localhost:3000 in your browser to explore the timeline.

## Tracing Real Programs

```bash
# A web request (lots of network + file + TLS activity)
f8_run_all.sh curl -fsSL https://example.com

# A build (process spawning, file I/O, compiler invocations)
f8_run_all.sh make -j4

# A Python script
f8_run_all.sh python3 my_script.py

# Something with arguments that include flags
f8_run_all.sh wget -O /tmp/page.html example.com
```

### Tracing macOS Apps

To trace a `.app` bundle (like Steam, Safari, etc.), use `f8_open`:

```bash
# See what's inside the bundle:
f8_open --list /Applications/Steam.app

# Trace it (full pipeline):
f8_open --run-all /Applications/Steam.app
```

Why not just `f8_run_all.sh open /Applications/Steam.app`? Because `open` is a launcher — it asks macOS to start the app, then exits immediately. You'd only trace the `open` command itself (a few hundred syscalls over ~5 seconds), not Steam. `f8_open` finds the real binary inside the bundle and traces that directly.

### Custom Names

By default, the trace is named after the program (`curl`, `make`, etc.). Use `-n` for a custom name:

```bash
f8_run_all.sh -n bbc-fetch wget -O /tmp/bbc.html bbc.co.uk
```

Output: `bbc-fetch.json`, `bbc-fetch/` (I/O files), `bbc-fetch.txt` (analysis)

### Re-running a Trace

If a trace with the same name already exists:

```bash
# See what's there
f8_run_all.sh wget ...
# → "Output file already exists ... Use --force to auto-remove"

# Overwrite it
f8_run_all.sh --force wget ...
```

### Attaching to a Running Process

```bash
# Find the PID
ps aux | grep my_app

# Attach (Ctrl-C to stop)
f8_run_all.sh -p 12345
```

### Throttling Heavy Programs

For programs that generate massive I/O (npm install, large builds), use `--throttle` to reduce DTrace drops:

```bash
f8_run_all.sh --throttle npm install
```

This sets macOS background QoS on the traced process — slower execution, but far fewer dropped events.

## Using f8 Directly

`f8_run_all.sh` is a convenience wrapper. For more control, use `f8` directly:

```bash
# Basic trace (JSON to stdout)
sudo f8 ls

# Save to file, pretty JSON, show untraced syscalls
sudo f8 -o trace.json -jp -e ls

# Only trace file operations (faster, fewer probes)
sudo f8 --trace=file -o trace.json ls

# Only trace network activity
sudo f8 --trace=net -o trace.json curl example.com

# Capture I/O data (see actual bytes read/written)
sudo f8 --capture-io -o trace.json cat /etc/passwd

# Capture vectored I/O (readv/writev buffers)
sudo f8 --capture-io --iovec 4 -o trace.json ./my_server

# Multiple categories
sudo f8 --trace=file,net -o trace.json wget example.com

# Single syscall
sudo f8 --trace=open -o trace.json ls
```

### Category Reference

| Category | Alias | What it traces |
|----------|-------|----------------|
| `file` | `fs` | open, read, write, stat, link, chmod, directory ops |
| `network` | `net` | connect, send/recv, DNS, socket options, NECP |
| `process` | `exec` | fork, exec, exit, wait, getpid/uid, MAC policy |
| `memory` | — | mmap, mprotect, munmap |
| `poll` | — | select, poll, kqueue/kevent |
| `signal` | — | kill, sigaction, sigprocmask |
| `mac` | — | Sandbox, AMFI policy checks |
| `io` | — | Alias: file + network |
| `all` | — | Everything (default) |

### Post-Processing

```bash
# Text analysis with I/O extraction
f8_analyze trace.json --save-io trace_io/ --hexdump --render-terminal

# Import to database for web viewer
f8_import trace.json --io-dir trace_io/

# Start web server
f8_server
```

## What's in the Output

### JSON trace (`trace.json`)

Every syscall event with:
- Timestamp, PID, TID, syscall name, category
- Decoded arguments (file paths, flags, addresses, socket info)
- Return value and errno
- I/O data (hex-encoded, with `--capture-io`)

### I/O directory (`trace_io/`)

Extracted I/O data as separate files:
- `{pid}-{program}-read-fd{N}.bin` — raw bytes
- `*.hexdump` — hexdump -C format
- `*.rendered` — terminal output as the user would see it

### Text analysis (`trace.txt`)

Human-readable summary: syscall counts, file access patterns, network connections, errors, timing.

### Web timeline (http://localhost:3000)

Interactive visualization:
- Color-coded syscall categories
- Category filter buttons and text search
- Click-to-expand I/O hexdump viewer
- Process tree
- Per-syscall timing and return values

## Tips

- **Start narrow**: `--trace=file` or `--trace=net` is faster and less noisy than tracing everything
- **Use `--throttle`** for programs that do massive I/O — you'll lose fewer events
- **Check untraced**: `-e` shows syscalls f8 knows about but isn't tracing — useful for finding what you're missing
- **Name your traces**: `-n build-debug-march1` beats `make.json` when you have 50 traces
- **I/O capture is expensive**: `--capture-io` with the default 1MB buffer generates large DTrace output. Use `--io-size 64K` if you only need small reads/writes
