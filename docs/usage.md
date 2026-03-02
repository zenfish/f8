# Usage Guide

> For a guided walkthrough, see [TUTORIAL.md](../TUTORIAL.md).
> For environment variables and config, see [ENVIRONMENT.md](../ENVIRONMENT.md).

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
sudo mactrace -o make ./configure      # → make.1740000000.json (auto epoch)
sudo mactrace -o make ./configure      # → make.1740000001.json (no collision)
sudo mactrace -o make.json ./configure # → make.json (explicit .json = exact name)
```

If you specify `.json` explicitly, the filename is used as-is — no epoch, no rewriting.
Otherwise the epoch and `.json` are appended automatically.

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

