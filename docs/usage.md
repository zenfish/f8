# Usage Guide

> For a guided walkthrough, see [TUTORIAL.md](../TUTORIAL.md).
> For environment variables and config, see [ENVIRONMENT.md](../ENVIRONMENT.md).

## Environment Variables

Set these to run f8 from anywhere:

| Variable | Default | Description |
|----------|---------|-------------|
| `F8_HOME` | `$HOME/.f8` | Base directory for all f8 data |
| `F8_DB` | `$F8_HOME/f8.db` | SQLite database for timeline server |
| `F8_OUTPUT` | `.` (cwd) | Where to save/read JSON trace files |
| `F8_PORT` | `3000` | Default port for timeline server |
| `F8_USER` | (none) | Default user to run traced programs as |

Add to your shell config:

```bash
# Add to PATH
export PATH="$HOME/phd/src/f8:$PATH"

# Create config file (works without sudo -E)
mkdir -p ~/.f8 ~/traces
cat > ~/.f8/config << 'EOF'
F8_HOME=~/.f8
F8_OUTPUT=~/traces
F8_DB=$F8_HOME/f8.db
EOF
```

Now you can run from anywhere and outputs go to `~/traces/`. Traced programs automatically run as the sudo caller (not root).

The config file is read using `SUDO_USER`, so it works even though sudo resets environment variables. See [ENVIRONMENT.md](ENVIRONMENT.md) for full config file syntax (supports `~`, `$VAR` expansion, comments).

## Output Naming

Output filenames automatically include a Unix epoch timestamp to prevent collisions:

```bash
sudo f8 -o make ./configure      # → make.1740000000.json (auto epoch)
sudo f8 -o make ./configure      # → make.1740000001.json (no collision)
sudo f8 -o make.json ./configure # → make.json (explicit .json = exact name)
```

If you specify `.json` explicitly, the filename is used as-is — no epoch, no rewriting.
Otherwise the epoch and `.json` are appended automatically.

The import and `f8_data` tools strip the epoch suffix for display:
`make.1740000000.json` shows as **make** in listings and the web UI.

## Path Resolution

All f8 tools use consistent path resolution:

- **Absolute paths** (`/path/to/file`) → used as-is
- **Explicit relative** (`./file`, `../file`) → used as-is
- **Simple filename** (`make`) → prefixed with `$F8_OUTPUT`, epoch appended

```bash
# With F8_OUTPUT="$HOME/traces":
sudo f8 -o make ./configure     # Writes to ~/traces/make.1740000000.json
sudo f8 -o ./make ./configure   # Writes to ./make.1740000000.json (explicit)

# Import and f8_data handle timestamped names transparently:
f8_import make.1740000000.json  # Reads from ~/traces/make.1740000000.json
f8_data list                    # Shows as "make"
```

See [ENVIRONMENT.md](ENVIRONMENT.md) for full details.


## Usage

```bash
# Basic usage - outputs JSON to stdout
sudo ./f8 ls -la

# Write to file with pretty printing
sudo ./f8 -o trace.json -jp ls -la

# Attach to a running process by PID (like strace -p)
sudo ./f8 -p 12345
sudo ./f8 -p 12345 -o trace.json -t 30   # with output file and 30s timeout

# Run traced program as a specific user (not root)
sudo ./f8 -u zen -o trace.json ./myapp
sudo ./f8 -u 501 -o trace.json ./myapp  # By UID

# With timeout (seconds)
sudo ./f8 -t 10 ./long_running_command

# Verbose mode (shows DTrace activity on stderr)
sudo ./f8 -v -o trace.json ./my_program

# Show untraced syscalls (detect gaps in coverage)
sudo ./f8 -e -o trace.json ./my_program

# Capture I/O data (read/write buffer contents)
sudo ./f8 --capture-io -o trace.json ./my_program

# Adjust buffer sizes for heavy tracing
sudo ./f8 --capture-io --strsize 65536 --io-size 65536 -o trace.json ./my_program
```

### Running as a Non-Root User

**By default, f8 automatically detects who ran sudo and runs the traced program as that user.** This avoids common issues:
- Files created by the traced program are owned by you, not root
- The program behaves the same as when run normally
- Programs that refuse to run as root work correctly

```bash
# Automatic: if you're 'zen' running sudo, the traced program runs as 'zen'
sudo ./f8 -o trace.json ./myapp

# Explicit user (overrides auto-detection)
sudo ./f8 -u testuser -o trace.json ./myapp

# Run as root explicitly
sudo ./f8 -u root -o trace.json ./myapp
```

User selection priority:
1. `-u`/`--user` flag
2. `F8_USER` env var
3. `SUDO_USER` (auto-detected)
4. root (fallback)


## Detecting Untraced Syscalls

Use `-e`/`--untraced` to identify syscalls your traced process makes that aren't explicitly captured:

```bash
sudo ./f8 -e -o trace.json /bin/ls
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

