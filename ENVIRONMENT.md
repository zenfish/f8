# mactrace Environment Variables

Set these to run mactrace from anywhere without worrying about paths.

## Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MACTRACE_HOME` | `$HOME/.mactrace` | Base directory for all mactrace data |
| `MACTRACE_DB` | `$MACTRACE_HOME/mactrace.db` | SQLite database for timeline server |
| `MACTRACE_OUTPUT` | `.` (cwd) | Where to save/read JSON trace files |
| `MACTRACE_IO_DIR` | `$MACTRACE_OUTPUT/<name>` | Where to save I/O capture files |
| `MACTRACE_PORT` | `3000` | Default port for timeline server |
| `MACTRACE_USER` | (none) | Default user to run traced programs as |

## Path Resolution

All mactrace tools use consistent path resolution rules:

| Path Type | Example | Behavior |
|-----------|---------|----------|
| Absolute | `/path/to/trace.json` | Used exactly as-is |
| Explicit relative | `./trace.json`, `../trace.json` | Used exactly as-is |
| Simple filename | `trace.json` | Prefixed with appropriate env var |

**Which env var is used depends on context:**

| Tool / Option | Env Var Used |
|---------------|--------------|
| `mactrace -o` | `MACTRACE_OUTPUT` |
| `mactrace-import <file>` | `MACTRACE_OUTPUT` |
| `mactrace-import --io-dir` | `MACTRACE_OUTPUT` |
| `mactrace-import --db` | `MACTRACE_HOME` |
| `mactrace-server --db` | `MACTRACE_HOME` |

**Examples:**
```bash
export MACTRACE_OUTPUT="$HOME/traces"
export MACTRACE_HOME="$HOME/.mactrace"

# These are equivalent:
mactrace-import myapp.json
mactrace-import $HOME/traces/myapp.json

# These use explicit paths (no prefix added):
mactrace-import ./myapp.json          # Current directory
mactrace-import /tmp/myapp.json       # Absolute path
```

## Running as a Different User

**By default, mactrace automatically runs the traced program as the user who invoked sudo** (detected via `$SUDO_USER`). This means files created by traced programs are owned by you, not root.

```bash
# Automatic: runs as 'zen' if you're zen running sudo
sudo mactrace -o trace.json ./myapp

# Explicit user via flag (overrides auto-detect)
sudo mactrace -u nobody -o trace.json ./myapp

# Explicit user via environment variable
export MACTRACE_USER=testuser
sudo mactrace -o trace.json ./myapp
```

### User Selection Priority

1. `-u`/`--user` command-line flag (highest)
2. `MACTRACE_USER` environment variable
3. `SUDO_USER` (auto-detected from sudo caller)
4. root (if none of the above apply)

The user can be specified as a username or numeric UID:
```bash
sudo mactrace -u 501 -o trace.json ./myapp
sudo mactrace -u zen -o trace.json ./myapp
```

### Running as Root

To explicitly run as root (disabling auto-detection):
```bash
sudo mactrace -u root -o trace.json ./myapp
# or
MACTRACE_USER=root sudo mactrace -o trace.json ./myapp
```

## Quick Setup

Add to `~/.bashrc` or `~/.zshrc`:

```bash
export MACTRACE_HOME="$HOME/.mactrace"
export MACTRACE_DB="$MACTRACE_HOME/mactrace.db"
export MACTRACE_OUTPUT="$HOME/traces"
export PATH="$HOME/phd/src/mactrace:$PATH"

# Create directories
mkdir -p "$MACTRACE_HOME" "$MACTRACE_OUTPUT"
```

Note: `MACTRACE_USER` is usually not needed — mactrace auto-detects the sudo caller.

## Usage Examples

```bash
# Trace from any directory, output goes to MACTRACE_OUTPUT
# Use sudo -E to preserve environment variables!
cd /some/random/dir
sudo -E mactrace -o myapp.json ./myapp

# Import to central database (finds myapp.json in MACTRACE_OUTPUT)
mactrace-import myapp.json

# Start server (uses MACTRACE_DB automatically)
mactrace-server
```

## Configuration File (Recommended)

Create `~/.mactrace/config` to set defaults that work even without `sudo -E`:

```bash
mkdir -p ~/.mactrace
cat > ~/.mactrace/config << 'EOF'
# mactrace configuration
MACTRACE_HOME=~/.mactrace
MACTRACE_OUTPUT=~/traces
MACTRACE_DB=$MACTRACE_HOME/mactrace.db
EOF
```

Now `sudo mactrace -o trace.json ./myapp` writes to `~/traces/trace.json` automatically.

**How it works:** mactrace detects `SUDO_USER` and reads `~$SUDO_USER/.mactrace/config`, so your settings work even when sudo resets environment variables.

### Config File Format

Simple `key=value` format with variable expansion:

```bash
# Comments start with #
KEY=value

# ~ expands to the sudo caller's home directory (not root's)
MACTRACE_HOME=~/.mactrace
MACTRACE_OUTPUT=~/traces

# $VAR and ${VAR} expand to previously defined config values
MACTRACE_DB=$MACTRACE_HOME/mactrace.db

# Quotes around values are optional (stripped if present)
SOME_PATH="~/path with spaces"
```

**Rules:**
- One `key=value` per line
- Lines starting with `#` are comments
- Blank lines are ignored
- `~` expands to `$SUDO_USER`'s home directory
- `$VAR` or `${VAR}` expands to a config value (or env var if not in config)
- Config is processed top-to-bottom, so define variables before referencing them
- Quotes (`"` or `'`) around values are stripped

**Example with variable references:**
```bash
# Set base directory first
MACTRACE_HOME=~/mactrace-data

# Then reference it in other settings
MACTRACE_OUTPUT=$MACTRACE_HOME/traces
MACTRACE_DB=$MACTRACE_HOME/db/mactrace.db
```

## Alternative: sudo -E

If you prefer environment variables over a config file, use `sudo -E` to preserve them:

```bash
export MACTRACE_OUTPUT="$HOME/traces"
sudo -E mactrace -o trace.json ./myapp     # -E preserves env vars
```

## Priority Order

Settings are resolved in this order (highest priority first):

1. Command-line flags
2. Environment variables (require `sudo -E`)
3. Config file (`~/.mactrace/config`)
4. Defaults

## Directory Structure

With defaults, your data lives in:

```
~/.mactrace/
├── mactrace.db          # SQLite database (all imported traces)
└── server/              # Symlink to install location (for web assets)

~/traces/                # Or wherever MACTRACE_OUTPUT points
├── myapp.json           # Trace output
├── myapp/               # I/O files (if --capture-io used)
│   ├── 1234-myapp-read-3.bin
│   └── ...
└── ...
```

## Environment Variable Precedence

For all options, the precedence is:

1. **Command-line flag** (highest priority)
2. **Environment variable**
3. **Default value** (lowest priority)

```bash
# Example: MACTRACE_USER
export MACTRACE_USER=zen

sudo mactrace ./app           # Runs as 'zen' (from env var)
sudo mactrace -u root ./app   # Runs as 'root' (flag overrides)
```
