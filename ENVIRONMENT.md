# f8 Environment Variables

Set these to run f8 from anywhere without worrying about paths.

## Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `F8_HOME` | `$HOME/.f8` | Base directory for all f8 data |
| `F8_DB` | `$F8_HOME/f8.db` | SQLite database for timeline server |
| `F8_OUTPUT` | `.` (cwd) | Where to save/read JSON trace files |
| `F8_IO_DIR` | `$F8_OUTPUT/<name>` | Where to save I/O capture files |
| `F8_PORT` | `3000` | Default port for timeline server |
| `F8_USER` | (none) | Default user to run traced programs as |

## Path Resolution

All f8 tools use consistent path resolution rules:

| Path Type | Example | Behavior |
|-----------|---------|----------|
| Absolute | `/path/to/trace.json` | Used exactly as-is |
| Explicit relative | `./trace.json`, `../trace.json` | Used exactly as-is |
| Simple filename | `trace.json` | Prefixed with appropriate env var |

**Which env var is used depends on context:**

| Tool / Option | Env Var Used |
|---------------|--------------|
| `f8 -o` | `F8_OUTPUT` |
| `f8-import <file>` | `F8_OUTPUT` |
| `f8-import --io-dir` | `F8_OUTPUT` |
| `f8-import --db` | `F8_HOME` |
| `f8-server --db` | `F8_HOME` |

**Examples:**
```bash
export F8_OUTPUT="$HOME/traces"
export F8_HOME="$HOME/.f8"

# These are equivalent:
f8-import myapp.json
f8-import $HOME/traces/myapp.json

# These use explicit paths (no prefix added):
f8-import ./myapp.json          # Current directory
f8-import /tmp/myapp.json       # Absolute path
```

## Running as a Different User

**By default, f8 automatically runs the traced program as the user who invoked sudo** (detected via `$SUDO_USER`). This means files created by traced programs are owned by you, not root.

```bash
# Automatic: runs as 'zen' if you're zen running sudo
sudo f8 -o trace.json ./myapp

# Explicit user via flag (overrides auto-detect)
sudo f8 -u nobody -o trace.json ./myapp

# Explicit user via environment variable
export F8_USER=testuser
sudo f8 -o trace.json ./myapp
```

### User Selection Priority

1. `-u`/`--user` command-line flag (highest)
2. `F8_USER` environment variable
3. `SUDO_USER` (auto-detected from sudo caller)
4. root (if none of the above apply)

The user can be specified as a username or numeric UID:
```bash
sudo f8 -u 501 -o trace.json ./myapp
sudo f8 -u zen -o trace.json ./myapp
```

### Running as Root

To explicitly run as root (disabling auto-detection):
```bash
sudo f8 -u root -o trace.json ./myapp
# or
F8_USER=root sudo f8 -o trace.json ./myapp
```

## Quick Setup

Add to `~/.bashrc` or `~/.zshrc`:

```bash
export F8_HOME="$HOME/.f8"
export F8_DB="$F8_HOME/f8.db"
export F8_OUTPUT="$HOME/traces"
export PATH="$HOME/phd/src/f8:$PATH"

# Create directories
mkdir -p "$F8_HOME" "$F8_OUTPUT"
```

Note: `F8_USER` is usually not needed — f8 auto-detects the sudo caller.

## Usage Examples

```bash
# Trace from any directory, output goes to F8_OUTPUT
# Use sudo -E to preserve environment variables!
cd /some/random/dir
sudo -E f8 -o myapp.json ./myapp

# Import to central database (finds myapp.json in F8_OUTPUT)
f8-import myapp.json

# Start server (uses F8_DB automatically)
f8-server
```

## Configuration File (Recommended)

Create `~/.f8/config` to set defaults that work even without `sudo -E`:

```bash
mkdir -p ~/.f8
cat > ~/.f8/config << 'EOF'
# f8 configuration
F8_HOME=~/.f8
F8_OUTPUT=~/traces
F8_DB=$F8_HOME/f8.db
EOF
```

Now `sudo f8 -o trace.json ./myapp` writes to `~/traces/trace.json` automatically.

**How it works:** f8 detects `SUDO_USER` and reads `~$SUDO_USER/.f8/config`, so your settings work even when sudo resets environment variables.

### Config File Format

Simple `key=value` format with variable expansion:

```bash
# Comments start with #
KEY=value

# ~ expands to the sudo caller's home directory (not root's)
F8_HOME=~/.f8
F8_OUTPUT=~/traces

# $VAR and ${VAR} expand to previously defined config values
F8_DB=$F8_HOME/f8.db

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
F8_HOME=~/f8-data

# Then reference it in other settings
F8_OUTPUT=$F8_HOME/traces
F8_DB=$F8_HOME/db/f8.db
```

## Alternative: sudo -E

If you prefer environment variables over a config file, use `sudo -E` to preserve them:

```bash
export F8_OUTPUT="$HOME/traces"
sudo -E f8 -o trace.json ./myapp     # -E preserves env vars
```

## Priority Order

Settings are resolved in this order (highest priority first):

1. Command-line flags
2. Environment variables (require `sudo -E`)
3. Config file (`~/.f8/config`)
4. Defaults

## Directory Structure

With defaults, your data lives in:

```
~/.f8/
├── f8.db          # SQLite database (all imported traces)
└── server/              # Symlink to install location (for web assets)

~/traces/                # Or wherever F8_OUTPUT points
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
# Example: F8_USER
export F8_USER=zen

sudo f8 ./app           # Runs as 'zen' (from env var)
sudo f8 -u root ./app   # Runs as 'root' (flag overrides)
```
