# Analysis & Visualization

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
mactrace_data list              # List all imported traces
mactrace_data info <id>         # Show details for a trace
mactrace_data delete <id>       # Delete a trace
mactrace_data vacuum            # Compact the database
mactrace_data stats             # Show database statistics
```

