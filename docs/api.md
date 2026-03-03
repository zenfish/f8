# f8 Server API Reference

Base URL: `http://localhost:3000` (default)

All endpoints return JSON. Errors return `{ "error": "message" }` with appropriate HTTP status codes.

---

## Traces

### `GET /api/traces`

List all imported traces, newest first.

**Response:** Array of trace objects.

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Trace ID |
| `name` | string | Short name (program basename) |
| `command` | string | Full command that was traced |
| `event_count` | int | Total syscall events recorded |
| `duration_ms` | float | Wall-clock duration in milliseconds |
| `target_pid` | int | PID of the traced root process |
| `exit_code` | int | Exit code of the traced process |
| `io_dir` | string | Filesystem path to captured I/O data |
| `imported_at` | string | ISO timestamp of import |

**Example:**
```
GET /api/traces

[
  { "id": 10, "name": "steam", "command": "open -a Steam", "event_count": 604554, ... },
  { "id": 3, "name": "dig", "command": "dig example.com", "event_count": 318, ... }
]
```

---

### `GET /api/traces/:id`

Get detailed metadata for a single trace, including aggregated stats.

**Response:**

All fields from the base trace record, plus:

| Field | Type | Description |
|-------|------|-------------|
| `categories` | array | `[{ category, count }]` — event counts per syscall category |
| `errorCount` | int | Total events with non-zero errno |
| `topSyscalls` | array | `[{ syscall, count }]` — top 10 syscalls by frequency |
| `dnsLookups` | array | DNS lookups with geo enrichment (see [DNS](#dns-lookups)) |
| `execCount` | int | Number of successful `execve`/`posix_spawn` calls |
| `pidCount` | int | Number of distinct PIDs |
| `ioStats` | object | Aggregated I/O byte counts (see below) |

**`ioStats` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `total_read` | int | Total bytes read (all targets) |
| `total_write` | int | Total bytes written (all targets) |
| `net_recv` | int | Bytes read from network targets |
| `net_send` | int | Bytes written to network targets |
| `file_read` | int | Bytes read from file targets |
| `file_write` | int | Bytes written to file targets |
| `file_count` | int | Distinct file paths accessed |
| `net_count` | int | Distinct network endpoints accessed |

---

## DNS Lookups

### `GET /api/traces/:id/dns`

Get all DNS lookups for a trace, enriched with geolocation data.

**Response:** Array of DNS lookup objects.

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | Queried hostname |
| `ip` | string | Resolved IP address |
| `source` | string | Resolution method: `mDNSResponder`, `port53`, `doh`, `dot`, `hosts`, or `unknown` |
| `lookup_seq` | int\|null | Seq number of the DNS lookup event |
| `connect_seq` | int\|null | Seq number of the first connect to the resolved IP |
| `geo` | object\|null | `{ country, countryCode, city, lat, lon, org, asn }` (when available) |

---

## Events

### `GET /api/traces/:id/events`

Paginated, filterable, sortable list of syscall events. This is the main data endpoint for the timeline view.

**Query parameters:**

| Param | Default | Description |
|-------|---------|-------------|
| `offset` | `0` | Pagination offset (0-based row index) |
| `limit` | `1000` | Max events to return |
| `category` | — | Filter by category (`file`, `network`, `process`, `memory`, `signal`, `error`, `all`) |
| `syscall` | — | Filter by exact syscall name |
| `pid` | — | Filter to a single PID |
| `pids` | — | Comma-separated PID list (for process subtree views) |
| `errors` | — | Set to `true` to show only events with errno ≠ 0 |
| `search` | — | Full-text search across syscall, target, details, time, errno, and PID |
| `sort` | `seq` | Sort column: `seq`, `time`, `pid`, `syscall`, `target` |
| `order` | `asc` | Sort direction: `asc` or `desc` |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `events` | array | Array of event objects (see below) |
| `total` | int | Total events in this trace (unfiltered) |
| `filtered` | int | Total events matching current filters |
| `offset` | int | Current pagination offset |
| `limit` | int | Current page size |

**Event object fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Database row ID |
| `seq` | int | Sequence number (trace-global ordering) |
| `timestamp_us` | float | Microsecond timestamp |
| `time_str` | string | Human-readable time (e.g. `"13:25:57.112"`) |
| `pid` | int | Process ID |
| `syscall` | string | Syscall name (e.g. `read`, `connect`, `execve`) |
| `category` | string | Category (e.g. `file`, `network`, `process`) |
| `return_value` | int | Return value (bytes for I/O, 0 for success, etc.) |
| `errno` | int | Error number (0 = success) |
| `errno_name` | string | Error name (e.g. `ENOENT`, `OK`) |
| `target` | string | Target: file path, IP:port, fd, signal name, etc. |
| `details` | string | Extra info (flags, sizes, protocol details) |
| `has_io` | int | 1 if this event has captured I/O data |
| `io_path` | string\|null | Relative path to the I/O data file (within io_dir) |
| `io_chunk` | int\|null | Chunk index within the I/O file |
| `data_raw` | string\|null | Inline raw data (for small payloads stored in DB) |

**Example:**
```
GET /api/traces/10/events?category=network&limit=5&sort=time&order=desc

{
  "events": [...],
  "total": 604554,
  "filtered": 27,
  "offset": 0,
  "limit": 5
}
```

---

### `GET /api/traces/:id/events/seq-index`

Find the 0-based row index of a specific event (by seq number) within the current filter and sort order. Used by the UI to scroll directly to a target event (e.g. from DNS lookup links).

**Query parameters:**

Same filter/sort params as `/events` (`category`, `syscall`, `pid`, `pids`, `errors`, `search`, `sort`, `order`), plus:

| Param | Required | Description |
|-------|----------|-------------|
| `seq` | **yes** | The sequence number to locate |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `index` | int | 0-based row position in the filtered/sorted result set. `-1` if the seq doesn't exist or isn't in the current filter. |

**Example:**
```
GET /api/traces/10/events/seq-index?seq=367791

{ "index": 367113 }
```

**Why this exists:** Seq numbers are not contiguous row indices. Traces can start at arbitrary seq values (e.g. seq 675) and have gaps. When filters are active, the mapping diverges further.

---

## I/O Data

### `GET /api/traces/:id/io/*`

Serve raw captured I/O files from the trace's `io_dir`.

The `*` wildcard matches the relative path within io_dir (e.g. `58998-unknown/write-app.log.bin`).

**Behavior:**
- Returns raw binary data with `application/octet-stream` content type
- `.hexdump` files: auto-generated from `.bin` via `hexdump -C` if not on disk; served as `text/plain`
- `.rendered` files: auto-generated from `.bin` (printable ASCII + dots for non-printable bytes); served as `text/plain`
- Path traversal (`..`) is rejected with 400

**Example:**
```
GET /api/traces/10/io/86685-dig/read-153.227.1.4:53.bin
→ raw DNS response bytes

GET /api/traces/10/io/86685-dig/read-153.227.1.4:53.bin.hexdump
→ hexdump -C formatted text
```

---

### `GET /api/traces/:id/hexdump-lines/*`

Paginated hexdump line access for virtual scrolling. Returns structured JSON lines instead of raw text.

**Query parameters:**

| Param | Default | Description |
|-------|---------|-------------|
| `offset` | `0` | Line offset (0-based) |
| `limit` | `500` | Max lines to return (capped at 5000). Set to `-1` for metadata only. |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `totalLines` | int | Total lines in the hexdump file |
| `offset` | int | Current line offset |
| `limit` | int | Lines requested |
| `lines` | array | Parsed hexdump lines (see below) |

When `limit=-1`, only `totalLines` and `fileSize` are returned (cheap metadata call).

**Line object:**

| Field | Type | Description |
|-------|------|-------------|
| `addr` | int | Byte address (parsed from hex) |
| `addrStr` | string | Hex address string (e.g. `"000001a0"`) |
| `bytes` | string | Hex byte columns |
| `ascii` | string | ASCII representation |

---

## Objects (Files & Network)

### `GET /api/traces/:id/objects`

Aggregated I/O statistics grouped by target (file path or network host).

**Query parameters:**

| Param | Default | Description |
|-------|---------|-------------|
| `type` | `files` | `files` for filesystem targets, `network` for IP/socket targets |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `trace` | object | `{ id, command, io_dir }` |
| `type` | string | `"files"` or `"network"` |
| `dnsLookups` | array\|undefined | DNS lookups with geo data (only for `type=network`) |
| `objects` | array | Aggregated object stats (see below) |

**Object fields:**

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | File path or IP address (ports stripped for network) |
| `pid` | int | First PID seen accessing this target |
| `read` | int | Total bytes read |
| `write` | int | Total bytes written |
| `readCount` | int | Number of read operations |
| `writeCount` | int | Number of write operations |
| `hasDataCount` | int | Events with captured I/O data available |
| `total` | int | `read + write` |
| `hostname` | string\|undefined | DNS hostname (network objects only, when DNS lookup exists) |

Results are sorted by total I/O (descending), capped at 500 objects.

---

### `GET /api/traces/:id/target-events`

Get individual I/O events for a specific target. Used by the hexdump view to show per-operation data.

**Query parameters:**

| Param | Required | Description |
|-------|----------|-------------|
| `target` | **yes** | Exact target string to match |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | The queried target |
| `ioDir` | string | Filesystem path to the trace's I/O directory |
| `events` | array | Filtered I/O events (read/write only, return_value > 0) |

**Event fields:** `seq`, `pid`, `syscall`, `bytes`, `ioPath`, `chunk`, `dataRaw`

---

## Process Tree

### `GET /api/traces/:id/process-tree`

Reconstructed process tree with per-PID I/O statistics and program identification.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `rootPid` | int | Root process PID |
| `command` | string | Original traced command |
| `totalExecCount` | int | Total successful exec/spawn calls across all PIDs |
| `nodes` | array | Process nodes (see below) |

**Node fields:**

| Field | Type | Description |
|-------|------|-------------|
| `pid` | int | Process ID |
| `parentPid` | int\|null | Parent PID |
| `childPids` | array | Child PIDs (sorted by first_seq) |
| `programs` | array | Program paths executed by this PID |
| `programSource` | string\|null | How the program was identified: `"exec"`, `"spawn"`, or `"inferred"` |
| `execCount` | int | Number of exec/spawn calls by this PID |
| `firstSeq` | int | First event seq for this PID |
| `lastSeq` | int | Last event seq |
| `eventCount` | int | Total events for this PID |
| `io` | object | `{ totalRead, totalWrite, netRead, netWrite, fileRead, fileWrite }` |

**Process identification priority:**
1. `processes` table (authoritative, from DTrace `F8_EXEC` probes)
2. `execve`/`posix_spawn` events in the syscall log
3. Inferred from first binary `open()`/`openat()` of a path containing `/bin/` or `/libexec/`

---

## Categories

### `GET /api/categories`

Get the color scheme for syscall categories. Loaded from `syscalls.json`.

**Response:** Object mapping category ID → `{ bg, text }` color strings.

```json
{
  "file": { "bg": "#a1d99b", "text": "#1a1a1a" },
  "network": { "bg": "#9ecae1", "text": "#1a1a1a" },
  "process": { "bg": "#fdae6b", "text": "#1a1a1a" },
  ...
}
```

---

## Database Schema

The server uses SQLite with these primary tables:

- **`traces`** — One row per imported trace (metadata, command, duration, io_dir path)
- **`events`** — All syscall events (indexed on trace_id + seq, trace_id + category)
- **`dns_lookups`** — Extracted DNS lookup/connect pairs per trace
- **`processes`** — Authoritative process table from DTrace probes (pid, parent_pid, exec_path)

Default database location: `~/.f8/f8.db`
