# Adding a System Call to mactrace

This guide walks through adding a new system call, using `renameat` as a worked example.

## Overview

There are two levels of syscall support in mactrace:

1. **Basic tracking** — the syscall is counted, categorized, and appears in traces with its return value. This only requires editing `syscalls.json`.

2. **Rich argument capture** — the syscall's arguments (paths, file descriptors, flags, etc.) are decoded and stored. This requires adding a DTrace probe in the `mactrace` script and a parser in `_parse_line()`.

Most syscalls only need level 1. Level 2 is for syscalls where the arguments matter (file paths, network addresses, buffer contents).

---

## Level 1: Basic Tracking (category + counting only)

**What you get:** The syscall appears in traces with its name, PID, timestamp, return value, and errno. It's assigned to a category with the correct color in all tools (Python analysis, web timeline, import).

**What you edit:** One file.

### Step 1: Add to `syscalls.json`

Find the appropriate category and add the syscall name to its `syscalls` array:

```json
{
  "id": "file",
  "label": "File",
  "description": "File system operations ...",
  "color": "#276419",
  "textColor": "#ffffff",
  "syscalls": [
    "open",
    "close",
    "read",
    "renameat",       ← add it here
    "renameat_nocancel",
    ...
  ]
}
```

**Rules:**
- Use the exact kernel syscall name (lowercase, as shown by `dtrace -ln 'syscall:::entry'`)
- If the syscall has a `_nocancel` variant, add both
- Array order doesn't matter for functionality, but group related calls together for readability
- One syscall can only belong to one category

**That's it.** All tools read `syscalls.json` at runtime:
- `mactrace_categories.py` → Python analysis tools
- `server/import.js` → database importer
- `server/server.js` → web API

The generic DTrace probe (`syscall:::entry` / `syscall:::return`) already captures every syscall. Adding it to `syscalls.json` just tells the tools what category to assign.

### Step 2: Verify

```bash
# Check the JSON is valid and the syscall is recognized
python3 mactrace_categories.py --verify

# Check it maps correctly
python3 -c "from mactrace_categories import get_category; print(get_category('renameat'))"
# Should print: file

# Run the unit tests
make test-unit
```

### Step 3: Test with a real trace

```bash
# Trace a command that uses the syscall
sudo mactrace -o test.json -jp mv /tmp/test1 /tmp/test2

# Check it appears
python3 -c "
import json
with open('test.json') as f:
    data = json.load(f)
for e in data['events']:
    if 'renameat' in e['syscall']:
        print(f\"{e['syscall']} → {e['return_value']}\")
"
```

---

## Level 2: Rich Argument Capture

**What you get:** In addition to basic tracking, the syscall's arguments are decoded and stored as structured data (paths, flags, file descriptors, etc.).

**What you edit:** Three files.

### Step 1: Add to `syscalls.json` (same as Level 1)

### Step 2: Add DTrace probes in `mactrace`

The `mactrace` script contains an embedded DTrace (D language) program. You need entry and return probes.

Find the probe section (after the generic `syscall:::entry` probe, around line 230+) and add:

```d
/* renameat - rename file relative to directory fd */
syscall::renameat:entry
/tracked[pid]/
{
    /* Save arguments for the return probe */
    self->renameat_fromfd = arg0;
    self->renameat_from = copyinstr(arg1);
    self->renameat_tofd = arg2;
    self->renameat_to = copyinstr(arg3);
}

syscall::renameat:return
/tracked[pid]/
{
    printf("MACTRACE_SYSCALL %d %d renameat %d %d %d %d \"%s\" %d \"%s\"\n",
        pid, tid, (int)arg1, errno, walltimestamp/1000,
        self->renameat_fromfd, self->renameat_from,
        self->renameat_tofd, self->renameat_to);

    /* Clean up thread-local variables */
    self->renameat_fromfd = 0;
    self->renameat_from = 0;
    self->renameat_tofd = 0;
    self->renameat_to = 0;
}
```

**Key patterns:**
- `entry` probes capture arguments (they're only available at entry, not return)
- `return` probes emit the `MACTRACE_SYSCALL` line with all data
- Use `self->` for thread-local storage between entry and return
- Always clean up `self->` variables to prevent stale data
- String arguments use `copyinstr()` and are quoted in output
- The base format is: `MACTRACE_SYSCALL <pid> <tid> <name> <retval> <errno> <timestamp> [args...]`

### Step 3: Add parser in `mactrace` (Python section)

Find `_parse_line()` in the Python code (around line 1600+). Add a case for the new syscall:

```python
elif syscall_name == 'renameat':
    if len(parts) >= 5:
        event['args'] = {
            'from_fd': safe_int(parts[0]),
            'from_path': parts[1].strip('"'),
            'to_fd': safe_int(parts[2]),
            'to_path': parts[3].strip('"'),
        }
        # Track as a file operation with both source and target
        event['target'] = f"{parts[1].strip('\"')} → {parts[3].strip('\"')}"
```

**Key patterns:**
- `parts` contains the arguments after pid/tid/name/retval/errno/timestamp
- Strip quotes from string arguments
- Set `event['target']` for display in the timeline (what file/socket/path was involved)
- Use `safe_int()` for numeric values that might be malformed
- Handle missing fields gracefully (DTrace output can be truncated)

### Step 4: Test

```bash
# Run the full test suite
make test

# Write a targeted test in tests/unit/test_parse_dtrace.py:
```

```python
def test_renameat_line(self, tracer):
    """Parse a renameat syscall with from/to paths."""
    line = 'MACTRACE_SYSCALL 100 100 renameat 0 0 1000000 3 "/tmp/old" 4 "/tmp/new"'
    tracer._parse_line(line)
    assert len(tracer.events) == 1
    evt = tracer.events[0]
    assert evt.syscall == 'renameat'
    assert evt.args['from_path'] == '/tmp/old'
    assert evt.args['to_path'] == '/tmp/new'
    assert evt.args['from_fd'] == 3
    assert evt.args['to_fd'] == 4
    assert '→' in evt.target
```

```bash
# Run just the parse tests
python3 -m pytest tests/unit/test_parse_dtrace.py -v

# Test with a real trace
sudo mactrace -o rename_test.json -jp python3 -c "import os; os.rename('/tmp/mt_a', '/tmp/mt_b')"
```

---

## Checklist

### Level 1 (basic tracking)
- [ ] Added syscall name to the right category in `syscalls.json`
- [ ] Added `_nocancel` variant if it exists
- [ ] `python3 mactrace_categories.py --verify` passes
- [ ] `make test-unit` passes

### Level 2 (rich arguments)
- [ ] Everything from Level 1
- [ ] Added DTrace `entry` probe to capture arguments
- [ ] Added DTrace `return` probe to emit `MACTRACE_SYSCALL` line
- [ ] Added parser case in `_parse_line()`
- [ ] Set `event['target']` for timeline display
- [ ] Cleaned up `self->` variables in DTrace return probe
- [ ] Added unit test in `tests/unit/test_parse_dtrace.py`
- [ ] Tested with a real trace (`sudo mactrace ...`)

---

## Finding syscall names

```bash
# List all available syscalls on this system
sudo dtrace -ln 'syscall:::entry' | awk '{print $NF}' | sort -u

# Check if a specific syscall exists
sudo dtrace -ln 'syscall::renameat:entry'

# See which syscalls mactrace doesn't track yet
sudo mactrace -e -o /dev/null echo hello
# The -e flag reports untraced syscalls at the end
```

## Reference

- **`syscalls.json`** — Single source of truth for syscall→category mappings. All tools read this.
- **`mactrace`** — Lines ~140-900: DTrace D script with probes. Lines ~1500-1800: `_parse_line()` Python parser.
- **`mactrace_categories.py`** — Loads `syscalls.json`, provides `get_category()`, `get_color()`, etc.
- **`tests/unit/test_parse_dtrace.py`** — Unit tests for line parsing.
- **`tests/unit/test_categories.py`** — Tests for `syscalls.json` integrity and category lookups.
