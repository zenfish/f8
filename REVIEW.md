# mactrace Code Review & Testing Proposal

**Date:** 2026-02-24  
**Reviewer:** Mox  
**Scope:** Full codebase (~14,100 lines across 13 source files)

---

## Architecture Overview

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌────────────────┐
│   mactrace   │────▶│  trace.json  │────▶│ mactrace_import│────▶│  mactrace.db   │
│  (Python +   │     │              │     │  (bash → JS)   │     │   (SQLite)     │
│   DTrace)    │     │              │     └───────────────┘     └───────┬────────┘
│              │     │              │                                    │
│  4764 lines  │     │              │     ┌───────────────┐     ┌───────▼────────┐
└─────────────┘     │              │────▶│mactrace_analyze│     │ mactrace_server │
                     │              │     │   (Python)     │     │  (bash → JS)   │
                     │              │     │  590 lines     │     │  + Web UI      │
                     │              │     └───────────────┘     │  ~3600 lines   │
                     │              │                            └────────────────┘
                     │              │     ┌───────────────┐
                     │              │────▶│mactrace_timeline│
                     └──────────────┘     │  (Python→HTML) │
                                          │  1041 lines    │
                                          └───────────────┘

Supporting:
  mactrace_categories.py  (265 lines)  — shared syscall→category definitions
  mactrace_db             (280 lines)  — DB management CLI
  mactrace_run_all.sh     (190 lines)  — orchestration wrapper
```

The pipeline is well-designed: trace → JSON → SQLite → web UI. Clean separation of concerns, each tool does one thing, and the JSON intermediate format is the right call for interop.

---

## What's Good

1. **DTrace script is solid.** The `TRACED` predicate using `progenyof() || self->is_child` correctly handles the full process tree. Entry/return probe pairing for argument capture is done right. The variable substitution system (`$BUFSIZE$`, `$SWITCHRATE$`) keeps magic numbers out of the DTrace code.

2. **Virtual scrolling in the web UI.** Handling 1M+ event traces in a browser is non-trivial and it works. The row rendering is tight and the filter/search implementation is responsive.

3. **DNS correlation from mDNSResponder traffic.** Parsing the IPC protocol to extract hostname→IP mappings is clever and genuinely useful for understanding network behavior. Not something strace or dtrace alone would give you.

4. **I/O capture pipeline.** The ability to capture raw I/O data, link it to specific syscalls via chunk indices, and view as hex/rendered in the web UI is a strong feature that goes beyond what strace offers out of the box.

5. **Config system.** `~/.mactrace/config` with variable expansion, env var overrides, and `SUDO_USER`-aware home directory resolution is well-thought-out for a tool that must run as root.

6. **Process tree reconstruction.** The importer reconstructs parent→child relationships from fork/exec events, falls back through multiple strategies (processes table → fork return values → posix_spawn heuristics → first binary open), and handles edge cases like forked-without-exec processes.

---

## Issues

### Critical — Correctness

**C1. Duplicated syscall categories across languages**

`mactrace_categories.py` is the authoritative source (12 categories, ~190 syscalls), but `server/import.js` has its own `SYSCALL_CATEGORIES` object that's a much smaller subset (~85 syscalls across 10 categories). They're already out of sync:

- Python has `fstatat64`, `getattrlistbulk`, `renameat`, `renamex_np`, `symlinkat`, `readlinkat`, `fchownat`, etc. — JS doesn't.
- Python has separate `necp`, `mac`, `thread` categories — JS lumps them into `other`.
- Any new syscall added to the Python file won't appear in the importer.

**Impact:** Every trace imported through `mactrace_import` has potentially wrong category assignments in the database. The web UI shows incorrect category counts and filter results.

**Fix:** Export categories from the Python file to JSON at build time, or move the canonical list to a shared JSON file that both Python and JS import.

---

**C2. Import has no transaction wrapping**

`import.js` inserts events one at a time via `insertStmt.run()` without an explicit `BEGIN TRANSACTION`. sql.js defaults to autocommit mode, so each INSERT is its own transaction. For a 100K-event trace, this means 100K fsync-equivalent operations.

This isn't just slow — it means a crashed import leaves a partially-populated trace in the database with no way to tell it's incomplete.

**Fix:** Wrap the event loop in `db.run('BEGIN TRANSACTION')` … `db.run('COMMIT')`. This will also make imports ~10-100x faster.

---

**C3. No input validation on DTrace output parsing**

The Python parser in `mactrace` uses regex and `split()` to parse DTrace output lines. There's no validation that:
- Timestamps are monotonically increasing
- PIDs are positive integers
- Return values are within expected ranges
- Strings don't contain format specifiers that could confuse downstream tools

DTrace under load drops events and can produce garbled output (partial lines, interleaved output from multiple CPUs). The parser should be defensive.

---

### Design Issues

**D1. Duplicated code across components**

| Function | Locations | Lines duplicated |
|----------|-----------|-----------------|
| `get_mactrace_config()` | mactrace_analyze, mactrace_timeline, mactrace_db | ~50 lines × 3 |
| `resolve_input_path()` | mactrace_analyze, mactrace_timeline, mactrace_db | ~20 lines × 3 |
| `read_config()` (shell) | mactrace_import, mactrace_server | ~30 lines × 2 |
| `format_bytes()` | mactrace_analyze, mactrace_timeline, mactrace_db, import.js | 4 implementations |
| `sanitize_filename()` | mactrace_analyze, mactrace_timeline, import.js | 3 implementations |
| `extractTarget()` / `_extract_target()` | mactrace_timeline, import.js | 2 implementations |
| `extractDetails()` / `_extract_details()` | mactrace_timeline, import.js | 2 implementations |

A bug fix in one location won't propagate. The implementations already diverge in minor ways (e.g., Python `format_bytes` returns `"1.0 KB"`, JS returns `"1.0K"`).

**Fix:** Extract shared Python code into a `mactrace_lib.py` module. For cross-language functions, either generate one from the other or write consistency tests.

---

**D2. Category colors differ between Python and JavaScript**

`mactrace_categories.py` uses the PiYG diverging palette:
```python
'file': '#276419'  # dark green
```

`server.js` `/api/categories` endpoint returns Material Design colors:
```javascript
'file': { bg: '#4CAF50' }  // Material green
```

The web UI's server-side endpoint and the static timeline generator show the same categories in completely different colors. **The server endpoint doesn't even import from any shared source — the colors are hardcoded in the route handler.**

**Fix:** The server should read category colors from the same source as the Python tools, or the categories JSON should be generated once and consumed everywhere.

---

**D3. Static timeline generator is largely redundant**

`mactrace_timeline` (1041 lines) duplicates most of what the web server provides:
- fd tracking and target extraction (reimplemented)
- Details formatting (reimplemented)  
- I/O file scanning (reimplemented)
- Category filtering and search (reimplemented in generated JS)

The web server version is more capable (database-backed pagination, process tree, hexdump viewer, objects view). The only advantage of the static generator is that it produces a single self-contained HTML file.

**Recommendation:** Either deprecate it or refactor it to call shared code. At minimum, stop maintaining two parallel implementations of target extraction and detail formatting.

---

**D4. No database schema versioning**

The schema has evolved (adding `processes`, `dns_lookups`, `data_raw`, FTS5). Old databases opened by new code will fail on queries like:

```sql
SELECT COUNT(*) FROM processes WHERE trace_id = ?
```

The server has a try/catch for the processes table, but nothing for dns_lookups or other schema changes. There's no `PRAGMA user_version` or migration system.

**Fix:** Set `PRAGMA user_version = N` on creation, check on open, run migrations if needed.

---

**D5. sql.js loads entire database into memory**

```javascript
const buffer = fs.readFileSync(dbFile);
const db = new SQL.Database(buffer);
```

A 200MB database needs ~400MB+ RAM (the Buffer + sql.js's copy). For large traces this is a real constraint. The server also never writes back to disk, so it's read-only — which is fine, but `better-sqlite3` would give you memory-mapped I/O with near-zero overhead.

**Recommendation:** Consider switching the server from sql.js to better-sqlite3 for production use. sql.js is great for portability but costly for large datasets.

---

### Minor Issues

**M1.** `server.js` generates hexdumps via `execSync('hexdump -C ...')` — a shell injection risk if filenames contain special characters. The filename is validated against `..` and `/` but not against shell metacharacters like `;`, `$`, backticks.

**M2.** The web UI's `index.html` is 2043 lines mixing HTML, CSS, and JavaScript. This makes it impossible to unit-test UI logic, lint the JS, or use a minifier. Consider extracting to separate files.

**M3.** `mactrace_run_all.sh` uses `lsof -i -P` output parsing that's fragile — lsof output format varies across macOS versions and the column positions aren't guaranteed.

**M4.** The importer's DNS hostname extraction from mDNSResponder binary data is neat but brittle — the IPC protocol format is undocumented and could change between macOS versions. No version detection or graceful degradation.

**M5.** `mactrace_analyze` and `mactrace_timeline` both have fallback `except ImportError` blocks for `mactrace_categories` that use completely different color palettes and fewer categories. If the import fails silently (e.g., Python path issue when running as root), the output is subtly wrong.

---

## Testing Proposal

### The Challenge

Testing a DTrace-based tracer is hard because:
- DTrace requires root privileges
- Trace output is non-deterministic (timestamps, PIDs, scheduling order)
- The tool spans 4 languages (Python, JavaScript, DTrace/D, Shell)
- Some behavior depends on macOS version
- The web UI needs browser-based testing

The solution is a **layered testing strategy** that maximizes coverage at each layer without requiring root for the majority of tests.

### Layer 1: Unit Tests (no root, no DTrace)

Test pure functions in isolation. These are fast, deterministic, and catch the most common bugs.

**Python (pytest):**

| Module | Functions to test | Key cases |
|--------|------------------|-----------|
| `mactrace_categories` | `get_category()`, `get_color()`, `get_text_color()` | Every syscall maps to exactly one category; no syscall in two categories; unknown syscalls → 'other'; all colors are valid 6-digit hex |
| `mactrace_analyze` | `extract_raw_bytes()` | Hex strings, escape sequences (`\n`, `\x41`, octal), byte lists, empty input, mixed content |
| | `sanitize_filename()` | Paths with `/`, special chars, very long strings, empty string, unicode |
| | `render_terminal()` | CR overwrites, ANSI stripping, tab expansion, cursor movement |
| | `python_hexdump()` | Compare output against `hexdump -C` for same input |
| | `format_bytes()`, `format_duration()` | Boundary values (0, 1023, 1024, 1M, 1G), negative values |
| | `is_config_file()`, `is_library()` | Known paths, edge cases |
| | `get_mactrace_config()` | Variable expansion, `~` expansion, comments, empty lines, missing file |
| `mactrace` | `parse_size()` | `'10M'`, `'500k'`, `'1G'`, `'1024'`, `''`, invalid input |
| | DTrace line parsing | `MACTRACE_SYSCALL` lines, `MACTRACE_FORK_CHILD`, `MACTRACE_EXIT`, malformed lines, truncated lines |
| | `filter_wrapper_processes()` | Traces with sudo/sh/bash wrappers, traces without |

**JavaScript (vitest):**

| Module | Functions to test | Key cases |
|--------|------------------|-----------|
| `import.js` | `getCategory()` | Same syscalls as Python → same categories (cross-language parity!) |
| | `extractTarget()` | File paths, socket addresses, fd lookups, stdin/stdout |
| | `extractDetails()` | Read/write with counts, mmap args, socket options |
| | `sanitizeFilename()` | Same inputs as Python version → same outputs |
| | `formatTime()` | Epoch math, midnight rollover, zero |
| | DNS hostname extraction | Known-good mDNSResponder binary payloads |

**Estimated coverage:** ~60% of non-DTrace code, ~90% of utility functions

### Layer 2: Integration Tests (no root)

Test component interactions using pre-recorded trace data.

**Golden File Tests:**

Ship 3-5 canonical trace JSON files in `tests/fixtures/`:

| Fixture | What it covers |
|---------|---------------|
| `simple_cat.json` | `cat /etc/passwd` — file open/read/write/close, clean exit |
| `fork_exec.json` | `sh -c 'echo hi | wc'` — fork, exec, pipe, wait |
| `network_curl.json` | `curl http://example.com` — socket, connect, DNS, send/recv |
| `error_cases.json` | Synthetic trace with ENOENT, EACCES, ECONNREFUSED errors |
| `multiproc.json` | 10+ process tree with nested fork/exec chains |

For each fixture, verify:

1. **Import roundtrip:** `import.js` → query DB → row counts, category distribution, and specific events match expected values
2. **Analyze output:** `mactrace_analyze` → text summary matches expected patterns (syscall counts, file lists, error counts)
3. **Server API:** Start server with test DB → each API endpoint returns expected JSON structure and values
4. **Timeline generation:** `mactrace_timeline` → generated HTML contains expected elements (row count, filter buttons, syscall badges)

**Config tests:** Various `~/.mactrace/config` files (variable expansion, missing values, circular references, special characters).

**Estimated coverage:** ~75% of import/server/analyze code

### Layer 3: Cross-Language Consistency Tests

Automated verification that Python and JS implementations agree:

```python
# test_consistency.py
def test_category_parity():
    """Every syscall gets the same category in Python and JavaScript."""
    py_categories = load_python_categories()
    js_categories = load_js_categories()  # run via subprocess or Node
    
    all_syscalls = set(py_categories.keys()) | set(js_categories.keys())
    for syscall in all_syscalls:
        assert py_categories.get(syscall, 'other') == js_categories.get(syscall, 'other'), \
            f"{syscall}: Python={py_categories.get(syscall)} JS={js_categories.get(syscall)}"

def test_format_parity():
    """format_bytes() returns identical strings in Python and JavaScript."""
    test_values = [0, 1, 512, 1023, 1024, 1025, 1048576, 1073741824]
    for val in test_values:
        assert py_format_bytes(val) == js_format_bytes(val)
```

**These tests are the canary for code drift.** If someone updates a category in Python but not JS, this test fails.

### Layer 4: End-to-End Tests (requires sudo)

Small deterministic C programs that make specific syscalls:

```c
// tests/programs/test_fileops.c
// Opens /tmp/mactrace_test, writes "hello", reads it back, unlinks it.
// Expected: open → write(5 bytes) → close → open → read(5 bytes) → close → unlink
```

```c
// tests/programs/test_forkexec.c  
// Forks, child execs /bin/echo "test", parent waits.
// Expected: fork → (child) execve → write("test\n") → exit → (parent) wait4
```

```c
// tests/programs/test_network.c
// Creates TCP socket, connects to localhost:1 (will fail with ECONNREFUSED).
// Expected: socket(AF_INET, SOCK_STREAM) → connect(127.0.0.1:1) → errno=ECONNREFUSED
```

Test harness:
1. Compile the C program
2. `sudo mactrace -o /tmp/test.json ./test_program`
3. Parse output JSON
4. Assert expected syscalls are present, in the right order, with correct arguments
5. Assert fd→path mapping is correct
6. Assert I/O data (if `--capture-io`) matches what was written

**Key principle:** Don't assert exact output — assert **structural properties**:
- "There exists an `open` event for `/tmp/mactrace_test` with return value > 0"
- "There exists a `write` event on that fd with return_value == 5"
- "The process tree has exactly 2 processes with a parent→child relationship"

### Layer 5: Stress & Edge Cases

- **Large trace:** Import a 500K-event trace, verify server handles it (response times, memory usage)
- **Malformed input:** Feed truncated JSON, empty JSON, JSON with missing fields to importer
- **DTrace garbling:** Feed lines with missing fields, interleaved partial lines to the parser
- **Unicode paths:** Trace a program that opens files with emoji/CJK/RTL characters
- **Rapid fork/exit:** Trace a fork bomb (limited) to verify process tree doesn't infinite-loop

### Layer 6: Web UI Tests (Playwright)

Automate browser testing of the web interface:

- Load trace → verify row count matches DB
- Click category filter → verify only matching rows visible
- Search for a syscall → verify highlighting
- Expand process tree node → verify children appear
- Click I/O hexdump link → verify hexdump viewer opens with data
- Resize a column → verify it sticks
- Navigate to objects view → verify file list populated

### Proposed Directory Structure

```
tests/
├── conftest.py                 # Shared pytest fixtures, temp dirs, DB helpers
├── fixtures/
│   ├── traces/                 # Golden trace JSON files
│   │   ├── simple_cat.json
│   │   ├── fork_exec.json
│   │   ├── network_curl.json
│   │   ├── error_cases.json
│   │   └── multiproc.json
│   ├── configs/                # Test config files
│   │   ├── basic.config
│   │   ├── with_vars.config
│   │   └── empty.config
│   └── dtrace_output/          # Raw DTrace output samples
│       ├── clean.txt
│       └── garbled.txt
├── unit/
│   ├── test_categories.py      # Category mapping, colors, no-overlap
│   ├── test_analyze_utils.py   # extract_raw_bytes, sanitize, render, hexdump
│   ├── test_format.py          # format_bytes, format_duration
│   ├── test_config.py          # Config parsing
│   ├── test_parse_dtrace.py    # DTrace output line parsing
│   └── test_parse_size.py      # parse_size()
├── integration/
│   ├── test_import.py          # JSON → SQLite roundtrip
│   ├── test_server_api.py      # API endpoints with test DB
│   ├── test_analyze.py         # Full analysis of fixture traces
│   └── test_timeline.py        # Timeline HTML generation
├── consistency/
│   └── test_cross_language.py  # Python↔JS parity (categories, formats)
├── e2e/
│   ├── programs/               # Deterministic C test programs
│   │   ├── Makefile
│   │   ├── test_fileops.c
│   │   ├── test_forkexec.c
│   │   └── test_network.c
│   ├── test_tracing.py         # Full mactrace → verify (needs sudo)
│   └── conftest.py             # Skip if not root
├── ui/
│   └── test_web_ui.py          # Playwright browser tests
├── server/
│   ├── vitest.config.js
│   └── import.test.js          # JS unit tests
├── Makefile                    # `make test`, `make test-unit`, `make test-e2e`
└── README.md                   # How to run tests
```

### Implementation Priority

| Phase | What | Effort | Coverage gain | Root needed |
|-------|------|--------|--------------|-------------|
| **1** | Unit tests for Python utils + categories | 1 day | +25% | No |
| **2** | Golden file fixtures + import roundtrip | 1 day | +20% | No |
| **3** | Cross-language consistency tests | 0.5 day | Catches drift | No |
| **4** | Server API integration tests | 1 day | +15% | No |
| **5** | E2E deterministic programs | 1-2 days | +10% | **Yes** |
| **6** | DTrace output parser hardening + tests | 1 day | +5% | No |
| **7** | Playwright web UI tests | 1 day | +5% | No |

Phases 1-4 give you ~60% coverage without needing root, and catch the most likely bugs (wrong categories, format drift, import corruption, API regressions).

### Recommended Tooling

- **Python:** `pytest` + `pytest-cov` (already standard)
- **JavaScript:** `vitest` (ESM-native, fast, good mocking)
- **Coverage:** `pytest-cov` for Python, `c8`/`vitest --coverage` for JS
- **CI:** GitHub Actions with two jobs:
  - `test-unit-integration` (no root, runs on every push)
  - `test-e2e` (needs macos-latest runner with sudo, runs on PR/release)
- **Web UI:** Playwright (already installed)

### Refactoring Recommendations (do before or alongside testing)

1. **Extract `mactrace_lib.py`** — shared config, format, sanitize functions used by analyze, timeline, and db. Import instead of copy-paste.
2. **Generate `categories.json`** from `mactrace_categories.py` — consumed by both Python tools and `import.js`. Single source of truth.
3. **Wrap import in a transaction** — immediate correctness and performance win.
4. **Add `PRAGMA user_version`** — enables future schema migrations.
5. **Sanitize filenames in shell commands** — `server.js` hexdump generation should use array args, not string interpolation.

---

## Summary

The codebase is well-architected for its purpose — the pipeline design is clean, the DTrace script is sophisticated, and the web UI is genuinely useful. The main risks are **cross-language drift** (Python vs JS reimplementations diverging silently) and **lack of regression anchors** (no tests means any change could break the import/analysis pipeline without anyone noticing).

The testing strategy prioritizes bang-for-buck: unit tests for utility functions and golden-file integration tests catch the most bugs with the least effort. E2E tests with actual DTrace are important but should come after the foundation is solid.

**Recommended starting point:** Phase 1 (Python unit tests) + Phase 2 (golden files) + Phase 3 (consistency). These three phases take ~2.5 days and cover the critical paths without needing root.
