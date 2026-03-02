## Testing

f8 has a comprehensive test suite covering unit tests, integration tests, cross-language consistency checks, and end-to-end tracing.

### Quick Start

```bash
make test          # Run all tests (no root needed)
make test-unit     # Unit tests only (~0.3s)
make test-cov      # With coverage report
make test-e2e      # E2E tests (requires sudo)
make verify        # Quick category validation
```

### Test Structure

```
tests/
├── conftest.py                    # Shared fixtures (traces, temp dirs, configs)
├── unit/
│   ├── test_categories.py         # syscalls.json integrity, lookups, colors (35 tests)
│   ├── test_lib.py                # f8_lib shared utilities (76 tests)
│   ├── test_parse_dtrace.py       # DTrace output parsing, all event types (24 tests)
│   └── test_parse_malformed.py    # Bad input: truncated, garbled, drops (29 tests)
├── consistency/
│   └── test_cross_language.py     # Python ↔ JS category/color parity (8 tests)
├── integration/
│   ├── test_import_roundtrip.py   # JSON → import.js → SQLite → verify (16 tests)
│   └── test_server_api.py         # Server API endpoints (16 tests)
├── e2e/
│   └── test_tracing.py            # Real DTrace runs against C programs (16 tests, needs sudo)
└── fixtures/
    ├── traces/                    # Golden JSON trace files
    ├── configs/                   # Test config files
    └── dtrace_output/             # Raw DTrace output samples
```

### What's Tested

- **Unit (164 tests):** Format functions, path resolution, hex dump rendering, terminal escape processing, file classification, config parsing, syscall category lookups, JSON schema integrity, DTrace line parsing for all `F8_*` event types, malformed/truncated input handling, DTrace drop/warning messages
- **Consistency (8 tests):** Python `f8_categories.py` and JS `import.js`/`server.js` produce identical category mappings, colors, and text colors from the shared `syscalls.json`
- **Integration (32 tests):** Import roundtrip (JSON → SQLite → query), server API endpoints (traces, events, process-tree, categories), pagination, filtering, search, error handling
- **E2E (16 tests):** Deterministic C programs traced with real DTrace. Tests file ops, fork/exec, and network syscalls. Requires `sudo` and SIP dtrace restrictions disabled.

### Dependencies

```bash
pip install pytest pytest-cov       # Python test runner
cd server && npm install             # better-sqlite3 for integration/consistency tests
```

### Coverage

```bash
make test-cov
# Current: 48% overall (322 tests)
# Highlights: syscalls/ handlers 80-100%, f8_lib 77%, f8_data 63%
# The main tracer (f8) is 22% — most of it requires real DTrace (E2E tests)
```

