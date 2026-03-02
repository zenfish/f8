# I/O Capture

## I/O Metadata Tracking

The `--capture-io` flag emits `MACTRACE_IO` events for read/write/send/recv syscalls:

```bash
sudo ./mactrace --capture-io -o trace.json /bin/cat /etc/passwd
```

### What It Captures

**Metadata only** - syscall name, fd, and byte count:
```
MACTRACE_IO 12345 12345 read 3 1024
MACTRACE_IO 12345 12345 write 1 512
```

**Note:** DTrace cannot practically capture actual buffer contents for variable-length I/O. 
For full buffer capture, use `strace` on Linux or reconstruct from file/network captures.

### DTrace Buffer Options

| Flag | Default | Description |
|------|---------|-------------|
| `--capture-io` / `-d` | off | Emit MACTRACE_IO events |
| `--strsize` | 16384 | DTrace strsize - max string size |
| `--bufsize` | 256m | DTrace bufsize - trace buffer size |
| `--dynvarsize` | 128m | DTrace dynvarsize - dynamic variable space |

### Analyzer I/O Support

The analyzer tracks I/O bytes from syscall return values (not buffer contents):

```bash
# Show network activity with byte counts (from read/write on socket fds)
./mactrace_analyze trace.json
# Output: fd=6 AF_INET/SOCK_STREAM [connected] (sent 1.9 KB, recv 1.8 MB)
```


## Vectored I/O Capture (`--iovec`)

### What This Is

Some programs don't write data in one shot — they scatter it across multiple buffers and
write them all at once. An HTTP server might write the headers from one buffer and the body
from another in a single `writev()` call. Databases do this constantly.

Without `--iovec`, mactrace traces these calls but only captures metadata (fd, byte count,
number of buffers). With `--iovec`, it captures the **actual contents** of each buffer.

### How Many Buffers?

`--iovec N` tells mactrace how many scattered buffers to capture per call. The question is:
what should N be?

Here's what real software actually does:

| What you're tracing | Typical buffers per call | Suggested N |
|---------------------|-------------------------:|------------:|
| HTTP servers (nginx, Apache) | 2–4 | 4 |
| Databases (PostgreSQL, MySQL) | 2–8 | 8 |
| Logging frameworks | 2–3 | 4 |
| Network protocol stacks | 2–6 | 8 |
| `printf`/stdio | 1–3 | 4 |

**If you're not sure, use `--iovec 4`.** That covers the vast majority of real-world code.
If you see truncated captures in the output (the syscall metadata says 6 buffers but you only
got 4), bump it up. The kernel limit is 1024, but virtually nothing uses more than 8.

### Usage

```bash
# Capture scattered buffers (up to 4 per call)
sudo mactrace --iovec 4 -o trace.json ./my_server

# More headroom for database workloads
sudo mactrace --iovec 8 --trace=file -o trace.json ./my_database

# Only capture writev buffers (not readv/preadv/pwritev) — lightest option
sudo mactrace --iovec 8 --iovec-syscalls=writev -o trace.json ./my_program
```

`--iovec` implies `-c` (IO capture). You don't need to specify both.

### Output Format

Each buffer is emitted as a separate event with its position in the scatter list:

```
MACTRACE_IOV <pid> <tid> <syscall> <fd> <index>/<total> <bytes> <hex_data>
```

So a `writev` with 3 buffers produces 3 `MACTRACE_IOV` lines (`0/3`, `1/3`, `2/3`),
letting the parser reconstruct the full write in order.

### The Cost: DIF Budget

DTrace compiles each probe clause into a DIF program, and the kernel has a
size limit (`kern.dtrace.difo_maxsize`). **mactrace automatically adjusts this
limit** to fit your tracing configuration, then restores it when done. You
shouldn't need to think about this — but here's how it works under the hood.

Capturing scattered buffers requires **unrolling** — DTrace has no loops, so each buffer
slot is a separate compiled clause. The cost formula:

```
DIF cost = (number of syscall variants) × N × 4 programs per slot
```

mactrace has 6 vectored I/O syscall variants under the hood (readv, writev, preadv, pwritev,
plus _nocancel versions of readv and writev). Using `--iovec-syscalls` reduces the variant count.

| --iovec N | All variants (6) | writev only (2) | writev+readv (4) |
|-----------|------------------:|-----------------:|------------------:|
| 2 | 48 | 16 | 32 |
| 4 | 96 | 32 | 64 |
| 8 | 192 | 64 | 128 |
| 16 | 384 | 128 | 256 |

For context, current mactrace usage:

| Configuration | DIF programs | % of budget |
|---------------|------------:|------------:|
| `--trace=file` | 136 | 54% |
| `--trace=all` | 234 | 93% |

So `--iovec 4` with `--trace=file` adds 96 → total 232 (93%). Fits.
But `--iovec 8` with `--trace=all` adds 192 → total 426 (170%). Doesn't fit.

In most cases, mactrace's automatic DIF sizing handles this transparently. If you
hit limits on very large configurations, you can help by:
- Narrowing your trace: `--trace=file` instead of `--trace=all`
- Restricting iovec syscalls: `--iovec-syscalls=writev`
- Lowering N: `--iovec 4` instead of `--iovec 8`
- Manual override: `-d 524288` (forces a specific `difo_maxsize`)

### `--iovec-syscalls` (power user)

By default, `--iovec` captures buffers for all vectored I/O syscalls. If you know you only
care about writes (or only reads), you can restrict it:

```bash
# Only writev (2 variants instead of 6 — 3× cheaper)
--iovec-syscalls=writev

# writev + readv (4 variants)
--iovec-syscalls=writev,readv

# Just pwritev (1 variant — cheapest possible)
--iovec-syscalls=pwritev
```

Valid values: `readv`, `writev`, `preadv`, `pwritev`. The `_nocancel` variants are
included automatically when you name the base syscall.
