# DNS Resolution Tracking in mactrace

This document explains how mactrace captures and correlates DNS hostname→IP
lookups, the different paths DNS resolution takes on macOS, and what each
path means for visibility.

## How DNS Works on macOS

When an application resolves a hostname to an IP address, the request can
take several paths depending on the application and its DNS configuration:

### Path 1: System Resolver → mDNSResponder (most common)

```
Application
  → getaddrinfo() / gethostbyname() / NSHost / CFHost
    → libsystem_info.dylib
      → Mach IPC to mDNSResponder daemon
        → /var/run/mDNSResponder (Unix domain socket)
          → mDNSResponder sends UDP query to configured DNS server
            → Response cached by mDNSResponder
```

**Who uses this:** Python (`socket.getaddrinfo`), curl, wget, browsers,
virtually every macOS application that uses the standard C library or
Apple frameworks.

**mactrace visibility:** ✅ Full. We capture the `sendto` data on the
`/var/run/mDNSResponder` Unix socket and parse the mDNSResponder IPC
protocol to extract the queried hostname. We then correlate with the
next `connect()` call to determine which IP the hostname resolved to.

### Path 2: Direct UDP to Port 53

```
Application
  → Builds raw DNS wire-format packet (RFC 1035)
    → sendto() / sendmsg() to DNS server IP on port 53
      → recvfrom() / recvmsg() with response
```

**Who uses this:** `dig`, `nslookup`, `host`, Go programs using their
built-in resolver, custom DNS clients, security/recon tools, some
database drivers.

**mactrace visibility:** ✅ Full (with `--capture-io`). We capture the
raw DNS wire protocol from `sendto`/`recvfrom` and `sendmsg`/`recvmsg`
buffer data, then parse RFC 1035 queries and responses to extract
hostnames and resolved IPs.

**Note on sendmsg:** The `sendmsg` syscall passes its buffer through a
`struct msghdr → struct iovec` pointer chain. mactrace chases this chain
with three sequential `copyin()` calls in DTrace. Due to a macOS ARM64
DTrace limitation where `self->` (thread-local) variables truncate to
32-bit, we split 64-bit userspace pointers into hi/lo halves for storage
between entry and return probes.

### Path 3: DNS-over-TLS (DoT) — Port 853

```
Application
  → TLS connection to DNS server on port 853
    → DNS wire-format query inside TLS tunnel
```

**Who uses this:** `knot-resolver`, `stubby`, `systemd-resolved`,
some VPN configurations, applications using DoT-aware libraries.

**mactrace visibility:** ❌ Encrypted. We can see the `connect()` to
port 853 and the TLS handshake, but the DNS query inside is encrypted.
We know DNS *is happening* (port 853 is a strong signal) but can't
extract the hostname.

### Path 4: DNS-over-HTTPS (DoH) — Port 443

```
Application
  → HTTPS POST/GET to DNS resolver endpoint
    → e.g., https://dns.google/dns-query
    → DNS wire-format or JSON query inside HTTPS
```

**Who uses this:** Firefox (default in many regions), Chrome (when
configured), `cloudflared`, `dnscrypt-proxy`, newer curl builds,
applications using DoH libraries.

**mactrace visibility:** ❌ Encrypted and indistinguishable from regular
HTTPS traffic. We can see the `connect()` to the DoH resolver IP, but
can't tell it apart from a normal web request without knowing the
resolver's IP in advance.

### Path 5: Multicast DNS (mDNS) — .local domains

```
Application
  → getaddrinfo("myprinter.local")
    → mDNSResponder
      → Multicast UDP to 224.0.0.251:5353 (or ff02::fb for IPv6)
        → Device on local network responds
```

**Who uses this:** Any `.local` hostname resolution, AirDrop/AirPlay
discovery, Bonjour services.

**mactrace visibility:** ✅ Partial. The mDNSResponder IPC captures the
queried `.local` hostname. The multicast query/response happens inside
mDNSResponder (a separate process), not in the traced application.

## What mactrace Captures

### At trace time (DTrace probes)

| Syscall | Buffer data | Dest address | Captured by |
|---------|------------|--------------|-------------|
| `sendto` to mDNSResponder socket | ✅ via `copyin(arg1)` | ✅ Unix socket path | RAWIO probes |
| `sendto` to port 53 | ✅ via `copyin(arg1)` | ✅ sockaddr from `arg4` | RAWIO probes |
| `sendmsg` to port 53 | ✅ via msghdr→iov chain | ❌ dest inside msghdr | RAWIO probes |
| `recvfrom` from port 53 | ✅ via `copyin(arg1)` | ✅ sockaddr from `arg4` | RAWIO probes |
| `recvmsg` from port 53 | ✅ via msghdr→iov chain | ❌ src inside msghdr | RAWIO probes |
| `connect` to any IP | N/A | ✅ sockaddr parsed | Handler probes |

### At import time (server/import.js)

The importer extracts DNS correlations from two sources:

**Source 1: mDNSResponder IPC parsing**
- Finds `sendto` events targeting `/var/run/mDNSResponder`
- Parses the mDNSResponder IPC protocol (big-endian header, op codes 7/8)
- Extracts null-terminated hostname strings after the 28-byte header
- Correlates each hostname with the next `connect()` to an IP within 1000 events

**Source 2: DNS wire protocol parsing (RFC 1035)**
- Finds `sendto`/`sendmsg` events where the target contains `:53`
- Parses the DNS query packet: header (12 bytes) → question section → hostname
- Finds matching response packets by transaction ID
- Parses A (type 1) and AAAA (type 28) answer records for resolved IPs
- Falls back to correlating with subsequent `connect()` calls

Both sources merge into a single `dns_lookups` table. mDNSResponder
entries take priority (they fire first for apps using `getaddrinfo`).

### At display time (web UI)

- Each DNS lookup is shown in the "🌐 DNS Lookups" summary card
- IPs are geo-located using `fast-geoip` (MaxMind GeoLite2 database)
- Country flags from `flagcdn.com` CDN with hover tooltips showing
  country, city, region, and timezone
- DNS lookup events are highlighted in the timeline with blue borders
- Jump links connect DNS lookups to their timeline position

## DTrace Pitfalls on macOS ARM64

### self-> 64-bit Truncation

DTrace `self->` (thread-local) variables silently truncate 64-bit values
to 32-bit on macOS ARM64. The workaround is to split pointers into hi/lo
halves (used for recvmsg return-time capture):

```d
self->ptr_hi = (uint32_t)(this->ptr >> 32);
self->ptr_lo = (uint32_t)(this->ptr & 0xffffffff);
// ...later...
this->ptr = ((uint64_t)self->ptr_hi << 32) | (uint64_t)self->ptr_lo;
```

For sendmsg, mactrace avoids this entirely by capturing at entry time
(the buffer is valid when the user sends it), keeping everything in
clause-local `this->` variables.

### tracemem Hexdump Parsing

DTrace's `tracemem()` outputs hex dumps like:
```
        20: 64 72 04 61 72 70 61 00 00 0c 00 01 00 00 29 10  dr.arpa.......)^P
```

The hex column and ASCII column are separated by two spaces. A naive
regex that greedily matches hex pairs can bleed into the ASCII column
when it starts with hex-valid characters (e.g., `70` from `70.247...`).
mactrace's parser uses a two-space terminator in the regex to prevent this.

## Testing

Use the geo test script to generate traces with diverse DNS data:

```bash
# Standard test (uses system resolver → mDNSResponder path)
sudo mactrace -o geo.json --capture-io -jp python3 tests/scripts/geo_test.py

# Direct DNS test (uses sendto/sendmsg → port 53 path)
sudo mactrace -o dig.json --capture-io -jp dig +short example.com kernel.org

# Import and view
cd server && node import.js ../geo.json && node server.js
```

## Future Work

- **DoT detection:** Flag `connect()` calls to port 853 as "encrypted DNS"
  in the timeline, even though we can't read the query
- **DoH resolver fingerprinting:** Maintain a list of known DoH resolver
  IPs (8.8.8.8, 1.1.1.1, etc.) and flag HTTPS connections to them
- **sendmsg destination address:** Extract `msg_name` from the msghdr
  struct (same copyin chain technique) to show which DNS server was queried
- **Multi-iovec support:** Currently we only read `iov[0]`; DNS queries
  are almost always single-buffer, but completeness would mean iterating
  the iovec array
