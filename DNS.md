# DNS Resolution Detection in f8

f8 captures and classifies DNS lookups by detecting how each hostname was resolved. This matters because modern applications use multiple resolution paths — and the path affects what you can observe, intercept, and trust.

## Resolution Sources

| Badge | Source | How it works |
|-------|--------|-------------|
| **system resolver** | mDNSResponder IPC | App calls `getaddrinfo()` → macOS routes to mDNSResponder via `/var/run/mDNSResponder` socket. This is the standard path for most applications. f8 parses the IPC protocol to extract the queried hostname. |
| **DNS (port 53)** | Direct UDP/TCP | App sends raw DNS wire-protocol queries to a DNS server on port 53, bypassing the system resolver. Common in `dig`, `nslookup`, Go applications (which have their own resolver), and security tools. f8 parses the DNS packet (RFC 1035) to extract hostnames and correlates with responses. |
| **DNS-over-HTTPS** | DoH (port 443) | App sends DNS queries inside HTTPS requests to a DoH provider (e.g., `chrome.cloudflare-dns.com`). The actual DNS query is invisible to f8 (it's encrypted inside TLS), but f8 detects it by recognizing connects to known DoH provider IPs on port 443. |
| **DNS-over-TLS** | DoT (port 853) | Similar to DoH but uses a dedicated TLS port (853) instead of HTTPS. Less common; used by some Android devices and systemd-resolved. Detected by connects to DNS server IPs on port 853. |
| **/etc/hosts** | Static hosts file | Hostname resolved from `/etc/hosts`. Detected when the traced program reads `/etc/hosts` and a subsequent connect matches an IP in the file. |

## Why This Matters

### Same hostname, different answers

A hostname can resolve differently depending on the path:

```
# System resolver (respects /etc/hosts, mDNS, search domains):
$ dscacheutil -q host -a name chrome.cloudflare-dns.com
→ may return a CDN edge IP

# Direct DNS query to Cloudflare:
$ dig @1.1.1.1 chrome.cloudflare-dns.com
→ 1.1.1.1, 1.0.0.1

# DNS-over-HTTPS (what Chrome actually does):
→ encrypted, potentially different answer than plaintext DNS
```

### Security implications

- **System resolver**: Respects enterprise DNS policies, split-horizon DNS, content filtering. Can be monitored and intercepted.
- **Direct port 53**: Bypasses system resolver policies but is still plaintext — visible to network monitors, can be spoofed or intercepted.
- **DoH/DoT**: Encrypted — invisible to network monitors, bypasses DNS-based content filtering and monitoring. This is why some enterprise networks block known DoH providers.
- **/etc/hosts**: Hardcoded — immune to DNS spoofing but also to legitimate DNS changes. Malware sometimes modifies this file.

### What f8 can and can't see

| Source | Hostname visible? | Resolved IP visible? | Query content visible? |
|--------|:-:|:-:|:-:|
| System resolver | ✅ (parsed from IPC) | ⚠️ (correlated with next connect) | ❌ |
| DNS port 53 | ✅ (parsed from wire format) | ✅ (parsed from response) | ✅ |
| DNS-over-HTTPS | ⚠️ (provider hostname only) | ❌ (encrypted) | ❌ |
| DNS-over-TLS | ⚠️ (provider hostname only) | ❌ (encrypted) | ❌ |
| /etc/hosts | ✅ (parsed from file) | ✅ (from file) | N/A |

For DoH and DoT, f8 knows the app *is using* encrypted DNS (and which provider), but can't see what hostnames were queried through it. The actual DNS queries are inside the encrypted HTTPS/TLS stream.

## Known DoH Providers

f8 recognizes these DoH endpoints:

| Provider | Hostnames | IPs |
|----------|-----------|-----|
| Cloudflare | `cloudflare-dns.com`, `chrome.cloudflare-dns.com`, `mozilla.cloudflare-dns.com`, `one.one.one.one` | `1.1.1.1`, `1.0.0.1` |
| Google | `dns.google`, `dns.google.com`, `dns64.dns.google` | `8.8.8.8`, `8.8.4.4` |
| Quad9 | `dns.quad9.net`, `dns9.quad9.net` | `9.9.9.9`, `149.112.112.112` |
| OpenDNS | `doh.opendns.com` | `208.67.222.222`, `208.67.220.220` |
| Others | `dns.nextdns.io`, `dns.adguard.com`, `doh.cleanbrowsing.org` | (varies) |

## Special Hostnames

- **`disabled.invalid`** — A probe domain used by macOS to detect encrypted DNS. The `.invalid` TLD should never resolve (RFC 6761). If it does, something is intercepting DNS. Seeing this in a trace means the app (or macOS) is checking whether DoH/DoT is active.

## Correlation Limitations

The system resolver path (mDNSResponder) doesn't directly expose which IP a hostname resolved to. f8 correlates by finding the next `connect()` call after the DNS lookup, skipping connections to port 53 (DNS servers themselves). This heuristic works well in practice but can produce incorrect correlations when:

- Multiple DNS lookups happen in rapid succession
- The app connects to a different host between the lookup and the connection
- The lookup is speculative (prefetching) and no connection follows

The direct port 53 path doesn't have this problem — the resolved IP is parsed from the DNS response packet itself.
