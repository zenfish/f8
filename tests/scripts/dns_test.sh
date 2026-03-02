#!/usr/bin/env bash
# dns_test.sh — Exercise all DNS resolution paths that f8 can capture
#
# Path 1: System resolver → mDNSResponder (getaddrinfo + connect via Python)
# Path 2: Direct port 53 via sendmsg (dig)
# Path 3: Direct port 53 via sendto (host)
#
# Targets chosen for country diversity (locally-hosted, not CDN-fronted).
#
# Usage:
#   sudo f8 --capture-io -o dns_test.json -jp bash tests/scripts/dns_test.sh
#   cd server && node import.js ../dns_test.json && node server.js

set -e

echo "=== DNS Test: exercising multiple resolution paths ==="

# ── Path 1: System resolver (mDNSResponder + connect) ────────────
# Python resolves via getaddrinfo (mDNSResponder IPC) then connects
# to port 80 so f8 can correlate the hostname → IP.
echo ""
echo "--- Path 1: System resolver + connect (Python) ---"
python3 -c "
import socket

targets = [
    ('www.u-tokyo.ac.jp', 'Japan'),
    ('www.usp.br', 'Brazil'),
    ('www.tu-berlin.de', 'Germany'),
    ('www.uct.ac.za', 'South Africa'),
    ('www.unsw.edu.au', 'Australia'),
    ('www.snu.ac.kr', 'South Korea'),
    ('www.iitb.ac.in', 'India'),
]

for host, country in targets:
    try:
        ips = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
        if not ips:
            print(f'  {country:15s} {host:30s} → no result')
            continue
        ip = ips[0][4][0]
        # Connect briefly so f8 sees the connect() syscall
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((ip, 80))
            s.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        print(f'  {country:15s} {host:30s} → {ip}')
    except Exception as e:
        print(f'  {country:15s} {host:30s} → ERROR: {e}')
"

# ── Path 2: Direct DNS via sendmsg (dig A records) ───────────────
echo ""
echo "--- Path 2: Direct DNS via dig (A records) ---"
for domain in \
    www.msu.ru \
    www.cam.ac.uk \
    www.ethz.ch \
    www.nic.br \
    www.ripe.net \
    www.iis.se; do
    result=$(dig +short "$domain" A 2>/dev/null | head -1)
    echo "  $domain → ${result:-NXDOMAIN}"
done

# ── Path 2b: Reverse DNS (dig PTR) ───────────────────────────────
echo ""
echo "--- Path 2b: Reverse DNS via dig (PTR records) ---"
for ip in 8.8.8.8 1.1.1.1 9.9.9.9 198.41.0.4; do
    result=$(dig +short -x "$ip" 2>/dev/null | head -1)
    echo "  $ip → ${result:-NO_PTR}"
done

# ── Path 2c: AAAA records (IPv6) ─────────────────────────────────
echo ""
echo "--- Path 2c: IPv6 via dig (AAAA records) ---"
for domain in www.google.com www.facebook.com; do
    result=$(dig +short "$domain" AAAA 2>/dev/null | head -1)
    echo "  $domain AAAA → ${result:-NONE}"
done

# ── Path 3: Direct DNS via host command ───────────────────────────
echo ""
echo "--- Path 3: DNS via host command ---"
for domain in www.arin.net www.apnic.net www.afrinic.net; do
    result=$(host -t A "$domain" 2>/dev/null | grep 'has address' | head -1 | awk '{print $NF}')
    echo "  $domain → ${result:-FAILED}"
done

echo ""
echo "=== DNS test complete ==="
