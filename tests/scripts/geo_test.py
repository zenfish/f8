#!/usr/bin/env python3
"""
geo_test.py — Connect to servers across the globe for f8 geo flag testing.

Makes HTTPS connections to well-known sites hosted in different countries
and continents.  Targets are chosen to be *locally hosted* (universities,
government sites, NICs) rather than behind US CDNs, so the IP addresses
geo-locate to their actual countries.

Usage:
    sudo f8 -o geo_test.json --capture-io -jp python3 tests/scripts/geo_test.py
"""

import socket
import ssl
import sys
import time

# ── Servers by region ────────────────────────────────────────────────
# Each entry: (hostname, description)
# Selected for local hosting — not behind Cloudflare/Fastly/Akamai.
TARGETS = [
    # ── North America ──
    ("github.com",              "GitHub (US)"),
    ("www.mit.edu",             "MIT (US)"),

    # ── South America ──
    ("www.gov.br",              "Brazil Government"),
    ("www.usp.br",              "Univ of São Paulo (Brazil)"),
    ("www.nic.ar",              "NIC Argentina"),
    ("www.nic.br",              "NIC Brazil"),

    # ── Europe ──
    ("www.heise.de",            "Heise (Germany)"),
    ("www.ethz.ch",             "ETH Zurich (Switzerland)"),
    ("www.uio.no",              "Univ of Oslo (Norway)"),
    ("www.ansa.it",             "ANSA (Italy)"),

    # ── Africa ──
    ("www.gov.za",              "South Africa Government"),
    ("www.uct.ac.za",           "Univ Cape Town (South Africa)"),

    # ── Asia ──
    ("www.u-tokyo.ac.jp",       "Univ of Tokyo (Japan)"),
    ("www.tsinghua.edu.cn",     "Tsinghua University (China)"),
    ("www.baidu.com",           "Baidu (China/HK)"),

    # ── Oceania ──
    ("www.anu.edu.au",          "ANU (Australia)"),
    ("www.gov.au",              "Australia Government"),
]

TIMEOUT_SECONDS = 5
SSL_CONTEXT = ssl.create_default_context()


def probe_host(hostname, description):
    """Connect to a host via HTTPS, triggering DNS + TLS."""
    try:
        # DNS resolution (getaddrinfo → recorded by f8)
        addrs = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
        ip = addrs[0][4][0] if addrs else "?"

        # TLS connection (connect/send/recv → recorded by f8)
        with socket.create_connection((hostname, 443), timeout=TIMEOUT_SECONDS) as sock:
            with SSL_CONTEXT.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Send a minimal HTTP request
                ssock.send(f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                resp = ssock.recv(512).decode("utf-8", errors="replace")
                status = resp.split("\r\n")[0] if resp else "?"

        print(f"  ✓ {description:<40} {ip:<18} {status}")
        return True

    except Exception as e:
        print(f"  ✗ {description:<40} {'error':<18} {e}")
        return False


def main():
    print(f"🌍 Geo Test — probing {len(TARGETS)} servers\n")

    ok = 0
    fail = 0
    t0 = time.monotonic()

    for hostname, desc in TARGETS:
        if probe_host(hostname, desc):
            ok += 1
        else:
            fail += 1

    elapsed = time.monotonic() - t0
    print(f"\nDone: {ok} connected, {fail} failed, {elapsed:.1f}s elapsed")
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    main()
