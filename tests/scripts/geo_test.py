#!/usr/bin/env python3
"""
geo_test.py — Connect to servers across the globe for mactrace geo flag testing.

Makes HTTPS connections to well-known sites hosted in different countries
and continents. Designed to be traced with mactrace to generate DNS lookups
with diverse geo data for the web UI's flag display.

Usage:
    sudo mactrace -o geo_test.json -jp python3 tests/scripts/geo_test.py
"""

import socket
import ssl
import sys
import time

# ── Servers by region ────────────────────────────────────────────────
# Each entry: (hostname, description, expected_country)
TARGETS = [
    # North America
    ("www.google.com",          "Google (US)",              "US"),
    ("github.com",              "GitHub (US)",              "US"),
    ("www.cbc.ca",              "CBC News (Canada)",        "CA"),

    # Europe
    ("www.bbc.co.uk",           "BBC (UK)",                 "GB"),
    ("www.lemonde.fr",          "Le Monde (France)",        "FR"),
    ("www.heise.de",            "Heise (Germany)",          "DE"),
    ("www.ansa.it",             "ANSA (Italy)",             "IT"),
    ("www.svt.se",              "SVT (Sweden)",             "SE"),

    # Asia
    ("www.nhk.or.jp",           "NHK (Japan)",              "JP"),
    ("www.naver.com",           "Naver (South Korea)",      "KR"),
    ("www.baidu.com",           "Baidu (China)",            "CN"),
    ("timesofindia.indiatimes.com", "Times of India",       "IN"),

    # Oceania
    ("www.abc.net.au",          "ABC News (Australia)",     "AU"),
    ("www.rnz.co.nz",           "RNZ (New Zealand)",        "NZ"),

    # South America
    ("www.globo.com",           "Globo (Brazil)",           "BR"),
    ("www.clarin.com",          "Clarín (Argentina)",       "AR"),

    # Africa
    ("www.news24.com",          "News24 (South Africa)",    "ZA"),
    ("www.nation.africa",       "Nation Africa (Kenya)",    "KE"),

    # Middle East
    ("www.aljazeera.com",       "Al Jazeera (Qatar)",       "QA"),
]

TIMEOUT_SECONDS = 5
SSL_CONTEXT = ssl.create_default_context()


def probe_host(hostname, description, expected_cc):
    """Connect to a host via HTTPS, triggering DNS + TLS."""
    try:
        # DNS resolution (getaddrinfo → recorded by mactrace)
        addrs = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
        ip = addrs[0][4][0] if addrs else "?"

        # TLS connection (connect/send/recv → recorded by mactrace)
        with socket.create_connection((hostname, 443), timeout=TIMEOUT_SECONDS) as sock:
            with SSL_CONTEXT.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Send a minimal HTTP request
                ssock.send(f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                resp = ssock.recv(512).decode("utf-8", errors="replace")
                status = resp.split("\r\n")[0] if resp else "?"

        print(f"  ✓ {description:<35} {ip:<18} [{expected_cc}]  {status}")
        return True

    except Exception as e:
        print(f"  ✗ {description:<35} {'error':<18} [{expected_cc}]  {e}")
        return False


def main():
    print(f"🌍 Geo Test — probing {len(TARGETS)} servers across {len(set(t[2] for t in TARGETS))} countries\n")

    ok = 0
    fail = 0
    t0 = time.monotonic()

    for hostname, desc, cc in TARGETS:
        if probe_host(hostname, desc, cc):
            ok += 1
        else:
            fail += 1

    elapsed = time.monotonic() - t0
    print(f"\nDone: {ok} connected, {fail} failed, {elapsed:.1f}s elapsed")
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    main()
