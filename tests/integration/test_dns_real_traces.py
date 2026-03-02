"""
Integration tests using real captured traces from actual curl commands.

These fixtures were captured by tracing real network commands with f8:
  - real_curl_doh.json: curl --doh-url https://1.1.1.1/dns-query http://example.com
  - real_curl_plain.json: curl http://example.com (plain DNS)

Trimmed to network syscalls only (connect/sendmsg/recvmsg/socket) to keep
fixtures small while preserving the exact event patterns that the DNS
classification engine sees in production.

No sudo required — these test the import pipeline against real-world traces.
"""

import json
import os
import sqlite3
import subprocess
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'fixtures', 'traces')
SERVER_DIR = os.path.join(PROJECT_ROOT, 'server')
IMPORT_JS = os.path.join(SERVER_DIR, 'import.js')


def import_trace(json_file, tmp_path, name):
    """Import a trace fixture and return the db path."""
    db_path = str(tmp_path / f'{name}.db')
    io_dir = str(tmp_path / f'{name}_io')
    result = subprocess.run(
        ['node', IMPORT_JS, json_file, '--db', db_path, '--io-dir', io_dir],
        capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
    )
    assert result.returncode == 0, f"Import failed: {result.stderr}"
    return db_path


def get_dns_entries(db_path):
    """Get all DNS lookup entries from the database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT hostname, ip, source FROM dns_lookups').fetchall()
    conn.close()
    return [dict(r) for r in rows]


class TestRealDoHTrace:
    """Tests against a real captured trace of curl --doh-url."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        fixture = os.path.join(FIXTURES_DIR, 'real_curl_doh.json')
        self.db_path = import_trace(fixture, tmp_path, 'real_doh')
        self.dns = get_dns_entries(self.db_path)

    def test_doh_detected(self):
        """Real DoH curl trace must produce at least one 'doh' DNS entry."""
        doh_entries = [e for e in self.dns if e['source'] == 'doh']
        assert len(doh_entries) >= 1, \
            f"Expected DoH entry from real curl --doh-url trace, got: {self.dns}"

    def test_cloudflare_identified(self):
        """The DoH provider should be identified as Cloudflare."""
        providers = [e['hostname'] for e in self.dns if e['source'] == 'doh']
        assert any('cloudflare' in p.lower() for p in providers), \
            f"Expected Cloudflare as DoH provider, got: {providers}"

    def test_doh_ip_is_cloudflare(self):
        """The DoH entry should point to 1.1.1.1:443."""
        doh_entries = [e for e in self.dns if e['source'] == 'doh']
        ips = [e['ip'] for e in doh_entries]
        assert any('1.1.1.1:443' in ip for ip in ips), \
            f"Expected 1.1.1.1:443 in DoH entry, got: {ips}"

    def test_no_system_dns_for_doh_ip(self):
        """1.1.1.1 should not appear as 'system' or 'mdns' source."""
        for entry in self.dns:
            if entry['ip'] and '1.1.1.1' in entry['ip']:
                assert entry['source'] not in ('system', 'mdns'), \
                    f"1.1.1.1 mislabeled as {entry['source']}: {entry}"


class TestRealPlainTrace:
    """Tests against a real captured trace of plain curl (no DoH)."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        fixture = os.path.join(FIXTURES_DIR, 'real_curl_plain.json')
        self.db_path = import_trace(fixture, tmp_path, 'real_plain')
        self.dns = get_dns_entries(self.db_path)

    def test_no_doh_entries(self):
        """Plain curl must not produce any DoH-labeled DNS entries."""
        doh_entries = [e for e in self.dns if e['source'] == 'doh']
        assert len(doh_entries) == 0, \
            f"Plain curl should have no DoH entries, got: {doh_entries}"

    def test_no_dot_entries(self):
        """Plain curl must not produce any DoT-labeled DNS entries."""
        dot_entries = [e for e in self.dns if e['source'] == 'dot']
        assert len(dot_entries) == 0, \
            f"Plain curl should have no DoT entries, got: {dot_entries}"
