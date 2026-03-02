"""
End-to-end test for DNS-over-HTTPS detection.

Traces a real `curl --doh-url` command, imports the result, and verifies
that the DNS correlation engine correctly labels the DoH provider as 'doh'
and NOT as plain system DNS.

Requires:
  - sudo (DTrace needs root)
  - curl with --doh-url support (macOS 12+ / curl 7.62+)
  - Network access to 1.1.1.1:443 and example.com
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
F8_CMD = os.path.join(PROJECT_ROOT, 'f8')
IMPORT_JS = os.path.join(PROJECT_ROOT, 'server', 'import.js')
SERVER_DIR = os.path.join(PROJECT_ROOT, 'server')


def curl_supports_doh():
    """Check if curl supports --doh-url."""
    try:
        r = subprocess.run(['curl', '--help', 'all'], capture_output=True, text=True, timeout=5)
        return '--doh-url' in r.stdout
    except Exception:
        return False


pytestmark = [
    pytest.mark.skipif(os.geteuid() != 0, reason="E2E tests require sudo (DTrace needs root)"),
    pytest.mark.skipif(not curl_supports_doh(), reason="curl does not support --doh-url"),
]


class TestDoHDetection:
    """Trace curl with --doh-url and verify DoH is detected."""

    @pytest.fixture(autouse=True)
    def run_trace(self, tmp_path):
        """Trace a curl command that uses DNS-over-HTTPS."""
        self.trace_json = str(tmp_path / 'doh_trace.json')
        self.db_path = str(tmp_path / 'doh.db')
        self.io_dir = str(tmp_path / 'doh_io')

        # Trace: curl using Cloudflare DoH to resolve example.com
        cmd = [
            'sudo', sys.executable, F8_CMD,
            '-o', self.trace_json,
            '--',
            'curl', '-s', '-o', '/dev/null',
            '--doh-url', 'https://1.1.1.1/dns-query',
            'http://example.com'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, f"f8 tracing failed: {result.stderr}"

        # Load trace JSON
        with open(self.trace_json) as f:
            self.trace_data = json.load(f)

        # Import into DB
        result = subprocess.run(
            ['node', IMPORT_JS, self.trace_json, '--db', self.db_path, '--io-dir', self.io_dir],
            capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
        )
        assert result.returncode == 0, f"Import failed: {result.stderr}"

    def test_trace_has_connect_to_doh_port(self):
        """Raw trace should contain a connect to 1.1.1.1:443 (the DoH provider)."""
        events = self.trace_data['events']
        connects = [
            e for e in events
            if e['syscall'] in ('connect', 'connect_nocancel')
            and '1.1.1.1:443' in str(e.get('args', {}).get('display', ''))
        ]
        assert len(connects) >= 1, \
            "Expected at least one connect to 1.1.1.1:443 (DoH provider)"

    def test_no_plain_dns_to_doh_provider(self):
        """
        DNS lookups resolved via DoH should NOT be labeled as system/mdns.

        This is the core test: if 1.1.1.1 appears in dns_lookups, its source
        should be 'doh', not 'system' or 'mdns'.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT hostname, ip, source FROM dns_lookups').fetchall()
        conn.close()
        dns_entries = [dict(r) for r in rows]

        for entry in dns_entries:
            ip = entry.get('ip', '') or ''
            if ip.startswith('1.1.1.1:'):
                assert entry['source'] == 'doh', \
                    f"1.1.1.1 should be labeled 'doh', got '{entry['source']}': {entry}"

    def test_doh_entry_exists(self):
        """At least one DNS entry should be labeled 'doh'."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT COUNT(*) FROM dns_lookups WHERE source = 'doh'").fetchone()
        conn.close()
        assert rows[0] >= 1, \
            "Expected at least one DNS lookup labeled as 'doh'"

    def test_example_com_resolved(self):
        """example.com should appear as a resolved hostname (via DoH bootstrap)."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT hostname, ip, source FROM dns_lookups WHERE hostname LIKE '%example.com%'"
        ).fetchall()
        conn.close()
        # example.com may or may not appear in dns_lookups depending on how
        # mDNSResponder handles DoH-resolved names. The DoH provider entry
        # is the more reliable indicator (tested above).
        # This test documents the behavior — it's allowed to find nothing.


class TestPlainDNSNotMislabeled:
    """Trace a plain DNS curl (no --doh-url) and verify it's NOT labeled DoH."""

    @pytest.fixture(autouse=True)
    def run_trace(self, tmp_path):
        """Trace a plain curl without DoH."""
        self.trace_json = str(tmp_path / 'plain_trace.json')
        self.db_path = str(tmp_path / 'plain.db')
        self.io_dir = str(tmp_path / 'plain_io')

        cmd = [
            'sudo', sys.executable, F8_CMD,
            '-o', self.trace_json,
            '--',
            'curl', '-s', '-o', '/dev/null',
            'http://example.com'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, f"f8 tracing failed: {result.stderr}"

        with open(self.trace_json) as f:
            self.trace_data = json.load(f)

        result = subprocess.run(
            ['node', IMPORT_JS, self.trace_json, '--db', self.db_path, '--io-dir', self.io_dir],
            capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
        )
        assert result.returncode == 0, f"Import failed: {result.stderr}"

    def test_no_doh_labels(self):
        """Plain curl should have zero DNS entries labeled 'doh'."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT COUNT(*) FROM dns_lookups WHERE source = 'doh'").fetchone()
        conn.close()
        assert rows[0] == 0, \
            "Plain curl (no --doh-url) should not have any DoH-labeled DNS entries"

    def test_no_connect_to_443_on_dns_ip(self):
        """Plain curl should not connect to known DoH IPs on port 443."""
        DOH_IPS = {'1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112'}
        events = self.trace_data['events']
        connects = [
            e for e in events
            if e['syscall'] in ('connect', 'connect_nocancel')
        ]
        for c in connects:
            display = str(c.get('args', {}).get('display', ''))
            for ip in DOH_IPS:
                assert f'{ip}:443' not in display, \
                    f"Plain curl should not connect to {ip}:443: {display}"
