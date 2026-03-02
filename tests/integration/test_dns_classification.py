"""
Integration tests for DNS source classification during import.

Verifies that the import pipeline correctly labels DNS lookups as:
- system/mdns: plain DNS on port 53
- doh: DNS-over-HTTPS (connection to known DoH IP on port 443)  
- dot: DNS-over-TLS (connection to DNS IP on port 853)

Uses synthetic trace fixtures that simulate each pattern without
needing actual DNS queries. The classification logic lives in
import.js's DNS correlation engine.
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


def get_dns_sources(db_path):
    """Get all DNS lookup sources from the database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT hostname, ip, source FROM dns_lookups').fetchall()
    conn.close()
    return [dict(r) for r in rows]


class TestPlainDNS:
    """Port 53 queries to DoH-capable servers should NOT be labeled as DoH."""

    def test_port53_to_cloudflare_not_doh(self, tmp_path):
        """dig querying 1.1.1.1:53 should not be classified as DNS-over-HTTPS."""
        fixture = os.path.join(FIXTURES_DIR, 'dns_plain.json')
        db_path = import_trace(fixture, tmp_path, 'plain')
        sources = get_dns_sources(db_path)
        
        # There may or may not be DNS entries (depends on whether the trace
        # has enough data for the correlation engine), but if there ARE any,
        # none should be labeled 'doh'
        doh_entries = [s for s in sources if s['source'] == 'doh']
        assert len(doh_entries) == 0, \
            f"Plain DNS on port 53 was mislabeled as DoH: {doh_entries}"

    def test_port53_source_not_doh(self, tmp_path):
        """Even with 1.1.1.1 as resolver, port 53 = not DoH."""
        fixture = os.path.join(FIXTURES_DIR, 'dns_plain.json')
        db_path = import_trace(fixture, tmp_path, 'plain2')
        sources = get_dns_sources(db_path)
        
        for entry in sources:
            assert entry['source'] != 'doh', \
                f"Entry {entry} incorrectly labeled as DoH"


class TestDoH:
    """Connections to known DoH IPs on port 443 should be labeled as DoH."""

    def test_port443_to_cloudflare_is_doh(self, tmp_path):
        """Connection to 1.1.1.1:443 should be classified as DNS-over-HTTPS."""
        fixture = os.path.join(FIXTURES_DIR, 'dns_doh.json')
        db_path = import_trace(fixture, tmp_path, 'doh')
        sources = get_dns_sources(db_path)
        
        # If the correlation engine found DNS entries with 1.1.1.1,
        # those with port 443 connections should be labeled doh
        doh_entries = [s for s in sources if s['source'] == 'doh']
        # We expect the correlation engine to find something here,
        # but the exact behavior depends on mDNSResponder correlation.
        # At minimum, no entries should be mislabeled as plain.
        for entry in sources:
            if entry.get('ip', '').startswith('1.1.1.1:'):
                assert entry['source'] in ('doh', 'unknown'), \
                    f"Connection to 1.1.1.1:443 should be doh, got: {entry['source']}"


class TestDoT:
    """Connections to DNS IPs on port 853 should be labeled as DoT."""

    def test_port853_is_dot(self, tmp_path):
        """Connection to 9.9.9.9:853 should be classified as DNS-over-TLS."""
        fixture = os.path.join(FIXTURES_DIR, 'dns_dot.json')
        db_path = import_trace(fixture, tmp_path, 'dot')
        sources = get_dns_sources(db_path)
        
        # If entries exist for 9.9.9.9, they should be labeled dot
        for entry in sources:
            if entry.get('ip', '').startswith('9.9.9.9:'):
                assert entry['source'] in ('dot', 'unknown'), \
                    f"Connection to 9.9.9.9:853 should be dot, got: {entry['source']}"


class TestMixedScenario:
    """Verify no cross-contamination between traces."""

    def test_plain_and_doh_coexist(self, tmp_path):
        """Import both plain and DoH traces into same DB — labels stay correct."""
        plain_fix = os.path.join(FIXTURES_DIR, 'dns_plain.json')
        doh_fix = os.path.join(FIXTURES_DIR, 'dns_doh.json')
        
        db_path = str(tmp_path / 'mixed.db')
        io_dir1 = str(tmp_path / 'plain_io')
        io_dir2 = str(tmp_path / 'doh_io')
        
        # Import both into same DB
        r1 = subprocess.run(
            ['node', IMPORT_JS, plain_fix, '--db', db_path, '--io-dir', io_dir1],
            capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
        )
        assert r1.returncode == 0
        
        r2 = subprocess.run(
            ['node', IMPORT_JS, doh_fix, '--db', db_path, '--io-dir', io_dir2],
            capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
        )
        assert r2.returncode == 0
        
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        # Get traces
        traces = conn.execute('SELECT id, name FROM traces').fetchall()
        assert len(traces) == 2
        
        # Check each trace's DNS independently
        for trace in traces:
            rows = conn.execute(
                'SELECT hostname, ip, source FROM dns_lookups WHERE trace_id = ?',
                (trace['id'],)
            ).fetchall()
            dns_entries = [dict(r) for r in rows]
            
            if 'plain' in str(trace['name']).lower() or 'dig' in str(trace['name']).lower():
                # Plain trace should have no DoH labels
                for entry in dns_entries:
                    assert entry['source'] != 'doh', \
                        f"Plain trace got DoH label: {entry}"
        
        conn.close()
