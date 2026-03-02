"""
Integration tests for the f8 server API endpoints.

Starts the server with a test database, hits each API endpoint,
and verifies the response structure and content.
"""

import os
import sys
import json
import time
import signal
import subprocess
import tempfile
import pytest
import urllib.request
import urllib.error

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'fixtures', 'traces')
SERVER_DIR = os.path.join(PROJECT_ROOT, 'server')
IMPORT_JS = os.path.join(SERVER_DIR, 'import.js')
SERVER_JS = os.path.join(SERVER_DIR, 'server.js')

PORT = 19876  # Unlikely to conflict


def api_get(path):
    """GET an API endpoint and return parsed JSON."""
    url = f'http://localhost:{PORT}{path}'
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


@pytest.fixture(scope='module')
def server_with_test_db(tmp_path_factory):
    """
    Import fixture traces, start the server, yield, then tear down.
    Shared across all tests in this module for speed.
    """
    tmp_dir = tmp_path_factory.mktemp('server_test')
    db_path = str(tmp_dir / 'test.db')
    
    # Import all fixture traces
    for fixture_file in ['simple_echo.json', 'fork_exec_pipeline.json', 'network_with_errors.json']:
        fixture_path = os.path.join(FIXTURES_DIR, fixture_file)
        result = subprocess.run(
            ['node', IMPORT_JS, fixture_path, '--db', db_path],
            capture_output=True, text=True, cwd=SERVER_DIR, timeout=30
        )
        assert result.returncode == 0, f"Import failed for {fixture_file}: {result.stderr}"
    
    # Start server
    server_proc = subprocess.Popen(
        ['node', SERVER_JS, '--db', db_path, '--port', str(PORT)],
        cwd=SERVER_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    
    # Wait for server to be ready
    for i in range(30):
        try:
            urllib.request.urlopen(f'http://localhost:{PORT}/api/traces', timeout=1)
            break
        except (urllib.error.URLError, ConnectionRefusedError):
            time.sleep(0.2)
    else:
        server_proc.kill()
        pytest.fail("Server didn't start within 6 seconds")
    
    yield db_path
    
    # Teardown
    server_proc.send_signal(signal.SIGTERM)
    try:
        server_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server_proc.kill()


class TestTracesEndpoint:
    """Test /api/traces endpoint."""

    def test_lists_all_traces(self, server_with_test_db):
        traces = api_get('/api/traces')
        assert isinstance(traces, list)
        assert len(traces) == 3

    def test_trace_has_required_fields(self, server_with_test_db):
        traces = api_get('/api/traces')
        required = {'id', 'name', 'command', 'event_count', 'duration_ms', 'target_pid'}
        for trace in traces:
            missing = required - set(trace.keys())
            assert not missing, f"Trace {trace.get('name')} missing: {missing}"

    def test_trace_names_match_fixtures(self, server_with_test_db):
        traces = api_get('/api/traces')
        names = {t['name'] for t in traces}
        assert 'simple_echo' in names
        assert 'fork_exec_pipeline' in names
        assert 'network_with_errors' in names


class TestTraceDetailEndpoint:
    """Test /api/traces/:id endpoint."""

    def test_single_trace_detail(self, server_with_test_db):
        traces = api_get('/api/traces')
        trace_id = traces[0]['id']
        detail = api_get(f'/api/traces/{trace_id}')
        assert detail['id'] == trace_id
        assert 'categories' in detail
        assert 'topSyscalls' in detail
        assert 'errorCount' in detail

    def test_categories_have_counts(self, server_with_test_db):
        traces = api_get('/api/traces')
        trace_id = traces[0]['id']
        detail = api_get(f'/api/traces/{trace_id}')
        cats = detail['categories']
        assert isinstance(cats, list)
        for cat in cats:
            assert 'category' in cat
            assert 'count' in cat
            assert cat['count'] > 0

    def test_nonexistent_trace_returns_404(self, server_with_test_db):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            api_get('/api/traces/99999')
        assert exc_info.value.code == 404


class TestEventsEndpoint:
    """Test /api/traces/:id/events endpoint."""

    def test_returns_events(self, server_with_test_db):
        traces = api_get('/api/traces')
        trace_id = traces[0]['id']
        result = api_get(f'/api/traces/{trace_id}/events')
        assert 'events' in result
        assert 'total' in result
        assert 'filtered' in result
        assert len(result['events']) > 0

    def test_category_filter(self, server_with_test_db):
        traces = api_get('/api/traces')
        # Find the network_with_errors trace
        net_trace = next(t for t in traces if t['name'] == 'network_with_errors')
        
        result = api_get(f'/api/traces/{net_trace["id"]}/events?category=network')
        for event in result['events']:
            assert event['category'] == 'network'

    def test_error_filter(self, server_with_test_db):
        traces = api_get('/api/traces')
        net_trace = next(t for t in traces if t['name'] == 'network_with_errors')
        
        result = api_get(f'/api/traces/{net_trace["id"]}/events?errors=true')
        for event in result['events']:
            assert event['errno'] != 0

    def test_pagination(self, server_with_test_db):
        traces = api_get('/api/traces')
        trace_id = traces[0]['id']
        
        page1 = api_get(f'/api/traces/{trace_id}/events?limit=2&offset=0')
        page2 = api_get(f'/api/traces/{trace_id}/events?limit=2&offset=2')
        
        assert len(page1['events']) <= 2
        # Events should be different between pages
        if page1['events'] and page2['events']:
            assert page1['events'][0]['id'] != page2['events'][0]['id']

    def test_search(self, server_with_test_db):
        traces = api_get('/api/traces')
        net_trace = next(t for t in traces if t['name'] == 'network_with_errors')
        
        result = api_get(f'/api/traces/{net_trace["id"]}/events?search=ECONNREFUSED')
        assert result['filtered'] >= 1


class TestProcessTreeEndpoint:
    """Test /api/traces/:id/process-tree endpoint."""

    def test_process_tree_structure(self, server_with_test_db):
        traces = api_get('/api/traces')
        pipe_trace = next(t for t in traces if t['name'] == 'fork_exec_pipeline')
        
        tree = api_get(f'/api/traces/{pipe_trace["id"]}/process-tree')
        assert 'rootPid' in tree
        assert 'nodes' in tree
        assert tree['rootPid'] == 20000

    def test_process_tree_nodes(self, server_with_test_db):
        traces = api_get('/api/traces')
        pipe_trace = next(t for t in traces if t['name'] == 'fork_exec_pipeline')
        
        tree = api_get(f'/api/traces/{pipe_trace["id"]}/process-tree')
        nodes = tree['nodes']
        pids = {n['pid'] for n in nodes}
        assert 20000 in pids
        assert 20001 in pids
        assert 20002 in pids

    def test_process_tree_programs(self, server_with_test_db):
        traces = api_get('/api/traces')
        pipe_trace = next(t for t in traces if t['name'] == 'fork_exec_pipeline')
        
        tree = api_get(f'/api/traces/{pipe_trace["id"]}/process-tree')
        node_map = {n['pid']: n for n in tree['nodes']}
        
        # PID 20001 should have /bin/echo as program
        echo_node = node_map.get(20001, {})
        assert any('/bin/echo' in p for p in echo_node.get('programs', []))


class TestCategoriesEndpoint:
    """Test /api/categories endpoint."""

    def test_returns_all_categories(self, server_with_test_db):
        cats = api_get('/api/categories')
        assert isinstance(cats, dict)
        assert 'file' in cats
        assert 'network' in cats
        assert 'process' in cats
        assert 'other' in cats

    def test_category_has_colors(self, server_with_test_db):
        cats = api_get('/api/categories')
        for cat_id, data in cats.items():
            assert 'bg' in data, f"Category '{cat_id}' missing 'bg'"
            assert 'text' in data, f"Category '{cat_id}' missing 'text'"
            assert data['bg'].startswith('#')
            assert data['text'].startswith('#')
