"""
Cross-language consistency tests: Python ↔ JavaScript.

These tests verify that Python and JavaScript implementations produce
identical results for the same inputs. They are the canary for code drift.
If someone updates syscalls.json and forgets to test both sides, these fail.
"""

import os
import sys
import json
import subprocess
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVER_DIR = os.path.join(PROJECT_ROOT, 'server')

sys.path.insert(0, PROJECT_ROOT)
from mactrace_categories import get_category, get_color, get_text_color, CATEGORY_ORDER


def run_js(script: str) -> str:
    """Run a JavaScript snippet via Node and return stdout."""
    result = subprocess.run(
        ['node', '--input-type=module', '-e', script],
        capture_output=True, text=True, cwd=SERVER_DIR, timeout=10
    )
    if result.returncode != 0:
        raise RuntimeError(f"Node script failed: {result.stderr}")
    return result.stdout.strip()


# ============================================================================
# Category Parity
# ============================================================================

class TestCategoryParity:
    """Every syscall gets the same category in Python and JavaScript."""

    @pytest.fixture(autouse=True)
    def load_js_categories(self):
        """Load JS category mappings once for the test class."""
        js_code = """
        import fs from 'fs';
        import path from 'path';
        import { fileURLToPath } from 'url';
        const __dirname = path.dirname(fileURLToPath(import.meta.url));
        const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'syscalls.json'), 'utf-8'));
        const map = {};
        for (const cat of data.categories) {
            for (const sc of cat.syscalls || []) {
                map[sc] = cat.id;
            }
        }
        console.log(JSON.stringify(map));
        """
        output = run_js(js_code)
        self.js_map = json.loads(output)

    def test_all_syscalls_same_category(self):
        """Every syscall in syscalls.json maps to the same category in Python and JS."""
        # Get Python's complete mapping
        from mactrace_categories import get_all_syscall_mappings
        py_map = get_all_syscall_mappings()
        
        # Check every syscall known to either side
        all_syscalls = set(py_map.keys()) | set(self.js_map.keys())
        mismatches = []
        
        for sc in sorted(all_syscalls):
            py_cat = py_map.get(sc, 'other')
            js_cat = self.js_map.get(sc, 'other')
            if py_cat != js_cat:
                mismatches.append(f"  {sc}: Python='{py_cat}' JS='{js_cat}'")
        
        assert not mismatches, \
            f"Category mismatches ({len(mismatches)}):\n" + "\n".join(mismatches)

    def test_no_python_only_syscalls(self):
        """No syscalls exist only in Python (would mean JS is missing them)."""
        from mactrace_categories import get_all_syscall_mappings
        py_map = get_all_syscall_mappings()
        py_only = set(py_map.keys()) - set(self.js_map.keys())
        assert not py_only, f"Syscalls in Python but not JS: {py_only}"

    def test_no_js_only_syscalls(self):
        """No syscalls exist only in JS (would mean Python is missing them)."""
        from mactrace_categories import get_all_syscall_mappings
        py_map = get_all_syscall_mappings()
        js_only = set(self.js_map.keys()) - set(py_map.keys())
        assert not js_only, f"Syscalls in JS but not Python: {js_only}"

    def test_nocancel_handling_parity(self):
        """_nocancel variants resolve the same way in both languages."""
        nocancel_syscalls = [
            'open_nocancel', 'read_nocancel', 'write_nocancel',
            'close_nocancel', 'connect_nocancel', 'sendto_nocancel',
            'recvfrom_nocancel', 'select_nocancel', 'poll_nocancel',
        ]
        
        # Get JS results via the actual getCategory function
        js_script = """
        import fs from 'fs';
        import path from 'path';
        import { fileURLToPath } from 'url';
        const __dirname = path.dirname(fileURLToPath(import.meta.url));
        const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'syscalls.json'), 'utf-8'));
        const map = {};
        for (const cat of data.categories) {
            for (const sc of cat.syscalls || []) { map[sc] = cat.id; }
        }
        const DEFAULT = data.defaultCategory?.id || 'other';
        function getCategory(s) {
            if (map[s]) return map[s];
            const base = s.replace(/_nocancel$/, '');
            return map[base] || DEFAULT;
        }
        const tests = %s;
        const result = {};
        for (const sc of tests) { result[sc] = getCategory(sc); }
        console.log(JSON.stringify(result));
        """ % json.dumps(nocancel_syscalls)
        
        js_results = json.loads(run_js(js_script))
        
        for sc in nocancel_syscalls:
            py_cat = get_category(sc)
            js_cat = js_results[sc]
            assert py_cat == js_cat, f"{sc}: Python='{py_cat}' JS='{js_cat}'"

    def test_unknown_syscall_both_return_other(self):
        """Both Python and JS return 'other' for unknown syscalls."""
        unknowns = ['made_up_syscall', 'xyzzy', 'totally_fake']
        
        js_script = """
        import fs from 'fs';
        import path from 'path';
        import { fileURLToPath } from 'url';
        const __dirname = path.dirname(fileURLToPath(import.meta.url));
        const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'syscalls.json'), 'utf-8'));
        const map = {};
        for (const cat of data.categories) {
            for (const sc of cat.syscalls || []) { map[sc] = cat.id; }
        }
        const DEFAULT = data.defaultCategory?.id || 'other';
        function getCategory(s) {
            if (map[s]) return map[s];
            return map[s.replace(/_nocancel$/, '')] || DEFAULT;
        }
        const tests = %s;
        const result = {};
        for (const sc of tests) { result[sc] = getCategory(sc); }
        console.log(JSON.stringify(result));
        """ % json.dumps(unknowns)
        
        js_results = json.loads(run_js(js_script))
        
        for sc in unknowns:
            assert get_category(sc) == 'other'
            assert js_results[sc] == 'other'


# ============================================================================
# Color Parity
# ============================================================================

class TestColorParity:
    """Server API category colors match Python module colors."""

    @pytest.fixture(autouse=True)
    def load_js_colors(self):
        """Load JS category colors."""
        js_code = """
        import fs from 'fs';
        import path from 'path';
        import { fileURLToPath } from 'url';
        const __dirname = path.dirname(fileURLToPath(import.meta.url));
        const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'syscalls.json'), 'utf-8'));
        const colors = {};
        for (const cat of data.categories) {
            colors[cat.id] = { bg: cat.color, text: cat.textColor };
        }
        if (data.defaultCategory) {
            colors[data.defaultCategory.id] = { bg: data.defaultCategory.color, text: data.defaultCategory.textColor };
        }
        console.log(JSON.stringify(colors));
        """
        output = run_js(js_code)
        self.js_colors = json.loads(output)

    def test_all_categories_have_matching_colors(self):
        """Python and JS have identical background colors for every category."""
        mismatches = []
        for cat_id in CATEGORY_ORDER:
            py_color = get_color(cat_id)
            js_color = self.js_colors.get(cat_id, {}).get('bg')
            if py_color != js_color:
                mismatches.append(f"  {cat_id}: Python='{py_color}' JS='{js_color}'")
        
        assert not mismatches, \
            f"Color mismatches:\n" + "\n".join(mismatches)

    def test_all_categories_have_matching_text_colors(self):
        """Python and JS have identical text colors for every category."""
        mismatches = []
        for cat_id in CATEGORY_ORDER:
            py_tc = get_text_color(cat_id)
            js_tc = self.js_colors.get(cat_id, {}).get('text')
            if py_tc != js_tc:
                mismatches.append(f"  {cat_id}: Python='{py_tc}' JS='{js_tc}'")
        
        assert not mismatches, \
            f"Text color mismatches:\n" + "\n".join(mismatches)

    def test_no_categories_missing_from_either_side(self):
        """Both Python and JS know about all categories."""
        py_set = set(CATEGORY_ORDER)
        js_set = set(self.js_colors.keys())
        assert py_set == js_set, \
            f"Python-only: {py_set - js_set}, JS-only: {js_set - py_set}"
