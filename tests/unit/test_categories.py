"""
Tests for f8_categories.py — syscall→category mappings from syscalls.json.

Validates:
- Every syscall maps to exactly one category (no duplicates)
- All colors are valid hex
- Category order is consistent
- get_category() returns correct results
- Unknown syscalls fall through to 'other'
- _nocancel variants are handled
- The JSON data is well-formed
"""

import re
import json
import pytest

from f8_categories import (
    get_category, get_color, get_text_color, get_label,
    get_categories_for_display, get_all_category_data, get_all_syscall_mappings,
    SYSCALL_CATEGORIES, CATEGORY_COLORS, CATEGORY_ORDER,
)


# ============================================================================
# JSON Data Integrity
# ============================================================================

class TestSyscallsJsonIntegrity:
    """Validate the structure and integrity of syscalls.json."""

    def test_json_loads(self, syscalls_json_path):
        """syscalls.json is valid JSON."""
        with open(syscalls_json_path) as f:
            data = json.load(f)
        assert 'categories' in data
        assert isinstance(data['categories'], list)

    def test_categories_have_required_fields(self, syscalls_data):
        """Every category has id, label, color, textColor, syscalls."""
        required = {'id', 'label', 'color', 'textColor', 'syscalls'}
        for cat in syscalls_data['categories']:
            missing = required - set(cat.keys())
            assert not missing, f"Category '{cat.get('id', '?')}' missing: {missing}"

    def test_category_ids_are_unique(self, syscalls_data):
        """No two categories share the same id."""
        ids = [cat['id'] for cat in syscalls_data['categories']]
        assert len(ids) == len(set(ids)), f"Duplicate category ids: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_colors_are_valid_hex(self, syscalls_data):
        """All color values are valid 6-digit hex colors."""
        hex_pattern = re.compile(r'^#[0-9a-fA-F]{6}$')
        for cat in syscalls_data['categories']:
            assert hex_pattern.match(cat['color']), \
                f"Invalid color '{cat['color']}' in category '{cat['id']}'"
            assert hex_pattern.match(cat['textColor']), \
                f"Invalid textColor '{cat['textColor']}' in category '{cat['id']}'"
        
        # Also check defaultCategory
        default = syscalls_data.get('defaultCategory', {})
        if 'color' in default:
            assert hex_pattern.match(default['color'])
        if 'textColor' in default:
            assert hex_pattern.match(default['textColor'])

    def test_no_duplicate_syscalls(self, syscalls_data):
        """No syscall appears in more than one category."""
        seen = {}
        duplicates = []
        for cat in syscalls_data['categories']:
            for sc in cat.get('syscalls', []):
                if sc in seen:
                    duplicates.append(f"'{sc}' in both '{seen[sc]}' and '{cat['id']}'")
                seen[sc] = cat['id']
        assert not duplicates, f"Duplicate syscalls:\n" + "\n".join(duplicates)

    def test_no_empty_syscall_names(self, syscalls_data):
        """No empty strings in syscall lists."""
        for cat in syscalls_data['categories']:
            for sc in cat.get('syscalls', []):
                assert sc.strip(), f"Empty syscall name in category '{cat['id']}'"

    def test_syscall_names_are_valid_identifiers(self, syscalls_data):
        """Syscall names are valid C identifiers (letters, digits, underscores)."""
        identifier_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
        for cat in syscalls_data['categories']:
            for sc in cat.get('syscalls', []):
                assert identifier_re.match(sc), \
                    f"Invalid syscall name '{sc}' in category '{cat['id']}'"

    def test_has_default_category(self, syscalls_data):
        """syscalls.json defines a defaultCategory."""
        assert 'defaultCategory' in syscalls_data
        default = syscalls_data['defaultCategory']
        assert 'id' in default
        assert 'color' in default

    def test_has_doc(self, syscalls_data):
        """syscalls.json has a _doc field explaining how to use it."""
        assert '_doc' in syscalls_data
        doc = syscalls_data['_doc']
        assert isinstance(doc, list) or isinstance(doc, str)


# ============================================================================
# Category Lookup
# ============================================================================

class TestGetCategory:
    """Test get_category() function."""

    def test_known_file_syscalls(self):
        """File category includes open, read, write, close."""
        assert get_category('open') == 'file'
        assert get_category('read') == 'file'
        assert get_category('write') == 'file'
        assert get_category('close') == 'file'
        assert get_category('stat') == 'file'
        assert get_category('fstat') == 'file'
        assert get_category('lstat') == 'file'
        assert get_category('openat') == 'file'
        assert get_category('unlink') == 'file'

    def test_known_network_syscalls(self):
        """Network category includes socket, connect, send, recv."""
        assert get_category('socket') == 'network'
        assert get_category('connect') == 'network'
        assert get_category('bind') == 'network'
        assert get_category('listen') == 'network'
        assert get_category('accept') == 'network'
        assert get_category('sendto') == 'network'
        assert get_category('recvfrom') == 'network'

    def test_known_process_syscalls(self):
        """Process category includes fork, exec, exit, wait."""
        assert get_category('fork') == 'process'
        assert get_category('vfork') == 'process'
        assert get_category('execve') == 'process'
        assert get_category('posix_spawn') == 'process'
        assert get_category('exit') == 'process'
        assert get_category('wait4') == 'process'
        assert get_category('getpid') == 'process'

    def test_known_memory_syscalls(self):
        assert get_category('mmap') == 'memory'
        assert get_category('munmap') == 'memory'
        assert get_category('mprotect') == 'memory'

    def test_known_signal_syscalls(self):
        assert get_category('sigaction') == 'signal'
        assert get_category('kill') == 'signal'

    def test_known_ipc_syscalls(self):
        assert get_category('pipe') == 'ipc'
        assert get_category('shm_open') == 'ipc'

    def test_known_poll_syscalls(self):
        assert get_category('kevent') == 'poll'
        assert get_category('kqueue') == 'poll'
        assert get_category('select') == 'poll'
        assert get_category('poll') == 'poll'

    def test_known_time_syscalls(self):
        assert get_category('gettimeofday') == 'time'
        assert get_category('clock_gettime') == 'time'
        assert get_category('nanosleep') == 'time'

    def test_known_mac_syscalls(self):
        assert get_category('__mac_syscall') == 'mac'
        assert get_category('__mac_get_proc') == 'mac'

    def test_known_necp_syscalls(self):
        assert get_category('necp_client_action') == 'necp'
        assert get_category('necp_open') == 'necp'

    def test_known_thread_syscalls(self):
        assert get_category('bsdthread_create') == 'thread'
        assert get_category('workq_kernreturn') == 'thread'

    def test_nocancel_variants(self):
        """_nocancel variants in syscalls.json should be found directly."""
        assert get_category('open_nocancel') == 'file'
        assert get_category('read_nocancel') == 'file'
        assert get_category('write_nocancel') == 'file'
        assert get_category('close_nocancel') == 'file'
        assert get_category('connect_nocancel') == 'network'
        assert get_category('sendto_nocancel') == 'network'
        assert get_category('recvfrom_nocancel') == 'network'

    def test_unknown_syscall_returns_other(self):
        """Unknown syscalls should return 'other'."""
        assert get_category('completely_made_up_syscall') == 'other'
        assert get_category('') == 'other'
        assert get_category('xyzzy') == 'other'

    def test_every_listed_syscall_maps_to_its_category(self, syscalls_data):
        """Cross-check: every syscall in JSON returns its listed category."""
        for cat in syscalls_data['categories']:
            for sc in cat.get('syscalls', []):
                result = get_category(sc)
                assert result == cat['id'], \
                    f"get_category('{sc}') returned '{result}', expected '{cat['id']}'"


# ============================================================================
# Color Functions
# ============================================================================

class TestColors:
    """Test color retrieval functions."""

    def test_get_color_for_all_categories(self):
        """get_color() returns valid hex for every category in order."""
        hex_re = re.compile(r'^#[0-9a-fA-F]{6}$')
        for cat in CATEGORY_ORDER:
            color = get_color(cat)
            assert hex_re.match(color), f"Invalid color for '{cat}': {color}"

    def test_get_text_color_for_all_categories(self):
        """get_text_color() returns valid hex for every category."""
        hex_re = re.compile(r'^#[0-9a-fA-F]{6}$')
        for cat in CATEGORY_ORDER:
            text_color = get_text_color(cat)
            assert hex_re.match(text_color), f"Invalid text color for '{cat}': {text_color}"

    def test_unknown_category_color_returns_default(self):
        """Unknown category returns the 'other' category's color."""
        color = get_color('nonexistent_category')
        other_color = get_color('other')
        assert color == other_color

    def test_text_color_is_black_or_white(self):
        """Text colors should be high contrast (black or white)."""
        for cat in CATEGORY_ORDER:
            tc = get_text_color(cat).lower()
            assert tc in ('#ffffff', '#000000'), \
                f"Category '{cat}' text color '{tc}' is not black or white"


# ============================================================================
# Category Order & Labels
# ============================================================================

class TestCategoryOrder:
    """Test category ordering and label functions."""

    def test_order_includes_all_categories(self, syscalls_data):
        """CATEGORY_ORDER includes every category from JSON plus defaultCategory."""
        json_ids = {cat['id'] for cat in syscalls_data['categories']}
        default_id = syscalls_data.get('defaultCategory', {}).get('id')
        if default_id:
            json_ids.add(default_id)
        
        order_set = set(CATEGORY_ORDER)
        assert json_ids == order_set, \
            f"Mismatch: in JSON but not order: {json_ids - order_set}, " \
            f"in order but not JSON: {order_set - json_ids}"

    def test_order_has_no_duplicates(self):
        """CATEGORY_ORDER has no duplicate entries."""
        assert len(CATEGORY_ORDER) == len(set(CATEGORY_ORDER))

    def test_other_is_last(self):
        """'other' should be the last category in display order."""
        assert CATEGORY_ORDER[-1] == 'other'

    def test_get_label(self):
        """get_label() returns human-readable labels."""
        assert get_label('file') == 'File'
        assert get_label('necp') == 'NECP'
        assert get_label('mac') == 'MAC'
        assert get_label('other') == 'Other'

    def test_get_categories_for_display_returns_copy(self):
        """get_categories_for_display() returns a copy, not the original."""
        display = get_categories_for_display()
        display.append('garbage')
        assert 'garbage' not in CATEGORY_ORDER


# ============================================================================
# Serialization
# ============================================================================

class TestSerialization:
    """Test functions used for JS consumers."""

    def test_get_all_category_data(self):
        """get_all_category_data() returns complete data for all categories."""
        data = get_all_category_data()
        for cat in CATEGORY_ORDER:
            assert cat in data, f"Missing category '{cat}' in serialized data"
            assert 'color' in data[cat]
            assert 'textColor' in data[cat]
            assert 'label' in data[cat]
            assert 'order' in data[cat]

    def test_get_all_syscall_mappings(self):
        """get_all_syscall_mappings() returns complete mapping."""
        mappings = get_all_syscall_mappings()
        assert isinstance(mappings, dict)
        assert len(mappings) > 200  # We have 249 syscalls
        assert mappings['open'] == 'file'
        assert mappings['socket'] == 'network'

    def test_category_data_order_is_sequential(self):
        """Category order values should be 0, 1, 2, ..., N."""
        data = get_all_category_data()
        orders = sorted(v['order'] for v in data.values())
        assert orders == list(range(len(orders)))
