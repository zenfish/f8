#!/usr/bin/env python3
"""
mactrace_categories.py - Syscall category definitions (loaded from syscalls.json)

This module provides the mapping of syscalls to categories, colors, and display
order. All data is loaded from syscalls.json — edit THAT file to add/remove
syscalls or categories.

Usage as module:
    from mactrace_categories import get_category, get_color, get_text_color

Usage standalone:
    ./mactrace_categories.py           # Summary
    ./mactrace_categories.py -a        # All syscalls
    ./mactrace_categories.py --verify  # Verify no duplicates, valid colors
"""

import json
import os
import sys
sys.dont_write_bytecode = True

# =============================================================================
# LOAD DATA FROM syscalls.json
# =============================================================================

def _find_syscalls_json():
    """Find syscalls.json relative to this script's location."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, 'syscalls.json')
    if os.path.exists(path):
        return path
    # Fallback: check current directory
    if os.path.exists('syscalls.json'):
        return 'syscalls.json'
    raise FileNotFoundError(
        f"syscalls.json not found in {script_dir} or current directory. "
        "This file is required — it defines all syscall categories."
    )


def _load_syscall_data():
    """Load and parse syscalls.json, returning structured data."""
    path = _find_syscalls_json()
    with open(path, 'r') as f:
        data = json.load(f)
    
    categories = data.get('categories', [])
    default_cat = data.get('defaultCategory', {
        'id': 'other', 'label': 'Other',
        'color': '#878787', 'textColor': '#ffffff'
    })
    
    # Build lookup tables
    syscall_to_category = {}
    category_colors = {}
    category_text_colors = {}
    category_order = []
    category_labels = {}
    category_descriptions = {}
    syscall_sets = {}
    
    for cat in categories:
        cat_id = cat['id']
        category_order.append(cat_id)
        category_colors[cat_id] = cat['color']
        category_text_colors[cat_id] = cat.get('textColor', '#ffffff')
        category_labels[cat_id] = cat.get('label', cat_id.capitalize())
        category_descriptions[cat_id] = cat.get('description', '')
        syscall_sets[cat_id] = set(cat.get('syscalls', []))
        
        for syscall in cat.get('syscalls', []):
            if syscall in syscall_to_category:
                print(f"WARNING: syscall '{syscall}' in both "
                      f"'{syscall_to_category[syscall]}' and '{cat_id}' — "
                      f"using '{cat_id}'", file=sys.stderr)
            syscall_to_category[syscall] = cat_id
    
    # Add default category
    default_id = default_cat['id']
    category_order.append(default_id)
    category_colors[default_id] = default_cat['color']
    category_text_colors[default_id] = default_cat.get('textColor', '#ffffff')
    category_labels[default_id] = default_cat.get('label', 'Other')
    category_descriptions[default_id] = default_cat.get('description', '')
    
    return {
        'syscall_to_category': syscall_to_category,
        'category_colors': category_colors,
        'category_text_colors': category_text_colors,
        'category_order': category_order,
        'category_labels': category_labels,
        'category_descriptions': category_descriptions,
        'syscall_sets': syscall_sets,
    }


# Load once at import time
_DATA = _load_syscall_data()

# =============================================================================
# PUBLIC API (same interface as before — drop-in replacement)
# =============================================================================

SYSCALL_CATEGORIES = _DATA['syscall_sets']
CATEGORY_COLORS = _DATA['category_colors']
CATEGORY_ORDER = _DATA['category_order']


def get_category(syscall: str) -> str:
    """
    Get the category for a syscall.
    
    Args:
        syscall: The syscall name (e.g., 'open', 'socket', '__mac_get_file')
        
    Returns:
        Category name (e.g., 'file', 'network', 'mac') or 'other' if unknown.
    """
    return _DATA['syscall_to_category'].get(syscall, 'other')


def get_color(category: str) -> str:
    """
    Get the background color for a category.
    
    Args:
        category: The category name
        
    Returns:
        Hex color string (e.g., '#276419')
    """
    return _DATA['category_colors'].get(category, _DATA['category_colors'].get('other', '#878787'))


def get_text_color(category: str) -> str:
    """
    Get appropriate text color for a category background.
    
    Args:
        category: The category name
        
    Returns:
        Hex color string for readable text on the category's background.
    """
    return _DATA['category_text_colors'].get(category, '#ffffff')


def get_label(category: str) -> str:
    """
    Get the display label for a category.
    
    Args:
        category: The category id (e.g., 'necp')
        
    Returns:
        Human-readable label (e.g., 'NECP')
    """
    return _DATA['category_labels'].get(category, category.capitalize())


def get_categories_for_display() -> list:
    """
    Get list of categories in display order.
    
    Returns:
        List of category names in preferred display order.
    """
    return CATEGORY_ORDER.copy()


def get_all_category_data() -> dict:
    """
    Get complete category data for serialization (used by JS consumers).
    
    Returns:
        Dict of category_id → {color, textColor, label, order}
    """
    result = {}
    for i, cat_id in enumerate(CATEGORY_ORDER):
        result[cat_id] = {
            'color': _DATA['category_colors'].get(cat_id),
            'textColor': _DATA['category_text_colors'].get(cat_id),
            'label': _DATA['category_labels'].get(cat_id),
            'order': i,
        }
    return result


def get_all_syscall_mappings() -> dict:
    """
    Get complete syscall→category mapping for serialization.
    
    Returns:
        Dict of syscall_name → category_id
    """
    return dict(_DATA['syscall_to_category'])


# =============================================================================
# MAIN - Print category summary when run directly
# =============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Display mactrace syscall categories (from syscalls.json).',
        epilog='Edit syscalls.json to add/remove syscalls or categories.'
    )
    parser.add_argument('-a', '--all', action='store_true',
                        help='Show all syscalls (default: first 5 per category)')
    parser.add_argument('--verify', action='store_true',
                        help='Verify data integrity (no duplicate syscalls, valid colors)')
    parser.add_argument('--json', action='store_true',
                        help='Output category→syscall mapping as JSON')
    args = parser.parse_args()
    
    if args.json:
        output = {
            'categories': get_all_category_data(),
            'syscalls': get_all_syscall_mappings(),
        }
        print(json.dumps(output, indent=2))
        sys.exit(0)
    
    if args.verify:
        errors = 0
        # Check for duplicate syscalls
        seen = {}
        for cat_id, syscalls in SYSCALL_CATEGORIES.items():
            for s in syscalls:
                if s in seen:
                    print(f"ERROR: '{s}' in both '{seen[s]}' and '{cat_id}'")
                    errors += 1
                seen[s] = cat_id
        
        # Check valid hex colors
        import re
        for cat_id, color in CATEGORY_COLORS.items():
            if not re.match(r'^#[0-9a-fA-F]{6}$', color):
                print(f"ERROR: Invalid color '{color}' for category '{cat_id}'")
                errors += 1
        
        if errors == 0:
            print(f"OK: {len(seen)} syscalls across {len(SYSCALL_CATEGORIES)} categories, all valid")
        else:
            print(f"FAILED: {errors} error(s)")
            sys.exit(1)
        sys.exit(0)
    
    print("mactrace syscall categories (from syscalls.json)\n")
    print(f"{'Category':<12} {'Count':>6}  Syscalls")
    print("-" * 70)
    
    for cat in CATEGORY_ORDER:
        if cat in SYSCALL_CATEGORIES:
            syscalls = sorted(SYSCALL_CATEGORIES[cat])
            if args.all:
                syscall_str = ', '.join(syscalls)
            else:
                preview = ', '.join(syscalls[:5])
                if len(syscalls) > 5:
                    preview += f', ... (+{len(syscalls) - 5} more)'
                syscall_str = preview
            print(f"{cat:<12} {len(syscalls):>6}  {syscall_str}")
    
    total = sum(len(s) for s in SYSCALL_CATEGORIES.values())
    print("-" * 70)
    print(f"{'Total':<12} {total:>6}")
