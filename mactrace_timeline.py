#!/usr/bin/env python3
"""
Generate an HTML timeline view of mactrace syscall data.

Reads JSON output from mactrace and generates an interactive HTML
timeline with sortable/filterable table and syscall categorization.

Usage:
    ./mactrace_timeline.py trace.json -o timeline.html
    ./mactrace -o - /bin/ls | ./mactrace_timeline.py - -o timeline.html
"""

import sys
import json
import argparse
import os
import re
import html
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from collections import defaultdict
from pathlib import Path


# Color palette for column headers
HEADER_COLORS = [
    "#e08214",  # seq
    "#fdb863",  # pid
    "#fee0b6",  # syscall
    "#d8daeb",  # result
    "#b2abd2",  # target
    "#8073ac",  # details
]

def lighten_color(hex_color: str, factor: float = 0.85) -> str:
    """Lighten a hex color by mixing with white."""
    hex_color = hex_color.lstrip('#')
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    r = int(r + (255 - r) * factor)
    g = int(g + (255 - g) * factor)
    b = int(b + (255 - b) * factor)
    return f"#{r:02x}{g:02x}{b:02x}"

DATA_COLORS = [lighten_color(c) for c in HEADER_COLORS]

# Syscall categories for coloring
SYSCALL_CATEGORIES = {
    'file': {
        'open', 'open_nocancel', 'openat', 'openat_nocancel',
        'close', 'close_nocancel',
        'read', 'read_nocancel', 'pread', 'pread_nocancel',
        'write', 'write_nocancel', 'pwrite', 'pwrite_nocancel',
        'stat64', 'lstat64', 'fstat64', 'fstatat64',
        'access', 'faccessat',
        'unlink', 'rename', 'mkdir', 'rmdir', 'chdir', 'fchdir',
        'chmod', 'fchmod', 'truncate', 'ftruncate',
        'link', 'symlink', 'readlink',
        'dup', 'dup2', 'fcntl', 'fcntl_nocancel',
        'fsync', 'fsync_nocancel',
        'getdirentries64', 'getattrlistbulk',
    },
    'network': {
        'socket', 'connect', 'connect_nocancel',
        'bind', 'listen', 'accept', 'accept_nocancel',
        'sendto', 'sendto_nocancel', 'recvfrom', 'recvfrom_nocancel',
        'shutdown', 'setsockopt', 'getsockopt',
    },
    'process': {
        'fork', 'execve', 'posix_spawn', 'exit',
        'wait4', 'wait4_nocancel', 'kill',
        'getpid', 'getppid', 'getuid', 'geteuid', 'getgid', 'getegid',
    },
    'memory': {
        'mmap', 'munmap', 'mprotect',
    },
    'signal': {
        'sigaction', 'sigprocmask',
    },
}

CATEGORY_COLORS = {
    'file': '#4CAF50',      # green
    'network': '#2196F3',   # blue
    'process': '#FF9800',   # orange
    'memory': '#9C27B0',    # purple
    'signal': '#F44336',    # red
    'other': '#607D8B',     # gray
}

def get_syscall_category(syscall: str) -> str:
    """Get the category for a syscall."""
    for cat, syscalls in SYSCALL_CATEGORIES.items():
        if syscall in syscalls:
            return cat
    return 'other'


def format_bytes(n: int) -> str:
    """Format bytes with K, M, G suffixes."""
    if n < 1024:
        return f"{n}"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f}K"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f}M"
    else:
        return f"{n / (1024 * 1024 * 1024):.2f}G"


def format_duration(ms: float) -> str:
    """Format duration."""
    if ms < 1:
        return f"{ms * 1000:.1f}µs"
    elif ms < 1000:
        return f"{ms:.1f}ms"
    else:
        return f"{ms / 1000:.2f}s"


class TimelineGenerator:
    """Generate HTML timeline from mactrace JSON data."""

    def __init__(self, input_file: str = None):
        self.input_file = input_file or "stdin"
        self.trace_data: Dict[str, Any] = {}
        self.fd_to_path: Dict[int, Dict[int, str]] = defaultdict(dict)  # pid -> {fd -> path}

    def load(self, filepath: str) -> None:
        """Load trace data from file or stdin."""
        if filepath == '-':
            self.trace_data = json.load(sys.stdin)
        else:
            with open(filepath, 'r') as f:
                self.trace_data = json.load(f)

    def _extract_target(self, event: Dict) -> str:
        """Extract the primary target (file/socket/etc) from a syscall event."""
        syscall = event.get('syscall', '')
        args = event.get('args', {})
        
        # File operations
        if 'path' in args:
            return args['path']
        
        # fd-based operations
        if 'fd' in args:
            fd = args['fd']
            pid = event.get('pid', 0)
            # Look up fd -> path mapping
            if fd in self.fd_to_path.get(pid, {}):
                return f"fd={fd} ({self.fd_to_path[pid][fd]})"
            return f"fd={fd}"
        
        # Socket operations
        if syscall == 'socket':
            domain = args.get('domain', '?')
            sock_type = args.get('type', '?')
            return f"{domain}/{sock_type}"
        
        return ""

    def _extract_details(self, event: Dict) -> str:
        """Extract additional details from a syscall event."""
        syscall = event.get('syscall', '')
        args = event.get('args', {})
        retval = event.get('return_value', 0)
        
        parts = []
        
        # Flags for open
        if 'flags' in args and syscall in ('open', 'openat', 'open_nocancel', 'openat_nocancel'):
            parts.append(args['flags'])
        
        # Count for read/write
        if 'count' in args:
            parts.append(f"count={args['count']}")
        
        # Return value info
        if syscall in ('read', 'write', 'pread', 'pwrite') and retval > 0:
            parts.append(f"→ {format_bytes(retval)}")
        elif syscall in ('open', 'openat', 'socket') and retval >= 0:
            parts.append(f"→ fd={retval}")
        
        return " ".join(parts)

    def _track_fd(self, event: Dict) -> None:
        """Track file descriptor to path mapping."""
        syscall = event.get('syscall', '')
        args = event.get('args', {})
        retval = event.get('return_value', 0)
        pid = event.get('pid', 0)
        errno = event.get('errno', 0)
        
        if syscall in ('open', 'open_nocancel', 'openat', 'openat_nocancel'):
            if errno == 0 and retval >= 0:
                path = args.get('path', '')
                if path:
                    self.fd_to_path[pid][retval] = path
                    
        elif syscall in ('close', 'close_nocancel'):
            fd = args.get('fd')
            if fd is not None and fd in self.fd_to_path.get(pid, {}):
                del self.fd_to_path[pid][fd]

    def generate(self) -> str:
        """Generate HTML timeline."""
        events = self.trace_data.get('events', [])
        
        # First pass: track fd mappings
        for event in events:
            self._track_fd(event)
        
        # Reset fd tracking for second pass
        self.fd_to_path = defaultdict(dict)
        
        # Build table rows
        rows = []
        for event in events:
            self._track_fd(event)
            
            seq = event.get('timestamp_us', 0)
            pid = event.get('pid', 0)
            syscall = event.get('syscall', '')
            retval = event.get('return_value', 0)
            errno = event.get('errno', 0)
            args = event.get('args', {})
            
            category = get_syscall_category(syscall)
            target = self._extract_target(event)
            details = self._extract_details(event)
            
            # Format result
            errno_name = args.get('errno_name', '')
            if errno != 0:
                result = f'<span class="error">{retval} ({errno_name})</span>'
            else:
                result = str(retval)
            
            rows.append({
                'seq': seq,
                'pid': pid,
                'syscall': syscall,
                'category': category,
                'result': result,
                'result_raw': retval,
                'target': target,
                'details': details,
                'is_error': errno != 0,
            })
        
        return self._render_html(rows)

    def _render_html(self, rows: List[Dict]) -> str:
        """Render the HTML page."""
        
        # Build summary
        cmd = self.trace_data.get('command', [])
        duration = self.trace_data.get('duration_ms', 0)
        target_pid = self.trace_data.get('target_pid', 0)
        exit_code = self.trace_data.get('exit_code', 0)
        syscall_count = self.trace_data.get('syscall_count', 0)
        
        # Count by category
        cat_counts = defaultdict(int)
        for row in rows:
            cat_counts[row['category']] += 1
        
        # Generate category badges
        cat_badges = []
        for cat in ['file', 'network', 'process', 'memory', 'signal', 'other']:
            if cat_counts[cat] > 0:
                color = CATEGORY_COLORS[cat]
                cat_badges.append(
                    f'<span class="cat-badge" style="background:{color}">{cat}: {cat_counts[cat]}</span>'
                )
        
        # Generate table rows HTML
        rows_html = []
        for row in rows:
            cat_color = CATEGORY_COLORS[row['category']]
            error_class = ' class="error-row"' if row['is_error'] else ''
            
            rows_html.append(f'''<tr{error_class}>
                <td style="background:{DATA_COLORS[0]}">{row['seq']}</td>
                <td style="background:{DATA_COLORS[1]}">{row['pid']}</td>
                <td style="background:{DATA_COLORS[2]}"><span class="syscall-badge" style="border-left:4px solid {cat_color}">{html.escape(row['syscall'])}</span></td>
                <td style="background:{DATA_COLORS[3]}">{row['result']}</td>
                <td style="background:{DATA_COLORS[4]}">{html.escape(row['target'])}</td>
                <td style="background:{DATA_COLORS[5]}">{html.escape(row['details'])}</td>
            </tr>''')

        input_basename = os.path.basename(self.input_file) if self.input_file else 'stdin'
        page_title = f"mactrace: {' '.join(cmd)}"

        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(page_title)}</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 20px;
            background: #fafafa;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 1.5em;
        }}
        .summary {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-row {{
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }}
        .summary-item {{
            font-family: monospace;
            font-size: 13px;
        }}
        .summary-item strong {{
            color: #666;
        }}
        .cat-badges {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .cat-badge {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            color: white;
            font-weight: 500;
        }}
        .table-container {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow-x: auto;
        }}
        table.dataTable {{
            width: 100% !important;
            border-collapse: collapse;
        }}
        table.dataTable thead th {{
            font-weight: bold;
            text-align: left;
            padding: 12px 8px;
            border-bottom: 2px solid #666;
        }}
        table.dataTable thead th:nth-child(1) {{ background: {HEADER_COLORS[0]}; }}
        table.dataTable thead th:nth-child(2) {{ background: {HEADER_COLORS[1]}; }}
        table.dataTable thead th:nth-child(3) {{ background: {HEADER_COLORS[2]}; }}
        table.dataTable thead th:nth-child(4) {{ background: {HEADER_COLORS[3]}; }}
        table.dataTable thead th:nth-child(5) {{ background: {HEADER_COLORS[4]}; }}
        table.dataTable thead th:nth-child(6) {{ background: {HEADER_COLORS[5]}; color: white; }}
        table.dataTable tbody td {{
            padding: 6px 8px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px;
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }}
        table.dataTable tbody tr:hover td {{
            box-shadow: inset 0 0 0 1000px rgba(0, 0, 0, 0.03);
        }}
        .syscall-badge {{
            padding: 2px 6px;
            background: #f5f5f5;
            border-radius: 3px;
            display: inline-block;
        }}
        .error {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .error-row td {{
            background-color: #ffebee !important;
        }}
        /* Category filter buttons */
        .filters {{
            margin-bottom: 15px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .filter-btn {{
            padding: 5px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: white;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }}
        .filter-btn:hover {{
            background: #f0f0f0;
        }}
        .filter-btn.active {{
            background: #333;
            color: white;
            border-color: #333;
        }}
        .filter-label {{
            font-size: 12px;
            color: #666;
            margin-right: 5px;
        }}
    </style>
</head>
<body>
    <h1>🔍 {html.escape(' '.join(cmd))}</h1>
    
    <div class="summary">
        <div class="summary-row">
            <div class="summary-item"><strong>Duration:</strong> {format_duration(duration)}</div>
            <div class="summary-item"><strong>PID:</strong> {target_pid}</div>
            <div class="summary-item"><strong>Exit:</strong> {exit_code}</div>
            <div class="summary-item"><strong>Syscalls:</strong> {syscall_count}</div>
        </div>
        <div class="cat-badges">
            {' '.join(cat_badges)}
        </div>
    </div>
    
    <div class="table-container">
        <div class="filters">
            <span class="filter-label">Filter:</span>
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="file">File</button>
            <button class="filter-btn" data-filter="network">Network</button>
            <button class="filter-btn" data-filter="process">Process</button>
            <button class="filter-btn" data-filter="memory">Memory</button>
            <button class="filter-btn" data-filter="error">Errors</button>
        </div>
        
        <table id="timeline" class="display">
            <thead>
                <tr>
                    <th>#</th>
                    <th>PID</th>
                    <th>Syscall</th>
                    <th>Result</th>
                    <th>Target</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>
    </div>

    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script>
        $(document).ready(function() {{
            var table = $('#timeline').DataTable({{
                pageLength: 100,
                order: [[0, 'asc']],
                columnDefs: [
                    {{ targets: [0, 1, 3], className: 'dt-body-right' }}
                ]
            }});
            
            // Custom filtering
            var currentFilter = 'all';
            
            $.fn.dataTable.ext.search.push(function(settings, data, dataIndex) {{
                if (currentFilter === 'all') return true;
                
                var row = table.row(dataIndex).node();
                var syscall = $(row).find('td:eq(2)').text().trim();
                var isError = $(row).hasClass('error-row');
                
                if (currentFilter === 'error') return isError;
                
                // Category matching
                var categories = {{
                    'file': {list(SYSCALL_CATEGORIES['file'])},
                    'network': {list(SYSCALL_CATEGORIES['network'])},
                    'process': {list(SYSCALL_CATEGORIES['process'])},
                    'memory': {list(SYSCALL_CATEGORIES['memory'])}
                }};
                
                if (categories[currentFilter]) {{
                    return categories[currentFilter].includes(syscall);
                }}
                
                return true;
            }});
            
            $('.filter-btn').on('click', function() {{
                $('.filter-btn').removeClass('active');
                $(this).addClass('active');
                currentFilter = $(this).data('filter');
                table.draw();
            }});
        }});
    </script>
</body>
</html>'''
        
        return html_content


def main():
    parser = argparse.ArgumentParser(
        description='Generate HTML timeline from mactrace JSON',
        epilog='Reads JSON from mactrace and generates interactive HTML timeline.'
    )
    parser.add_argument('file', help='mactrace JSON file (use - for stdin)')
    parser.add_argument('-o', '--output', required=True, help='Output HTML file')
    
    args = parser.parse_args()
    
    generator = TimelineGenerator(input_file=args.file)
    
    try:
        generator.load(args.file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    
    html_content = generator.generate()
    
    with open(args.output, 'w') as f:
        f.write(html_content)
    
    print(f"Timeline written to: {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
