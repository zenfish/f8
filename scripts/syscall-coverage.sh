#!/bin/bash
# syscall-coverage.sh — Gather macOS syscall data for coverage analysis
#
# Dumps all DTrace syscall probes and OS version info to a JSON file.
# Run on different macOS versions to build a cross-version comparison.
#
# Usage: sudo ./scripts/syscall-coverage.sh [output.json]
# Output: JSON with os_info + array of all syscall probe names
#
# Requires: root (DTrace needs it)

set -euo pipefail

OUTPUT="${1:-}"

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: requires root (DTrace needs it). Run with sudo." >&2
    exit 1
fi

# Gather all syscall probes (entry only — each syscall has entry+return)
TMPFILE=$(mktemp)
trap "rm -f $TMPFILE" EXIT

/usr/sbin/dtrace -l -P syscall 2>/dev/null \
    | awk 'NR>1 && /entry$/ { print $(NF-1) }' \
    | sort -u > "$TMPFILE"

# Build JSON via python3
python3 - "$OUTPUT" "$TMPFILE" << 'PYEOF'
import json, sys, subprocess, platform
from datetime import datetime, timezone

output_path = sys.argv[1] if sys.argv[1] else None
tmpfile = sys.argv[2]

# OS info
def sysctl(key):
    try:
        r = subprocess.run(['/usr/sbin/sysctl', '-n', key], capture_output=True, text=True)
        return r.stdout.strip()
    except Exception:
        return 'unknown'

def swvers(flag):
    try:
        r = subprocess.run(['sw_vers', flag], capture_output=True, text=True)
        return r.stdout.strip()
    except Exception:
        return 'unknown'

import socket
data = {
    'generated': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'hostname': socket.gethostname().split('.')[0],
    'os': {
        'name': swvers('-productName'),
        'version': swvers('-productVersion'),
        'build': swvers('-buildVersion'),
        'kernel': platform.release(),
        'kernel_version': sysctl('kern.version').split('\n')[0],
        'arch': platform.machine(),
        'difo_maxsize': int(sysctl('kern.dtrace.difo_maxsize') or 0),
    },
}

# Read syscalls
with open(tmpfile) as f:
    syscalls = [line.strip() for line in f if line.strip()]

named = sorted(s for s in syscalls if not s.startswith('#'))
unnamed = sorted((s for s in syscalls if s.startswith('#')),
                 key=lambda x: int(x.lstrip('#')))

data['counts'] = {
    'total': len(syscalls),
    'named': len(named),
    'unnamed': len(unnamed),
}
data['syscalls'] = {
    'named': named,
    'unnamed': unnamed,
}

if output_path:
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'Written to {output_path}', file=sys.stderr)
else:
    json.dump(data, sys.stdout, indent=2)
    print()

print(f'{len(named)} named + {len(unnamed)} unnamed = {len(syscalls)} total', file=sys.stderr)
print(f'{data["os"]["name"]} {data["os"]["version"]} ({data["os"]["build"]}), {data["os"]["arch"]}', file=sys.stderr)
PYEOF
