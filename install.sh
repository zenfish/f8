#!/bin/bash
#
# install.sh — Set up mactrace for use
#
# What it does:
#   1. Installs Node.js dependencies (server/node_modules)
#   2. Creates ~/.mactrace/config with sensible defaults
#   3. Creates ~/traces/ directory for output
#   4. Adds mactrace to PATH (via symlinks in /usr/local/bin or prints instructions)
#
# Usage:
#   ./install.sh              # Interactive install
#   ./install.sh --no-link    # Skip PATH symlinks (just deps + config)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MACTRACE_HOME="${HOME}/.mactrace"
TRACES_DIR="${HOME}/traces"
LINK_DIR="/usr/local/bin"
NO_LINK=false

for arg in "$@"; do
    case "$arg" in
        --no-link) NO_LINK=true ;;
        --help|-h)
            echo "Usage: ./install.sh [--no-link]"
            echo "  --no-link  Skip creating symlinks in ${LINK_DIR}"
            exit 0
            ;;
    esac
done

echo "=== mactrace installer ==="
echo "Source: ${SCRIPT_DIR}"
echo ""

# ── 1. Node.js dependencies ─────────────────────────────────────────

echo "1. Installing Node.js dependencies..."
if command -v node >/dev/null 2>&1; then
    (cd "${SCRIPT_DIR}/server" && npm install --production 2>&1 | tail -3)
    echo "   ✓ server/node_modules installed"
else
    echo "   ⚠ Node.js not found — server/import won't work until you install Node 18+"
fi

# ── 2. Config file ──────────────────────────────────────────────────

echo ""
echo "2. Setting up config..."
mkdir -p "${MACTRACE_HOME}"
mkdir -p "${TRACES_DIR}"

if [[ -f "${MACTRACE_HOME}/config" ]]; then
    echo "   ✓ ${MACTRACE_HOME}/config already exists (not overwriting)"
else
    cat > "${MACTRACE_HOME}/config" << EOF
# mactrace configuration
# See ENVIRONMENT.md for full syntax (supports ~, \$VAR expansion, comments)

MACTRACE_HOME=~/.mactrace
MACTRACE_OUTPUT=~/traces
MACTRACE_DB=\$MACTRACE_HOME/mactrace.db
EOF
    echo "   ✓ Created ${MACTRACE_HOME}/config"
fi
echo "   ✓ Trace output directory: ${TRACES_DIR}"

# ── 3. PATH setup ───────────────────────────────────────────────────

echo ""
echo "3. PATH setup..."

TOOLS=(mactrace mactrace_analyze mactrace_timeline mactrace_import mactrace_server mactrace_data mactrace_open mactrace_run_all.sh)

if [[ "$NO_LINK" == true ]]; then
    echo "   Skipped (--no-link). Add to PATH manually:"
    echo "   export PATH=\"${SCRIPT_DIR}:\$PATH\""
else
    # Check if already on PATH
    if command -v mactrace >/dev/null 2>&1; then
        EXISTING=$(command -v mactrace)
        if [[ "$(readlink -f "$EXISTING" 2>/dev/null || echo "$EXISTING")" == "${SCRIPT_DIR}/mactrace" ]]; then
            echo "   ✓ mactrace already on PATH (${EXISTING})"
        else
            echo "   ⚠ mactrace found at ${EXISTING} (different location)"
            echo "     To use this installation, add to your shell config:"
            echo "     export PATH=\"${SCRIPT_DIR}:\$PATH\""
        fi
    elif [[ -d "$LINK_DIR" && -w "$LINK_DIR" ]]; then
        for tool in "${TOOLS[@]}"; do
            if [[ -x "${SCRIPT_DIR}/${tool}" ]]; then
                ln -sf "${SCRIPT_DIR}/${tool}" "${LINK_DIR}/${tool}"
            fi
        done
        echo "   ✓ Symlinked tools to ${LINK_DIR}"
    else
        echo "   ${LINK_DIR} not writable. Options:"
        echo ""
        echo "   a) Add to PATH (add to ~/.zshrc or ~/.bashrc):"
        echo "      export PATH=\"${SCRIPT_DIR}:\$PATH\""
        echo ""
        echo "   b) Create symlinks with sudo:"
        echo "      sudo ./install.sh"
    fi
fi

# ── 4. SIP check ─────────────────────────────────────────────────────

echo ""
echo "4. Checking SIP status..."
if csrutil status 2>/dev/null | grep -qi "dtrace restrictions disabled"; then
    echo "   ✓ DTrace restrictions disabled — full tracing available"
elif csrutil status 2>/dev/null | grep -qi "disabled"; then
    echo "   ✓ SIP disabled — full tracing available"
else
    echo "   ⚠ SIP dtrace restrictions appear to be ENABLED"
    echo "     mactrace requires DTrace access. To disable dtrace restrictions:"
    echo "     1. Reboot into Recovery Mode (hold power button on Apple Silicon)"
    echo "     2. Open Terminal from Utilities menu"
    echo "     3. Run: csrutil enable --without dtrace"
    echo "     4. Reboot"
    echo "     This only disables the DTrace restriction, not all of SIP."
fi

# ── 5. Done ──────────────────────────────────────────────────────────

echo ""
echo "=== Done ==="
echo ""
echo "Quick test:"
echo "  sudo mactrace -o test.json -jp echo hello"
echo ""
echo "Then view in browser:"
echo "  mactrace_import test.json && mactrace_server"
echo "  → http://localhost:3000"
