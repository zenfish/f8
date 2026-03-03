#!/bin/bash
#
# install.sh — Set up f8 for use
#
# What it does:
#   1. Installs Node.js dependencies (server/node_modules)
#   2. Creates ~/.f8/config with sensible defaults
#   3. Creates ~/traces/ directory for output
#   4. Adds f8 to PATH (via symlinks in /usr/local/bin or prints instructions)
#
# Usage:
#   ./install.sh              # Interactive install
#   ./install.sh --no-link    # Skip PATH symlinks (just deps + config)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
F8_HOME="${HOME}/.f8"
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

echo "=== f8 installer ==="
echo "Source: ${SCRIPT_DIR}"
echo ""

# ── 1. Node.js dependencies ─────────────────────────────────────────

echo "1. Installing Node.js dependencies..."
if command -v node >/dev/null 2>&1; then
    (cd "${SCRIPT_DIR}/server" && npm install --production 2>&1 | tail -3)
    echo "   ✓ server/node_modules installed"
else
    echo "   ⚠ Node.js not found — server/import won't work until you install Node 20+"
fi

# ── 2. Config file ──────────────────────────────────────────────────

echo ""
echo "2. Setting up config..."
mkdir -p "${F8_HOME}"
mkdir -p "${TRACES_DIR}"

if [[ -f "${F8_HOME}/config" ]]; then
    echo "   ✓ ${F8_HOME}/config already exists (not overwriting)"
else
    cat > "${F8_HOME}/config" << EOF
# f8 configuration
# See ENVIRONMENT.md for full syntax (supports ~, \$VAR expansion, comments)

F8_HOME=~/.f8
F8_OUTPUT=~/traces
F8_DB=\$F8_HOME/f8.db
EOF
    echo "   ✓ Created ${F8_HOME}/config"
fi
echo "   ✓ Trace output directory: ${TRACES_DIR}"

# ── 3. PATH setup ───────────────────────────────────────────────────

echo ""
echo "3. PATH setup..."

TOOLS=(f8 f8_analyze f8_timeline f8_import f8_server f8_data f8_open f8_run_all.sh)

if [[ "$NO_LINK" == true ]]; then
    echo "   Skipped (--no-link). Add to PATH manually:"
    echo "   export PATH=\"${SCRIPT_DIR}:\$PATH\""
else
    # Check if already on PATH
    if command -v f8 >/dev/null 2>&1; then
        EXISTING=$(command -v f8)
        if [[ "$(readlink -f "$EXISTING" 2>/dev/null || echo "$EXISTING")" == "${SCRIPT_DIR}/f8" ]]; then
            echo "   ✓ f8 already on PATH (${EXISTING})"
        else
            echo "   ⚠ f8 found at ${EXISTING} (different location)"
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
    echo "     f8 requires DTrace access. To disable dtrace restrictions:"
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
echo "  sudo f8 -o test.json -jp echo hello"
echo ""
echo "Then view in browser:"
echo "  f8_import test.json && f8_server"
echo "  → http://localhost:3000"
