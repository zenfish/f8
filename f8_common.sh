#!/bin/bash
#
# f8_common.sh — Shared shell utilities for f8 tools
#
# Source this file from other f8 shell scripts:
#   source "$(dirname "$0")/f8_common.sh"
#
# Provides:
#   read_config     — Load ~/.f8/config into environment
#   resolve_path    — Resolve bare filenames using env var prefixes
#

# ── read_config: Load f8 config file ──────────────────────────
# Reads ~/.f8/config (or SUDO_USER's config if running as root).
# Only sets variables that aren't already in the environment.
# Supports ~ expansion, $VAR references, and # comments.
read_config() {
    local config_home="$HOME"

    # If running as root via sudo, use the original user's home
    if [[ $EUID -eq 0 && -n "$SUDO_USER" ]]; then
        config_home=$(eval echo "~$SUDO_USER")
    fi

    local config_file="$config_home/.f8/config"
    [[ -f "$config_file" ]] || return

    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        # Skip comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue

        # Trim whitespace
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)

        # Skip if already set in environment
        [[ -n "${!key}" ]] && continue

        # Expand ~ to config_home
        value="${value//\~/$config_home}"

        # Expand $VAR references (simple expansion)
        while [[ "$value" =~ \$([A-Za-z_][A-Za-z0-9_]*) ]]; do
            local var_name="${BASH_REMATCH[1]}"
            local var_value="${!var_name}"
            value="${value//\$$var_name/$var_value}"
        done

        # Export the variable
        export "$key=$value"
    done < "$config_file"
}

# ── resolve_path: Apply env var prefix to bare filenames ────────────
# Usage: resolve_path "filename" "ENV_VAR_NAME"
#
# Path resolution rules (same as f8 Python tools):
#   Absolute path (/path/to/file)     → used as-is
#   Explicit relative (./file, ../file) → used as-is
#   Bare filename (file.json)          → $ENV_VAR/file.json (if env var set)
resolve_path() {
    local path="$1"
    local env_var="$2"
    local prefix="${!env_var}"

    # Absolute path — use as-is
    [[ "$path" == /* ]] && { echo "$path"; return; }

    # Explicit relative (./ or ../) — use as-is
    [[ "$path" == ./* || "$path" == ../* ]] && { echo "$path"; return; }

    # If env var is set, use it as prefix (whether or not file exists yet —
    # callers may be computing a path for output, not just reading)
    if [[ -n "$prefix" ]]; then
        echo "$prefix/$path"
        return
    fi

    # Fall back to original path
    echo "$path"
}
