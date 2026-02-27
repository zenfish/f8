#!/bin/bash
#
# mactrace_run_all.sh — Trace, analyze, import, and serve in one shot
#
# Reads ~/.mactrace/config for MACTRACE_OUTPUT / MACTRACE_HOME so that
# file paths stay consistent with mactrace, mactrace_import, etc.
#

# ── Shared config reader and path resolver ──────────────────────────
# Resolve symlinks to find actual script location (for sourcing common lib)
_SOURCE="$0"
while [[ -L "$_SOURCE" ]]; do
    _DIR="$(cd "$(dirname "$_SOURCE")" && pwd)"
    _SOURCE="$(readlink "$_SOURCE")"
    [[ "$_SOURCE" != /* ]] && _SOURCE="$_DIR/$_SOURCE"
done
_SCRIPT_DIR="$(cd "$(dirname "$_SOURCE")" && pwd)"
source "$_SCRIPT_DIR/mactrace_common.sh"

read_config

# Performance flags: override via MACTRACE_PERF_FLAGS in ~/.mactrace/config,
# or set on the command line. Defaults to high-speed settings.
# Example config line:  MACTRACE_PERF_FLAGS=--switchrate 200hz --bufsize 512m
performance_flags="${MACTRACE_PERF_FLAGS:---switchrate 200hz --bufsize 512m}"

# ── Parse arguments ─────────────────────────────────────────────────
throttle_flag=""
force_mode=""
attach_pid=""
custom_name=""

# Parse flags (order-independent, before positional args)
while [[ "$1" == -* ]]; do
    case "$1" in
        --throttle) throttle_flag="--throttle"; shift ;;
        --force)    force_mode=1; shift ;;
        -n|--name)
            if [ -z "$2" ]; then
                echo "Error: $1 requires a name argument"
                exit 1
            fi
            custom_name="$2"; shift 2 ;;
        -p)
            if [ -z "$2" ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                echo "Error: -p requires a numeric PID"
                exit 1
            fi
            attach_pid="$2"; shift 2 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

if [ -z "$attach_pid" ] && [ -z "$1" ]; then
    echo "Usage: $0 [--throttle] [--force] [-n name] -p PID"
    echo "       $0 [--throttle] [--force] [-n name] program-to-trace [args...]"
    exit 1
fi

set -e

# ── Derive base name and resolve output paths ──────────────────────
if [ -n "$attach_pid" ]; then
    proc_name=$(ps -p "$attach_pid" -o comm= 2>/dev/null | sed 's:.*/::' || true)
    if [ -z "$proc_name" ]; then
        echo "Error: No process with PID $attach_pid"
        exit 1
    fi
    traceme="PID $attach_pid ($proc_name)"
else
    traceme="$*"
fi

if [ -n "$custom_name" ]; then
    base="$custom_name"
elif [ -n "$attach_pid" ]; then
    base="${proc_name}_${attach_pid}"
else
    # Strip directory path and file extension: /tmp/oc.sh → oc
    base=$(basename "$1" | sed -e 's/\.[^.]*$//')
fi

# Resolve paths the same way mactrace does:
#   bare "oc.json" → $MACTRACE_OUTPUT/oc.json (if configured)
json_path=$(resolve_path "$base.json" MACTRACE_OUTPUT)
io_dir=$(resolve_path "$base" MACTRACE_OUTPUT)

# ── Cleanup function ────────────────────────────────────────────────
cleanup_artifacts() {
    echo -e "\nCleaning up trace artifacts..." >&2
    if [ -f "$json_path" ]; then
        rm -f "$json_path"
        echo "  Removed: $json_path" >&2
    fi
    if [ -d "$io_dir" ]; then
        rm -rf "$io_dir"
        echo "  Removed: $io_dir/" >&2
    fi
    # DB entry (best-effort)
    local db_id
    db_id=$(mactrace_db list -j 2>/dev/null | jq -r ".[] | select(.name == \"$base\") | .id" 2>/dev/null || true)
    if [ -n "$db_id" ]; then
        mactrace_db delete "$db_id" 2>/dev/null || true
        echo "  Removed DB entry: $base (id=$db_id)" >&2
    fi
}

# ── Handle existing artifacts ────────────────────────────────────────
existing_db_id=$(mactrace_db list -j 2>/dev/null | jq -r ".[] | select(.name == \"$base\") | .id" 2>/dev/null || true)

if [ -n "$existing_db_id" ]; then
    if [ -n "$force_mode" ]; then
        echo "Removing existing DB entry: $base (id=$(echo $existing_db_id | tr '\n' ' '))"
        # shellcheck disable=SC2086
        # Intentionally unquoted: $existing_db_id may contain multiple IDs
        # separated by newlines; mactrace_db delete accepts multiple ID args.
        mactrace_db delete -f $existing_db_id 2>/dev/null || true
    else
        echo -e "\nAn existing saved DB is already present with the name \"$base\", cowardly bailin' out!"
        echo -e "you can remove that entry with the command:\n"
        echo -e "    mactrace_db delete $existing_db_id\n"
        echo -e "Or use --force to auto-remove.\n"
        exit 0
    fi
fi

# Remove existing output files if --force
if [ -n "$force_mode" ]; then
    if [ -f "$json_path" ]; then
        echo "Removing existing: $json_path"
        rm -f "$json_path"
    fi
    if [ -d "$io_dir" ]; then
        echo "Removing existing: $io_dir/"
        rm -rf "$io_dir"
    fi
    # Also remove the txt summary if it exists
    txt_path_clean=$(resolve_path "$base.txt" MACTRACE_OUTPUT)
    if [ -f "$txt_path_clean" ]; then
        rm -f "$txt_path_clean"
    fi
fi

echo -e "\nstarting mactrace run, using \"$base\" as base to use in run.... going to be tracing:\n"
echo -e "    $traceme\n"

# ── Run mactrace ────────────────────────────────────────────────────
if [ -n "$attach_pid" ]; then
    trap 'true' INT
    sudo mactrace $performance_flags $throttle_flag --capture-io -o "$base.json" -jp -e -p "$attach_pid"
    mactrace_exit=$?
    trap - INT
else
    sudo mactrace $throttle_flag --capture-io -o "$base.json" -jp -e $traceme
    mactrace_exit=$?
fi

# If mactrace was interrupted (exit 130), clean up and bail
if [ $mactrace_exit -eq 130 ]; then
    cleanup_artifacts
    exit 130
fi

# Verify trace output (use resolved path, not bare name)
if [ ! -f "$json_path" ]; then
    echo -e "\nError: trace output $json_path not found — mactrace may have failed"
    exit 1
fi

# Trap INT during post-processing
trap 'cleanup_artifacts; exit 130' INT

echo -e "\n... saving i/o\n"

# Save I/O files (pass bare names — mactrace_analyze resolves them too)
# Tee full analysis to a text file alongside the JSON for scrollback reference
txt_path=$(resolve_path "$base.txt" MACTRACE_OUTPUT)
mactrace_analyze "$base.json" --save-io "$base" --hexdump --render-terminal 2>&1 | tee "$txt_path"
echo -e "\nAnalysis saved to: $txt_path" >&2

echo -e "\nimporting to sqlite\n"

# Import to SQLite
mactrace_import "$base.json" --io-dir "$base"

# Post-processing done
trap - INT

set +e
killall mactrace_server

echo -e "\nstarting server on http://localhost:3000/\n"

mactrace_server
