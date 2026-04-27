#!/bin/bash
#
# f8_run_all.sh -- End-to-end f8 workflow: trace, analyze, import, serve
#
# WHAT:    Single command to run a complete f8 syscall tracing session:
#          (1) Traces a program or attaches to a PID using f8 (DTrace-based
#              syscall tracer with I/O capture), (2) runs f8_analyze to
#              save captured I/O and produce a text analysis, (3) imports
#              the trace into SQLite via f8_import, (4) starts f8_server
#              for interactive timeline visualization in the browser.
#          Handles artifact cleanup on interrupt, collision detection for
#          named traces, epoch-stamped output filenames, and DTrace health
#          reporting.
#
# WHY:     The f8 workflow has multiple steps (trace -> analyze -> import ->
#          serve) that are tedious to run manually.  This script chains them
#          with proper error handling, making it trivial to go from "I want
#          to trace this program" to "browsing the timeline in my browser."
#
# RESULT:  Works reliably for tracing arbitrary programs and PIDs.  Handles
#          edge cases: empty traces (DTrace allocation failures), interrupted
#          traces (cleans up artifacts), name collisions (--force or bail).
#          Output lands in F8_OUTPUT directory per ~/.f8/config.
#
# TARGET:  macOS (requires DTrace, which needs root/SIP exceptions).
#
# BUILD/RUN:
#     f8_run_all.sh [--throttle] [--force] [-n name] [-p PID] [f8-flags...] program [args...]
#
#     Examples:
#       f8_run_all.sh ls -la                    # Trace ls, auto-name
#       f8_run_all.sh -n mytest ./my_program    # Custom name
#       f8_run_all.sh -p 12345                  # Attach to running PID
#       f8_run_all.sh --force -n redo ./test    # Overwrite existing
#       f8_run_all.sh --switchrate 100hz ./app  # Pass flags through to f8
#
#     Requires: sudo (for DTrace), f8 + f8_analyze + f8_import + f8_server
#               in PATH, ~/.f8/config for output paths, python3, jq.
#
# SEE ALSO:
#     - f8                          (the DTrace-based syscall tracer)
#     - f8_analyze                  (trace analysis and I/O extraction)
#     - f8_import                   (SQLite import)
#     - f8_server                   (web-based timeline viewer)
#     - f8_common.sh                (shared config reader, sourced by this)
#     - f8_categories.py            (syscall category definitions)
#     - ~/.f8/config                (F8_OUTPUT, F8_HOME, F8_PERF_FLAGS)
#
# Authors: Dan Farmer & Claude
#
# Reads ~/.f8/config for F8_OUTPUT / F8_HOME so that
# file paths stay consistent with f8, f8_import, etc.
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
source "$_SCRIPT_DIR/f8_common.sh"

read_config

# Performance flags: override via F8_PERF_FLAGS in ~/.f8/config,
# or set on the command line. Defaults to high-speed settings.
# Example config line:  F8_PERF_FLAGS=--switchrate 200hz --bufsize 512m
performance_flags="${F8_PERF_FLAGS:---switchrate 200hz --bufsize 512m}"

# ── Parse arguments ─────────────────────────────────────────────────
throttle_flag=""
force_mode=""
attach_pid=""
custom_name=""
f8_extra_flags=()

# Parse flags (order-independent, before positional args)
# Flags not recognized here are passed through to f8.
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
        --) shift; break ;;
        *)
            # Pass unknown flags through to f8 (e.g. --switchrate, --bufsize, --io-size, --cache)
            f8_extra_flags+=("$1")
            shift
            # If next arg doesn't start with - and isn't a command, it's the flag's value
            if [[ -n "$1" && "$1" != -* && ! -e "$1" ]]; then
                f8_extra_flags+=("$1")
                shift
            fi
            ;;
    esac
done

if [ -z "$attach_pid" ] && [ -z "$1" ]; then
    echo "Usage: $0 [--throttle] [--force] [-n name] [-p PID] [--f8-flags...] program [args...]"
    echo "       Unknown flags are passed through to f8 (e.g. --switchrate 200hz --bufsize 512m)."
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



# Resolve paths the same way f8 does:
#   bare "oc.json" → $F8_OUTPUT/oc.json (if configured)
# Initial estimates — actual path (with epoch) is captured from f8 output
json_path=$(resolve_path "$base.json" F8_OUTPUT)
io_dir=$(resolve_path "$base" F8_OUTPUT)

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
    # Temp files
    rm -f "$f8_stderr_log" 2>/dev/null
    # DB entry (best-effort)
    local db_id
    db_id=$(f8_data list -j 2>/dev/null | jq -r ".[] | select(.name == \"$base\") | .num" 2>/dev/null || true)
    if [ -n "$db_id" ]; then
        f8_data delete "$db_id" 2>/dev/null || true
        echo "  Removed DB entry: $base (id=$db_id)" >&2
    fi
}

# ── Handle existing artifacts ────────────────────────────────────────
# Only check for DB name collisions when using a custom name (-n).
# Auto-derived names will collide because import.js strips the epoch
# (python3.1740963600 → python3), but that's fine — multiple traces
# of the same command just stack up in the DB with unique JSON files.
if [ -n "$custom_name" ]; then
    existing_db_id=$(f8_data list -j 2>/dev/null | jq -r ".[] | select(.name == \"$base\") | .num" 2>/dev/null || true)

    if [ -n "$existing_db_id" ]; then
        if [ -n "$force_mode" ]; then
            echo "Removing existing DB entry: $base (id=$(echo $existing_db_id | tr '\n' ' '))"
            # shellcheck disable=SC2086
            # Intentionally unquoted: $existing_db_id may contain multiple IDs
            # separated by newlines; f8_data delete accepts multiple ID args.
            f8_data delete -f $existing_db_id 2>/dev/null || true
        else
            echo -e "\nAn existing saved DB is already present with the name \"$base\", cowardly bailin' out!"
            echo -e "you can remove that entry with the command:\n"
            echo -e "    f8_data delete $existing_db_id\n"
            echo -e "Or use --force to auto-remove.\n"
            exit 0
        fi
    fi
fi

# Note: epoch-stamped filenames prevent collisions, so no file existence check needed.
# Each run produces a unique name like configure.1772420167.json.

echo -e "\nstarting f8 run, using \"$base\" as base to use in run.... going to be tracing:\n"
echo -e "    $traceme\n"

# Temp file to capture f8 stderr
f8_stderr_log=$(mktemp)

# Skip nested sudo if already root — re-sudo'ing flips SUDO_USER to root,
# stripping F8_OUTPUT/F8_HOME context that f8's config reader needs.
sudo_cmd=()
[[ $EUID -ne 0 ]] && sudo_cmd=(sudo -E)

# ── Run f8 ────────────────────────────────────────────────────
if [ -n "$attach_pid" ]; then
    trap 'true' INT
    "${sudo_cmd[@]}" f8 $performance_flags $throttle_flag "${f8_extra_flags[@]}" --capture-io -o "$base" -jp -e -p "$attach_pid" 2> >(tee /dev/stderr >> "$f8_stderr_log")
    f8_exit=$?
    trap - INT
else
    "${sudo_cmd[@]}" f8 $throttle_flag "${f8_extra_flags[@]}" --capture-io -o "$base" -jp -e "$@" 2> >(tee /dev/stderr >> "$f8_stderr_log")
    f8_exit=$?
fi

# If f8 was interrupted (exit 130), clean up and bail
if [ $f8_exit -eq 130 ]; then
    cleanup_artifacts
    exit 130
fi

# Extract actual output path from f8 (it injects epoch into filename)
actual_json=$(sed -n 's/^Trace written to: //p' "$f8_stderr_log" 2>/dev/null | head -1)

if [ -n "$actual_json" ]; then
    json_path="$actual_json"
    # Derive io_dir and base from actual json path: configure.1772420167.json → configure.1772420167
    io_dir="${json_path%.json}"
    base=$(basename "$io_dir")
fi

# Verify trace output
if [ ! -f "$json_path" ]; then
    echo -e "\nError: trace output $json_path not found — f8 may have failed"
    exit 1
fi

# Bail on empty traces (0 events = DTrace failed to attach or ran out of memory)
event_count=$(python3 -c "import json; d=json.load(open('$json_path')); print(len(d.get('events',[])))" 2>/dev/null || echo "0")
if [ "$event_count" = "0" ]; then
    echo -e "\nTrace captured 0 events — DTrace may have failed to attach."
    echo "Check the output above for errors (e.g., 'Cannot allocate memory')."
    echo "Cleaning up empty trace..."
    rm -f "$json_path"
    exit 1
fi

# Trap INT during post-processing
trap 'cleanup_artifacts; exit 130' INT

echo -e "\n... saving i/o\n"

# Save I/O files (pass bare names — f8_analyze resolves them too)
# Tee full analysis to a text file alongside the JSON for scrollback reference
txt_path=$(resolve_path "$base.txt" F8_OUTPUT)
f8_analyze "$base.json" --save-io "$base" --hexdump --render-terminal 2>&1 | tee "$txt_path"
echo -e "\nAnalysis saved to: $txt_path" >&2

echo -e "\nimporting to sqlite\n"

# Import to SQLite
f8_import "$base.json" --io-dir "$base"

# Post-processing done
trap - INT

# ── Replay DTrace health/suggestions in red so they're visible ────
# Extract health + rerun suggestion sections from captured stderr
f8_health=$(awk '
    /^--- DTrace health ---$/ { capture=1 }
    /^--- Rerun suggestions ---$/ { capture=1 }
    capture { print }
    capture && /^$/ { capture=0 }
' "$f8_stderr_log" 2>/dev/null)
rm -f "$f8_stderr_log"

if [ -n "$f8_health" ]; then
    echo ""
    echo -e "\033[1;31m════════════════════════════════════════════════════════════\033[0m"
    echo "$f8_health" | while IFS= read -r line; do
        echo -e "\033[1;31m${line}\033[0m"
    done
    echo -e "\033[1;31m════════════════════════════════════════════════════════════\033[0m"
fi

set +e
killall f8_server

echo -e "\nstarting server on http://localhost:3000/\n"

f8_server
