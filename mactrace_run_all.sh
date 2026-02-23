
# Parse -p PID if present
attach_pid=""
if [ "$1" = "-p" ]; then
    if [ -z "$2" ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
        echo "Usage: $0 -p PID"
        echo "       $0 program-to-trace [args...]"
        exit 1
    fi
    attach_pid="$2"
    shift 2
fi

if [ -z "$attach_pid" ] && [ -z "$1" ]; then
    echo "Usage: $0 -p PID"
    echo "       $0 program-to-trace [args...]"
    exit 1
fi

# die on errz
set -e

#
# Figure out the base name for output files
#
if [ -n "$attach_pid" ]; then
    # For attached PIDs, use the process name (or fall back to "pid_NNNN")
    proc_name=$(ps -p "$attach_pid" -o comm= 2>/dev/null | sed 's:.*/::' || true)
    if [ -z "$proc_name" ]; then
        echo "Error: No process with PID $attach_pid"
        exit 1
    fi
    base="${proc_name}_${attach_pid}"
    traceme="PID $attach_pid ($proc_name)"
else
    traceme="$*"
    # Derive base name: strip directory path, then strip file extension
    # /tmp/oc.sh → oc   |   ./configure → configure   |   n → n
    base=$(basename "$1" | sed -e 's/\.[^.]*$//')
fi

#
# Cleanup function — removes any artifacts created by this run
#
cleanup_artifacts() {
    echo -e "\nCleaning up trace artifacts..." >&2
    # JSON trace output
    if [ -f "$base.json" ]; then
        rm -f "$base.json"
        echo "  Removed: $base.json" >&2
    fi
    # I/O analysis directory
    if [ -d "$base" ]; then
        rm -rf "$base"
        echo "  Removed: $base/" >&2
    fi
    # DB entry (best-effort — might not exist yet)
    local db_id
    db_id=$(mactrace_db list -j 2>/dev/null | jq -r ".[] | select(.name == \"$base\") | .id" 2>/dev/null || true)
    if [ -n "$db_id" ]; then
        mactrace_db delete "$db_id" 2>/dev/null || true
        echo "  Removed DB entry: $base (id=$db_id)" >&2
    fi
}

mactrace_db list -j |jq -r '.[] | .name + "\t" + (.id | tostring)' | while IFS=$'\t' read name id; do 
    if [ "$base" = "$name" ]; 
        then    
        echo -e "\nAn existing saved DB is already present with the name \"$base\", cowardly bailin' out!"
        echo -e "you can remove that entry with the command:\n"
        echo -e "    mactrace_db delete $id\n"
        exit 9
    fi
done

### just a small hoop to jump to catch the exit inside the subshell above, if it triggered....
if [[ $? -eq 9 ]]; then
    exit 0
fi

echo -e "\nstarting mactrace run, using \"$base\" as base to use in run.... going to be tracing:\n"
echo -e "    $traceme\n"

# basic mactrace run
if [ -n "$attach_pid" ]; then
    # Trap SIGINT so Ctrl+C stops mactrace tracing but not this script.
    # Using a handler (not '') so child processes still get default SIGINT
    # and mactrace can catch it internally to flush output.
    trap 'true' INT
    sudo mactrace --capture-io -o "$base.json" -jp -e -p "$attach_pid"
    mactrace_exit=$?
    # Restore default SIGINT — next Ctrl+C kills as normal
    trap - INT
else
    sudo mactrace --capture-io -o "$base.json" -jp -e $traceme
    mactrace_exit=$?
fi

# If mactrace was interrupted (exit 130), clean up and bail
if [ $mactrace_exit -eq 130 ]; then
    cleanup_artifacts
    exit 130
fi

# Verify trace output was written before continuing
if [ ! -f "$base.json" ]; then
    echo -e "\nError: trace output $base.json not found — mactrace may have failed"
    exit 1
fi

# Trap INT during post-processing to clean up if interrupted here too
trap 'cleanup_artifacts; exit 130' INT

echo -e "\n... saving i/o\n"

# Save I/O files
mactrace_analyze "$base.json" --save-io "$base" --hexdump --render-terminal

echo -e "\nimporting to sqlite\n"

# Import to SQLite
mactrace_import     "$base.json" --io-dir "$base"

# Post-processing done, remove INT trap
trap - INT

# so it doesn't die if it doesn't kill the server!
set +e

killall mactrace_server

# Browse (can import multiple traces)
echo -e "\nstarting server on http://localhost:3000/\n"

mactrace_server
