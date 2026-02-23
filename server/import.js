#!/usr/bin/env node
/**
 * Import mactrace JSON into SQLite database (using sql.js).
 * 
 * Usage: mactrace-import trace.json [--db mactrace.db] [--io-dir ./io_output]
 */

import initSqlJs from 'sql.js';
import fs from 'fs';
import path from 'path';

// Parse arguments
const args = process.argv.slice(2);
let jsonFile = null;
let dbFile = 'mactrace.db';
let ioDir = null;

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--db' && args[i + 1]) {
        dbFile = args[++i];
    } else if (args[i] === '--io-dir' && args[i + 1]) {
        ioDir = args[++i];
    } else if (!args[i].startsWith('-')) {
        jsonFile = args[i];
    }
}

if (!jsonFile) {
    console.error('Usage: mactrace-import <trace.json> [--db mactrace.db] [--io-dir ./io_output]');
    process.exit(1);
}

// Auto-create io-dir from JSON filename if not specified
if (!ioDir) {
    const baseName = path.basename(jsonFile, '.json');
    ioDir = path.join(path.dirname(jsonFile), baseName);
}

// Ensure ioDir exists
if (!fs.existsSync(ioDir)) {
    fs.mkdirSync(ioDir, { recursive: true });
    console.log(`Created I/O directory: ${ioDir}`);
}

// Category detection
const SYSCALL_CATEGORIES = {
    file: ['open', 'close', 'read', 'write', 'pread', 'pwrite', 'lseek', 'fstat', 'stat', 'lstat',
           'fstat64', 'stat64', 'lstat64', 'access', 'faccessat', 'unlink', 'rename', 'mkdir',
           'rmdir', 'chmod', 'fchmod', 'truncate', 'ftruncate', 'link', 'symlink', 'readlink',
           'openat', 'mkdirat', 'unlinkat', 'fcntl', 'dup', 'dup2', 'fsync', 'getdirentries64'],
    network: ['socket', 'bind', 'listen', 'accept', 'connect', 'sendto', 'recvfrom',
              'sendmsg', 'recvmsg', 'shutdown', 'setsockopt', 'getsockopt'],
    process: ['fork', 'vfork', 'execve', 'posix_spawn', 'exit', 'wait4', 'waitpid',
              'kill', 'getpid', 'getppid', 'getuid', 'geteuid', 'getgid'],
    memory: ['mmap', 'munmap', 'mprotect', 'madvise', 'mincore', 'mlock', 'munlock'],
    signal: ['sigaction', 'sigprocmask', 'sigaltstack', 'sigsuspend'],
    ipc: ['pipe', 'shm_open', 'sem_open', 'sem_wait', 'sem_post'],
    poll: ['select', 'poll', 'kevent', 'kevent64', 'kqueue'],
    time: ['gettimeofday', 'clock_gettime', 'nanosleep'],
    mac: ['__mac_syscall', '__mac_get_pid', '__mac_get_proc'],
    necp: ['necp_client_action', 'necp_open', 'necp_session_open'],
};

function getCategory(syscall) {
    const base = syscall.replace(/_nocancel$/, '');
    for (const [cat, syscalls] of Object.entries(SYSCALL_CATEGORIES)) {
        if (syscalls.includes(base)) return cat;
    }
    return 'other';
}

function sanitizeFilename(s, maxLen = 60) {
    if (!s) return 'unknown';
    return s.replace(/[\/\\:*?"<>|]/g, '_').replace(/\s/g, '_').replace(/_+/g, '_').slice(0, maxLen) || 'unknown';
}

function extractRawData(event, maxLen = 512) {
    const args = event.args || {};
    const data = args.data;
    if (!data || typeof data !== 'string') return null;
    // Store raw hex, truncated
    return data.slice(0, maxLen * 2); // 2 hex chars per byte
}

// Track generated I/O files: Map<filename, {offsets: [], total_size: number}>
const generatedIoFiles = new Map();

// Generate .bin file from args.data if it doesn't exist
function generateIoFile(event, target) {
    const args = event.args || {};
    const data = args.data;
    if (!data || typeof data !== 'string' || data.length < 2) return null;
    
    const pid = event.pid || 0;
    const syscall = event.syscall || '';
    const seq = event.timestamp_us || 0;
    
    // Determine operation type
    const isRead = syscall.includes('read') || syscall.includes('recv');
    const isWrite = syscall.includes('write') || syscall.includes('send');
    if (!isRead && !isWrite) return null;
    const op = isRead ? 'read' : 'write';
    
    // Get process name from fdInfo or use 'unknown'
    const fdInfo = args.fd !== undefined ? getFdInfo(pid, args.fd) : null;
    let procName = 'unknown';
    // We'll use a simple approach - just use the target basename
    const targetName = target ? sanitizeFilename(path.basename(target), 40) : 'unknown';
    
    // Build filename: pid-proc-op-target.bin
    const filename = `${pid}-${procName}-${op}-${targetName}.bin`;
    const filepath = path.join(ioDir, filename);
    
    // Convert hex to binary
    const hexData = data;
    const bytes = Buffer.from(hexData, 'hex');
    
    // Track this file for metadata
    let fileInfo = generatedIoFiles.get(filename);
    if (!fileInfo) {
        fileInfo = { offsets: [], total_size: 0, filepath };
        generatedIoFiles.set(filename, fileInfo);
    }
    
    // Record this chunk
    const offset = fileInfo.total_size;
    fileInfo.offsets.push({ offset, length: bytes.length, seq });
    fileInfo.total_size += bytes.length;
    
    // Append to file
    try {
        fs.appendFileSync(filepath, bytes);
    } catch (e) {
        console.error(`Warning: Could not write ${filepath}: ${e.message}`);
        return null;
    }
    
    return filename;
}

// Write metadata files for generated I/O
function writeIoMetadata() {
    for (const [filename, info] of generatedIoFiles) {
        const metaPath = info.filepath + '.meta.json';
        const meta = {
            offsets: info.offsets,
            total_size: info.total_size
        };
        try {
            fs.writeFileSync(metaPath, JSON.stringify(meta));
        } catch (e) {
            console.error(`Warning: Could not write ${metaPath}: ${e.message}`);
        }
    }
    if (generatedIoFiles.size > 0) {
        console.log(`Generated ${generatedIoFiles.size} I/O files from captured data`);
    }
}

// Check file size for streaming decision
const MAX_DIRECT_LOAD = 400 * 1024 * 1024; // 400MB - leave headroom for V8 limit
const fileSize = fs.statSync(jsonFile).size;
const useStreaming = fileSize > MAX_DIRECT_LOAD;

// Load JSON (streaming for large files)
console.log(`Loading ${jsonFile}... (${(fileSize / 1024 / 1024).toFixed(1)} MB${useStreaming ? ', using streaming parser' : ''})`);

let trace = {};
let events = [];

if (useStreaming) {
    // Use stream-json for large files (CommonJS modules, access via .default)
    const streamJson = (await import('stream-json')).default;
    const StreamArray = (await import('stream-json/streamers/StreamArray.js')).default;
    const streamChain = (await import('stream-chain')).default;
    const parser = streamJson.parser;
    const streamArray = StreamArray.streamArray;
    const chain = streamChain.chain;
    
    // First pass: get metadata (read first 10KB only to find non-events fields)
    const fd = fs.openSync(jsonFile, 'r');
    const metaBuffer = Buffer.alloc(10000);
    fs.readSync(fd, metaBuffer, 0, 10000, 0);
    fs.closeSync(fd);
    const metaChunk = metaBuffer.toString('utf-8');
    const metaMatch = metaChunk.match(/"command"\s*:\s*(\[[^\]]*\])/);
    if (metaMatch) {
        try { trace.command = JSON.parse(metaMatch[1]); } catch {}
    }
    const durMatch = metaChunk.match(/"duration_ms"\s*:\s*([\d.]+)/);
    if (durMatch) trace.duration_ms = parseFloat(durMatch[1]);
    const pidMatch = metaChunk.match(/"target_pid"\s*:\s*(\d+)/);
    if (pidMatch) trace.target_pid = parseInt(pidMatch[1]);
    const exitMatch = metaChunk.match(/"exit_code"\s*:\s*(\d+)/);
    if (exitMatch) trace.exit_code = parseInt(exitMatch[1]);
    const startMatch = metaChunk.match(/"start_time"\s*:\s*"([^"]+)"/);
    if (startMatch) trace.start_time = startMatch[1];
    
    // Stream events array using pick to select just 'events'
    const Pick = (await import('stream-json/filters/Pick.js')).default;
    const pick = Pick.pick;
    
    console.log('Streaming events...');
    await new Promise((resolve, reject) => {
        const pipeline = chain([
            fs.createReadStream(jsonFile),
            parser(),
            pick({ filter: 'events' }),
            streamArray()
        ]);
        
        pipeline.on('data', ({ key, value }) => {
            events.push(value);
            if (events.length % 50000 === 0) {
                process.stdout.write(`\r  Loaded ${events.length.toLocaleString()} events...`);
            }
        });
        
        pipeline.on('end', () => {
            console.log(`\r  Loaded ${events.length.toLocaleString()} events    `);
            resolve();
        });
        
        pipeline.on('error', reject);
    });
} else {
    // Direct load for smaller files
    try {
        trace = JSON.parse(fs.readFileSync(jsonFile, 'utf-8'));
        events = trace.events || [];
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.error(`Error: File not found: ${jsonFile}`);
        } else if (err instanceof SyntaxError) {
            console.error(`Error: Invalid JSON in ${jsonFile}: ${err.message}`);
        } else {
            console.error(`Error reading ${jsonFile}: ${err.message}`);
        }
        process.exit(1);
    }
}

const command = (trace.command || []).join(' ');
const durationMs = trace.duration_ms || 0;
const targetPid = trace.target_pid || 0;
const exitCode = trace.exit_code || 0;
const startTime = trace.start_time || null;

console.log(`Loaded ${events.length.toLocaleString()} events`);

// Initialize SQL.js
const SQL = await initSqlJs();

// Load existing DB or create new
let db;
if (fs.existsSync(dbFile)) {
    const buffer = fs.readFileSync(dbFile);
    db = new SQL.Database(buffer);
    console.log(`Opened existing database: ${dbFile}`);
} else {
    db = new SQL.Database();
    console.log(`Creating new database: ${dbFile}`);
}

// Create schema
db.run(`
    CREATE TABLE IF NOT EXISTS traces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        command TEXT,
        json_file TEXT,
        io_dir TEXT,
        target_pid INTEGER,
        exit_code INTEGER,
        duration_ms REAL,
        event_count INTEGER,
        start_time TEXT,
        imported_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`);

db.run(`
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id INTEGER NOT NULL,
        seq INTEGER,
        timestamp_us INTEGER,
        time_str TEXT,
        pid INTEGER,
        syscall TEXT,
        category TEXT,
        return_value INTEGER,
        errno INTEGER,
        errno_name TEXT,
        target TEXT,
        details TEXT,
        has_io INTEGER DEFAULT 0,
        io_path TEXT,
        io_chunk INTEGER,
        data_raw TEXT,
        FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
    )
`);

db.run('CREATE INDEX IF NOT EXISTS idx_events_trace ON events(trace_id)');
db.run('CREATE INDEX IF NOT EXISTS idx_events_category ON events(trace_id, category)');
db.run('CREATE INDEX IF NOT EXISTS idx_events_syscall ON events(trace_id, syscall)');
db.run('CREATE INDEX IF NOT EXISTS idx_events_errno ON events(trace_id, errno)');

// Process lifecycle table (from process_tree + process_events)
db.run(`
    CREATE TABLE IF NOT EXISTS processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id INTEGER NOT NULL,
        pid INTEGER NOT NULL,
        parent_pid INTEGER,
        exec_path TEXT,
        fork_time_us INTEGER,
        exec_time_us INTEGER,
        exit_time_us INTEGER,
        exit_code INTEGER,
        FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
    )
`);
db.run('CREATE INDEX IF NOT EXISTS idx_processes_trace ON processes(trace_id)');
db.run('CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(trace_id, pid)');

// DNS lookups table for hostname → IP correlation
db.run(`
    CREATE TABLE IF NOT EXISTS dns_lookups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id INTEGER NOT NULL,
        hostname TEXT NOT NULL,
        ip TEXT,
        lookup_seq INTEGER,
        connect_seq INTEGER,
        FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
    )
`);
db.run('CREATE INDEX IF NOT EXISTS idx_dns_trace ON dns_lookups(trace_id)');
db.run('CREATE INDEX IF NOT EXISTS idx_dns_ip ON dns_lookups(trace_id, ip)');

// Insert trace
const traceName = path.basename(jsonFile, '.json');
db.run(`INSERT INTO traces (name, command, json_file, io_dir, target_pid, exit_code, duration_ms, event_count, start_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
       [traceName, command, path.resolve(jsonFile), ioDir ? path.resolve(ioDir) : null,
        targetPid, exitCode, durationMs, events.length, startTime]);

const traceId = db.exec('SELECT last_insert_rowid() as id')[0].values[0][0];
console.log(`Created trace #${traceId}: ${traceName}`);

// Track file descriptors
const fdMap = new Map();
function getFdInfo(pid, fd) { return fdMap.get(`${pid}:${fd}`); }
function setFdInfo(pid, fd, info) { fdMap.set(`${pid}:${fd}`, info); }

function extractTarget(event) {
    const args = event.args || {};
    const pid = event.pid || 0;
    const fd = args.fd;
    const syscall = event.syscall || '';
    
    // Socket address from connect/bind/accept/sendto/recvfrom
    if (args.display) return args.display;
    
    // File path
    if (args.path) return args.path;
    
    // Memory operations — show address as target
    if (args.addr !== undefined) {
        return args.addr;  // hex string like "0x1045a0000"
    }
    
    // fd-based operations
    if (fd !== undefined) {
        if (fd === 0) return 'stdin';
        if (fd === 1) return 'stdout';
        if (fd === 2) return 'stderr';
        
        const info = getFdInfo(pid, fd);
        if (info) {
            // Prefer remote address for sockets
            if (info.display) return info.display;
            if (info.remote) return info.remote;
            if (info.path) return info.path;
            // Show socket type if we have it
            if (info.domain && info.type) return `${info.domain}/${info.type}`;
        }
        return `fd=${fd}`;
    }
    
    // Socket creation
    if (syscall === 'socket') {
        return `${args.domain || '?'}/${args.type || '?'}`;
    }
    
    return '';
}

function formatBytes(n) {
    if (n < 1024) return n + 'B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + 'K';
    return (n / (1024 * 1024)).toFixed(1) + 'M';
}

function extractDetails(event) {
    const args = event.args || {};
    const retval = event.return_value || 0;
    const syscall = event.syscall || '';
    const parts = [];
    
    // I/O size for read/write family
    if (args.count !== undefined) parts.push(`count=${args.count}`);
    if (['read', 'write', 'sendto', 'recvfrom'].some(s => syscall.includes(s)) && retval > 0) {
        parts.push(`→ ${formatBytes(retval)}`);
    }
    
    // Memory ops: show length + protection
    if (syscall === 'mprotect') {
        if (args.length !== undefined) parts.push(formatBytes(args.length));
        if (args.prot_str) parts.push(args.prot_str);
    } else if (syscall === 'mmap') {
        if (args.length !== undefined) parts.push(formatBytes(args.length));
        if (args.prot_str) parts.push(args.prot_str);
        if (args.flags_str) parts.push(args.flags_str);
        if (args.fd !== undefined && args.fd >= 0) parts.push(`fd=${args.fd}`);
        if (args.offset) parts.push(`off=0x${args.offset.toString(16)}`);
    } else if (syscall === 'munmap') {
        if (args.length !== undefined) parts.push(formatBytes(args.length));
    }
    
    // Socket options
    if (syscall === 'setsockopt' || syscall === 'getsockopt') {
        if (args.level_str) parts.push(args.level_str);
        if (args.optname_str) parts.push(args.optname_str);
    }
    
    // shutdown how
    if (syscall === 'shutdown' && args.how_str) {
        parts.push(args.how_str);
    }
    
    // kill signal
    if (syscall === 'kill' && args.signal_str) {
        parts.push(`→ ${args.signal_str}`);
    }
    
    // poll/select
    if (args.nfds !== undefined) parts.push(`nfds=${args.nfds}`);
    if (syscall.includes('poll') && args.timeout !== undefined) {
        parts.push(args.timeout < 0 ? 'timeout=∞' : `timeout=${args.timeout}ms`);
    }
    
    // File mode for mkdir/chmod/fchmod
    if (args.mode !== undefined && ['mkdir', 'chmod', 'fchmod'].some(s => syscall.includes(s))) {
        parts.push(`mode=${args.mode}`);
    }
    
    // truncate/ftruncate length
    if (args.length !== undefined && syscall.includes('truncat')) {
        parts.push(`→ ${formatBytes(args.length)}`);
    }
    
    // Catch-all: show raw_args if nothing else matched
    if (parts.length === 0 && args.raw_args && args.raw_args.length > 0) {
        parts.push(args.raw_args.join(' '));
    }
    
    return parts.join(' ');
}

function trackFd(event) {
    const syscall = event.syscall || '';
    const args = event.args || {};
    const retval = event.return_value || 0;
    const errno = event.errno || 0;
    const pid = event.pid || 0;
    
    if (['open', 'openat'].some(s => syscall.includes(s)) && errno === 0 && retval >= 0) {
        setFdInfo(pid, retval, { path: args.path || '' });
    } else if (syscall === 'socket' && errno === 0 && retval >= 0) {
        setFdInfo(pid, retval, { domain: args.domain, type: args.type });
    } else if (syscall.includes('connect') && args.display) {
        const info = getFdInfo(pid, args.fd) || {};
        info.display = args.display;
        info.remote = args.display;
        setFdInfo(pid, args.fd, info);
    } else if (syscall === 'bind' && args.display) {
        const info = getFdInfo(pid, args.fd) || {};
        info.local = args.display;
        if (!info.display) info.display = args.display;
        setFdInfo(pid, args.fd, info);
    }
}

// Find I/O file matching an event
let ioFileCache = null;
let ioFileCacheLogged = false;
function findIoFile(pid, syscall, target, fd) {
    if (!ioDir) return null;
    
    // Build cache of I/O files on first call
    if (ioFileCache === null) {
        ioFileCache = new Map();
        try {
            const files = fs.readdirSync(ioDir);
            for (const f of files) {
                if (f.endsWith('.bin') && !f.includes('.hexdump') && !f.includes('.rendered')) {
                    ioFileCache.set(f, true);
                }
            }
            if (!ioFileCacheLogged) {
                console.log(`Found ${ioFileCache.size} I/O files in ${ioDir}`);
                ioFileCacheLogged = true;
            }
        } catch (e) {
            if (!ioFileCacheLogged) {
                console.log(`Warning: Could not read I/O directory ${ioDir}: ${e.message}`);
                ioFileCacheLogged = true;
            }
            ioFileCache = new Map();
        }
    }
    
    const isRead = syscall.includes('read') || syscall.includes('recv');
    const isWrite = syscall.includes('write') || syscall.includes('send');
    if (!isRead && !isWrite) return null;
    
    const op = isRead ? ['read', 'recv'] : ['write', 'send'];
    
    // Get fd info for socket matching
    const fdInfo = fd !== undefined ? getFdInfo(pid, fd) : null;
    
    // Try to find matching file
    for (const [filename] of ioFileCache) {
        if (!filename.startsWith(`${pid}-`)) continue;
        if (!op.some(o => filename.includes(`-${o}-`))) continue;
        
        // Match by target name (sanitized path)
        if (target && target !== 'stdin' && target !== 'stdout' && target !== 'stderr') {
            const targetSafe = sanitizeFilename(path.basename(target), 40);
            if (targetSafe && filename.includes(targetSafe)) return filename;
        }
        
        // Match socket by family-type pattern (e.g., AF_INET-SOCK_STREAM)
        if (fdInfo && fdInfo.domain && fdInfo.type) {
            const sockPattern = `${fdInfo.domain}-${fdInfo.type}`;
            if (filename.includes(sockPattern)) return filename;
        }
        
        // Match stdin/stdout/stderr
        if (['stdin', 'stdout', 'stderr'].includes(target) && filename.includes(`-${target}.`)) {
            return filename;
        }
    }
    
    return null;
}

// Track chunk indices per io_path
const ioChunkCounters = new Map();

function getNextChunkIndex(ioPath) {
    if (!ioPath) return null;
    const idx = ioChunkCounters.get(ioPath) || 0;
    ioChunkCounters.set(ioPath, idx + 1);
    return idx;
}

// Compute start time as epoch ms
const startEpochMs = startTime ? new Date(startTime).getTime() : 0;

// Format timestamp as HH:MM:SS.mmm
function formatTime(timestampUs) {
    if (!startEpochMs) return '';
    const epochMs = startEpochMs + Math.floor(timestampUs / 1000);
    const d = new Date(epochMs);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${hh}:${mm}:${ss}.${ms}`;
}

// Prepare insert
const insertStmt = db.prepare(`
    INSERT INTO events (trace_id, seq, timestamp_us, time_str, pid, syscall, category,
                        return_value, errno, errno_name, target, details, has_io, io_path, io_chunk,
                        data_raw)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

console.log('Importing events...');
let imported = 0;

for (const event of events) {
    trackFd(event);
    
    const category = event.category || getCategory(event.syscall || '');
    const target = extractTarget(event);
    const details = extractDetails(event);
    const syscall = event.syscall || '';
    const fd = (event.args || {}).fd;
    const isIo = ['read', 'write', 'pread', 'pwrite', 'sendto', 'recvfrom']
        .some(s => syscall.includes(s)) && (event.return_value || 0) > 0;
    
    // Try to find existing .bin file, or generate from args.data
    let ioPath = isIo ? findIoFile(event.pid || 0, syscall, target, fd) : null;
    if (!ioPath && isIo && (event.args || {}).data) {
        ioPath = generateIoFile(event, target);
    }
    const ioChunk = getNextChunkIndex(ioPath);
    const dataRaw = extractRawData(event);
    
    const timestampUs = event.timestamp_us || 0;
    const timeStr = formatTime(timestampUs);
    
    insertStmt.run([
        traceId,
        event.timestamp_us || imported,
        timestampUs,
        timeStr,
        event.pid || 0,
        syscall,
        category,
        event.return_value || 0,
        event.errno || 0,
        (event.args || {}).errno_name || '',
        target,
        details,
        isIo ? 1 : 0,
        ioPath,
        ioChunk,
        dataRaw
    ]);
    
    imported++;
    if (imported % 5000 === 0) {
        process.stdout.write(`\r  ${imported.toLocaleString()} / ${events.length.toLocaleString()} events`);
    }
}

insertStmt.free();
console.log(`\n  ${imported.toLocaleString()} events imported`);

// Write metadata for any generated I/O files
writeIoMetadata();

// Import process tree and process events
const processTree = trace.process_tree || {};
const processEvents = trace.process_events || [];

if (Object.keys(processTree).length > 0 || processEvents.length > 0) {
    console.log('Importing process lifecycle data...');
    
    // Build per-PID info from process_tree (parent links) and process_events (exec, fork, exit)
    const procInfo = new Map(); // pid → {parent_pid, exec_path, fork_time, exec_time, exit_time, exit_code}
    
    // process_tree gives us child→parent mappings
    for (const [childStr, parent] of Object.entries(processTree)) {
        const child = parseInt(childStr, 10);
        if (!procInfo.has(child)) procInfo.set(child, {});
        procInfo.get(child).parent_pid = parent;
    }
    
    // process_events give us exec paths, fork/exit times
    for (const pe of processEvents) {
        const pid = pe.pid || 0;
        if (!procInfo.has(pid)) procInfo.set(pid, {});
        const info = procInfo.get(pid);
        
        const details = pe.details || {};
        const ts = pe.timestamp_us || 0;
        
        switch (pe.event_type) {
            case 'fork':
            case 'child_detected':
                if (details.parent_pid) info.parent_pid = details.parent_pid;
                if (!info.fork_time) info.fork_time = ts;
                break;
            case 'exec':
                if (details.path) info.exec_path = details.path;
                if (!info.exec_time) info.exec_time = ts;
                break;
            case 'exit':
                info.exit_time = ts;
                if (details.exit_code !== undefined) info.exit_code = details.exit_code;
                break;
        }
    }
    
    // Also ensure target PID is in the map
    if (targetPid && !procInfo.has(targetPid)) {
        procInfo.set(targetPid, { exec_path: (trace.command || [])[0] || null });
    }
    
    const procStmt = db.prepare(`
        INSERT INTO processes (trace_id, pid, parent_pid, exec_path, fork_time_us, exec_time_us, exit_time_us, exit_code)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    let procCount = 0;
    for (const [pid, info] of procInfo) {
        procStmt.run([
            traceId, pid,
            info.parent_pid ?? null,
            info.exec_path ?? null,
            info.fork_time ?? null,
            info.exec_time ?? null,
            info.exit_time ?? null,
            info.exit_code ?? null
        ]);
        procCount++;
    }
    procStmt.free();
    console.log(`  ${procCount.toLocaleString()} processes imported`);
}

// Extract DNS hostname → IP correlations from mDNSResponder traffic
function extractDnsLookups() {
    console.log('Extracting DNS lookups from mDNSResponder traffic...');
    
    // Find all sendto to mDNSResponder with captured data
    const dnsEvents = [];
    const connectEvents = [];
    
    // Query for mDNSResponder sends
    const dnsStmt = db.prepare(`
        SELECT seq, data_raw FROM events 
        WHERE trace_id = ? AND target = '/var/run/mDNSResponder'
        AND data_raw IS NOT NULL AND syscall LIKE '%send%'
        ORDER BY seq
    `);
    dnsStmt.bind([traceId]);
    while (dnsStmt.step()) {
        const row = dnsStmt.getAsObject();
        dnsEvents.push(row);
    }
    dnsStmt.free();
    
    // Query for connect to IPs
    const connStmt = db.prepare(`
        SELECT seq, target FROM events 
        WHERE trace_id = ? AND syscall = 'connect'
        AND target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:*'
        ORDER BY seq
    `);
    connStmt.bind([traceId]);
    while (connStmt.step()) {
        const row = connStmt.getAsObject();
        connectEvents.push(row);
    }
    connStmt.free();
    
    if (dnsEvents.length === 0) {
        console.log('  No mDNSResponder traffic found');
        return;
    }
    
    // Parse DNS lookups from mDNSResponder IPC protocol
    const lookups = [];
    for (const ev of dnsEvents) {
        try {
            const bytes = Buffer.from(ev.data_raw, 'hex');
            if (bytes.length < 28) continue;
            
            // IPC header is big-endian
            const op = bytes.readUInt32BE(12);
            
            // Op 8 = addrinfo_request, Op 7 = query_request
            if (op !== 8 && op !== 7) continue;
            
            // Extract null-terminated strings after header (hostname is not at fixed offset)
            let pos = 28;
            let found = false;
            while (pos < bytes.length && !found) {
                const end = bytes.indexOf(0, pos);
                if (end < 0) break;
                if (end === pos) { pos++; continue; } // Skip null bytes
                const str = bytes.toString('utf8', pos, end);
                // Check if it looks like a hostname
                if (str.length > 3 && /^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z]$/.test(str)) {
                    lookups.push({ seq: ev.seq, hostname: str });
                    found = true;
                }
                pos = end + 1;
            }
        } catch (e) {
            // Skip malformed data
        }
    }
    
    if (lookups.length === 0) {
        console.log('  No DNS hostnames found in mDNSResponder traffic');
        return;
    }
    
    // Correlate with connect() calls
    const dnsInsert = db.prepare(`
        INSERT INTO dns_lookups (trace_id, hostname, ip, lookup_seq, connect_seq)
        VALUES (?, ?, ?, ?, ?)
    `);
    
    const correlations = new Map(); // hostname -> {ip, lookup_seq, connect_seq}
    
    for (const lookup of lookups) {
        // Skip if we already have this hostname
        if (correlations.has(lookup.hostname)) continue;
        
        // Find next connect() to an IP within 1000 events
        const conn = connectEvents.find(c => c.seq > lookup.seq && c.seq < lookup.seq + 1000);
        if (conn) {
            const ip = conn.target.split(':')[0]; // Extract IP without port
            correlations.set(lookup.hostname, {
                ip: conn.target,
                lookup_seq: lookup.seq,
                connect_seq: conn.seq
            });
        }
    }
    
    // Insert unique correlations
    for (const [hostname, info] of correlations) {
        dnsInsert.run([traceId, hostname, info.ip, info.lookup_seq, info.connect_seq]);
    }
    dnsInsert.free();
    
    console.log(`  Found ${correlations.size} hostname → IP correlations`);
    for (const [hostname, info] of correlations) {
        console.log(`    ${hostname} → ${info.ip}`);
    }
}

extractDnsLookups();

// Create FTS table for search (if SQLite FTS5 is available)
try {
    db.run('DROP TABLE IF EXISTS events_fts');
    db.run(`CREATE VIRTUAL TABLE events_fts USING fts5(syscall, target, details, time_str, errno_name, content=events, content_rowid=id)`);
    db.run(`INSERT INTO events_fts(rowid, syscall, target, details, time_str, errno_name) SELECT id, syscall, target, details, time_str, errno_name FROM events WHERE trace_id = ${traceId}`);
    console.log('Created full-text search index');
} catch (e) {
    console.log('Note: FTS5 not available, search will use LIKE (see README.md)');
}

// Save database
const data = db.export();
fs.writeFileSync(dbFile, Buffer.from(data));
db.close();

console.log(`Done! Saved to ${dbFile}`);
console.log(`\nRun: mactrace-server --db ${dbFile}`);
