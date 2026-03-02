#!/usr/bin/env node
/**
 * Import mactrace JSON into SQLite database (using sql.js).
 * 
 * Usage: mactrace-import trace.json [--db mactrace.db] [--io-dir ./io_output]
 */

import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

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


// ── Process name tracking (for structured I/O directories) ──────────────
// Maps PID → process name for directory naming. Built from:
// 1. process_events (exec paths)  2. execve syscalls  3. trace command
const pidNames = new Map();
const pidIoStats = new Map(); // PID → {reads, writes, read_bytes, write_bytes, fds: Set}

function getProcessName(pid) {
    return pidNames.get(pid) || 'unknown';
}

function sanitizeDirName(s, maxLen = 30) {
    if (!s) return 'unknown';
    s = s.split('/').pop() || s;
    s = s.replace(/[^a-zA-Z0-9._-]/g, '_');
    s = s.replace(/__+/g, '_').replace(/^[_.]/, '');
    return (s.slice(0, maxLen) || 'unknown');
}

function getPidSubdir(pid) {
    const name = sanitizeDirName(getProcessName(pid));
    return `${pid}-${name}`;
}

function ensurePidDir(pid) {
    const subdir = getPidSubdir(pid);
    const dirPath = path.join(ioDir, subdir);
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
    return dirPath;
}

function trackPidIo(pid, syscall, fd, bytes) {
    if (!pidIoStats.has(pid)) {
        pidIoStats.set(pid, { reads: 0, writes: 0, read_bytes: 0, write_bytes: 0, fds: new Set() });
    }
    const stats = pidIoStats.get(pid);
    const isRead = syscall.includes('read') || syscall.includes('recv');
    if (isRead) {
        stats.reads++;
        stats.read_bytes += bytes;
    } else {
        stats.writes++;
        stats.write_bytes += bytes;
    }
    if (fd !== undefined) stats.fds.add(fd);
}

// Category detection — loaded from shared syscalls.json (single source of truth)
const __dirname_import = path.dirname(fileURLToPath(import.meta.url));
const syscallsJsonPath = path.join(__dirname_import, '..', 'syscalls.json');
const syscallsData = JSON.parse(fs.readFileSync(syscallsJsonPath, 'utf-8'));

// Build reverse lookup: syscall name → category id
const SYSCALL_TO_CATEGORY = {};
for (const cat of syscallsData.categories) {
    for (const sc of cat.syscalls || []) {
        SYSCALL_TO_CATEGORY[sc] = cat.id;
    }
}
const DEFAULT_CATEGORY = syscallsData.defaultCategory?.id || 'other';

function getCategory(syscall) {
    // Try exact match first, then strip _nocancel suffix
    if (SYSCALL_TO_CATEGORY[syscall]) return SYSCALL_TO_CATEGORY[syscall];
    const base = syscall.replace(/_nocancel$/, '');
    return SYSCALL_TO_CATEGORY[base] || DEFAULT_CATEGORY;
}

function sanitizeFilename(s, maxLen = 60) {
    if (!s) return 'unknown';
    return s.replace(/[\/\\:*?"<>|]/g, '_').replace(/\s/g, '_').replace(/_+/g, '_').slice(0, maxLen) || 'unknown';
}

function extractRawData(event, maxLen = 512) {
    const args = event.args || {};
    // Standard single-buffer I/O data
    if (args.data && typeof args.data === "string") {
        return args.data.slice(0, maxLen * 2);
    }
    // Vectored I/O: concatenate iov buffer hex data
    if (args.iov_buffers && Array.isArray(args.iov_buffers)) {
        const hex = args.iov_buffers.map(b => b.data || "").join("");
        return hex.slice(0, maxLen * 2) || null;
    }
    return null;
}

// Track generated I/O files: Map<filename, {offsets: [], total_size: number}>
const generatedIoFiles = new Map();

// Generate .bin file from args.data, organized into per-PID subdirectories
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
    
    // Target basename for filename
    const targetName = target ? sanitizeFilename(path.basename(target), 40) : 'unknown';
    
    // Build path: ioDir/PID-procname/op-target.bin
    const pidDir = ensurePidDir(pid);
    const filename = `${op}-${targetName}.bin`;
    const relPath = `${getPidSubdir(pid)}/${filename}`;
    const filepath = path.join(pidDir, filename);
    
    // Track I/O stats for per-process meta.json
    const bytes = Buffer.from(data, 'hex');
    trackPidIo(pid, syscall, args.fd, bytes.length);
    
    // Track this file for metadata
    let fileInfo = generatedIoFiles.get(relPath);
    if (!fileInfo) {
        fileInfo = { offsets: [], total_size: 0, filepath };
        generatedIoFiles.set(relPath, fileInfo);
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
    
    return relPath;
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

// Write structured meta.json files (per-process + top-level)
function writeStructuredMeta(traceName, traceCommand, targetPid, duration, eventCount) {
    if (!ioDir) return;
    
    const processTree = trace.process_tree || {};
    
    // Per-process meta.json
    let processCount = 0;
    for (const [pid, stats] of pidIoStats) {
        const pidSubdir = getPidSubdir(pid);
        const pidDirPath = path.join(ioDir, pidSubdir);
        if (!fs.existsSync(pidDirPath)) continue;
        
        const meta = {
            format_version: 2,
            pid: pid,
            name: getProcessName(pid),
            parent_pid: processTree[String(pid)] || null,
            io_summary: {
                reads: stats.reads,
                writes: stats.writes,
                read_bytes: stats.read_bytes,
                write_bytes: stats.write_bytes,
                total_bytes: stats.read_bytes + stats.write_bytes,
            },
            fds: Array.from(stats.fds).sort((a, b) => a - b),
        };
        
        try {
            fs.writeFileSync(path.join(pidDirPath, 'meta.json'), JSON.stringify(meta, null, 2));
            processCount++;
        } catch (e) {
            console.error(`Warning: Could not write meta.json for PID ${pid}: ${e.message}`);
        }
    }
    
    // Top-level meta.json for the run
    const topMeta = {
        format_version: 2,
        name: traceName,
        command: traceCommand,
        target_pid: targetPid,
        duration_ms: duration,
        event_count: eventCount,
        process_count: processCount,
        io_summary: {
            total_processes_with_io: pidIoStats.size,
            total_reads: 0,
            total_writes: 0,
            total_read_bytes: 0,
            total_write_bytes: 0,
        },
        processes: [],
    };
    
    // Aggregate and list processes
    for (const [pid, stats] of pidIoStats) {
        topMeta.io_summary.total_reads += stats.reads;
        topMeta.io_summary.total_writes += stats.writes;
        topMeta.io_summary.total_read_bytes += stats.read_bytes;
        topMeta.io_summary.total_write_bytes += stats.write_bytes;
        topMeta.processes.push({
            pid,
            name: getProcessName(pid),
            parent_pid: processTree[String(pid)] || null,
            dir: getPidSubdir(pid),
            reads: stats.reads,
            writes: stats.writes,
            total_bytes: stats.read_bytes + stats.write_bytes,
        });
    }
    topMeta.io_summary.total_bytes = topMeta.io_summary.total_read_bytes + topMeta.io_summary.total_write_bytes;
    
    // Sort processes by total bytes (largest first)
    topMeta.processes.sort((a, b) => b.total_bytes - a.total_bytes);
    
    try {
        fs.writeFileSync(path.join(ioDir, 'meta.json'), JSON.stringify(topMeta, null, 2));
        console.log(`Wrote structured meta.json: ${processCount} process(es) with I/O`);
    } catch (e) {
        console.error(`Warning: Could not write top-level meta.json: ${e.message}`);
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

// Open or create database (better-sqlite3 writes directly to disk —
// no need to export/save manually)
const db = new Database(dbFile);
db.pragma('journal_mode = WAL');
if (fs.existsSync(dbFile)) {
    console.log(`Opened existing database: ${dbFile}`);
} else {
    console.log(`Creating new database: ${dbFile}`);
}

// Create schema
db.exec(`
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

db.exec(`
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

db.exec('CREATE INDEX IF NOT EXISTS idx_events_trace ON events(trace_id)');
db.exec('CREATE INDEX IF NOT EXISTS idx_events_category ON events(trace_id, category)');
db.exec('CREATE INDEX IF NOT EXISTS idx_events_syscall ON events(trace_id, syscall)');
db.exec('CREATE INDEX IF NOT EXISTS idx_events_errno ON events(trace_id, errno)');

// Process lifecycle table (from process_tree + process_events)
db.exec(`
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
db.exec('CREATE INDEX IF NOT EXISTS idx_processes_trace ON processes(trace_id)');
db.exec('CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(trace_id, pid)');

// DNS lookups table for hostname → IP correlation
db.exec(`
    CREATE TABLE IF NOT EXISTS dns_lookups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id INTEGER NOT NULL,
        hostname TEXT NOT NULL,
        ip TEXT,
        lookup_seq INTEGER,
        connect_seq INTEGER,
        source TEXT DEFAULT 'unknown',
        FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
    )
`);
db.exec('CREATE INDEX IF NOT EXISTS idx_dns_trace ON dns_lookups(trace_id)');
db.exec('CREATE INDEX IF NOT EXISTS idx_dns_ip ON dns_lookups(trace_id, ip)');
// Migration: add source column if missing (existing DBs)
try { db.exec("ALTER TABLE dns_lookups ADD COLUMN source TEXT DEFAULT 'unknown'"); } catch (e) { /* already exists */ }

// Insert trace
// Strip epoch timestamp suffix from filename for display name
// "make.1740000000.json" → "make", "nmap.json" → "nmap"
let traceName = path.basename(jsonFile, '.json');
if (/\.\d{10}$/.test(traceName)) {
    traceName = traceName.replace(/\.\d{10}$/, '');
}
db.prepare(`INSERT INTO traces (name, command, json_file, io_dir, target_pid, exit_code, duration_ms, event_count, start_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(traceName, command, path.resolve(jsonFile), ioDir ? path.resolve(ioDir) : null,
         targetPid, exitCode, durationMs, events.length, startTime);

const traceId = db.prepare('SELECT last_insert_rowid() as id').get().id;
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
    
    // Vectored I/O (readv/writev/preadv/pwritev)
    if (args.iovcnt !== undefined) {
        parts.push(`iovcnt=${args.iovcnt}`);
        if (args.iov_buffers) {
            const captured = args.iov_buffers.length;
            if (captured < args.iovcnt) parts.push(`(${captured} captured)`);
        }
    }
    if (args.offset !== undefined && syscall.startsWith("p")) parts.push(`off=${args.offset}`);
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
    
    // First check PID subdirectory (new structured layout)
    const pidSubdir = getPidSubdir(pid);
    const pidDirPath = path.join(ioDir, pidSubdir);
    if (fs.existsSync(pidDirPath)) {
        const isRead = syscall.includes('read') || syscall.includes('recv');
        const op = isRead ? 'read' : 'write';
        const targetName = target ? sanitizeFilename(path.basename(target), 40) : 'unknown';
        const expected = `${op}-${targetName}.bin`;
        const expectedPath = path.join(pidDirPath, expected);
        if (fs.existsSync(expectedPath)) {
            return `${pidSubdir}/${expected}`;
        }
    }
    
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

// Pre-scan: build PID→name map from process_events and trace command
const processEventsForNames = trace.process_events || [];
for (const pe of processEventsForNames) {
    if (pe.event_type === 'exec' && pe.details && pe.details.path) {
        pidNames.set(pe.pid, pe.details.path);
    }
}
// Target PID gets the trace command name
const traceCommand = trace.command || [];
if (targetPid && traceCommand.length > 0) {
    if (!pidNames.has(targetPid)) {
        pidNames.set(targetPid, traceCommand[0]);
    }
}
if (pidNames.size > 0) {
    console.log(`Pre-scanned ${pidNames.size} process name(s)`);
}

console.log('Importing events...');
let imported = 0;

// Wrap in a transaction for correctness (atomic import) and performance
// (~100x faster than autocommit per-row).
db.exec('BEGIN TRANSACTION');

for (const event of events) {
    trackFd(event);
    
    // Track process names from exec syscalls
    if ((event.syscall || '').includes('exec') && event.args && event.args.path) {
        pidNames.set(event.pid || 0, event.args.path);
    }
    
    const category = event.category || getCategory(event.syscall || '');
    const target = extractTarget(event);
    const details = extractDetails(event);
    const syscall = event.syscall || '';
    const fd = (event.args || {}).fd;
    const isIo = ['read', 'write', 'pread', 'pwrite', 'readv', 'writev', 'preadv', 'pwritev', 'sendto', 'recvfrom']
        .some(s => syscall.includes(s)) && (event.return_value || 0) > 0;
    
    // Try to find existing .bin file, or generate from args.data
    let ioPath = isIo ? findIoFile(event.pid || 0, syscall, target, fd) : null;
    if (!ioPath && isIo && (event.args || {}).data) {
        ioPath = generateIoFile(event, target);
    }
    // Track I/O stats for structured meta (even for pre-existing files)
    if (isIo && !ioPath) {
        trackPidIo(event.pid || 0, syscall, fd, event.return_value || 0);
    }
    const ioChunk = getNextChunkIndex(ioPath);
    const dataRaw = extractRawData(event);
    
    const timestampUs = event.timestamp_us || 0;
    const timeStr = formatTime(timestampUs);
    
    insertStmt.run(
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
    );
    
    imported++;
    if (imported % 5000 === 0) {
        process.stdout.write(`\r  ${imported.toLocaleString()} / ${events.length.toLocaleString()} events`);
    }
}

db.exec('COMMIT');
console.log(`\n  ${imported.toLocaleString()} events imported`);

// Write metadata for any generated I/O files
writeIoMetadata();

// Write structured per-process meta.json files
writeStructuredMeta(traceName, command, targetPid, durationMs, events.length);

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
        procStmt.run(
            traceId, pid,
            info.parent_pid ?? null,
            info.exec_path ?? null,
            info.fork_time ?? null,
            info.exec_time ?? null,
            info.exit_time ?? null,
            info.exit_code ?? null
        );
        procCount++;
    }
    console.log(`  ${procCount.toLocaleString()} processes imported`);
}

// ── DNS wire protocol parser (RFC 1035) ─────────────────────────────────

/**
 * Parse a DNS name from wire format at the given offset.
 * Handles label-length encoding (no compression pointer support needed
 * for queries; responses may use pointers but we only parse queries).
 * Returns { name, nextOffset } or null on failure.
 */
function parseDnsName(buf, offset) {
    const labels = [];
    let pos = offset;
    let jumps = 0;
    while (pos < buf.length) {
        const len = buf[pos];
        if (len === 0) { pos++; break; }                 // Root label — end of name
        if ((len & 0xC0) === 0xC0) {                      // Compression pointer
            if (pos + 1 >= buf.length) return null;
            const ptr = ((len & 0x3F) << 8) | buf[pos + 1];
            if (++jumps > 10) return null;                 // Loop guard
            if (labels.length === 0) pos += 2;             // Advance past pointer only on first jump
            // For queries we shouldn't hit pointers, but handle gracefully
            pos = ptr;
            continue;
        }
        if (len > 63) return null;                         // Invalid label length
        pos++;
        if (pos + len > buf.length) return null;
        labels.push(buf.toString('ascii', pos, pos + len));
        pos += len;
    }
    if (labels.length === 0) return null;
    return { name: labels.join('.'), nextOffset: pos };
}

/**
 * Parse a DNS query packet and extract the queried hostname.
 * Returns the hostname string or null if unparseable.
 */
function parseDnsQuery(buf) {
    // DNS header: 12 bytes (ID, flags, qdcount, ancount, nscount, arcount)
    if (buf.length < 13) return null;
    const flags = buf.readUInt16BE(2);
    const qr = (flags >> 15) & 1;        // 0 = query, 1 = response
    if (qr !== 0) return null;            // We only want queries
    const qdcount = buf.readUInt16BE(4);
    if (qdcount < 1) return null;
    // Sanity: ancount/nscount/arcount should be 0 in a query
    const ancount = buf.readUInt16BE(6);
    if (ancount > 50) return null;        // Not a real DNS packet
    const result = parseDnsName(buf, 12);
    if (!result) return null;
    // Validate hostname: must contain only valid DNS chars (letters, digits, hyphens, dots)
    // and have at least one dot (TLD). Rejects binary garbage that happens to parse.
    const name = result.name;
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/.test(name)) return null;
    if (!name.includes('.')) return null;  // Must have at least one dot
    if (name.length > 253) return null;   // RFC 1035 max
    return name;
}

/**
 * Parse a DNS response packet and extract A/AAAA answer IPs.
 * Returns array of IP strings, or empty array.
 */
function parseDnsResponse(buf) {
    if (buf.length < 12) return [];
    const flags = buf.readUInt16BE(2);
    const qr = (flags >> 15) & 1;
    if (qr !== 1) return [];              // Not a response
    const qdcount = buf.readUInt16BE(4);
    const ancount = buf.readUInt16BE(6);
    if (ancount === 0) return [];

    // Skip question section
    let pos = 12;
    for (let i = 0; i < qdcount; i++) {
        const r = parseDnsName(buf, pos);
        if (!r) return [];
        pos = r.nextOffset + 4;           // Skip QTYPE (2) + QCLASS (2)
    }

    // Parse answer section for A (1) and AAAA (28) records
    const ips = [];
    for (let i = 0; i < ancount && pos < buf.length; i++) {
        // Name (may be compressed)
        if (pos >= buf.length) break;
        if ((buf[pos] & 0xC0) === 0xC0) {
            pos += 2;                     // Compression pointer
        } else {
            const r = parseDnsName(buf, pos);
            if (!r) break;
            pos = r.nextOffset;
        }
        if (pos + 10 > buf.length) break;
        const rtype = buf.readUInt16BE(pos);
        const rdlength = buf.readUInt16BE(pos + 8);
        pos += 10;
        if (pos + rdlength > buf.length) break;
        if (rtype === 1 && rdlength === 4) {
            // A record — IPv4
            ips.push(`${buf[pos]}.${buf[pos+1]}.${buf[pos+2]}.${buf[pos+3]}`);
        } else if (rtype === 28 && rdlength === 16) {
            // AAAA record — IPv6
            const parts = [];
            for (let j = 0; j < 16; j += 2) {
                parts.push(buf.readUInt16BE(pos + j).toString(16));
            }
            ips.push(parts.join(':'));
        } else if (rtype === 12) {
            // PTR record — domain name (for reverse DNS lookups)
            const r = parseDnsName(buf, pos);
            if (r) ips.push('PTR:' + r.name);
        }
        pos += rdlength;
    }
    return ips;
}

/**
 * Extract IP from an in-addr.arpa reverse DNS name.
 * "4.0.41.198.in-addr.arpa" → "198.41.0.4"
 * Returns null if not an in-addr.arpa name.
 */
function reverseArpaToIp(hostname) {
    const m = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa\.?$/i);
    if (m) return `${m[4]}.${m[3]}.${m[2]}.${m[1]}`;
    return null;
}


// ── DNS extraction from traces ──────────────────────────────────────────

function extractDnsLookups() {
    console.log('Extracting DNS lookups...');
    
    const correlations = new Map(); // hostname -> {ip, lookup_seq, connect_seq}
    
    // Query for connect to IPs (used by all sources for correlation)
    const connectEvents = db.prepare(`
        SELECT seq, target FROM events 
        WHERE trace_id = ? AND syscall = 'connect'
        AND target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:*'
        ORDER BY seq
    `).all(traceId);
    
    // ── Source 0: /etc/hosts (static resolution) ──────────────────
    // Check if the traced program read /etc/hosts and parse any entries
    const hostsRows = db.prepare(`
        SELECT data_raw FROM events 
        WHERE trace_id = ? AND target = '/etc/hosts'
        AND data_raw IS NOT NULL AND syscall LIKE '%read%'
        AND return_value > 0
        ORDER BY seq LIMIT 5
    `).all(traceId);
    
    const hostsEntries = new Map();  // hostname → ip
    for (const row of hostsRows) {
        try {
            const text = Buffer.from(row.data_raw, 'hex').toString('utf8');
            for (const line of text.split('\n')) {
                const trimmed = line.replace(/#.*/, '').trim();
                if (!trimmed) continue;
                const parts = trimmed.split(/\s+/);
                if (parts.length >= 2) {
                    const ip = parts[0];
                    for (let i = 1; i < parts.length; i++) {
                        hostsEntries.set(parts[i].toLowerCase(), ip);
                    }
                }
            }
        } catch (e) { /* skip */ }
    }
    
    // Add /etc/hosts entries to correlations
    for (const [hostname, ip] of hostsEntries) {
        if (hostname === 'localhost' || hostname === 'broadcasthost') continue;
        // Only add if we see a connect to this IP
        const conn = connectEvents.find(c => c.target.startsWith(ip + ':'));
        if (conn) {
            correlations.set(hostname, {
                ip: conn.target,
                lookup_seq: null,
                connect_seq: conn.seq,
                source: '/etc/hosts'
            });
        }
    }
    
    if (hostsEntries.size > 0) {
        console.log(`  /etc/hosts: ${hostsEntries.size} entries parsed`);
    }
    
    // ── Source 1: mDNSResponder IPC (system resolver) ──────────────
    const dnsRows = db.prepare(`
        SELECT seq, data_raw FROM events 
        WHERE trace_id = ? AND target = '/var/run/mDNSResponder'
        AND data_raw IS NOT NULL AND syscall LIKE '%send%'
        ORDER BY seq
    `).all(traceId);
    
    // Parse mDNSResponder IPC protocol
    const mdnsLookups = [];
    for (const ev of dnsRows) {
        try {
            const bytes = Buffer.from(ev.data_raw, 'hex');
            if (bytes.length < 28) continue;
            
            // IPC header is big-endian
            const op = bytes.readUInt32BE(12);
            
            // Op 8 = addrinfo_request, Op 7 = query_request
            if (op !== 8 && op !== 7) continue;
            
            // Extract null-terminated strings after header
            let pos = 28;
            let found = false;
            while (pos < bytes.length && !found) {
                const end = bytes.indexOf(0, pos);
                if (end < 0) break;
                if (end === pos) { pos++; continue; }
                const str = bytes.toString('utf8', pos, end);
                if (str.length > 3 && /^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z]$/.test(str)) {
                    mdnsLookups.push({ seq: ev.seq, hostname: str });
                    found = true;
                }
                pos = end + 1;
            }
        } catch (e) {
            // Skip malformed data
        }
    }
    
    // Correlate mDNSResponder lookups with connect() calls
    // Skip connects to port 53 — those are DNS server connections, not resolved hosts
    for (const lookup of mdnsLookups) {
        if (correlations.has(lookup.hostname)) continue;
        const conn = connectEvents.find(c => 
            c.seq > lookup.seq && 
            c.seq < lookup.seq + 1000 &&
            !c.target.endsWith(':53')   // Skip DNS server connections
        );
        if (conn) {
            correlations.set(lookup.hostname, {
                ip: conn.target,
                lookup_seq: lookup.seq,
                connect_seq: conn.seq,
                source: 'mDNSResponder'
            });
        }
    }
    
    if (mdnsLookups.length > 0) {
        console.log(`  mDNSResponder: ${mdnsLookups.length} lookups, ${correlations.size} correlated`);
    }
    
    // ── Source 2: Direct DNS wire protocol (port 53) ────────────────
    // Catch apps that bypass the system resolver (dig, nslookup, Go apps,
    // custom DNS clients, security tools).
    //
    // Look for sendto/write to port 53 targets, and also for sendmsg/write
    // on sockets that were connect()'d to port 53.
    
    // Find sockets connected to port 53
    const port53Connects = db.prepare(`
        SELECT seq, target FROM events
        WHERE trace_id = ? AND syscall IN ('connect', 'connect_nocancel')
        AND target LIKE '%:53'
        ORDER BY seq
    `).all(traceId);
    
    // Find sendto to port 53 with captured data
    const port53Sends = db.prepare(`
        SELECT seq, target, data_raw FROM events
        WHERE trace_id = ? AND data_raw IS NOT NULL
        AND syscall IN ('sendto', 'sendto_nocancel')
        AND target LIKE '%:53'
        ORDER BY seq
    `).all(traceId);
    
    // Find sendmsg with captured data — sendmsg doesn't expose the
    // destination in the target field (it's inside msghdr), so we
    // identify DNS by checking if the buffer is a valid DNS query.
    const sendmsgSends = db.prepare(`
        SELECT seq, pid, data_raw FROM events
        WHERE trace_id = ? AND data_raw IS NOT NULL
        AND syscall IN ('sendmsg', 'sendmsg_nocancel')
        ORDER BY seq
    `).all(traceId);
    
    // Find write/send on sockets connected to port 53 (for TCP DNS or connected UDP)
    // We need fd tracking for this — check if any connect-to-:53 events exist
    // and look for subsequent writes on the same fd
    const port53Fds = new Set();
    for (const c of port53Connects) {
        // Extract fd from connect event args
        const fdMatch = c.target?.match(/^(\d+\.\d+\.\d+\.\d+):53$/);
        if (fdMatch) port53Fds.add(c.seq); // Track the seq for correlation
    }
    
    // Also look for recvfrom from port 53 (DNS responses with answer data)
    const port53Recvs = db.prepare(`
        SELECT seq, target, data_raw FROM events
        WHERE trace_id = ? AND data_raw IS NOT NULL
        AND syscall IN ('recvfrom', 'recvfrom_nocancel')
        AND target LIKE '%:53'
        ORDER BY seq
    `).all(traceId);
    
    // Also look for recvmsg DNS responses (same approach as sendmsg)
    const recvmsgRecvs = db.prepare(`
        SELECT seq, pid, data_raw FROM events
        WHERE trace_id = ? AND data_raw IS NOT NULL
        AND syscall IN ('recvmsg', 'recvmsg_nocancel')
        ORDER BY seq
    `).all(traceId);
    
    let port53Count = 0;
    
    // Parse DNS queries from sendto data
    for (const ev of port53Sends) {
        try {
            const bytes = Buffer.from(ev.data_raw, 'hex');
            const hostname = parseDnsQuery(bytes);
            if (!hostname || correlations.has(hostname)) continue;
            
            const txid = bytes.readUInt16BE(0);
            
            // Look for matching response (same txid) in recvfrom
            let resolvedIp = null;
            for (const recv of port53Recvs) {
                if (recv.seq <= ev.seq) continue;
                if (recv.seq > ev.seq + 500) break;  // Don't look too far ahead
                try {
                    const rbytes = Buffer.from(recv.data_raw, 'hex');
                    if (rbytes.length >= 2 && rbytes.readUInt16BE(0) === txid) {
                        const ips = parseDnsResponse(rbytes);
                        if (ips.length > 0) {
                            resolvedIp = ips[0];  // Take first A/AAAA answer
                            break;
                        }
                    }
                } catch (e) { /* skip */ }
            }
            
            // Also try to correlate with a connect() to the resolved IP
            let connectSeq = null;
            if (resolvedIp) {
                const conn = connectEvents.find(c => 
                    c.seq > ev.seq && c.target.startsWith(resolvedIp + ':'));
                if (conn) connectSeq = conn.seq;
            }
            
            const dnsServer = ev.target;  // e.g. "8.8.8.8:53"
            correlations.set(hostname, {
                ip: resolvedIp ? `${resolvedIp}:0` : dnsServer,
                lookup_seq: ev.seq,
                connect_seq: connectSeq,
                source: 'port53'
            });
            port53Count++;
        } catch (e) {
            // Skip malformed packets
        }
    }
    
    // Parse DNS queries from sendmsg data (dig, Go resolver, etc.)
    // sendmsg doesn't expose the target address, so we identify DNS packets
    // by structure: valid header + parseable question section, length > 12.
    for (const ev of sendmsgSends) {
        try {
            const bytes = Buffer.from(ev.data_raw, 'hex');
            if (bytes.length <= 12) continue;  // Too short for DNS
            const hostname = parseDnsQuery(bytes);
            if (!hostname) continue;
            
            // For reverse DNS (PTR), extract the actual IP from in-addr.arpa
            const reverseIp = reverseArpaToIp(hostname);
            // Use the forward hostname or the reverse IP as the key
            const displayName = reverseIp ? hostname : hostname;
            if (correlations.has(displayName)) continue;
            
            const txid = bytes.readUInt16BE(0);
            
            // Look for matching response in recvmsg (same pid, same txid)
            let resolvedIp = null;
            let ptrName = null;
            for (const recv of recvmsgRecvs) {
                if (recv.seq <= ev.seq) continue;
                if (recv.seq > ev.seq + 500) break;
                if (recv.pid !== ev.pid) continue;  // Same process
                try {
                    const rbytes = Buffer.from(recv.data_raw, 'hex');
                    if (rbytes.length >= 2 && rbytes.readUInt16BE(0) === txid) {
                        const answers = parseDnsResponse(rbytes);
                        for (const ans of answers) {
                            if (ans.startsWith('PTR:')) {
                                ptrName = ans.slice(4);
                            } else if (!resolvedIp) {
                                resolvedIp = ans;
                            }
                        }
                        break;
                    }
                } catch (e) { /* skip */ }
            }
            
            // For PTR lookups: show "PTR-name → original-IP"
            // For forward lookups: show "hostname → resolved-IP"
            if (reverseIp) {
                // Reverse DNS: the "hostname" is the PTR result, the "IP" is the queried IP
                const label = ptrName || hostname;
                correlations.set(label, {
                    ip: reverseIp + ':0',
                    lookup_seq: ev.seq,
                    connect_seq: null,
                    source: 'port53'
                });
            } else {
                correlations.set(hostname, {
                    ip: resolvedIp ? resolvedIp + ':0' : 'unknown:53',
                    lookup_seq: ev.seq,
                    connect_seq: null,
                    source: 'port53'
                });
            }
            port53Count++;
        } catch (e) {
            // Skip malformed packets
        }
    }
    
    // Also check connect-to-:53 events for DNS-over-TCP / connected UDP
    // These won't have query data in sendto, but we can note the DNS server
    for (const c of port53Connects) {
        // The target itself is the DNS server — note it for debugging
        // but we can't extract the query hostname without the wire data
    }
    
    if (port53Count > 0) {
        console.log(`  Port 53 (direct DNS): ${port53Count} lookups parsed from wire protocol`);
    }
    
    // ── Source 3: DNS-over-HTTPS (DoH) detection ────────────────────
    // Known DoH provider hostnames — if we see mDNSResponder lookups for these,
    // mark them as DoH bootstrap (the actual DNS queries happen inside HTTPS)
    const DOH_PROVIDERS = new Set([
        'cloudflare-dns.com', 'chrome.cloudflare-dns.com', 'mozilla.cloudflare-dns.com',
        '1dot1dot1dot1.cloudflare-dns.com', 'one.one.one.one',
        'dns.google', 'dns.google.com', 'dns64.dns.google',
        'doh.opendns.com', 'dns.quad9.net', 'dns9.quad9.net',
        'dns.nextdns.io', 'doh.cleanbrowsing.org', 'security.cloudflare-dns.com',
        'family.cloudflare-dns.com', 'dns.adguard.com', 'dns-family.adguard.com',
    ]);
    
    // Also detect by connect to known DoH IPs on port 443
    const DOH_IPS = new Set([
        '1.1.1.1', '1.0.0.1',                      // Cloudflare
        '8.8.8.8', '8.8.4.4',                      // Google
        '9.9.9.9', '149.112.112.112',              // Quad9
        '208.67.222.222', '208.67.220.220',        // OpenDNS
    ]);
    
    // Re-label existing correlations that are DoH providers
    for (const [hostname, info] of correlations) {
        if (DOH_PROVIDERS.has(hostname.toLowerCase())) {
            info.source = 'doh';
        }
    }
    
    // Check for connects to known DoH IPs on port 443
    for (const conn of connectEvents) {
        if (!conn.target) continue;
        const [ip, port] = conn.target.split(':');
        if (port === '443' && DOH_IPS.has(ip)) {
            // Find if any mDNSResponder lookup corresponds to a DoH provider name
            // that resolved to this IP — if not, add a synthetic entry
            let found = false;
            for (const [hostname, info] of correlations) {
                if (info.ip && info.ip.startsWith(ip + ':')) {
                    info.source = 'doh';
                    found = true;
                }
            }
        }
    }
    
    // Also detect DNS-over-TLS (port 853)
    for (const conn of connectEvents) {
        if (!conn.target) continue;
        const [ip, port] = conn.target.split(':');
        if (port === '853') {
            for (const [hostname, info] of correlations) {
                if (info.ip && info.ip.startsWith(ip + ':')) {
                    info.source = 'dot';
                }
            }
        }
    }

    // ── Insert all correlations ─────────────────────────────────────
    if (correlations.size === 0) {
        console.log('  No DNS lookups found');
        return;
    }
    
    const dnsInsert = db.prepare(`
        INSERT INTO dns_lookups (trace_id, hostname, ip, lookup_seq, connect_seq, source)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    for (const [hostname, info] of correlations) {
        dnsInsert.run(traceId, hostname, info.ip, info.lookup_seq, info.connect_seq, info.source || 'unknown');
    }
    
    console.log(`  Found ${correlations.size} hostname → IP correlations`);
    for (const [hostname, info] of correlations) {
        const src = info.source === 'port53' ? ' [port 53]' : '';
        console.log(`    ${hostname} → ${info.ip}${src}`);
    }
}

extractDnsLookups();

// Create FTS table for search (if SQLite FTS5 is available)
try {
    db.exec('DROP TABLE IF EXISTS events_fts');
    db.exec(`CREATE VIRTUAL TABLE events_fts USING fts5(syscall, target, details, time_str, errno_name, content=events, content_rowid=id)`);
    db.exec(`INSERT INTO events_fts(rowid, syscall, target, details, time_str, errno_name) SELECT id, syscall, target, details, time_str, errno_name FROM events WHERE trace_id = ${traceId}`);
    console.log('Created full-text search index');
} catch (e) {
    console.log('Note: FTS5 not available, search will use LIKE (see README.md)');
}

// better-sqlite3 writes directly to disk — no export/save step needed
db.close();

console.log(`Done! Saved to ${dbFile}`);
console.log(`\nRun: mactrace_server --db ${dbFile}`);
