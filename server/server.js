#!/usr/bin/env node
/**
 * mactrace timeline server (using better-sqlite3)
 * 
 * Database is memory-mapped and read on demand — no full-RAM copy.
 * Usage: mactrace-server [--db mactrace.db] [--port 3000]
 */

import Database from 'better-sqlite3';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { execSync, execFileSync } from 'child_process';
import geoip from 'fast-geoip';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── IP Geolocation helpers ─────────────────────────────────────────────

const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.|169\.254\.|::1|fe80:|fc00:|fd00:)/i;

/**
 * Look up geo data for an IP address.
 * Returns { country, region, city, timezone, ll } or null for private/unknown IPs.
 */
async function geoLookup(ip) {
    if (!ip || PRIVATE_IP_RE.test(ip)) return null;
    try {
        const geo = await geoip.lookup(ip);
        if (!geo || !geo.country) return null;
        return {
            country: geo.country,       // 2-letter ISO code
            region: geo.region || '',
            city: geo.city || '',
            timezone: geo.timezone || '',
            ll: geo.ll || [0, 0],
        };
    } catch {
        return null;
    }
}

/**
 * Enrich an array of DNS lookup rows with geo data for each IP.
 */
async function enrichDnsWithGeo(lookups) {
    // Deduplicate IPs to avoid redundant lookups
    const ipSet = new Set();
    for (const d of lookups) {
        if (d.ip) {
            // ip field may be "addr:port" — extract just the address
            const addr = d.ip.split(':')[0];
            if (addr) ipSet.add(addr);
        }
    }
    // Batch lookup all unique IPs in parallel
    const geoCache = {};
    await Promise.all([...ipSet].map(async (addr) => {
        geoCache[addr] = await geoLookup(addr);
    }));
    // Attach geo to each row
    return lookups.map(d => {
        const addr = d.ip ? d.ip.split(':')[0] : '';
        return { ...d, geo: geoCache[addr] || null };
    });
}

// Parse arguments
const args = process.argv.slice(2);
let dbFile = 'mactrace.db';
let port = 3000;

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--db' && args[i + 1]) dbFile = args[++i];
    else if (args[i] === '--port' && args[i + 1]) port = parseInt(args[++i], 10);
}

if (!fs.existsSync(dbFile)) {
    console.error(`Database not found: ${dbFile}`);
    console.error('Run: mactrace-import <trace.json> --db mactrace.db');
    process.exit(1);
}

// Open database read-only with WAL mode for concurrent reads.
// better-sqlite3 uses memory-mapped I/O — only pages actually
// accessed are loaded, so a 500MB DB doesn't need 500MB RAM.
const db = new Database(dbFile, { readonly: true, fileMustExist: true });
db.pragma('mmap_size = 268435456'); // 256MB mmap window

// Helpers — better-sqlite3 returns rows as plain objects directly
function query(sql, params = []) {
    try {
        return db.prepare(sql).all(...params);
    } catch (e) {
        console.error('Query error:', e.message, sql);
        return [];
    }
}

function queryOne(sql, params = []) {
    try {
        return db.prepare(sql).get(...params) || null;
    } catch (e) {
        console.error('Query error:', e.message, sql);
        return null;
    }
}

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

// List all traces
app.get('/api/traces', (req, res) => {
    const traces = query(`
        SELECT id, name, command, event_count, duration_ms, target_pid, exit_code, 
               io_dir, imported_at
        FROM traces ORDER BY imported_at DESC
    `);
    res.json(traces);
});

// Get single trace metadata
app.get('/api/traces/:id', async (req, res) => {
    const trace = queryOne('SELECT * FROM traces WHERE id = ?', [req.params.id]);
    if (!trace) return res.status(404).json({ error: 'Trace not found' });
    
    const categories = query(
        'SELECT category, COUNT(*) as count FROM events WHERE trace_id = ? GROUP BY category',
        [req.params.id]
    );
    
    const errorCount = queryOne(
        'SELECT COUNT(*) as count FROM events WHERE trace_id = ? AND errno != 0',
        [req.params.id]
    )?.count || 0;
    
    const topSyscalls = query(
        'SELECT syscall, COUNT(*) as count FROM events WHERE trace_id = ? GROUP BY syscall ORDER BY count DESC LIMIT 10',
        [req.params.id]
    );
    
    // Get DNS lookups for this trace, enriched with geo data
    const rawDns = query(
        'SELECT hostname, ip FROM dns_lookups WHERE trace_id = ?',
        [req.params.id]
    );
    const dnsLookups = await enrichDnsWithGeo(rawDns);
    
    // Count exec'd/spawn'd programs
    const execCount = queryOne(
        "SELECT COUNT(*) as count FROM events WHERE trace_id = ? AND syscall IN ('execve', 'posix_spawn') AND errno = 0",
        [req.params.id]
    )?.count || 0;
    
    // Count unique PIDs (processes)
    const pidCount = queryOne(
        'SELECT COUNT(DISTINCT pid) as count FROM events WHERE trace_id = ?',
        [req.params.id]
    )?.count || 0;
    
    res.json({ ...trace, categories, errorCount, topSyscalls, dnsLookups, execCount, pidCount });
});

// Get DNS lookups for a trace (with geo enrichment)
app.get('/api/traces/:id/dns', async (req, res) => {
    const lookups = query(
        'SELECT hostname, ip, lookup_seq, connect_seq FROM dns_lookups WHERE trace_id = ? ORDER BY hostname',
        [req.params.id]
    );
    res.json(await enrichDnsWithGeo(lookups));
});

// Get events with filtering/pagination
app.get('/api/traces/:id/events', (req, res) => {
    const traceId = req.params.id;
    const { offset = 0, limit = 1000, category, syscall, pid, errors, search, all } = req.query;
    
    const trace = queryOne('SELECT event_count FROM traces WHERE id = ?', [traceId]);
    if (!trace) return res.status(404).json({ error: 'Trace not found' });
    
    // Build WHERE clause
    let conditions = ['trace_id = ?'];
    let params = [traceId];
    
    if (category && category !== 'all') {
        conditions.push('category = ?');
        params.push(category);
    }
    if (syscall) {
        conditions.push('syscall = ?');
        params.push(syscall);
    }
    if (pid) {
        conditions.push('pid = ?');
        params.push(parseInt(pid, 10));
    }
    if (errors === 'true') {
        conditions.push('errno != 0');
    }
    if (search) {
        // Simple LIKE search across all useful fields
        conditions.push("(syscall LIKE ? OR target LIKE ? OR details LIKE ? OR time_str LIKE ? OR errno_name LIKE ? OR CAST(pid AS TEXT) LIKE ?)");
        const term = `%${search}%`;
        params.push(term, term, term, term, term, term);
    }
    
    const where = conditions.join(' AND ');
    
    // Get filtered count
    const countResult = queryOne(`SELECT COUNT(*) as count FROM events WHERE ${where}`, params);
    const filteredCount = countResult?.count || 0;
    
    // Get events
    let sql = `SELECT id, seq, timestamp_us, time_str, pid, syscall, category,
                      return_value, errno, errno_name, target, details, has_io, io_path, io_chunk,
                      data_raw
               FROM events WHERE ${where} ORDER BY seq`;
    
    if (all !== 'true' || filteredCount > 100000) {
        sql += ` LIMIT ? OFFSET ?`;
        params.push(parseInt(limit, 10), parseInt(offset, 10));
    }
    
    const events = query(sql, params);
    
    res.json({
        events,
        total: trace.event_count,
        filtered: filteredCount,
        offset: parseInt(offset, 10),
        limit: parseInt(limit, 10)
    });
});

// Serve I/O files (with on-the-fly hexdump generation)
app.get('/api/traces/:id/io/:filename', (req, res) => {
    const trace = queryOne('SELECT io_dir FROM traces WHERE id = ?', [req.params.id]);
    if (!trace?.io_dir) return res.status(404).json({ error: 'I/O directory not found' });
    
    const filename = req.params.filename;
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
        return res.status(400).json({ error: 'Invalid filename' });
    }
    
    // Defense-in-depth: strip any directory components that slipped past the check
    const safeName = path.basename(filename);
    const filepath = path.join(trace.io_dir, safeName);
    
    // If requesting a .hexdump file that doesn't exist, generate from .bin
    if (filename.endsWith('.hexdump') && !fs.existsSync(filepath)) {
        const binPath = filepath.replace(/\.hexdump$/, '');
        if (fs.existsSync(binPath)) {
            try {
                // Buffer sized from actual file: hexdump output is ~4x input size
                const binSize = fs.statSync(binPath).size;
                const maxBuffer = Math.max(binSize * 5, 1024 * 1024); // 5x file size, min 1MB
                // execFileSync avoids shell interpolation (no command injection via filenames)
                const hexdump = execFileSync('hexdump', ['-C', binPath], { maxBuffer });
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                res.send(hexdump);
                return;
            } catch (e) {
                console.error('Hexdump generation failed:', e.message);
                return res.status(500).json({ error: 'Failed to generate hexdump: ' + e.message });
            }
        }
    }
    
    // If requesting a .rendered file that doesn't exist, generate from .bin
    if (filename.endsWith('.rendered') && !fs.existsSync(filepath)) {
        const binPath = filepath.replace(/\.rendered$/, '');
        if (fs.existsSync(binPath)) {
            try {
                const binData = fs.readFileSync(binPath);
                // Convert to text, replacing non-printable chars with dots
                let text = '';
                for (let i = 0; i < binData.length; i++) {
                    const b = binData[i];
                    if (b >= 32 && b < 127) {
                        text += String.fromCharCode(b);
                    } else if (b === 10 || b === 13 || b === 9) {
                        text += String.fromCharCode(b); // Keep newlines/tabs
                    } else {
                        text += '.';
                    }
                }
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                res.send(text);
                return;
            } catch (e) {
                console.error('Rendered generation failed:', e.message);
                return res.status(500).json({ error: 'Failed to generate rendered: ' + e.message });
            }
        }
    }
    
    if (!fs.existsSync(filepath)) {
        return res.status(404).json({ error: 'File not found' });
    }
    
    let contentType = 'application/octet-stream';
    if (filename.endsWith('.hexdump') || filename.endsWith('.rendered')) {
        contentType = 'text/plain; charset=utf-8';
    }
    
    res.setHeader('Content-Type', contentType);
    fs.createReadStream(filepath).pipe(res);
});

// Get aggregated object stats (files or network hosts)
app.get('/api/traces/:id/objects', async (req, res) => {
    try {
    const traceId = req.params.id;
    const type = req.query.type || 'files';
    
    const trace = queryOne('SELECT * FROM traces WHERE id = ?', [traceId]);
    if (!trace) return res.status(404).json({ error: 'Trace not found' });
    
    // Build filter for file vs network targets
    let targetFilter;
    if (type === 'files') {
        targetFilter = "target LIKE '/%'";
    } else {
        // Network: IP:port patterns (must start with digit and have :port), socket families, or URLs
        // Exclude file paths that happen to contain 'sock' in the name
        targetFilter = `(
            (target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:[0-9]*' AND target NOT LIKE '/%')
            OR target LIKE 'AF_%'
            OR target LIKE 'https://%'
            OR target LIKE 'http://%'
            OR target LIKE 'ssh://%'
        )`;
    }
    
    // Aggregate I/O stats per target using SQL
    const objects = query(`
        SELECT 
            target,
            MIN(pid) as pid,
            SUM(CASE WHEN (syscall LIKE '%read%' OR syscall IN ('recv','recvfrom','recvmsg')) 
                     AND return_value > 0 THEN return_value ELSE 0 END) as read,
            SUM(CASE WHEN (syscall LIKE '%write%' OR syscall IN ('send','sendto','sendmsg')) 
                     AND return_value > 0 THEN return_value ELSE 0 END) as write,
            SUM(CASE WHEN (syscall LIKE '%read%' OR syscall IN ('recv','recvfrom','recvmsg')) 
                     AND return_value > 0 THEN 1 ELSE 0 END) as readCount,
            SUM(CASE WHEN (syscall LIKE '%write%' OR syscall IN ('send','sendto','sendmsg')) 
                     AND return_value > 0 THEN 1 ELSE 0 END) as writeCount,
            COUNT(CASE WHEN io_path IS NOT NULL OR data_raw IS NOT NULL THEN 1 END) as hasDataCount
        FROM events 
        WHERE trace_id = ? AND target IS NOT NULL AND target != '' AND ${targetFilter}
        GROUP BY target
        ORDER BY (read + write) DESC
        LIMIT 500
    `, [traceId]);
    
    // Get DNS lookups for hostname enrichment
    const dnsLookups = query('SELECT hostname, ip FROM dns_lookups WHERE trace_id = ?', [traceId]);
    const ipToHostname = new Map();
    for (const d of dnsLookups) {
        if (d.ip) {
            const ip = d.ip.split(':')[0]; // Strip port
            ipToHostname.set(ip, d.hostname);
        }
    }
    
    // Add total, hostname, and events placeholder
    const result = objects.map(o => {
        const obj = {
            ...o,
            total: (o.read || 0) + (o.write || 0),
            events: [] // Loaded on demand
        };
        // Add hostname if we have it (for IP targets)
        if (type === 'network' && o.target) {
            const ip = o.target.split(':')[0];
            const hostname = ipToHostname.get(ip);
            if (hostname) obj.hostname = hostname;
        }
        return obj;
    });
    
    res.json({
        trace: { id: trace.id, command: trace.command, io_dir: trace.io_dir },
        type,
        dnsLookups: type === 'network' ? await enrichDnsWithGeo(dnsLookups) : undefined,
        objects: result
    });
    } catch (err) {
        console.error('Error in /objects:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get events for a specific target (for hexdump aggregation)
app.get('/api/traces/:id/target-events', (req, res) => {
    try {
    const traceId = req.params.id;
    const target = req.query.target;
    
    if (!target) return res.status(400).json({ error: 'target required' });
    
    const trace = queryOne('SELECT io_dir FROM traces WHERE id = ?', [traceId]);
    if (!trace) return res.status(404).json({ error: 'Trace not found' });
    
    const events = query(`
        SELECT seq, pid, syscall, target, return_value, io_path, io_chunk, data_raw
        FROM events 
        WHERE trace_id = ? AND target = ?
        ORDER BY seq
    `, [traceId, target]);
    
    // Filter to only I/O events
    const ioEvents = events.filter(e => {
        const sc = e.syscall || '';
        const isRead = sc.includes('read') || sc === 'recv' || sc === 'recvfrom' || sc === 'recvmsg';
        const isWrite = sc.includes('write') || sc === 'send' || sc === 'sendto' || sc === 'sendmsg';
        return (isRead || isWrite) && e.return_value > 0;
    }).map(e => ({
        seq: e.seq,
        pid: e.pid,
        syscall: e.syscall,
        bytes: e.return_value,
        ioPath: e.io_path,
        chunk: e.io_chunk,
        dataRaw: e.data_raw
    }));
    
    res.json({
        target,
        ioDir: trace.io_dir,
        events: ioEvents
    });
    } catch (err) {
        console.error('Error in /target-events:', err);
        res.status(500).json({ error: err.message });
    }
});

// Process tree for tree visualization
app.get('/api/traces/:id/process-tree', (req, res) => {
    try {
        const traceId = req.params.id;
        const trace = queryOne('SELECT * FROM traces WHERE id = ?', [traceId]);
        if (!trace) return res.status(404).json({ error: 'Trace not found' });

        const rootPid = trace.target_pid;

        // Per-PID I/O stats (also grab first binary open as fallback program name)
        const pidStats = query(`
            SELECT pid,
                COUNT(*) as event_count,
                MIN(seq) as first_seq,
                MAX(seq) as last_seq,
                SUM(CASE WHEN (syscall LIKE '%read%' OR syscall IN ('recv','recvfrom','recvmsg'))
                         AND return_value > 0 THEN return_value ELSE 0 END) as total_read,
                SUM(CASE WHEN (syscall LIKE '%write%' OR syscall IN ('send','sendto','sendmsg'))
                         AND return_value > 0 THEN return_value ELSE 0 END) as total_write,
                SUM(CASE WHEN (target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:*' OR target LIKE 'AF_%')
                         AND (syscall LIKE '%read%' OR syscall IN ('recv','recvfrom','recvmsg'))
                         AND return_value > 0 THEN return_value ELSE 0 END) as net_read,
                SUM(CASE WHEN (target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:*' OR target LIKE 'AF_%')
                         AND (syscall LIKE '%write%' OR syscall IN ('send','sendto','sendmsg'))
                         AND return_value > 0 THEN return_value ELSE 0 END) as net_write,
                SUM(CASE WHEN target LIKE '/%'
                         AND (syscall LIKE '%read%') AND return_value > 0 THEN return_value ELSE 0 END) as file_read,
                SUM(CASE WHEN target LIKE '/%'
                         AND (syscall LIKE '%write%') AND return_value > 0 THEN return_value ELSE 0 END) as file_write
            FROM events WHERE trace_id = ?
            GROUP BY pid
        `, [traceId]);

        const allPids = new Set(pidStats.map(p => p.pid));
        const parentMap = new Map(); // childPid → parentPid
        
        // Try the processes table first (has authoritative parent links from mactrace)
        let hasProcessesTable = false;
        try {
            hasProcessesTable = queryOne(
                "SELECT COUNT(*) as count FROM processes WHERE trace_id = ?",
                [traceId]
            )?.count > 0;
        } catch (e) {
            // Table doesn't exist yet (old DB) — fall back to event-based reconstruction
        }
        
        if (hasProcessesTable) {
            // Use authoritative process tree from mactrace's DTrace probes
            const procRows = query(
                'SELECT pid, parent_pid, exec_path FROM processes WHERE trace_id = ? AND parent_pid IS NOT NULL',
                [traceId]
            );
            for (const pr of procRows) {
                if (allPids.has(pr.pid)) {
                    parentMap.set(pr.pid, pr.parent_pid);
                }
            }
        } else {
            // Fallback: reconstruct from fork/vfork syscall return values
            const forkEvents = query(`
                SELECT pid, return_value, seq FROM events
                WHERE trace_id = ? AND syscall IN ('fork', 'vfork') AND return_value > 0 AND errno = 0
                ORDER BY seq
            `, [traceId]);

            for (const fe of forkEvents) {
                const childPid = fe.return_value;
                if (allPids.has(childPid) && !parentMap.has(childPid)) {
                    parentMap.set(childPid, fe.pid);
                }
            }

            // Handle posix_spawn: find child PIDs by looking at next new PID after spawn event
            const spawnEvents = query(`
                SELECT pid, seq, target FROM events
                WHERE trace_id = ? AND syscall = 'posix_spawn' AND errno = 0
                ORDER BY seq
            `, [traceId]);

            for (const se of spawnEvents) {
                const nextPidRow = queryOne(`
                    SELECT DISTINCT pid FROM events
                    WHERE trace_id = ? AND seq > ? AND seq < ? + 50
                    AND pid != ?
                    ORDER BY seq LIMIT 1
                `, [traceId, se.seq, se.seq, se.pid]);
                if (nextPidRow && !parentMap.has(nextPidRow.pid)) {
                    parentMap.set(nextPidRow.pid, se.pid);
                }
            }
        }

        // Get program names per PID
        const pidPrograms = new Map(); // pid → [program paths]
        const pidProgramSource = new Map(); // pid → 'exec' | 'spawn' | 'inferred'
        
        // Use processes table if available (has authoritative exec_path from MACTRACE_EXEC)
        if (hasProcessesTable) {
            const procExecs = query(
                "SELECT pid, exec_path FROM processes WHERE trace_id = ? AND exec_path IS NOT NULL AND exec_path != ''",
                [traceId]
            );
            for (const pe of procExecs) {
                pidPrograms.set(pe.pid, [pe.exec_path]);
                pidProgramSource.set(pe.pid, 'exec');
            }
        }
        
        // Supplement from execve/posix_spawn syscall events (covers cases processes table may miss)
        const execEvents = query(`
            SELECT pid, target, syscall, seq FROM events
            WHERE trace_id = ? AND syscall IN ('execve', 'posix_spawn') AND errno = 0 AND target != ''
            ORDER BY seq
        `, [traceId]);

        for (const ee of execEvents) {
            if (ee.syscall === 'execve') {
                if (!pidPrograms.has(ee.pid)) {
                    pidPrograms.set(ee.pid, []);
                    pidProgramSource.set(ee.pid, 'exec');
                }
                pidPrograms.get(ee.pid).push(ee.target);
            } else {
                // posix_spawn fires in the parent — find the child PID
                const childRow = queryOne(`
                    SELECT DISTINCT pid FROM events
                    WHERE trace_id = ? AND seq > ? AND seq < ? + 50
                    AND pid != ?
                    ORDER BY seq LIMIT 1
                `, [traceId, ee.seq, ee.seq, ee.pid]);
                if (childRow && !pidPrograms.has(childRow.pid)) {
                    pidPrograms.set(childRow.pid, [ee.target]);
                    pidProgramSource.set(childRow.pid, 'spawn');
                }
            }
        }
        
        // For PIDs still without a program name, infer from first binary open()
        const orphanPids = pidStats
            .filter(p => !pidPrograms.has(p.pid) && p.event_count > 5)
            .map(p => p.pid);
        
        if (orphanPids.length > 0) {
            for (const opid of orphanPids) {
                const firstBin = queryOne(`
                    SELECT target FROM events
                    WHERE trace_id = ? AND pid = ? AND syscall IN ('open', 'openat')
                    AND (target LIKE '/%bin/%' OR target LIKE '/%libexec/%')
                    AND errno = 0
                    ORDER BY seq LIMIT 1
                `, [traceId, opid]);
                if (firstBin?.target) {
                    pidPrograms.set(opid, [firstBin.target]);
                    pidProgramSource.set(opid, 'inferred');
                }
            }
        }

        // Count exec/spawn per PID
        const execCounts = query(`
            SELECT pid, COUNT(*) as count FROM events
            WHERE trace_id = ? AND syscall IN ('execve', 'posix_spawn') AND errno = 0
            GROUP BY pid
        `, [traceId]);
        const pidExecCount = new Map(execCounts.map(e => [e.pid, e.count]));

        // Build children map
        const childrenMap = new Map(); // pid → [child pids]
        for (const [child, parent] of parentMap) {
            if (!childrenMap.has(parent)) childrenMap.set(parent, []);
            childrenMap.get(parent).push(child);
        }

        // Sort children by first_seq
        const pidFirstSeq = new Map(pidStats.map(p => [p.pid, p.first_seq]));
        for (const [, children] of childrenMap) {
            children.sort((a, b) => (pidFirstSeq.get(a) || 0) - (pidFirstSeq.get(b) || 0));
        }

        // Build nodes array
        const nodes = pidStats.map(p => ({
            pid: p.pid,
            parentPid: parentMap.get(p.pid) ?? null,
            childPids: childrenMap.get(p.pid) || [],
            programs: pidPrograms.get(p.pid) || [],
            programSource: pidProgramSource.get(p.pid) || null, // 'exec'|'spawn'|'inferred'|null
            execCount: pidExecCount.get(p.pid) || 0,
            firstSeq: p.first_seq,
            lastSeq: p.last_seq,
            eventCount: p.event_count,
            io: {
                totalRead: p.total_read,
                totalWrite: p.total_write,
                netRead: p.net_read,
                netWrite: p.net_write,
                fileRead: p.file_read,
                fileWrite: p.file_write
            }
        }));

        // Total exec count
        const totalExec = queryOne(`
            SELECT COUNT(*) as count FROM events
            WHERE trace_id = ? AND syscall IN ('execve', 'posix_spawn') AND errno = 0
        `, [traceId]);

        res.json({
            rootPid,
            command: trace.command,
            nodes,
            totalExecCount: totalExec?.count || 0
        });
    } catch (err) {
        console.error('Error in /process-tree:', err);
        res.status(500).json({ error: err.message });
    }
});

// Category colors — loaded from shared syscalls.json (single source of truth)
const syscallsJsonPath = path.join(__dirname, '..', 'syscalls.json');
const syscallsData = JSON.parse(fs.readFileSync(syscallsJsonPath, 'utf-8'));
const categoryColors = {};
for (const cat of syscallsData.categories) {
    categoryColors[cat.id] = { bg: cat.color, text: cat.textColor };
}
if (syscallsData.defaultCategory) {
    categoryColors[syscallsData.defaultCategory.id] = {
        bg: syscallsData.defaultCategory.color,
        text: syscallsData.defaultCategory.textColor
    };
}

app.get('/api/categories', (req, res) => {
    res.json(categoryColors);
});

const server = app.listen(port, () => {
    console.log(`mactrace server running at http://localhost:${port}`);
    console.log(`Database: ${dbFile}`);
    const traces = queryOne('SELECT COUNT(*) as count FROM traces');
    console.log(`Traces in database: ${traces?.count || 0}`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Error: Port ${port} is already in use.`);
        console.error(`Either stop the other process or use: mactrace-server --port ${port + 1}`);
    } else {
        console.error(`Error starting server: ${err.message}`);
    }
    process.exit(1);
});
