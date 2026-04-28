#!/usr/bin/env node
/**
 * f8 timeline server (using better-sqlite3)
 * 
 * Database is memory-mapped and read on demand — no full-RAM copy.
 * Usage: f8-server [--db f8.db] [--port 3000]
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
let dbFile = 'f8.db';
let port = 3000;

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--db' && args[i + 1]) dbFile = args[++i];
    else if (args[i] === '--port' && args[i + 1]) port = parseInt(args[++i], 10);
}

if (!fs.existsSync(dbFile)) {
    console.error(`Database not found: ${dbFile}`);
    console.error('Run: f8-import <trace.json> --db f8.db');
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
  try {
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
        'SELECT hostname, ip, source, lookup_seq, connect_seq FROM dns_lookups WHERE trace_id = ?',
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
    
    // I/O summary stats (aggregated server-side)
    const ioStats = queryOne(`
        SELECT 
            COALESCE(SUM(CASE WHEN (syscall LIKE '%read%' OR syscall LIKE '%recv%') AND return_value > 0 THEN return_value ELSE 0 END), 0) as total_read,
            COALESCE(SUM(CASE WHEN (syscall LIKE '%write%' OR syscall LIKE '%send%') AND return_value > 0 THEN return_value ELSE 0 END), 0) as total_write,
            COALESCE(SUM(CASE WHEN (syscall LIKE '%read%' OR syscall LIKE '%recv%') AND return_value > 0 AND (target LIKE '%:%' AND target NOT LIKE '/%') THEN return_value ELSE 0 END), 0) as net_recv,
            COALESCE(SUM(CASE WHEN (syscall LIKE '%write%' OR syscall LIKE '%send%') AND return_value > 0 AND (target LIKE '%:%' AND target NOT LIKE '/%') THEN return_value ELSE 0 END), 0) as net_send,
            COALESCE(SUM(CASE WHEN (syscall LIKE '%read%' OR syscall LIKE '%recv%') AND return_value > 0 AND target LIKE '/%' THEN return_value ELSE 0 END), 0) as file_read,
            COALESCE(SUM(CASE WHEN (syscall LIKE '%write%' OR syscall LIKE '%send%') AND return_value > 0 AND target LIKE '/%' THEN return_value ELSE 0 END), 0) as file_write,
            (SELECT COUNT(DISTINCT target) FROM events WHERE trace_id = ? AND target LIKE '/%') as file_count,
            (SELECT COUNT(DISTINCT target) FROM events WHERE trace_id = ? AND target LIKE '%:%' AND target NOT LIKE '/%' AND target NOT LIKE 'fd=%') as net_count
        FROM events WHERE trace_id = ?
    `, [req.params.id, req.params.id, req.params.id]) || {};

    res.json({ ...trace, categories, errorCount, topSyscalls, dnsLookups, execCount, pidCount, ioStats });
  } catch (err) {
    console.error('Error in /api/traces/:id:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get DNS lookups for a trace (with geo enrichment)
app.get('/api/traces/:id/dns', async (req, res) => {
    const lookups = query(
        'SELECT hostname, ip, lookup_seq, connect_seq, source FROM dns_lookups WHERE trace_id = ? ORDER BY hostname',
        [req.params.id]
    );
    res.json(await enrichDnsWithGeo(lookups));
});

// Get events with filtering/pagination
app.get('/api/traces/:id/events', (req, res) => {
    const traceId = req.params.id;
    const { offset = 0, limit = 1000, category, syscall, pid, pids, errors, search, sort = 'seq', order = 'asc' } = req.query;
    
    const trace = queryOne('SELECT event_count FROM traces WHERE id = ?', [traceId]);
    if (!trace) return res.status(404).json({ error: 'Trace not found' });
    
    // Build WHERE clause
    let conditions = ['trace_id = ?'];
    let params = [traceId];
    
    if (category && category !== 'all') {
        if (category === 'error') {
            conditions.push('errno != 0');
        } else {
            conditions.push('category = ?');
            params.push(category);
        }
    }
    if (syscall) {
        conditions.push('syscall = ?');
        params.push(syscall);
    }
    if (pid) {
        conditions.push('pid = ?');
        params.push(parseInt(pid, 10));
    }
    if (pids) {
        // Comma-separated PID list for process-tree subset views
        const pidList = pids.split(',').map(p => parseInt(p, 10)).filter(p => !isNaN(p));
        if (pidList.length > 0) {
            conditions.push(`pid IN (${pidList.map(() => '?').join(',')})`);
            params.push(...pidList);
        }
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
    
    // Validate sort column (whitelist to prevent SQL injection)
    const SORT_COLS = { seq: 'seq', time: 'timestamp_us', pid: 'pid', syscall: 'syscall', target: 'target' };
    const sortCol = SORT_COLS[sort] || 'seq';
    const sortDir = order === 'desc' ? 'DESC' : 'ASC';
    
    // Always paginate server-side
    let sql = `SELECT id, seq, timestamp_us, time_str, pid, syscall, category,
                      return_value, errno, errno_name, target, details, has_io, io_path, io_chunk,
                      data_raw
               FROM events WHERE ${where} ORDER BY ${sortCol} ${sortDir}
               LIMIT ? OFFSET ?`;
    params.push(parseInt(limit, 10), parseInt(offset, 10));
    
    const events = query(sql, params);
    
    res.json({
        events,
        total: trace.event_count,
        filtered: filteredCount,
        offset: parseInt(offset, 10),
        limit: parseInt(limit, 10)
    });
});

// Find the 0-based row index of a specific seq in the current filter/sort
app.get('/api/traces/:id/events/seq-index', (req, res) => {
    const traceId = req.params.id;
    const { seq, category, syscall, pid, pids, errors, search, sort = 'seq', order = 'asc' } = req.query;

    if (!seq) return res.status(400).json({ error: 'seq parameter required' });

    const trace = queryOne('SELECT event_count FROM traces WHERE id = ?', [traceId]);
    if (!trace) return res.status(404).json({ error: 'Trace not found' });

    // Build the same WHERE clause as the events endpoint
    let conditions = ['trace_id = ?'];
    let params = [traceId];

    if (category && category !== 'all') {
        if (category === 'error') {
            conditions.push('errno != 0');
        } else {
            conditions.push('category = ?');
            params.push(category);
        }
    }
    if (syscall) {
        conditions.push('syscall = ?');
        params.push(syscall);
    }
    if (pid) {
        conditions.push('pid = ?');
        params.push(parseInt(pid, 10));
    }
    if (pids) {
        const pidList = pids.split(',').map(p => parseInt(p, 10)).filter(p => !isNaN(p));
        if (pidList.length > 0) {
            conditions.push(`pid IN (${pidList.map(() => '?').join(',')})`);
            params.push(...pidList);
        }
    }
    if (errors === 'true') {
        conditions.push('errno != 0');
    }
    if (search) {
        conditions.push("(syscall LIKE ? OR target LIKE ? OR details LIKE ? OR time_str LIKE ? OR errno_name LIKE ? OR CAST(pid AS TEXT) LIKE ?)");
        const term = `%${search}%`;
        params.push(term, term, term, term, term, term);
    }

    const where = conditions.join(' AND ');

    // Count how many matching rows come before this seq in the current sort order
    const SORT_COLS = { seq: 'seq', time: 'timestamp_us', pid: 'pid', syscall: 'syscall', target: 'target' };
    const sortCol = SORT_COLS[sort] || 'seq';
    const sortDir = order === 'desc' ? 'DESC' : 'ASC';

    // Get the sort value of the target seq
    const targetRow = queryOne(
        `SELECT ${sortCol} as sort_val FROM events WHERE trace_id = ? AND seq = ?`,
        [traceId, parseInt(seq, 10)]
    );
    if (!targetRow) return res.json({ index: -1 });

    // Count rows that come before it in the sort order
    const op = sortDir === 'ASC' ? '<' : '>';
    const countParams = [...params, targetRow.sort_val];
    const result = queryOne(
        `SELECT COUNT(*) as idx FROM events WHERE ${where} AND ${sortCol} ${op} ?`,
        countParams
    );

    res.json({ index: result?.idx ?? -1 });
});

// Serve I/O files (with on-the-fly hexdump generation)
// Wildcard route supports subdirectory I/O paths (e.g. 58998-unknown/write-app.log.bin)
app.get('/api/traces/:id/io/*', (req, res) => {
    const trace = queryOne('SELECT io_dir FROM traces WHERE id = ?', [req.params.id]);
    if (!trace?.io_dir) return res.status(404).json({ error: 'I/O directory not found' });
    
    const filename = req.params[0];
    if (!filename || filename.includes('..')) {
        return res.status(400).json({ error: 'Invalid filename' });
    }
    
    // Resolve within io_dir and verify it doesn't escape
    const filepath = path.resolve(trace.io_dir, filename);
    if (!filepath.startsWith(path.resolve(trace.io_dir))) {
        return res.status(400).json({ error: 'Path traversal rejected' });
    }
    
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

// Paginated hexdump API — returns JSON lines for virtual scrolling.
// Supports existing .hexdump files OR on-the-fly generation from .bin.
// Query params: offset (line #, default 0), limit (default 500)
// Special: if limit=-1, returns only { totalLines } (cheap metadata call).
app.get('/api/traces/:id/hexdump-lines/*', async (req, res) => {
    try {
        const trace = queryOne('SELECT io_dir FROM traces WHERE id = ?', [req.params.id]);
        if (!trace?.io_dir) return res.status(404).json({ error: 'I/O directory not found' });

        const filename = req.params[0];
        if (!filename || filename.includes('..')) {
            return res.status(400).json({ error: 'Invalid filename' });
        }

        const safeName = filename;
        // Resolve hexdump file path — accept either .hexdump or base name
        let hexPath;
        if (safeName.endsWith('.hexdump')) {
            hexPath = path.resolve(trace.io_dir, safeName);
        } else {
            hexPath = path.resolve(trace.io_dir, safeName.replace(/\.bin$/, '') + '.bin.hexdump');
        }
        // Verify resolved path doesn't escape io_dir
        if (!hexPath.startsWith(path.resolve(trace.io_dir))) {
            return res.status(400).json({ error: 'Path traversal rejected' });
        }

        // If hexdump doesn't exist, try generating from .bin on disk for next time
        const binPath = hexPath.replace(/\.hexdump$/, '');
        if (!fs.existsSync(hexPath) && fs.existsSync(binPath)) {
            try {
                execFileSync('/bin/sh', ['-c', `hexdump -C "${binPath}" > "${hexPath}"`], {
                    maxBuffer: 1024 * 1024,
                    timeout: 300000
                });
            } catch (e) {
                return res.status(500).json({ error: 'Failed to generate hexdump: ' + e.message });
            }
        }

        if (!fs.existsSync(hexPath)) {
            return res.status(404).json({ error: 'Hexdump file not found' });
        }

        const offsetParam = parseInt(req.query.offset, 10) || 0;
        const limitParam = parseInt(req.query.limit, 10);

        // Fast line count via wc -l (avoids reading entire file into memory)
        let totalLines;
        try {
            const wcOut = execFileSync('wc', ['-l', hexPath], { encoding: 'utf-8' });
            totalLines = parseInt(wcOut.trim().split(/\s+/)[0], 10) || 0;
        } catch {
            totalLines = 0;
        }

        // Metadata-only request (limit=-1)
        if (limitParam === -1) {
            const stat = fs.statSync(hexPath);
            return res.json({ totalLines, fileSize: stat.size });
        }

        const limit = isNaN(limitParam) ? 500 : Math.min(limitParam, 5000);
        const startLine = offsetParam + 1; // sed is 1-indexed
        const endLine = offsetParam + limit;

        // Extract line range with sed — memory-efficient, never reads whole file
        let rawLines;
        try {
            rawLines = execFileSync('sed', ['-n', `${startLine},${endLine}p`, hexPath], {
                encoding: 'utf-8',
                maxBuffer: limit * 200
            });
        } catch (e) {
            return res.status(500).json({ error: 'Failed to read hexdump range: ' + e.message });
        }

        // Parse hexdump -C lines into structured JSON
        const lines = [];
        for (const line of rawLines.split('\n')) {
            if (!line.trim()) continue;
            const match = line.match(/^([0-9a-f]+)\s+(.+?)\s+\|(.+)\|$/i);
            if (match) {
                lines.push({
                    addr: parseInt(match[1], 16),
                    addrStr: match[1],
                    bytes: match[2],
                    ascii: match[3]
                });
            }
        }

        res.json({
            totalLines,
            offset: offsetParam,
            limit,
            lines
        });
    } catch (err) {
        console.error('Error in /hexdump-lines:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get aggregated object stats (files or network hosts)
// In-memory cache of fully-aggregated object lists per (trace_id, type).
// The aggregate GROUP BY over the events table is the slow part: SQLite can
// use a TOP-N heap when there's a LIMIT (~3s for 2M rows), but the full
// materialized list (which is what we need for paginating + sorting + search
// in JS) takes ~11s. So:
//   - Cache HIT  -> filter/sort/paginate in JS, sub-100ms.
//   - Cache MISS -> serve this page from a fast LIMIT/OFFSET query and
//                   kick off the cache build in the background. Subsequent
//                   requests find the cache ready and become instant.
// Trace data is immutable once imported, so the cache never goes stale.
// Memory: ~70MB per (trace,type) for a 2M-event trace.
const objectsCache = new Map();
const objectsCacheBuilding = new Set();

function networkTargetFilter() {
    return `(
        (target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:[0-9]*' AND target NOT LIKE '/%')
        OR target LIKE 'AF_%'
        OR target LIKE 'https://%'
        OR target LIKE 'http://%'
        OR target LIKE 'ssh://%'
    )`;
}

function targetFilterFor(type) {
    return type === 'files' ? "target LIKE '/%'" : networkTargetFilter();
}

function aggregateSelectClause() {
    return `
        CASE
            WHEN target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:[0-9]*'
            THEN SUBSTR(target, 1, INSTR(target, ':') - 1)
            ELSE target
        END as target,
        MIN(pid) as pid,
        SUM(CASE WHEN syscall IN ('read','readv','readlink','pread','recv','recvfrom','recvmsg')
                 AND return_value > 0 THEN return_value ELSE 0 END) as read,
        SUM(CASE WHEN syscall IN ('write','writev','pwrite','pwritev','send','sendto','sendmsg')
                 AND return_value > 0 THEN return_value ELSE 0 END) as write,
        SUM(CASE WHEN syscall IN ('read','readv','readlink','pread','recv','recvfrom','recvmsg')
                 AND return_value > 0 THEN 1 ELSE 0 END) as readCount,
        SUM(CASE WHEN syscall IN ('write','writev','pwrite','pwritev','send','sendto','sendmsg')
                 AND return_value > 0 THEN 1 ELSE 0 END) as writeCount,
        COUNT(CASE WHEN io_path IS NOT NULL OR data_raw IS NOT NULL THEN 1 END) as hasDataCount
    `;
}

function aggregateGroupBy() {
    return `
        CASE
            WHEN target GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:[0-9]*'
            THEN SUBSTR(target, 1, INSTR(target, ':') - 1)
            ELSE target
        END
    `;
}

function buildObjectsForTrace(traceId, type) {
    const rows = query(`
        SELECT ${aggregateSelectClause()}
        FROM events
        WHERE trace_id = ? AND target IS NOT NULL AND target != '' AND ${targetFilterFor(type)}
        GROUP BY ${aggregateGroupBy()}
    `, [traceId]);
    for (const r of rows) {
        r.read = r.read || 0;
        r.write = r.write || 0;
        r.total = r.read + r.write;
    }
    return rows;
}

function triggerCacheBuild(traceId, type) {
    const key = `${traceId}:${type}`;
    if (objectsCache.has(key) || objectsCacheBuilding.has(key)) return;
    objectsCacheBuilding.add(key);
    // setImmediate yields one event loop tick. better-sqlite3 is sync so
    // this still blocks once it runs, but the caller is expected to invoke
    // us from a `res.on('finish')` callback (i.e. after the first response
    // has actually been written to the wire).
    setImmediate(() => {
        const t0 = Date.now();
        try {
            objectsCache.set(key, buildObjectsForTrace(traceId, type));
            if (process.env.F8_DEBUG) {
                console.log(`[objects] cache built for ${key}: ${objectsCache.get(key).length} rows in ${Date.now() - t0}ms`);
            }
        } catch (err) {
            console.error(`[objects] cache build failed for ${key}:`, err);
        } finally {
            objectsCacheBuilding.delete(key);
        }
    });
}

const SORT_KEYS = new Set(['target', 'pid', 'read', 'write', 'total']);

function sortObjects(arr, sortCol, sortAsc) {
    const dir = sortAsc ? 1 : -1;
    return arr.slice().sort((a, b) => {
        let va = a[sortCol];
        let vb = b[sortCol];
        if (sortCol === 'target') {
            const cmp = (va || '').localeCompare(vb || '');
            return cmp !== 0 ? cmp * dir : 0;
        }
        const cmp = (va || 0) - (vb || 0);
        if (cmp !== 0) return cmp * dir;
        return (a.target || '').localeCompare(b.target || '');
    });
}

app.get('/api/traces/:id/objects', async (req, res) => {
    try {
    const traceId = req.params.id;
    const type = req.query.type || 'files';
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 500), 5000);
    const search = (req.query.search || '').trim();
    const sortColRaw = req.query.sortCol || 'total';
    const sortCol = SORT_KEYS.has(sortColRaw) ? sortColRaw : 'total';
    const sortAsc = req.query.sortDir === 'asc';

    const trace = queryOne('SELECT * FROM traces WHERE id = ?', [traceId]);
    if (!trace) return res.status(404).json({ error: 'Trace not found' });

    const cacheKey = `${traceId}:${type}`;
    const cached = objectsCache.get(cacheKey);

    let resultObjects;
    let total;

    if (cached) {
        // Fast path — JS filter/sort/paginate
        let filtered = cached;
        if (search) {
            const s = search.toLowerCase();
            filtered = cached.filter(o => o.target && o.target.toLowerCase().includes(s));
        }
        const sorted = sortObjects(filtered, sortCol, sortAsc);
        total = sorted.length;
        resultObjects = sorted.slice(offset, offset + limit);
    } else {
        // Cache miss — fall back to SQL. Use TOP-N (LIMIT) so first page is
        // fast even on a 2M-row trace. Search/sort go through SQL too.
        // Trigger the full-cache build only AFTER the response has flushed,
        // so the user gets their first page before the long-running build
        // blocks the (synchronous better-sqlite3) event loop.
        res.on('finish', () => triggerCacheBuild(traceId, type));

        const sortMap = {
            target: 'target', pid: 'pid', read: 'read', write: 'write', total: '(read + write)'
        };
        const orderBy = sortMap[sortCol];
        const sortDir = sortAsc ? 'ASC' : 'DESC';

        let searchClause = '';
        const searchParams = [];
        if (search) {
            searchClause = " AND target LIKE ? COLLATE NOCASE";
            searchParams.push(`%${search}%`);
        }

        // Skip COUNT on cache miss — that query also does a full GROUP BY
        // and would block the first response by another ~2s. The client
        // sees total: null and shows a placeholder until the cache build
        // finishes; the next fetch comes from cache and includes total.
        total = null;

        const rows = query(`
            SELECT ${aggregateSelectClause()}
            FROM events
            WHERE trace_id = ? AND target IS NOT NULL AND target != '' AND ${targetFilterFor(type)}${searchClause}
            GROUP BY ${aggregateGroupBy()}
            ORDER BY ${orderBy} ${sortDir}, target ASC
            LIMIT ? OFFSET ?
        `, [traceId, ...searchParams, limit, offset]);
        for (const r of rows) {
            r.read = r.read || 0;
            r.write = r.write || 0;
            r.total = r.read + r.write;
        }
        resultObjects = rows;
    }

    // DNS enrichment for network type
    let dnsLookups = null;
    if (type === 'network') {
        dnsLookups = query('SELECT hostname, ip, source, lookup_seq, connect_seq FROM dns_lookups WHERE trace_id = ?', [traceId]);
    }
    const ipToHostname = new Map();
    if (dnsLookups) {
        for (const d of dnsLookups) {
            if (d.ip) {
                const ip = d.ip.split(':')[0];
                ipToHostname.set(ip, d.hostname);
            }
        }
    }

    const result = resultObjects.map(o => {
        const obj = { ...o, events: [] };
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
        total,
        offset,
        limit,
        search,
        sortCol,
        sortDir: sortAsc ? 'asc' : 'desc',
        cached: !!cached,
        dnsLookups: (type === 'network' && offset === 0) ? await enrichDnsWithGeo(dnsLookups) : undefined,
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
        
        // Try the processes table first (has authoritative parent links from f8)
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
            // Use authoritative process tree from f8's DTrace probes
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
        
        // Use processes table if available (has authoritative exec_path from F8_EXEC)
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
    console.log(`f8 server running at http://localhost:${port}`);
    console.log(`Database: ${dbFile}`);
    const traces = queryOne('SELECT COUNT(*) as count FROM traces');
    console.log(`Traces in database: ${traces?.count || 0}`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Error: Port ${port} is already in use.`);
    } else {
        console.error(`Error starting server: ${err.message}`);
    }
    process.exit(1);
});
