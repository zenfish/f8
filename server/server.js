#!/usr/bin/env node
/**
 * mactrace timeline server (using sql.js)
 * 
 * Usage: mactrace-server [--db mactrace.db] [--port 3000]
 */

import initSqlJs from 'sql.js';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { execSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

// Load database
const SQL = await initSqlJs();
const buffer = fs.readFileSync(dbFile);
const db = new SQL.Database(buffer);

// Helper to run query and get results as objects
function query(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const results = [];
        while (stmt.step()) {
            const row = stmt.getAsObject();
            results.push(row);
        }
        stmt.free();
        return results;
    } catch (e) {
        console.error('Query error:', e.message, sql);
        return [];
    }
}

function queryOne(sql, params = []) {
    const results = query(sql, params);
    return results[0] || null;
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
app.get('/api/traces/:id', (req, res) => {
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
    
    // Get DNS lookups for this trace
    const dnsLookups = query(
        'SELECT hostname, ip FROM dns_lookups WHERE trace_id = ?',
        [req.params.id]
    );
    
    res.json({ ...trace, categories, errorCount, topSyscalls, dnsLookups });
});

// Get DNS lookups for a trace
app.get('/api/traces/:id/dns', (req, res) => {
    const lookups = query(
        'SELECT hostname, ip, lookup_seq, connect_seq FROM dns_lookups WHERE trace_id = ? ORDER BY hostname',
        [req.params.id]
    );
    res.json(lookups);
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
    if (filename.includes('..') || filename.includes('/')) {
        return res.status(400).json({ error: 'Invalid filename' });
    }
    
    const filepath = path.join(trace.io_dir, filename);
    
    // If requesting a .hexdump file that doesn't exist, generate from .bin
    if (filename.endsWith('.hexdump') && !fs.existsSync(filepath)) {
        const binPath = filepath.replace(/\.hexdump$/, '');
        if (fs.existsSync(binPath)) {
            try {
                // Buffer sized from actual file: hexdump output is ~4x input size
                const binSize = fs.statSync(binPath).size;
                const maxBuffer = Math.max(binSize * 5, 1024 * 1024); // 5x file size, min 1MB
                const hexdump = execSync(`hexdump -C "${binPath}"`, { maxBuffer });
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
app.get('/api/traces/:id/objects', (req, res) => {
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
        dnsLookups: type === 'network' ? dnsLookups : undefined,
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

// Category colors
app.get('/api/categories', (req, res) => {
    res.json({
        file: { bg: '#4CAF50', text: '#ffffff' },
        network: { bg: '#2196F3', text: '#ffffff' },
        process: { bg: '#FF9800', text: '#000000' },
        memory: { bg: '#9C27B0', text: '#ffffff' },
        signal: { bg: '#F44336', text: '#ffffff' },
        ipc: { bg: '#00BCD4', text: '#000000' },
        poll: { bg: '#8BC34A', text: '#000000' },
        time: { bg: '#FFC107', text: '#000000' },
        mac: { bg: '#795548', text: '#ffffff' },
        necp: { bg: '#607D8B', text: '#ffffff' },
        other: { bg: '#9E9E9E', text: '#000000' }
    });
});

app.listen(port, () => {
    console.log(`mactrace server running at http://localhost:${port}`);
    console.log(`Database: ${dbFile}`);
    const traces = queryOne('SELECT COUNT(*) as count FROM traces');
    console.log(`Traces in database: ${traces?.count || 0}`);
});
