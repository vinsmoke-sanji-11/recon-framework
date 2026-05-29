// backend/phases/dns.cjs
// Phase 2 — DNS Resolution using dnsx

'use strict';
const _cfg = require('../config.cjs');

const { spawn } = require('child_process');
const fs   = require('fs');
const path = require('path');

const WORKSPACE_DIR    = path.resolve(__dirname, '../workspace');
const PHASE_TIMEOUT_MS = 300_000; // 5 min total
const DNSX_BIN         = _cfg.BINS.dnsx;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getDNSPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'dns');
  return {
    base,
    status:   path.join(base, 'status.json'),
    raw:      path.join(base, 'dnsx_raw.txt'),
    resolved: path.join(base, 'resolved.txt'),
    records:  path.join(base, 'records.json'),
  };
}

function getSubdomainMerged(target) {
  const filtered = path.join(WORKSPACE_DIR, target, 'subdomain', 'filtered.txt');
  const merged   = path.join(WORKSPACE_DIR, target, 'subdomain', 'merged.txt');
  if (fs.existsSync(filtered) && fs.readFileSync(filtered, 'utf8').trim()) {
    console.log('[dns] OOS filter active — using subdomain/filtered.txt');
    return filtered;
  }
  return merged;
}

function writeStatus(statusPath, data) {
  fs.writeFileSync(statusPath, JSON.stringify(data, null, 2));
}

function readStatus(statusPath) {
  if (!fs.existsSync(statusPath)) return null;
  try { return JSON.parse(fs.readFileSync(statusPath, 'utf8')); }
  catch { return null; }
}

// Parse one dnsx JSONL line
function parseDnsxLine(line) {
  line = line.trim();
  if (!line) return null;
  try {
    const obj = JSON.parse(line);
    return {
      host:  obj.host  || obj.input || '',
      a:     obj.a     || [],
      cname: obj.cname || [],
      mx:    obj.mx    || [],
      ns:    obj.ns    || [],
      txt:   obj.txt   || [],
      aaaa:  obj.aaaa  || [],
      statusCode: obj.status_code || '',
    };
  } catch {
    return null;
  }
}

// ─── Core runner ─────────────────────────────────────────────────────────────

function runDNSResolution(target) {
  return new Promise((resolve) => {
    const p          = getDNSPaths(target);
    const inputFile  = getSubdomainMerged(target);

    fs.mkdirSync(p.base, { recursive: true });

    // Clear stale running state
    const existing = readStatus(p.status);
    if (existing?.status === 'running') {
      console.log('[dns] clearing stale running status for', target);
    }

    if (!fs.existsSync(inputFile)) {
      const err = 'subdomain/merged.txt not found — run Phase 1 first';
      writeStatus(p.status, { status: 'error', error: err, updatedAt: new Date().toISOString() });
      return resolve({ success: false, error: err });
    }

    const lineCount = fs.readFileSync(inputFile, 'utf8').split('\n').filter(Boolean).length;
    if (lineCount === 0) {
      const err = 'subdomain/merged.txt is empty — no subdomains to resolve';
      writeStatus(p.status, { status: 'error', error: err, updatedAt: new Date().toISOString() });
      return resolve({ success: false, error: err });
    }

    writeStatus(p.status, { status: 'running', startedAt: new Date().toISOString() });

    const args = [
      '-l',       inputFile,
      '-json',
      '-silent',
      '-a',                 // A records
      '-aaaa',              // AAAA records
      '-cname',             // CNAME records
      '-mx',                // MX records
      '-ns',                // NS records
      '-txt',               // TXT records
      '-re',                // resolve errors too (for tracking)
      '-threads', '100',
      '-rate-limit', '500',
      '-retry',   '2',
    ];

    let rawOutput    = '';
    let stderrOutput = '';
    let timedOut     = false;

    console.log('[dns] spawning dnsx for', target, '—', lineCount, 'subdomains');

    const proc = spawn(DNSX_BIN, args, {
      env: { ...process.env, HOME: _cfg.HOME },
    });
    proc.stdin.end();

    const timer = setTimeout(() => {
      console.log('[dns] timeout reached, killing dnsx');
      timedOut = true;
      proc.kill('SIGTERM');
    }, PHASE_TIMEOUT_MS);

    proc.stdout.on('data', (chunk) => { rawOutput += chunk; });
    proc.stderr.on('data', (chunk) => { stderrOutput += chunk; });

    proc.on('close', (code) => {
      clearTimeout(timer);
      console.log('[dns] dnsx exit code:', code);
      console.log('[dns] stderr:', stderrOutput.slice(0, 200));

      fs.writeFileSync(p.raw, rawOutput);

      const lines   = rawOutput.split('\n').filter(Boolean);
      const entries = lines.map(parseDnsxLine).filter(Boolean).filter(e => e.host);

      console.log('[dns] total entries:', entries.length);

      // resolved.txt — only hosts with at least one A record or CNAME
      const resolved = entries
        .filter(e => e.a.length > 0 || e.cname.length > 0)
        .map(e => e.host);
      fs.writeFileSync(p.resolved, resolved.join('\n') + (resolved.length ? '\n' : ''));

      // records.json — full structured data
      const recordsMap = {};
      for (const e of entries) {
        if (!e.host) continue;
        recordsMap[e.host] = {
          a:     e.a,
          aaaa:  e.aaaa,
          cname: e.cname,
          mx:    e.mx,
          ns:    e.ns,
          txt:   e.txt,
          statusCode: e.statusCode,
        };
      }
      fs.writeFileSync(p.records, JSON.stringify(recordsMap, null, 2));

      const finalStatus = {
        status:        timedOut ? 'timeout' : (entries.length > 0 ? 'done' : (code === 0 ? 'done' : 'error')),
        totalQueried:  lineCount,
        resolvedCount: resolved.length,
        totalRecords:  entries.length,
        timedOut,
        exitCode:      code,
        completedAt:   new Date().toISOString(),
      };

      console.log('[dns] done —', resolved.length, 'resolved out of', lineCount);
      writeStatus(p.status, finalStatus);
      resolve({ success: true, ...finalStatus });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      const msg = err.code === 'ENOENT'
        ? `dnsx not found at ${DNSX_BIN}`
        : err.message;
      console.error('[dns] spawn error:', msg);
      writeStatus(p.status, { status: 'error', error: msg, updatedAt: new Date().toISOString() });
      resolve({ success: false, error: msg });
    });
  });
}

// ─── Status reader ────────────────────────────────────────────────────────────

function getDNSStatus(target) {
  const p      = getDNSPaths(target);
  const status = readStatus(p.status) || { status: 'not_started' };

  let records = {};
  if (fs.existsSync(p.records)) {
    try { records = JSON.parse(fs.readFileSync(p.records, 'utf8')); }
    catch { records = {}; }
  }

  return { ...status, records };
}

module.exports = { runDNSResolution, getDNSStatus, getDNSPaths };
