// backend/phases/live.cjs
// Phase 3 — Live Host Detection using httpx
// Input: dns/resolved.txt (from Phase 2)

'use strict';
const _cfg = require('../config.cjs');

const { spawn } = require('child_process');
const fs   = require('fs');
const path = require('path');

const WORKSPACE_DIR    = path.resolve(__dirname, '../workspace');
const PHASE_TIMEOUT_MS = 300_000; // 5 min
const HTTPX_BIN        = _cfg.BINS.httpx;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getLivePaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'live');
  return {
    base,
    status:   path.join(base, 'status.json'),
    httpxRaw: path.join(base, 'httpx_raw.txt'),
    merged:   path.join(base, 'merged.txt'),
    hosts:    path.join(base, 'hosts.txt'),
  };
}

// Use dns/resolved.txt if available, fallback to subdomain/filtered.txt then merged.txt
function getInputFile(target) {
  const dnsResolved  = path.join(WORKSPACE_DIR, target, 'dns', 'resolved.txt');
  const subFiltered  = path.join(WORKSPACE_DIR, target, 'subdomain', 'filtered.txt');
  const subMerged    = path.join(WORKSPACE_DIR, target, 'subdomain', 'merged.txt');
  if (fs.existsSync(dnsResolved) && fs.readFileSync(dnsResolved, 'utf8').trim()) {
    console.log('[live] using dns/resolved.txt as input');
    return { file: dnsResolved, source: 'dns' };
  }
  if (fs.existsSync(subFiltered) && fs.readFileSync(subFiltered, 'utf8').trim()) {
    console.log('[live] OOS filter active — using subdomain/filtered.txt');
    return { file: subFiltered, source: 'subdomain_filtered' };
  }
  console.log('[live] falling back to subdomain/merged.txt');
  return { file: subMerged, source: 'subdomain' };
}

function writeStatus(statusPath, data) {
  fs.writeFileSync(statusPath, JSON.stringify(data, null, 2));
}

function readStatus(statusPath) {
  if (!fs.existsSync(statusPath)) return null;
  try { return JSON.parse(fs.readFileSync(statusPath, 'utf8')); }
  catch { return null; }
}

function parseHttpxLine(line) {
  line = line.trim();
  if (!line) return null;
  try {
    const obj = JSON.parse(line);
    return {
      url:         obj.url        || obj.input || '',
      hostname:    (obj.url ? new URL(obj.url).hostname : obj.input) || '',
      statusCode:  obj.status_code ?? null,
      title:       obj.title      || '',
      webServer:   obj.webserver  || obj['web-server'] || '',
      techStack:   obj.tech       || [],
      ip:          obj.host_ip    || obj.host || '',
      redirectUrl: obj.final_url  || '',
    };
  } catch {
    return { url: line, hostname: '', statusCode: null };
  }
}

// ─── Core runner ─────────────────────────────────────────────────────────────

function runLiveDetection(target) {
  return new Promise((resolve) => {
    const p = getLivePaths(target);

    fs.mkdirSync(p.base, { recursive: true });

    // Clear stale running state
    const existing = readStatus(p.status);
    if (existing?.status === 'running') {
      console.log('[live] clearing stale running status for', target);
    }

    // Get input file — prefer dns/resolved.txt
    const { file: inputFile, source } = getInputFile(target);

    if (!fs.existsSync(inputFile)) {
      const err = 'No input file found — run Phase 01 (Subdomains) or Phase 02 (DNS) first';
      writeStatus(p.status, { status: 'error', error: err, updatedAt: new Date().toISOString() });
      return resolve({ success: false, error: err });
    }

    const lineCount = fs.readFileSync(inputFile, 'utf8').split('\n').filter(Boolean).length;
    if (lineCount === 0) {
      const err = 'Input file is empty — no hosts to probe';
      writeStatus(p.status, { status: 'error', error: err, updatedAt: new Date().toISOString() });
      return resolve({ success: false, error: err });
    }

    writeStatus(p.status, { status: 'running', source, startedAt: new Date().toISOString() });

    const args = [
      '-l', inputFile,
      '-json',
      '-silent',
      '-threads',  '50',
      '-timeout',  '10',
      '-follow-redirects',
      '-status-code',
      '-title',
      '-web-server',
      '-tech-detect',
      '-ip',
    ];

    let rawOutput    = '';
    let stderrOutput = '';
    let timedOut     = false;

    console.log('[live] spawning httpx for', target, '—', lineCount, 'hosts (source:', source + ')');

    const proc = spawn(HTTPX_BIN, args, {
      env: { ...process.env, HOME: _cfg.HOME },
    });
    proc.stdin.end();

    const timer = setTimeout(() => {
      console.log('[live] timeout reached, killing httpx');
      timedOut = true;
      proc.kill('SIGTERM');
    }, PHASE_TIMEOUT_MS);

    proc.stdout.on('data', (chunk) => { rawOutput += chunk; });
    proc.stderr.on('data', (chunk) => { stderrOutput += chunk; });

    proc.on('close', (code) => {
      clearTimeout(timer);
      console.log('[live] httpx exit code:', code);
      console.log('[live] raw output lines:', rawOutput.split('\n').filter(Boolean).length);

      fs.writeFileSync(p.httpxRaw, rawOutput);

      const lines   = rawOutput.split('\n').filter(Boolean);
      const entries = lines.map(parseHttpxLine).filter(Boolean).filter(e => e.url);

      const urls = entries.map(e => e.url).filter(Boolean);
      fs.writeFileSync(p.merged, urls.join('\n') + (urls.length ? '\n' : ''));

      const hostSet = new Set(
        entries.map(e => {
          if (e.hostname) return e.hostname;
          try { return new URL(e.url).hostname; } catch { return ''; }
        }).filter(Boolean)
      );
      const hostList = [...hostSet];
      fs.writeFileSync(p.hosts, hostList.join('\n') + (hostList.length ? '\n' : ''));

      const finalStatus = {
        status:    timedOut ? 'timeout' : (entries.length > 0 ? 'done' : (code === 0 ? 'done' : 'error')),
        liveCount: urls.length,
        hostCount: hostList.length,
        source,
        timedOut,
        exitCode:  code,
        completedAt: new Date().toISOString(),
      };

      console.log('[live] done —', finalStatus.liveCount, 'live URLs,', finalStatus.hostCount, 'unique hosts');
      writeStatus(p.status, finalStatus);
      resolve({ success: true, ...finalStatus });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      const msg = err.code === 'ENOENT'
        ? `httpx not found at ${HTTPX_BIN}`
        : err.message;
      console.error('[live] spawn error:', msg);
      writeStatus(p.status, { status: 'error', error: msg, updatedAt: new Date().toISOString() });
      resolve({ success: false, error: msg });
    });
  });
}

// ─── Status reader ────────────────────────────────────────────────────────────

function getLiveStatus(target) {
  const p      = getLivePaths(target);
  const status = readStatus(p.status) || { status: 'not_started' };

  let hosts = [];
  if (fs.existsSync(p.httpxRaw)) {
    const raw = fs.readFileSync(p.httpxRaw, 'utf8');
    hosts = raw.split('\n')
      .filter(Boolean)
      .map(parseHttpxLine)
      .filter(e => e && e.url);
  }

  return { ...status, hosts };
}

module.exports = { runLiveDetection, getLiveStatus, getLivePaths };
