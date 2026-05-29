// backend/phases/ports.cjs
// Phase 4 — Port Scanning using naabu + nmap
// naabu: fast top-1000 port discovery
// nmap: deep scan on ports found by naabu

'use strict';
const _cfg = require('../config.cjs');

const { spawn } = require('child_process');
const fs   = require('fs');
const path = require('path');

const WORKSPACE_DIR    = path.resolve(__dirname, '../workspace');
const NAABU_BIN        = _cfg.BINS.naabu;
const NMAP_BIN         = _cfg.BINS.nmap;
const NAABU_TIMEOUT_MS = 600_000; // 10 min
const NMAP_TIMEOUT_MS  = 600_000; // 10 min

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getPortsPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'ports');
  return {
    base,
    status:       path.join(base, 'status.json'),
    naabuRaw:     path.join(base, 'naabu_raw.txt'),
    nmapRaw:      path.join(base, 'nmap_raw.xml'),
    naabuPorts:   path.join(base, 'naabu_ports.txt'),  // host:port per line
    merged:       path.join(base, 'merged.txt'),        // final host:port per line
    json:         path.join(base, 'open_ports.json'),   // { host: { naabu:[ports], nmap:[{port,service,version}] } }
  };
}

function getLiveHostsPath(target) {
  return path.join(WORKSPACE_DIR, target, 'live', 'hosts.txt');
}

function writeStatus(statusPath, data) {
  fs.writeFileSync(statusPath, JSON.stringify(data, null, 2));
}

function readStatus(statusPath) {
  if (!fs.existsSync(statusPath)) return null;
  try { return JSON.parse(fs.readFileSync(statusPath, 'utf8')); }
  catch { return null; }
}

// Parse naabu JSONL line
function parseNaabuLine(line) {
  line = line.trim();
  if (!line) return null;
  try {
    const obj = JSON.parse(line);
    return {
      host: obj.host || obj.ip || '',
      port: obj.port ?? null,
    };
  } catch {
    // fallback: "host:port"
    const m = line.match(/^(.+):(\d+)$/);
    if (m) return { host: m[1], port: parseInt(m[2]) };
    return null;
  }
}

// Parse nmap XML for host/port/service/version data
function parseNmapXML(xml) {
  const results = {};
  // Extract hosts
  const hostBlocks = xml.match(/<host[\s\S]*?<\/host>/g) || [];
  for (const block of hostBlocks) {
    // Get IP
    const addrMatch = block.match(/<address addr="([^"]+)" addrtype="ipv4"/);
    const hostnameMatch = block.match(/<hostname name="([^"]+)"/);
    const ip = addrMatch?.[1] || '';
    const hostname = hostnameMatch?.[1] || ip;
    const key = hostname || ip;
    if (!key) continue;

    results[key] = results[key] || [];

    // Get ports
    const portBlocks = block.match(/<port[\s\S]*?<\/port>/g) || [];
    for (const pb of portBlocks) {
      const portMatch   = pb.match(/portid="(\d+)"/);
      const stateMatch  = pb.match(/state="([^"]+)"/);
      const serviceMatch = pb.match(/<service[^>]*name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?/);

      if (!portMatch || stateMatch?.[1] !== 'open') continue;

      results[key].push({
        port:    parseInt(portMatch[1]),
        service: serviceMatch?.[1] || '',
        product: serviceMatch?.[2] || '',
        version: serviceMatch?.[3] || '',
      });
    }
  }
  return results;
}

// Group naabu entries by host
function groupNaabuByHost(entries) {
  const map = {};
  for (const e of entries) {
    if (!e.host || e.port === null) continue;
    if (!map[e.host]) map[e.host] = [];
    map[e.host].push(e.port);
  }
  for (const h of Object.keys(map)) {
    map[h] = [...new Set(map[h])].sort((a, b) => a - b);
  }
  return map;
}

// ─── naabu runner ────────────────────────────────────────────────────────────

function runNaabu(target, inputFile, rawFile, portsFile) {
  return new Promise((resolve) => {
    console.log('[ports] starting naabu');
    const args = [
      '-list',      inputFile,
      '-json',
      '-silent',
      '-rate',      '1000',
      '-c',         '50',
      '-top-ports', '1000',
      '-timeout',   '5000',
      '-o',         portsFile,
    ];

    const proc = spawn(NAABU_BIN, args, {
      env: { ...process.env, HOME: _cfg.HOME },
    });
    proc.stdin.end();

    let rawOutput = '';
    let finished  = false;

    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        proc.kill('SIGKILL');
        console.log('[ports] naabu timeout');
        resolve({ timedOut: true, raw: rawOutput });
      }
    }, NAABU_TIMEOUT_MS);

    proc.stdout.on('data', d => { rawOutput += d.toString(); });
    proc.stderr.on('data', () => {});

    proc.on('close', (code) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        fs.writeFileSync(rawFile, rawOutput);
        console.log(`[ports] naabu done (exit ${code})`);
        resolve({ code, raw: rawOutput });
      }
    });

    proc.on('error', (err) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        console.log('[ports] naabu error:', err.message);
        resolve({ error: err.message, raw: rawOutput });
      }
    });
  });
}

// ─── nmap runner ─────────────────────────────────────────────────────────────

function runNmap(inputFile, openPortsMap, xmlOutputFile) {
  return new Promise((resolve) => {
    // Build port list from naabu results
    const allPorts = new Set();
    for (const ports of Object.values(openPortsMap)) {
      for (const p of ports) allPorts.add(p);
    }

    if (allPorts.size === 0) {
      console.log('[ports] nmap skipped — no open ports from naabu');
      return resolve({ skipped: true });
    }

    const portStr = [...allPorts].sort((a, b) => a - b).join(',');
    console.log('[ports] starting nmap on', allPorts.size, 'unique ports');

    const args = [
      '-iL',  inputFile,
      '-p',   portStr,
      '-sV',              // service/version detection
      '--version-intensity', '3',
      '-T4',              // aggressive timing
      '-oX',  xmlOutputFile,
      '--open',
      '--max-retries', '2',
      '--host-timeout', '30s',
    ];

    const proc = spawn(NMAP_BIN, args, {
      env: { ...process.env, HOME: _cfg.HOME },
    });
    proc.stdin.end();

    let finished = false;

    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        proc.kill('SIGKILL');
        console.log('[ports] nmap timeout');
        resolve({ timedOut: true });
      }
    }, NMAP_TIMEOUT_MS);

    proc.stdout.on('data', () => {});
    proc.stderr.on('data', () => {});

    proc.on('close', (code) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        console.log(`[ports] nmap done (exit ${code})`);
        resolve({ code });
      }
    });

    proc.on('error', (err) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        console.log('[ports] nmap error:', err.message);
        resolve({ error: err.message });
      }
    });
  });
}

// ─── Core runner ─────────────────────────────────────────────────────────────

async function runPortScan(target) {
  const p         = getPortsPaths(target);
  const inputFile = getLiveHostsPath(target);

  fs.mkdirSync(p.base, { recursive: true });

  // Clear stale running state
  const existing = readStatus(p.status);
  if (existing?.status === 'running') {
    console.log('[ports] clearing stale running status for', target);
  }

  if (!fs.existsSync(inputFile)) {
    const err = 'live/hosts.txt not found — run Phase 03 (Live Hosts) first';
    writeStatus(p.status, { status: 'error', error: err, updatedAt: new Date().toISOString() });
    return { success: false, error: err };
  }

  const hostCount = fs.readFileSync(inputFile, 'utf8').split('\n').filter(Boolean).length;
  if (hostCount === 0) {
    const err = 'live/hosts.txt is empty — no hosts to scan';
    writeStatus(p.status, { status: 'error', error: err, updatedAt: new Date().toISOString() });
    return { success: false, error: err };
  }

  writeStatus(p.status, {
    status: 'running',
    step: 'naabu',
    startedAt: new Date().toISOString(),
  });

  console.log('[ports] starting port scan for', target, '—', hostCount, 'hosts');

  // ── Step 1: naabu fast discovery ──────────────────────────────────────────
  const naabuResult = await runNaabu(target, inputFile, p.naabuRaw, p.naabuPorts);

  // Parse naabu output
  const naabuLines   = (naabuResult.raw || '').split('\n').filter(Boolean);
  const naabuEntries = naabuLines.map(parseNaabuLine).filter(e => e && e.host && e.port !== null);
  const naabuByHost  = groupNaabuByHost(naabuEntries);

  const naabuPortCount = naabuEntries.length;
  const naabuHostCount = Object.keys(naabuByHost).length;

  console.log('[ports] naabu found', naabuPortCount, 'open ports across', naabuHostCount, 'hosts');

  writeStatus(p.status, {
    status: 'running',
    step: 'nmap',
    naabuPortCount,
    naabuHostCount,
    startedAt: new Date().toISOString(),
  });

  // ── Step 2: nmap deep scan on discovered ports ────────────────────────────
  const nmapResult = await runNmap(inputFile, naabuByHost, p.nmapRaw);

  // Parse nmap XML
  let nmapByHost = {};
  if (!nmapResult.skipped && fs.existsSync(p.nmapRaw)) {
    try {
      const xml = fs.readFileSync(p.nmapRaw, 'utf8');
      nmapByHost = parseNmapXML(xml);
    } catch (e) {
      console.log('[ports] nmap XML parse error:', e.message);
    }
  }

  // ── Merge results ─────────────────────────────────────────────────────────
  // Build unified map: all hosts from both tools
  const allHosts = new Set([
    ...Object.keys(naabuByHost),
    ...Object.keys(nmapByHost),
  ]);

  const merged = {};
  for (const host of allHosts) {
    merged[host] = {
      naabu: naabuByHost[host] || [],
      nmap:  nmapByHost[host]  || [],
    };
  }

  fs.writeFileSync(p.json, JSON.stringify(merged, null, 2));

  // merged.txt — host:port per line (from naabu, authoritative)
  const mergedLines = [];
  for (const [host, data] of Object.entries(merged)) {
    for (const port of data.naabu) {
      mergedLines.push(`${host}:${port}`);
    }
  }
  fs.writeFileSync(p.merged, mergedLines.join('\n') + (mergedLines.length ? '\n' : ''));

  const totalOpenPorts = naabuPortCount;
  const totalHosts     = allHosts.size;

  const finalStatus = {
    status:         'done',
    totalOpenPorts,
    totalHosts,
    naabuPortCount,
    naabuHostCount,
    nmapHostCount:  Object.keys(nmapByHost).length,
    nmapSkipped:    !!nmapResult.skipped,
    naabuTimedOut:  !!naabuResult.timedOut,
    nmapTimedOut:   !!nmapResult.timedOut,
    completedAt:    new Date().toISOString(),
  };

  console.log('[ports] done —', totalOpenPorts, 'open ports across', totalHosts, 'hosts');
  writeStatus(p.status, finalStatus);
  return { success: true, ...finalStatus };
}

// ─── Status reader ────────────────────────────────────────────────────────────

function getPortsStatus(target) {
  const p      = getPortsPaths(target);
  const status = readStatus(p.status) || { status: 'not_started' };

  let merged = {};
  if (fs.existsSync(p.json)) {
    try { merged = JSON.parse(fs.readFileSync(p.json, 'utf8')); }
    catch { merged = {}; }
  }

  return { ...status, merged };
}

module.exports = { runPortScan, getPortsStatus, getPortsPaths };
