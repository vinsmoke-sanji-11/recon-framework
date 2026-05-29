// backend/phases/urls.cjs
// Phase 5 — URL Discovery
// Tools: gau, gospider, katana, waybackurls

'use strict';
const _cfg = require('../config.cjs');

const { spawn } = require('child_process');
const fs   = require('fs');
const path = require('path');

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');

const BINS = {
  gau:         _cfg.BINS.gau,
  gospider:    _cfg.BINS.gospider,
  katana:      _cfg.BINS.katana,
  waybackurls: _cfg.BINS.waybackurls,
};

const TOOL_TIMEOUT = 300_000; // 5 min per tool

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getURLsPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'urls');
  return {
    base,
    status:      path.join(base, 'status.json'),
    gau:         path.join(base, 'gau.txt'),
    gospider:    path.join(base, 'gospider.txt'),
    katana:      path.join(base, 'katana.txt'),
    waybackurls: path.join(base, 'waybackurls.txt'),
    merged:      path.join(base, 'merged.txt'),
  };
}

function getLiveMerged(target) {
  return path.join(WORKSPACE_DIR, target, 'live', 'merged.txt');
}

function writeStatus(statusPath, data) {
  fs.writeFileSync(statusPath, JSON.stringify(data, null, 2));
}

function readStatus(statusPath) {
  if (!fs.existsSync(statusPath)) return null;
  try { return JSON.parse(fs.readFileSync(statusPath, 'utf8')); }
  catch { return null; }
}

function toolExists(bin) {
  return !!bin && fs.existsSync(bin);
}

function resultOf(r) {
  if (!r) return 'error';
  if (r.skipped) return 'skipped';
  if (r.timedOut) return 'timeout';
  if (r.error) return 'error';
  return 'done';
}

// Clean and validate a URL line
function isValidURL(line) {
  line = line.trim();
  if (!line) return false;
  if (line.startsWith('#') || line.startsWith('[')) return false;
  try {
    const u = new URL(line);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

// Run a tool, stream stdout → outputFile
function runTool(binary, args, outputFile, timeoutMs) {
  return new Promise((resolve) => {
    if (!toolExists(binary)) {
      console.log(`[urls] skipping ${path.basename(binary || '?')} — not found`);
      return resolve({ skipped: true });
    }

    console.log(`[urls] starting ${path.basename(binary)}`);
    const proc = spawn(binary, args, {
      env: { ...process.env, HOME: _cfg.HOME },
    });
    proc.stdin.end();

    let finished = false;

    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        console.log(`[urls] timeout: ${path.basename(binary)}`);
        proc.kill('SIGKILL');
        resolve({ timedOut: true });
      }
    }, timeoutMs);

    if (outputFile && outputFile !== '/dev/null') {
      proc.stdout.on('data', (data) => {
        fs.appendFileSync(outputFile, data.toString());
      });
    }
    proc.stderr.on('data', () => {});

    proc.on('close', (code) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        console.log(`[urls] done ${path.basename(binary)} (exit ${code})`);
        resolve({ code });
      }
    });

    proc.on('error', (err) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        console.log(`[urls] error ${path.basename(binary)}: ${err.message}`);
        resolve({ error: err.message });
      }
    });
  });
}

// gospider outputs lines like "[url] - http://..." — extract just the URL
function cleanGospiderOutput(file) {
  if (!fs.existsSync(file)) return;
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const cleaned = lines
    .map(line => {
      // match http/https URLs anywhere in the line
      const m = line.match(/(https?:\/\/[^\s"'<>]+)/);
      return m ? m[1] : '';
    })
    .filter(Boolean);
  fs.writeFileSync(file, cleaned.join('\n') + '\n');
}

// Merge all tool outputs into a single deduplicated sorted file
function mergeURLs(files, mergedFile) {
  const seen = new Set();
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const url = line.trim();
      if (isValidURL(url) && !seen.has(url)) {
        seen.add(url);
      }
    }
  }
  const sorted = [...seen].sort();
  fs.writeFileSync(mergedFile, sorted.join('\n') + (sorted.length ? '\n' : ''));
  return sorted.length;
}

// Get unique domains from URL list
function countUniqueDomains(urls) {
  const domains = new Set();
  for (const url of urls) {
    try { domains.add(new URL(url).hostname); } catch {}
  }
  return domains.size;
}

// ─── Main Phase Runner ────────────────────────────────────────────────────────

async function runURLDiscovery(target) {
  const p         = getURLsPaths(target);
  const inputFile = getLiveMerged(target);

  fs.mkdirSync(p.base, { recursive: true });

  // Clear stale
  const existing = readStatus(p.status);
  if (existing?.status === 'running') {
    console.log('[urls] clearing stale running status for', target);
  }

  if (!fs.existsSync(inputFile)) {
    const err = 'live/merged.txt not found — run Phase 03 (Live Hosts) first';
    writeStatus(p.status, { status: 'error', error: err });
    return { success: false, error: err };
  }

  const liveURLs = fs.readFileSync(inputFile, 'utf8').split('\n').filter(Boolean);
  if (liveURLs.length === 0) {
    const err = 'live/merged.txt is empty — no live URLs to crawl';
    writeStatus(p.status, { status: 'error', error: err });
    return { success: false, error: err };
  }

  // Clear old output files
  Object.values(p).forEach(f => {
    if (f !== p.base && f !== p.status) {
      try { fs.writeFileSync(f, ''); } catch {}
    }
  });

  const tools = {};
  const setTool = (name, status) => {
    tools[name] = status;
    writeStatus(p.status, { status: 'running', tools });
  };

  writeStatus(p.status, { status: 'running', tools: {} });

  console.log('[urls] starting URL discovery for', target, '—', liveURLs.length, 'live URLs');

  // ── 1. gau — fetch all known URLs from archives ───────────────────────────
  // gau takes domain names, not URLs
  setTool('gau', 'running');
  const gauResult = await runTool(
    BINS.gau,
    [target, '--threads', '5', '--timeout', '60', '--retries', '2'],
    p.gau, TOOL_TIMEOUT
  );
  setTool('gau', resultOf(gauResult));

  // ── 2. waybackurls — wayback machine archive ──────────────────────────────
  setTool('waybackurls', 'running');
  const wbResult = await runTool(
    BINS.waybackurls,
    [target],
    p.waybackurls, TOOL_TIMEOUT
  );
  setTool('waybackurls', resultOf(wbResult));

  // ── 3. gospider — crawl live URLs ─────────────────────────────────────────
  setTool('gospider', 'running');
  const gsResult = await runTool(
    BINS.gospider,
    ['-S', inputFile, '-t', '5', '-c', '10', '--depth', '3', '-q'],
    p.gospider, TOOL_TIMEOUT
  );
  // gospider output needs cleaning
  cleanGospiderOutput(p.gospider);
  setTool('gospider', resultOf(gsResult));

  // ── 4. katana — modern crawler ────────────────────────────────────────────
  setTool('katana', 'running');
  const katResult = await runTool(
    BINS.katana,
    ['-list', inputFile, '-silent', '-d', '3', '-jc', '-o', p.katana],
    '/dev/null', TOOL_TIMEOUT
  );
  setTool('katana', resultOf(katResult));

  // ── Merge all results ─────────────────────────────────────────────────────
  const count = mergeURLs(
    [p.gau, p.gospider, p.katana, p.waybackurls],
    p.merged
  );

  // Count unique domains for stats
  const mergedURLs = fs.existsSync(p.merged)
    ? fs.readFileSync(p.merged, 'utf8').split('\n').filter(Boolean)
    : [];
  const uniqueDomains = countUniqueDomains(mergedURLs);

  // Per-tool counts
  const toolCounts = {};
  for (const [name, file] of Object.entries({
    gau: p.gau, gospider: p.gospider, katana: p.katana, waybackurls: p.waybackurls
  })) {
    try {
      toolCounts[name] = fs.existsSync(file)
        ? fs.readFileSync(file, 'utf8').split('\n').filter(l => isValidURL(l.trim())).length
        : 0;
    } catch { toolCounts[name] = 0; }
  }

  const finalStatus = {
    status: 'done',
    totalURLs: count,
    uniqueDomains,
    toolCounts,
    tools,
    completedAt: new Date().toISOString(),
  };

  console.log(`[urls] done — ${count} unique URLs across ${uniqueDomains} domains`);
  writeStatus(p.status, finalStatus);
  return { success: true, ...finalStatus };
}

// ─── Status reader ────────────────────────────────────────────────────────────

function getURLsStatus(target) {
  const p      = getURLsPaths(target);
  const status = readStatus(p.status) || { status: 'not_started' };

  // Return paginated URLs for the UI
  let urls = [];
  if (fs.existsSync(p.merged)) {
    urls = fs.readFileSync(p.merged, 'utf8').split('\n').filter(Boolean);
  }

  return { ...status, urls };
}

module.exports = { runURLDiscovery, getURLsStatus, getURLsPaths };
