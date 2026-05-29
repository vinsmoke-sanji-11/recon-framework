// backend/phases/screenshots.cjs
// Phase 6 — Screenshots using Chromium headless

'use strict';
const _cfg = require('../config.cjs');

const { spawn } = require('child_process');
const fs   = require('fs');
const path = require('path');

const WORKSPACE_DIR  = path.resolve(__dirname, '../workspace');
const CHROMIUM_BIN   = _cfg.BINS.chromium;
const PER_URL_TIMEOUT = 20_000;  // 20s per screenshot
const CONCURRENCY     = 3;       // screenshots in parallel

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getScreenshotsPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'screenshots');
  return {
    base,
    status: path.join(base, 'status.json'),
    index:  path.join(base, 'index.json'),  // [{ url, file, success, error }]
    imgs:   path.join(base, 'imgs'),        // actual PNG files
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

// Sanitize URL into a safe filename
function urlToFilename(url) {
  return url
    .replace(/^https?:\/\//, '')
    .replace(/[^a-zA-Z0-9.\-_]/g, '_')
    .slice(0, 120) + '.png';
}

// Take a single screenshot using chromium headless
function screenshotURL(url, outputFile) {
  return new Promise((resolve) => {
    const args = [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-software-rasterizer',
      '--disable-extensions',
      '--no-first-run',
      '--no-default-browser-check',
      '--hide-scrollbars',
      '--mute-audio',
      `--window-size=1280,800`,
      `--screenshot=${outputFile}`,
      `--virtual-time-budget=5000`,
      url,
    ];

    const proc = spawn(CHROMIUM_BIN, args, {
      env: { ...process.env, HOME: _cfg.HOME, DISPLAY: '' },
    });
    proc.stdin.end();

    let finished = false;

    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        proc.kill('SIGKILL');
        resolve({ success: false, error: 'timeout' });
      }
    }, PER_URL_TIMEOUT);

    proc.stdout.on('data', () => {});
    proc.stderr.on('data', () => {});

    proc.on('close', (code) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        const exists = fs.existsSync(outputFile) && fs.statSync(outputFile).size > 0;
        resolve({ success: exists, error: exists ? null : `exit ${code}` });
      }
    });

    proc.on('error', (err) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        resolve({ success: false, error: err.message });
      }
    });
  });
}

// Run N promises concurrently
async function runConcurrent(tasks, concurrency) {
  const results = [];
  let i = 0;
  async function worker() {
    while (i < tasks.length) {
      const idx = i++;
      results[idx] = await tasks[idx]();
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, worker);
  await Promise.all(workers);
  return results;
}

// ─── Main Phase Runner ────────────────────────────────────────────────────────

async function runScreenshots(target) {
  const p         = getScreenshotsPaths(target);
  const inputFile = getLiveMerged(target);

  fs.mkdirSync(p.base, { recursive: true });
  fs.mkdirSync(p.imgs, { recursive: true });

  const existing = readStatus(p.status);
  if (existing?.status === 'running') {
    console.log('[screenshots] clearing stale running status');
  }

  if (!fs.existsSync(inputFile)) {
    const err = 'live/merged.txt not found — run Phase 03 (Live Hosts) first';
    writeStatus(p.status, { status: 'error', error: err });
    return { success: false, error: err };
  }

  const urls = fs.readFileSync(inputFile, 'utf8').split('\n').filter(Boolean);
  if (urls.length === 0) {
    const err = 'live/merged.txt is empty';
    writeStatus(p.status, { status: 'error', error: err });
    return { success: false, error: err };
  }

  writeStatus(p.status, {
    status: 'running',
    total: urls.length,
    done: 0,
    startedAt: new Date().toISOString(),
  });

  console.log('[screenshots] starting for', target, '—', urls.length, 'URLs');

  const index = [];
  let doneCount = 0;

  const tasks = urls.map(url => async () => {
    const filename   = urlToFilename(url);
    const outputFile = path.join(p.imgs, filename);

    console.log(`[screenshots] capturing ${url}`);
    const result = await screenshotURL(url, outputFile);

    const entry = {
      url,
      file:    result.success ? filename : null,
      success: result.success,
      error:   result.error || null,
    };
    index.push(entry);

    doneCount++;
    writeStatus(p.status, {
      status:  'running',
      total:   urls.length,
      done:    doneCount,
      startedAt: new Date().toISOString(),
    });
    fs.writeFileSync(p.index, JSON.stringify(index, null, 2));

    return entry;
  });

  await runConcurrent(tasks, CONCURRENCY);

  const successCount = index.filter(e => e.success).length;
  const failCount    = index.length - successCount;

  const finalStatus = {
    status: 'done',
    total:  urls.length,
    success: successCount,
    failed:  failCount,
    completedAt: new Date().toISOString(),
  };

  console.log(`[screenshots] done — ${successCount} success, ${failCount} failed`);
  writeStatus(p.status, finalStatus);
  fs.writeFileSync(p.index, JSON.stringify(index, null, 2));
  return { success: true, ...finalStatus };
}

// ─── Status reader ────────────────────────────────────────────────────────────

function getScreenshotsStatus(target) {
  const p      = getScreenshotsPaths(target);
  const status = readStatus(p.status) || { status: 'not_started' };

  let index = [];
  if (fs.existsSync(p.index)) {
    try { index = JSON.parse(fs.readFileSync(p.index, 'utf8')); }
    catch { index = []; }
  }

  return { ...status, index };
}

module.exports = { runScreenshots, getScreenshotsStatus, getScreenshotsPaths };
