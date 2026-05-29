// phases/subdomain.cjs — Phase 1: Subdomain Enumeration
'use strict';

const { spawn } = require('child_process');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const _cfg   = require('../config.cjs');

const BINS           = _cfg.BINS;
const RESOLVERS_FILE = _cfg.RESOLVERS_FILE;

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');

function writeStatus(statusFile, data) {
  fs.writeFileSync(statusFile, JSON.stringify(data, null, 2));
}
function toolExists(bin) { return !!bin && fs.existsSync(bin); }
function resultOf(r) {
  if (!r) return 'error';
  if (r.skipped) return 'skipped';
  if (r.timedOut) return 'timeout';
  if (r.error) return 'error';
  return 'done';
}

function runTool(binary, args, outputFile, timeoutMs) {
  return new Promise((resolve) => {
    if (!toolExists(binary)) {
      console.log(`[subdomain] skipping ${path.basename(binary || '?')} — not found`);
      return resolve({ skipped: true });
    }
    console.log(`[subdomain] starting ${path.basename(binary)}`);
    const proc = spawn(binary, args, { env: { ...process.env, HOME: _cfg.HOME } });
    proc.stdin.end();
    let finished = false;
    const timer = setTimeout(() => {
      if (!finished) { finished = true; console.log(`[subdomain] timeout: ${path.basename(binary)}`); proc.kill('SIGKILL'); resolve({ timedOut: true }); }
    }, timeoutMs);
    if (outputFile && outputFile !== '/dev/null') {
      proc.stdout.on('data', (data) => { fs.appendFileSync(outputFile, data.toString()); });
    }
    proc.stderr.on('data', () => {});
    proc.on('close', (code) => {
      if (!finished) { finished = true; clearTimeout(timer); console.log(`[subdomain] done ${path.basename(binary)} (exit ${code})`); resolve({ code }); }
    });
    proc.on('error', (err) => {
      if (!finished) { finished = true; clearTimeout(timer); resolve({ error: err.message }); }
    });
  });
}

function fetchCrtsh(domain, outputFile) {
  return new Promise((resolve) => {
    console.log('[subdomain] starting crtsh');
    const req = https.get({
      hostname: 'crt.sh', path: `/?q=%25.${domain}&output=json`,
      method: 'GET', timeout: 30_000,
      headers: { 'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0' },
    }, (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => {
        try {
          if (!raw.trim().startsWith('[')) { fs.writeFileSync(outputFile, ''); return resolve(); }
          const entries = JSON.parse(raw);
          const domains = new Set();
          for (const entry of entries) {
            for (const n of (entry.name_value || '').split('\n')) {
              const clean = n.trim().replace(/^\*\./, '').toLowerCase();
              if (clean && (clean.endsWith(`.${domain}`) || clean === domain)) domains.add(clean);
            }
          }
          fs.writeFileSync(outputFile, [...domains].join('\n') + '\n');
          console.log(`[subdomain] crtsh found ${domains.size} entries`);
        } catch (e) { fs.writeFileSync(outputFile, ''); console.log('[subdomain] crtsh error:', e.message); }
        resolve();
      });
    });
    req.on('error', (err) => { fs.writeFileSync(outputFile, ''); resolve(); });
    req.on('timeout', () => { req.destroy(); fs.writeFileSync(outputFile, ''); resolve(); });
  });
}

function buildIntermediateList(files, domain) {
  const seen = new Set();
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
      const line = raw.trim().toLowerCase();
      if (!line || line.startsWith('{') || line.startsWith('[')) continue;
      if (line.includes('.') && (line.endsWith(`.${domain}`) || line === domain)) seen.add(line);
    }
  }
  return [...seen];
}

function runShuffleDNS(domain, inputFile, outputFile, timeoutMs) {
  return new Promise((resolve) => {
    if (!toolExists(BINS.shuffledns)) { console.log('[subdomain] skipping shuffledns — not found'); return resolve({ skipped: true }); }
    if (!fs.existsSync(RESOLVERS_FILE)) { console.log('[subdomain] skipping shuffledns — resolvers.txt missing'); return resolve({ skipped: true }); }
    const content = fs.existsSync(inputFile) ? fs.readFileSync(inputFile, 'utf8').trim() : '';
    if (!content) { console.log('[subdomain] skipping shuffledns — no input'); return resolve({ skipped: true }); }
    console.log('[subdomain] starting shuffledns');
    const args = ['-d', domain, '-list', inputFile, '-r', RESOLVERS_FILE, '-mode', 'resolve', '-o', outputFile, '-silent'];
    const proc = spawn(BINS.shuffledns, args, { env: { ...process.env, HOME: _cfg.HOME } });
    proc.stdin.end();
    let finished = false;
    const timer = setTimeout(() => { if (!finished) { finished = true; proc.kill('SIGKILL'); resolve({ timedOut: true }); } }, timeoutMs);
    proc.stdout.on('data', () => {});
    proc.stderr.on('data', () => {});
    proc.on('close', (code) => { if (!finished) { finished = true; clearTimeout(timer); resolve({ code }); } });
    proc.on('error', (err) => { if (!finished) { finished = true; clearTimeout(timer); resolve({ error: err.message }); } });
  });
}

function mergeResults(files, mergedFile, domain) {
  const seen = new Set();
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
      const line = raw.trim().toLowerCase();
      if (!line || !line.includes('.')) continue;
      if (!line.endsWith(`.${domain}`) && line !== domain) continue;
      seen.add(line);
    }
  }
  const sorted = [...seen].sort();
  fs.writeFileSync(mergedFile, sorted.join('\n') + (sorted.length ? '\n' : ''));
  return sorted.length;
}

async function runSubdomainPhase(target, targetPath) {
  console.log('[Phase] Subdomain started for', target);
  const phasePath  = path.join(targetPath, 'subdomain');
  fs.mkdirSync(phasePath, { recursive: true });
  const statusFile = path.join(phasePath, 'status.json');
  const files = {
    subfinder:     path.join(phasePath, 'subfinder.txt'),
    amass_passive: path.join(phasePath, 'amass_passive.txt'),
    amass_active:  path.join(phasePath, 'amass_active.txt'),
    assetfinder:   path.join(phasePath, 'assetfinder.txt'),
    sublist3r:     path.join(phasePath, 'sublist3r.txt'),
    crtsh:         path.join(phasePath, 'crtsh.txt'),
    cloud_enum:    path.join(phasePath, 'cloud_enum.txt'),
    subdomainizer: path.join(phasePath, 'subdomainizer.txt'),
    shuffledns:    path.join(phasePath, 'shuffledns.txt'),
    intermediate:  path.join(phasePath, '_intermediate.txt'),
    merged:        path.join(phasePath, 'merged.txt'),
  };
  Object.values(files).forEach(f => fs.writeFileSync(f, ''));
  const tools = {};
  const setTool = (name, status) => { tools[name] = status; writeStatus(statusFile, { status: 'running', tools }); };
  writeStatus(statusFile, { status: 'running', tools: {} });

  setTool('subfinder', 'running');
  setTool('subfinder', resultOf(await runTool(BINS.subfinder, ['-d', target, '-silent', '-all'], files.subfinder, 120_000)));
  setTool('amass_passive', 'running');
  setTool('amass_passive', resultOf(await runTool(BINS.amass, ['enum', '-passive', '-d', target], files.amass_passive, 600_000)));
  setTool('amass_active', 'running');
  setTool('amass_active', resultOf(await runTool(BINS.amass, ['enum', '-active', '-d', target], files.amass_active, 600_000)));
  setTool('assetfinder', 'running');
  setTool('assetfinder', resultOf(await runTool(BINS.assetfinder, ['--subs-only', target], files.assetfinder, 60_000)));
  setTool('sublist3r', 'running');
  setTool('sublist3r', resultOf(await runTool(BINS.sublist3r, ['-d', target, '-o', files.sublist3r], '/dev/null', 180_000)));
  setTool('crtsh', 'running');
  await fetchCrtsh(target, files.crtsh);
  setTool('crtsh', 'done');
  setTool('cloud_enum', 'running');
  setTool('cloud_enum', resultOf(await runTool(BINS.python3, [BINS.cloud_enum, '-k', target, '--disable-aws', '--disable-azure', '--disable-gcp'], files.cloud_enum, 120_000)));
  setTool('subdomainizer', 'running');
  setTool('subdomainizer', resultOf(await runTool(BINS.python3, [BINS.subdomainizer, '-u', `https://${target}`, '-o', files.subdomainizer], '/dev/null', 120_000)));
  setTool('shuffledns', 'running');
  const intermediate = buildIntermediateList([files.subfinder, files.amass_passive, files.amass_active, files.assetfinder, files.sublist3r, files.crtsh, files.cloud_enum, files.subdomainizer], target);
  fs.writeFileSync(files.intermediate, intermediate.join('\n') + '\n');
  setTool('shuffledns', resultOf(await runShuffleDNS(target, files.intermediate, files.shuffledns, 180_000)));
  const count = mergeResults([files.subfinder, files.amass_passive, files.amass_active, files.assetfinder, files.sublist3r, files.crtsh, files.cloud_enum, files.subdomainizer, files.shuffledns], files.merged, target);
  try { fs.unlinkSync(files.intermediate); } catch {}
  writeStatus(statusFile, { status: 'completed', subdomainCount: count, tools, completedAt: new Date().toISOString() });
  console.log(`[Phase] Subdomain completed — ${count} unique subdomains`);
}

module.exports = runSubdomainPhase;
