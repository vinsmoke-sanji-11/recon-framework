// backend/phases/nuclei.cjs
// PH-10 — Nuclei Vulnerability Scanner
// Runs nuclei against live hosts, parses JSONL output, stores findings

'use strict';
const _cfg = require('../config.cjs');

const fs      = require('fs');
const path    = require('path');
const { spawn } = require('child_process');

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'nuclei');
  return {
    base,
    status:    path.join(base, 'status.json'),
    findings:  path.join(base, 'findings.json'),
    rawOutput: path.join(base, 'raw.jsonl'),
    hostsList: path.join(base, 'hosts.txt'),
  };
}

function writeStatus(f, d) { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }
function readJSON(f) {
  if (!fs.existsSync(f)) return null;
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; }
}

function makeID() { return Math.random().toString(36).slice(2, 9); }

// ─── Severity normaliser ──────────────────────────────────────────────────────
// Nuclei uses: critical, high, medium, low, info, unknown
function normaliseSev(sev) {
  const s = (sev || '').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'info';
}

// ─── Convert nuclei JSONL line → internal finding format ─────────────────────
function nucleiLineToFinding(line) {
  let parsed;
  try { parsed = JSON.parse(line); } catch { return null; }

  const info      = parsed.info || {};
  const severity  = normaliseSev(info.severity);
  const templateID = parsed['template-id'] || parsed.templateID || 'unknown';
  const name       = info.name || templateID;
  const matchedAt  = parsed['matched-at'] || parsed.host || '';
  const url        = matchedAt.startsWith('http') ? matchedAt : `https://${matchedAt}`;

  // Build evidence block
  const evidence = [
    `Template:   ${templateID}`,
    `Matched:    ${matchedAt}`,
    info.description ? `Description: ${info.description}` : null,
    parsed.matcher_name  ? `Matcher:    ${parsed.matcher_name}` : null,
    parsed['curl-command'] ? `cURL:       ${parsed['curl-command'].slice(0, 300)}` : null,
    parsed.extracted_results?.length
      ? `Extracted:  ${parsed.extracted_results.slice(0, 5).join(', ')}` : null,
  ].filter(Boolean).join('\n');

  const tags = Array.isArray(info.tags) ? info.tags.join(', ') :
               (typeof info.tags === 'string' ? info.tags : '');
  const reference = Array.isArray(info.reference) ? info.reference[0] || '' :
                    (typeof info.reference === 'string' ? info.reference : '');

  return {
    id:           makeID(),
    severity,
    type:         tags || 'nuclei',
    title:        name,
    evidence,
    url,
    source_phase: 'nuclei',
    template_id:  templateID,
    tags,
    reference,
    recommendation: reference
      ? `See: ${reference}`
      : 'Review the matched finding and apply vendor-recommended remediation.',
    ts: new Date().toISOString(),
  };
}

// ─── Check nuclei is installed ────────────────────────────────────────────────
function checkNuclei() {
  return new Promise((resolve) => {
    const p = spawn('nuclei', ['-version'], { stdio: 'pipe' });
    p.on('error', () => resolve(false));
    p.on('close', (code) => resolve(code === 0));
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

async function runNuclei(target, options = {}) {
  const {
    severity    = ['critical', 'high', 'medium', 'low', 'info'],
    tags        = [],          // e.g. ['cve','misconfig']
    excludeTags = [],          // e.g. ['dos','fuzz']
    templates   = [],          // specific template paths
    rateLimit   = 150,
    concurrency = 25,
    timeout     = 10,
    retries     = 1,
  } = options;

  const p = getPaths(target);
  fs.mkdirSync(p.base, { recursive: true });

  // ── Verify nuclei is installed ──
  const installed = await checkNuclei();
  if (!installed) {
    const errStatus = {
      status: 'failed',
      error:  'nuclei not found — install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
      total:  0,
    };
    writeStatus(p.status, errStatus);
    return { success: false, ...errStatus };
  }

  // ── Read live hosts ──
  const hostsSource = path.join(WORKSPACE_DIR, target, 'live', 'merged.txt');
  if (!fs.existsSync(hostsSource)) {
    const errStatus = {
      status: 'failed',
      error:  'live/merged.txt not found — run Live Check phase first',
      total:  0,
    };
    writeStatus(p.status, errStatus);
    return { success: false, ...errStatus };
  }

  // Copy hosts to nuclei dir so we have a clean list
  fs.copyFileSync(hostsSource, p.hostsList);

  const hostCount = fs.readFileSync(p.hostsList, 'utf8')
    .split('\n').filter(Boolean).length;

  console.log(`[nuclei] starting scan on ${hostCount} hosts for ${target}`);

  writeStatus(p.status, {
    status:    'running',
    total:     0,
    critical:  0,
    high:      0,
    medium:    0,
    low:       0,
    info:      0,
    hosts:     hostCount,
    startedAt: new Date().toISOString(),
  });

  // ── Build nuclei args ──
  const args = [
    '-l',          p.hostsList,
    '-json-export', p.rawOutput,
    '-severity',   severity.join(','),
    '-rate-limit', String(rateLimit),
    '-c',          String(concurrency),
    '-timeout',    String(timeout),
    '-retries',    String(retries),
    '-no-color',
    '-silent',
    '-stats',
  ];

  if (tags.length)        args.push('-tags',         tags.join(','));
  if (excludeTags.length) args.push('-exclude-tags', excludeTags.join(','));
  if (templates.length)   templates.forEach(t => args.push('-t', t));

  // ── Spawn nuclei ──
  const allFindings = [];

  await new Promise((resolve, reject) => {
    const proc = spawn('nuclei', args, { stdio: ['ignore', 'pipe', 'pipe'] });

    let lineBuffer = '';

    // Nuclei writes JSONL to stdout when using -json (and to file with -json-export)
    // We also tail the raw output file for real-time updates
    proc.stdout.on('data', (chunk) => {
      lineBuffer += chunk.toString();
      const lines = lineBuffer.split('\n');
      lineBuffer = lines.pop(); // keep incomplete line

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('{')) continue;
        const finding = nucleiLineToFinding(trimmed);
        if (!finding) continue;

        allFindings.push(finding);
        fs.writeFileSync(p.findings, JSON.stringify(allFindings, null, 2));
        writeStatus(p.status, {
          status:   'running',
          total:    allFindings.length,
          critical: allFindings.filter(f => f.severity === 'critical').length,
          high:     allFindings.filter(f => f.severity === 'high').length,
          medium:   allFindings.filter(f => f.severity === 'medium').length,
          low:      allFindings.filter(f => f.severity === 'low').length,
          info:     allFindings.filter(f => f.severity === 'info').length,
          hosts:    hostCount,
          startedAt: new Date().toISOString(),
        });
      }
    });

    proc.stderr.on('data', (d) => {
      // nuclei writes progress stats to stderr — log but don't fail
      const msg = d.toString().trim();
      if (msg) console.log(`[nuclei] ${msg}`);
    });

    proc.on('error', (err) => reject(err));
    proc.on('close', (code) => {
      console.log(`[nuclei] process exited with code ${code}`);

      // If -json-export was used, also parse the raw file as fallback
      if (fs.existsSync(p.rawOutput) && allFindings.length === 0) {
        const rawLines = fs.readFileSync(p.rawOutput, 'utf8').split('\n');
        for (const line of rawLines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('{')) continue;
          const finding = nucleiLineToFinding(trimmed);
          if (finding) allFindings.push(finding);
        }
        fs.writeFileSync(p.findings, JSON.stringify(allFindings, null, 2));
      }

      resolve(code);
    });
  });

  const finalStatus = {
    status:      'done',
    total:       allFindings.length,
    critical:    allFindings.filter(f => f.severity === 'critical').length,
    high:        allFindings.filter(f => f.severity === 'high').length,
    medium:      allFindings.filter(f => f.severity === 'medium').length,
    low:         allFindings.filter(f => f.severity === 'low').length,
    info:        allFindings.filter(f => f.severity === 'info').length,
    hosts:       hostCount,
    completedAt: new Date().toISOString(),
  };

  console.log(`[nuclei] done — ${allFindings.length} findings for ${target}`);
  writeStatus(p.status, finalStatus);
  return { success: true, ...finalStatus };
}

// ─── Status getter (used by routes) ──────────────────────────────────────────
function getNucleiStatus(target) {
  const p        = getPaths(target);
  const status   = readJSON(p.status) || { status: 'not_started' };
  const findings = fs.existsSync(p.findings)
    ? (readJSON(p.findings) || [])
    : [];
  return { ...status, findings };
}

module.exports = { runNuclei, getNucleiStatus };
