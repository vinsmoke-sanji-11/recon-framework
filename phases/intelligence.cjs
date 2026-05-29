// backend/phases/intelligence.cjs
// PH-09 — Vulnerability Intelligence Engine
// 6 modules, all optional, unified finding format

'use strict';
const _cfg = require('../config.cjs');

const https      = require('https');
const http       = require('http');
const fs         = require('fs');
const path       = require('path');
const { URL }    = require('url');
const { spawn }  = require('child_process');

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');
const JS_BEAUTIFY   = path.resolve(__dirname, '../node_modules/.bin/js-beautify');

// ─── Severity levels ──────────────────────────────────────────────────────────
const SEV = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'intelligence');
  return {
    base,
    status:   path.join(base, 'status.json'),
    findings: path.join(base, 'findings.json'),
  };
}

function writeStatus(f, d) { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }
function readJSON(f) {
  if (!fs.existsSync(f)) return null;
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; }
}

function makeID() { return Math.random().toString(36).slice(2, 9); }

function httpGET(url, headers = {}, timeoutMs = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const mod    = parsed.protocol === 'https:' ? https : http;
      const req    = mod.get({
        hostname:           parsed.hostname,
        port:               parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:               parsed.pathname + parsed.search,
        timeout:            timeoutMs,
        rejectUnauthorized: false,
        headers: { 'User-Agent': 'Mozilla/5.0', ...headers },
      }, (res) => {
        let raw = '';
        res.on('data', d => { raw += d; if (raw.length > 500000) res.destroy(); });
        res.on('end', () => resolve({ ok: true, status: res.statusCode, data: raw, headers: res.headers }));
      });
      req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
      req.on('error',   () => resolve({ ok: false }));
    } catch { resolve({ ok: false }); }
  });
}

function headURL(url, timeoutMs = 6000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const mod    = parsed.protocol === 'https:' ? https : http;
      const options = {
        method: 'HEAD', hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        timeout: timeoutMs, rejectUnauthorized: false,
        headers: { 'User-Agent': 'Mozilla/5.0' },
      };
      const req = mod.request(options, (res) => {
        resolve({ ok: true, status: res.statusCode, headers: res.headers });
        res.resume();
      });
      req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
      req.on('error',   () => resolve({ ok: false }));
      req.end();
    } catch { resolve({ ok: false }); }
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function runConcurrent(tasks, concurrency) {
  const results = new Array(tasks.length);
  let i = 0;
  async function worker() {
    while (i < tasks.length) {
      const idx = i++;
      results[idx] = await tasks[idx]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
  return results;
}

// ─── Finding builder ──────────────────────────────────────────────────────────

function finding(severity, type, title, evidence, url, sourcePhase, recommendation = '') {
  return { id: makeID(), severity, type, title, evidence, url, source_phase: sourcePhase, recommendation, ts: new Date().toISOString() };
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 1 — JS Analysis
// ═══════════════════════════════════════════════════════════════════════════════

const SECRET_PATTERNS = [
  { name: 'AWS Access Key',        sev: SEV.CRITICAL, re: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key',        sev: SEV.CRITICAL, re: /aws[_\-\s]secret[_\-\s]?(access[_\-\s]?)?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})/gi },
  { name: 'Google API Key',        sev: SEV.HIGH,     re: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Google OAuth',          sev: SEV.HIGH,     re: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g },
  { name: 'Stripe Secret Key',     sev: SEV.CRITICAL, re: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Stripe Publishable',    sev: SEV.MEDIUM,   re: /pk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Slack Token',           sev: SEV.HIGH,     re: /xox[baprs]-([0-9a-zA-Z]{10,48})/g },
  { name: 'Slack Webhook',         sev: SEV.HIGH,     re: /hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g },
  { name: 'GitHub Token',          sev: SEV.CRITICAL, re: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}/g },
  { name: 'GitHub OAuth',          sev: SEV.HIGH,     re: /[Gg]it[Hh]ub[_\-\s]?[Tt]oken\s*[:=]\s*['"]?([a-zA-Z0-9_]{35,40})/g },
  { name: 'JWT Token',             sev: SEV.HIGH,     re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'Private Key',           sev: SEV.CRITICAL, re: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'Twilio API Key',        sev: SEV.HIGH,     re: /SK[0-9a-fA-F]{32}/g },
  { name: 'SendGrid API Key',      sev: SEV.HIGH,     re: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g },
  { name: 'Mailgun API Key',       sev: SEV.HIGH,     re: /key-[0-9a-zA-Z]{32}/g },
  { name: 'Firebase URL',          sev: SEV.MEDIUM,   re: /[a-z0-9-]+\.firebaseio\.com/g },
  { name: 'Firebase API Key',      sev: SEV.HIGH,     re: /firebase[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{30,})/gi },
  { name: 'Heroku API Key',        sev: SEV.HIGH,     re: /[Hh]eroku[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})/g },
  { name: 'Cloudinary URL',        sev: SEV.MEDIUM,   re: /cloudinary:\/\/[0-9]+:[a-zA-Z0-9_\-]+@[a-z]+/g },
  { name: 'S3 Bucket URL',         sev: SEV.MEDIUM,   re: /s3\.amazonaws\.com\/[a-zA-Z0-9.\-_]+/g },
  { name: 'S3 Bucket Name',        sev: SEV.MEDIUM,   re: /[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com/g },
  { name: 'Internal IP',           sev: SEV.LOW,      re: /(?:^|[^0-9])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)/g },
  { name: 'Mapbox Token',          sev: SEV.MEDIUM,   re: /pk\.eyJ1[a-zA-Z0-9._\-]+/g },
  { name: 'Datadog API Key',       sev: SEV.HIGH,     re: /[Dd]atadog[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]?([a-zA-Z0-9]{32,40})/g },
  { name: 'Telegram Bot Token',    sev: SEV.HIGH,     re: /[0-9]{8,10}:[a-zA-Z0-9_\-]{35}/g },
  { name: 'PayPal Client ID',      sev: SEV.MEDIUM,   re: /paypal[_\-\s]?client[_\-\s]?id\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})/gi },
  { name: 'Square Access Token',   sev: SEV.CRITICAL, re: /sq0atp-[0-9A-Za-z\-_]{22}/g },
  { name: 'NPM Token',             sev: SEV.HIGH,     re: /npm_[A-Za-z0-9]{36}/g },
];

const ENDPOINT_PATTERNS = [
  /['"`](\/api\/[a-zA-Z0-9_\-\/]+)['"`]/g,
  /['"`](\/v[0-9]+\/[a-zA-Z0-9_\-\/]+)['"`]/g,
  /['"`](\/graphql[a-zA-Z0-9_\-\/]*)['"`]/g,
  /url\s*[:=]\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/gi,
  /fetch\s*\(\s*['"`](https?:\/\/[^'"` ]+)['"`]/g,
  /axios\.[a-z]+\s*\(\s*['"`](https?:\/\/[^'"` ]+|\/[^'"` ]+)['"`]/g,
  /baseURL\s*[:=]\s*['"`](https?:\/\/[^'"` ]+)['"`]/gi,
  /endpoint\s*[:=]\s*['"`](https?:\/\/[^'"` ]+|\/[^'"` ]+)['"`]/gi,
];

function beautifyJS(code) {
  try {
    const jsBeautify = require(path.resolve(__dirname, '../node_modules/js-beautify'));
    return jsBeautify.js(code, { indent_size: 2, max_preserve_newlines: 2 });
  } catch {
    return code; // fallback to raw
  }
}

async function runJSAnalysis(target, onFinding) {
  const urlsFile = path.join(WORKSPACE_DIR, target, 'urls', 'merged.txt');
  if (!fs.existsSync(urlsFile)) {
    console.log('[intelligence] JS: urls/merged.txt not found, skipping');
    return [];
  }

  const allURLs  = fs.readFileSync(urlsFile, 'utf8').split('\n').filter(Boolean);
  const jsURLs   = allURLs.filter(u => {
    try { return /\.(js|mjs|cjs)(\?|$)/.test(new URL(u).pathname); }
    catch { return false; }
  });

  // Deduplicate by pathname
  const seen    = new Set();
  const unique  = jsURLs.filter(u => {
    try {
      const k = new URL(u).pathname;
      if (seen.has(k)) return false;
      seen.add(k); return true;
    } catch { return false; }
  });

  console.log(`[intelligence] JS: ${unique.length} unique JS files to analyze`);

  const findings = [];
  const seenSecrets = new Set();

  const tasks = unique.slice(0, 300).map(jsURL => async () => {
    const res = await httpGET(jsURL, {}, 15000);
    if (!res.ok || !res.data) return;

    let code = res.data;
    if (code.length > 1000000) code = code.slice(0, 1000000); // 1MB limit

    // Beautify
    const beautified = beautifyJS(code);

    // Secret scanning — with surrounding context lines for readable evidence
    for (const pattern of SECRET_PATTERNS) {
      const re = new RegExp(pattern.re.source, pattern.re.flags);
      let m;
      while ((m = re.exec(beautified)) !== null) {
        const raw = m[0].slice(0, 300);
        const key = `${pattern.name}:${raw}`;
        if (seenSecrets.has(key)) continue;
        seenSecrets.add(key);
        // Extract 3 lines before + after for context
        const lines = beautified.split('\n');
        let chars = 0, matchLine = 0;
        for (let i = 0; i < lines.length; i++) {
          chars += lines[i].length + 1;
          if (chars > m.index) { matchLine = i; break; }
        }
        const start = Math.max(0, matchLine - 3);
        const end   = Math.min(lines.length - 1, matchLine + 3);
        const ctx   = lines.slice(start, end + 1)
          .map((l, i) => `L${start + i + 1}: ${l.trimEnd()}`)
          .join('\n');
        const f = finding(
          pattern.sev, 'hardcoded_secret',
          `${pattern.name} in ${new URL(jsURL).pathname.split('/').pop()}`,
          `File: ${jsURL}\n\n${ctx}`,
          jsURL, 'js',
          'Remove secret from client-side code immediately. Rotate the credential.'
        );
        findings.push(f);
        onFinding(f);
      }
    }

    // Endpoint extraction
    const endpoints = new Set();
    for (const pattern of ENDPOINT_PATTERNS) {
      const matches = [...beautified.matchAll(pattern)];
      for (const m of matches) {
        const ep = m[1];
        if (ep && ep.length > 3 && ep.length < 200) endpoints.add(ep);
      }
    }

    if (endpoints.size > 0) {
      const f = finding(
        SEV.INFO, 'hidden_endpoint',
        `${endpoints.size} endpoints found in JS`,
        [...endpoints].slice(0, 20).join('\n'),
        jsURL, 'js',
        'Review endpoints for authentication and authorization'
      );
      findings.push(f);
      onFinding(f);
    }

    // S3 bucket detection — found referenced in JS, verify access level
    const s3Matches = [...beautified.matchAll(/([a-zA-Z0-9][a-zA-Z0-9.\-]{2,62}[a-zA-Z0-9])\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/g)];
    const seenS3 = new Set();
    for (const m of s3Matches) {
      const bucket = m[1].toLowerCase().replace(/[^a-z0-9\-.]/g, '');
      if (bucket.length < 3 || seenS3.has(bucket)) continue;
      seenS3.add(bucket);
      const r = await httpGET(`https://${bucket}.s3.amazonaws.com/`, {}, 8000);
      if (!r.ok) continue;
      const body = r.data || '';
      if (body.includes('NoSuchBucket')) continue; // bucket doesn't exist
      const isListable = r.status === 200 && (body.includes('<ListBucketResult') || body.includes('<Contents>'));
      const isPublic   = r.status === 200 && !isListable;
      const isPrivate  = r.status === 403 && (body.includes('AccessDenied') || body.includes('AllAccessDisabled'));
      if (!isListable && !isPublic && !isPrivate) continue;
      const sev   = isListable ? SEV.CRITICAL : isPublic ? SEV.HIGH : SEV.MEDIUM;
      const title = isListable ? `S3 PUBLICLY LISTABLE: ${bucket}`
                  : isPublic   ? `S3 public read: ${bucket}`
                  :              `S3 bucket exists (private): ${bucket}`;
      const rec   = isListable ? 'CRITICAL: Block Public Access immediately, rotate any exposed data.'
                  : isPublic   ? 'Enable Block Public Access, audit object-level ACLs.'
                  :              'Bucket exists. Monitor for ACL changes.';
      const f = finding(sev, 's3_bucket', title,
        `Bucket: ${bucket}\nURL: https://${bucket}.s3.amazonaws.com\nHTTP: ${r.status}\nAccess: ${isListable ? 'PUBLIC_LISTABLE' : isPublic ? 'PUBLIC_READ' : 'PRIVATE'}\nFound in: ${jsURL}`,
        `https://${bucket}.s3.amazonaws.com`, 'js', rec);
      findings.push(f); onFinding(f);
    }
  });

  await runConcurrent(tasks, 5);
  console.log(`[intelligence] JS: ${findings.length} findings`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 3 — Header Analysis
// ═══════════════════════════════════════════════════════════════════════════════

const SECURITY_HEADERS = [
  { name: 'Strict-Transport-Security', sev: SEV.MEDIUM, title: 'Missing HSTS',         rec: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains' },
  { name: 'Content-Security-Policy',   sev: SEV.MEDIUM, title: 'Missing CSP',           rec: 'Implement Content-Security-Policy header' },
  { name: 'X-Frame-Options',           sev: SEV.MEDIUM, title: 'Missing X-Frame-Options', rec: 'Add X-Frame-Options: DENY or SAMEORIGIN' },
  { name: 'X-Content-Type-Options',    sev: SEV.LOW,    title: 'Missing X-Content-Type-Options', rec: 'Add X-Content-Type-Options: nosniff' },
  { name: 'X-XSS-Protection',          sev: SEV.LOW,    title: 'Missing X-XSS-Protection', rec: 'Add X-XSS-Protection: 1; mode=block' },
  { name: 'Referrer-Policy',           sev: SEV.LOW,    title: 'Missing Referrer-Policy', rec: 'Add Referrer-Policy: strict-origin-when-cross-origin' },
  { name: 'Permissions-Policy',        sev: SEV.LOW,    title: 'Missing Permissions-Policy', rec: 'Implement Permissions-Policy header' },
];

const SERVER_VERSION_RE = [
  { re: /apache\/([\d.]+)/i,          name: 'Apache' },
  { re: /nginx\/([\d.]+)/i,           name: 'nginx' },
  { re: /microsoft-iis\/([\d.]+)/i,   name: 'IIS' },
  { re: /php\/([\d.]+)/i,             name: 'PHP' },
  { re: /openssl\/([\d.]+)/i,         name: 'OpenSSL' },
  { re: /express\/([\d.]+)/i,         name: 'Express' },
  { re: /tomcat\/([\d.]+)/i,          name: 'Tomcat' },
];

async function runHeaderAnalysis(target, onFinding) {
  const hostsFile = path.join(WORKSPACE_DIR, target, 'live', 'merged.txt');
  if (!fs.existsSync(hostsFile)) return [];

  const hosts = fs.readFileSync(hostsFile, 'utf8').split('\n').filter(Boolean);
  console.log(`[intelligence] headers: analyzing ${hosts.length} hosts`);

  const findings = [];

  // Track which headers are missing across all hosts
  const missingHeaders = {}; // header name → [hosts]
  const versionDisclosures = [];
  const cookieIssues = [];

  const tasks = hosts.map(hostURL => async () => {
    const res = await headURL(hostURL, 8000);
    if (!res.ok) return;

    const hdrs = res.headers || {};

    // Security headers
    for (const hdr of SECURITY_HEADERS) {
      if (!hdrs[hdr.name.toLowerCase()]) {
        if (!missingHeaders[hdr.name]) missingHeaders[hdr.name] = { hdr, hosts: [] };
        missingHeaders[hdr.name].hosts.push(hostURL);
      }
    }

    // Server version disclosure
    const server = hdrs['server'] || hdrs['x-powered-by'] || '';
    for (const { re, name } of SERVER_VERSION_RE) {
      const m = server.match(re);
      if (m) {
        versionDisclosures.push({ host: hostURL, server: name, version: m[1], header: server });
      }
    }

    // Cookie analysis — need full GET for Set-Cookie
    if (hdrs['set-cookie']) {
      const cookies = Array.isArray(hdrs['set-cookie']) ? hdrs['set-cookie'] : [hdrs['set-cookie']];
      for (const cookie of cookies) {
        const issues = [];
        if (!cookie.toLowerCase().includes('httponly'))  issues.push('missing HttpOnly');
        if (!cookie.toLowerCase().includes('secure'))    issues.push('missing Secure');
        if (!cookie.toLowerCase().includes('samesite'))  issues.push('missing SameSite');
        if (issues.length > 0) {
          cookieIssues.push({ host: hostURL, cookie: cookie.split(';')[0].slice(0, 50), issues });
        }
      }
    }
  });

  await runConcurrent(tasks, 8);

  // Emit findings grouped by header
  for (const [name, data] of Object.entries(missingHeaders)) {
    const { hdr, hosts } = data;
    const f = finding(
      hdr.sev, 'missing_security_header',
      `${hdr.title} — ${hosts.length} hosts`,
      `Missing: ${name}\nHosts: ${hosts.slice(0, 5).join(', ')}`,
      hosts[0], 'headers', hdr.rec
    );
    findings.push(f);
    onFinding(f);
  }

  // Version disclosure
  if (versionDisclosures.length > 0) {
    const f = finding(
      SEV.LOW, 'server_version_disclosure',
      `Server version disclosed — ${versionDisclosures.length} hosts`,
      versionDisclosures.slice(0, 10).map(v => `${v.host} → ${v.header}`).join('\n'),
      versionDisclosures[0].host, 'headers',
      'Remove or obscure Server and X-Powered-By headers'
    );
    findings.push(f);
    onFinding(f);
  }

  // Cookie issues
  if (cookieIssues.length > 0) {
    const f = finding(
      SEV.MEDIUM, 'insecure_cookie',
      `Insecure cookie flags — ${cookieIssues.length} instances`,
      cookieIssues.slice(0, 10).map(c => `${c.host}: ${c.issues.join(', ')}`).join('\n'),
      cookieIssues[0].host, 'headers',
      'Add HttpOnly, Secure, SameSite=Strict to all cookies'
    );
    findings.push(f);
    onFinding(f);
  }

  console.log(`[intelligence] headers: ${findings.length} findings`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 4 — Port Intelligence
// ═══════════════════════════════════════════════════════════════════════════════

const SENSITIVE_PORTS = [
  { port: 21,    service: 'FTP',           sev: SEV.HIGH,     note: 'FTP unencrypted file transfer' },
  { port: 23,    service: 'Telnet',         sev: SEV.CRITICAL, note: 'Telnet unencrypted remote access' },
  { port: 25,    service: 'SMTP',           sev: SEV.MEDIUM,   note: 'SMTP open relay possible' },
  { port: 445,   service: 'SMB',            sev: SEV.CRITICAL, note: 'SMB exposed — EternalBlue risk' },
  { port: 1433,  service: 'MSSQL',          sev: SEV.CRITICAL, note: 'Database directly exposed' },
  { port: 1521,  service: 'Oracle DB',      sev: SEV.CRITICAL, note: 'Database directly exposed' },
  { port: 2375,  service: 'Docker API',     sev: SEV.CRITICAL, note: 'Docker daemon exposed unauthenticated' },
  { port: 2376,  service: 'Docker TLS',     sev: SEV.HIGH,     note: 'Docker daemon TLS exposed' },
  { port: 3306,  service: 'MySQL',          sev: SEV.CRITICAL, note: 'Database directly exposed' },
  { port: 3389,  service: 'RDP',            sev: SEV.HIGH,     note: 'Remote desktop exposed' },
  { port: 4444,  service: 'Metasploit',     sev: SEV.CRITICAL, note: 'Possible backdoor/C2' },
  { port: 5432,  service: 'PostgreSQL',     sev: SEV.CRITICAL, note: 'Database directly exposed' },
  { port: 5900,  service: 'VNC',            sev: SEV.HIGH,     note: 'VNC remote desktop exposed' },
  { port: 5984,  service: 'CouchDB',        sev: SEV.HIGH,     note: 'CouchDB admin may be unauthenticated' },
  { port: 6379,  service: 'Redis',          sev: SEV.CRITICAL, note: 'Redis commonly unauthenticated' },
  { port: 7001,  service: 'WebLogic',       sev: SEV.HIGH,     note: 'WebLogic RCE vulnerabilities' },
  { port: 8080,  service: 'HTTP Alt',       sev: SEV.MEDIUM,   note: 'Alternative HTTP — admin panel possible' },
  { port: 8443,  service: 'HTTPS Alt',      sev: SEV.MEDIUM,   note: 'Alternative HTTPS — admin panel possible' },
  { port: 8500,  service: 'Consul',         sev: SEV.HIGH,     note: 'Consul UI may be unauthenticated' },
  { port: 8888,  service: 'Jupyter',        sev: SEV.CRITICAL, note: 'Jupyter notebook RCE if unauthenticated' },
  { port: 9000,  service: 'SonarQube/PHP',  sev: SEV.HIGH,     note: 'Admin panel possibly exposed' },
  { port: 9090,  service: 'Prometheus',     sev: SEV.HIGH,     note: 'Prometheus metrics exposed' },
  { port: 9200,  service: 'Elasticsearch',  sev: SEV.CRITICAL, note: 'Elasticsearch unauthenticated access' },
  { port: 9300,  service: 'Elasticsearch',  sev: SEV.HIGH,     note: 'Elasticsearch cluster comms exposed' },
  { port: 11211, service: 'Memcached',      sev: SEV.HIGH,     note: 'Memcached DDoS amplification risk' },
  { port: 27017, service: 'MongoDB',        sev: SEV.CRITICAL, note: 'MongoDB commonly unauthenticated' },
  { port: 27018, service: 'MongoDB',        sev: SEV.HIGH,     note: 'MongoDB shard exposed' },
  { port: 50000, service: 'SAP',            sev: SEV.HIGH,     note: 'SAP instance exposed' },
];

async function runPortIntelligence(target, onFinding) {
  const portsFile = path.join(WORKSPACE_DIR, target, 'ports', 'open_ports.json');
  if (!fs.existsSync(portsFile)) return [];

  const portData = readJSON(portsFile) || {};
  const findings = [];

  console.log(`[intelligence] ports: analyzing ${Object.keys(portData).length} hosts`);

  for (const [host, data] of Object.entries(portData)) {
    const allPorts = [
      ...(data.naabu || []),
      ...(data.nmap  || []).map(n => n.port),
    ];

    for (const sp of SENSITIVE_PORTS) {
      if (!allPorts.includes(sp.port)) continue;

      // Get service version from nmap if available
      const nmapEntry = (data.nmap || []).find(n => n.port === sp.port);
      const version   = nmapEntry ? `${nmapEntry.product || ''} ${nmapEntry.version || ''}`.trim() : '';

      const f = finding(
        sp.sev, 'sensitive_port',
        `${sp.service} exposed on ${host}:${sp.port}`,
        `${host}:${sp.port} — ${sp.note}${version ? ` (${version})` : ''}`,
        `${host}:${sp.port}`, 'ports', `Firewall port ${sp.port}, require VPN access`
      );
      findings.push(f);
      onFinding(f);
    }
  }

  console.log(`[intelligence] ports: ${findings.length} findings`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 5 — Confidential Intelligence
// ═══════════════════════════════════════════════════════════════════════════════

async function runConfidentialIntel(target, onFinding) {
  const confFile = path.join(WORKSPACE_DIR, target, 'confidential', 'findings.json');
  if (!fs.existsSync(confFile)) return [];

  const confFindings = readJSON(confFile) || [];
  const findings = [];

  console.log(`[intelligence] confidential: analyzing ${confFindings.length} findings`);

  for (const cf of confFindings) {
    if (cf.status_code !== 200) continue;

    const url  = cf.file_path;
    const low  = url.toLowerCase();

    // .git / .svn / .hg exposure — re-verify body to reject soft-404s
    if (low.includes('/.git/') || low.includes('/.svn/') || low.includes('/.hg/')) {
      const verifyRes = await httpGET(url, {}, 8000);
      const body = verifyRes.data || '';
      const isRealGit = verifyRes.ok && verifyRes.status === 200 && !/<html/i.test(body) && (
        /\[core\]|\[remote|repositoryformatversion/i.test(body) ||  // .git/config
        /^ref: refs\/heads\//m.test(body) ||                         // .git/HEAD
        /^[0-9a-f]{40}$/m.test(body) ||                              // .git/HEAD (detached)
        /svn:\/\/|^10$|^dir$/m.test(body) ||                       // .svn/entries
        /\[paths\]|\[ui\]/i.test(body)                            // .hg/hgrc
      );
      if (!isRealGit) {
        console.log(`[intelligence] git: ${url} — 200 but body is not a real git file, skipping`);
        continue;
      }
      const preview = body.slice(0, 400);
      const f = finding(
        SEV.CRITICAL, 'git_repository_exposed',
        `${low.includes('.svn') ? '.svn' : low.includes('.hg') ? '.hg' : '.git'} directory exposed — source code accessible`,
        `${url} → HTTP 200 (body verified)\n\n${preview}`,
        url, 'confidential',
        'Block /.git/ /.svn/ /.hg/ in web server config. Full source can be recovered with: git-dumper https://github.com/arthaud/git-dumper'
      );
      findings.push(f); onFinding(f); continue;
    }

    // .env file
    if (/\.env($|\.)/.test(low)) {
      // Try to fetch and parse
      const res = await httpGET(url, {}, 8000);
      if (res.ok && res.data) {
        const lines = res.data.split('\n').filter(l => l.includes('=') && !l.startsWith('#'));
        const sensitiveLines = lines.filter(l =>
          /password|secret|key|token|auth|db_|database|api_/i.test(l)
        );
        const f = finding(
          SEV.CRITICAL, 'env_file_exposed',
          `.env file exposed — ${sensitiveLines.length} sensitive vars`,
          sensitiveLines.slice(0, 10).map(l => l.replace(/=.+/, '=[REDACTED]')).join('\n'),
          url, 'confidential',
          'Remove .env from web root immediately, rotate all exposed credentials'
        );
        findings.push(f);
        onFinding(f);
      }
      continue;
    }

    // Backup files
    if (/\.(bak|old|backup|tmp|orig|sql|zip|tar|gz)$/.test(low)) {
      const f = finding(
        SEV.HIGH, 'backup_file_exposed',
        `Backup file accessible: ${path.basename(url)}`,
        `${url} → ${cf.status_code}`,
        url, 'confidential',
        'Remove backup files from web root, add to .gitignore'
      );
      findings.push(f);
      onFinding(f);
    }

    // Config files
    if (/\.(config|conf|cfg|ini|xml|yaml|yml|json)$/.test(low) &&
        /config|setting|database|db|app|wp|server/i.test(low)) {
      const f = finding(
        SEV.HIGH, 'config_file_exposed',
        `Config file exposed: ${path.basename(url)}`,
        `${url} → ${cf.status_code}`,
        url, 'confidential',
        'Move config files outside web root or restrict access'
      );
      findings.push(f);
      onFinding(f);
    }
  }

  console.log(`[intelligence] confidential: ${findings.length} findings`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 6 — Subdomain Takeover
// ═══════════════════════════════════════════════════════════════════════════════

// Known takeover fingerprints
const TAKEOVER_FINGERPRINTS = [
  { service: 'GitHub Pages',    fingerprint: "There isn't a GitHub Pages site here", cname: ['github.io'] },
  { service: 'Heroku',          fingerprint: 'No such app', cname: ['herokuapp.com', 'herokussl.com'] },
  { service: 'Netlify',         fingerprint: "Not Found - Request ID", cname: ['netlify.app', 'netlify.com'] },
  { service: 'Vercel',          fingerprint: 'The deployment could not be found', cname: ['vercel.app', 'now.sh'] },
  { service: 'AWS S3',          fingerprint: 'NoSuchBucket', cname: ['s3.amazonaws.com', 's3-website'] },
  { service: 'Fastly',          fingerprint: 'Fastly error: unknown domain', cname: ['fastly.net'] },
  { service: 'Ghost',           fingerprint: 'Ghost blog not found', cname: ['ghost.io'] },
  { service: 'Surge.sh',        fingerprint: "project not found", cname: ['surge.sh'] },
  { service: 'Tumblr',          fingerprint: "Whatever you were looking for doesn't live here", cname: ['tumblr.com'] },
  { service: 'Wordpress',       fingerprint: 'Do you want to register', cname: ['wordpress.com'] },
  { service: 'Zendesk',         fingerprint: "Help Center Closed", cname: ['zendesk.com'] },
  { service: 'Shopify',         fingerprint: "Sorry, this shop is currently unavailable", cname: ['myshopify.com'] },
  { service: 'Azure',           fingerprint: '404 Web Site not found', cname: ['azurewebsites.net', 'cloudapp.net'] },
  { service: 'Pantheon',        fingerprint: '404 error unknown site', cname: ['pantheonsite.io'] },
  { service: 'Readme.io',       fingerprint: 'Project doesnt exist', cname: ['readme.io'] },
  { service: 'Statuspage',      fingerprint: 'You are being redirected', cname: ['statuspage.io'] },
  { service: 'UserVoice',       fingerprint: 'This UserVoice subdomain is currently available', cname: ['uservoice.com'] },
  { service: 'Intercom',        fingerprint: 'This page is reserved', cname: ['custom.intercom.help'] },
];

async function runSubdomainTakeover(target, onFinding) {
  const dnsFile = path.join(WORKSPACE_DIR, target, 'dns', 'records.json');
  if (!fs.existsSync(dnsFile)) return [];

  const dnsRecords = readJSON(dnsFile) || {};
  const findings   = [];

  console.log(`[intelligence] takeover: checking ${Object.keys(dnsRecords).length} subdomains`);

  const candidates = [];
  for (const [host, rec] of Object.entries(dnsRecords)) {
    const cnames = rec.cname || [];
    for (const cname of cnames) {
      const lowCNAME = cname.toLowerCase();
      for (const fp of TAKEOVER_FINGERPRINTS) {
        if (fp.cname.some(c => lowCNAME.includes(c))) {
          candidates.push({ host, cname, fp });
        }
      }
    }
  }

  console.log(`[intelligence] takeover: ${candidates.length} candidates to probe`);

  const tasks = candidates.map(({ host, cname, fp }) => async () => {
    // Probe the subdomain for takeover fingerprint
    const res = await httpGET(`https://${host}/`, {}, 8000);
    const body = res.data || '';
    if (res.ok && body.toLowerCase().includes(fp.fingerprint.toLowerCase())) {
      const f = finding(
        SEV.CRITICAL, 'subdomain_takeover',
        `Subdomain takeover — ${host} → ${fp.service}`,
        `CNAME: ${cname}\nFingerprint: "${fp.fingerprint}"\nService: ${fp.service}`,
        `https://${host}`, 'dns',
        `Claim the ${fp.service} resource or remove the CNAME record`
      );
      findings.push(f);
      onFinding(f);
      console.log(`[intelligence] TAKEOVER: ${host} → ${fp.service}`);
    }
  });

  await runConcurrent(tasks, 5);
  console.log(`[intelligence] takeover: ${findings.length} confirmed`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

async function runIntelligence(target, options = {}) {
  const {
    jsAnalysis       = true,
    headerAnalysis   = true,
    portIntelligence = true,
    confidentialIntel = true,
    subdomainTakeover = true,
  } = options;

  const p = getPaths(target);
  fs.mkdirSync(p.base, { recursive: true });

  const allFindings = [];

  const onFinding = (f) => {
    allFindings.push(f);
    fs.writeFileSync(p.findings, JSON.stringify(allFindings, null, 2));
    writeStatus(p.status, {
      status:   'running',
      total:    allFindings.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high:     allFindings.filter(f => f.severity === 'high').length,
      medium:   allFindings.filter(f => f.severity === 'medium').length,
      low:      allFindings.filter(f => f.severity === 'low').length,
      info:     allFindings.filter(f => f.severity === 'info').length,
    });
  };

  writeStatus(p.status, { status: 'running', total: 0, startedAt: new Date().toISOString() });
  console.log('[intelligence] starting for', target);

  if (jsAnalysis)        await runJSAnalysis(target, onFinding);
  if (headerAnalysis)    await runHeaderAnalysis(target, onFinding);
  if (portIntelligence)  await runPortIntelligence(target, onFinding);
  if (confidentialIntel) await runConfidentialIntel(target, onFinding);
  if (subdomainTakeover) await runSubdomainTakeover(target, onFinding);

  const finalStatus = {
    status:      'done',
    total:       allFindings.length,
    critical:    allFindings.filter(f => f.severity === 'critical').length,
    high:        allFindings.filter(f => f.severity === 'high').length,
    medium:      allFindings.filter(f => f.severity === 'medium').length,
    low:         allFindings.filter(f => f.severity === 'low').length,
    info:        allFindings.filter(f => f.severity === 'info').length,
    completedAt: new Date().toISOString(),
  };

  console.log(`[intelligence] done — ${allFindings.length} total findings`);
  writeStatus(p.status, finalStatus);
  return { success: true, ...finalStatus };
}

function getIntelligenceStatus(target) {
  const p      = getPaths(target);
  const status = readJSON(p.status) || { status: 'not_started' };
  const findings = fs.existsSync(p.findings)
    ? (readJSON(p.findings) || [])
    : [];
  return { ...status, findings };
}

module.exports = { runIntelligence, getIntelligenceStatus };
