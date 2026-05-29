// backend/phases/confidential.cjs
// Phase 7 — Confidential Surface Discovery
// Module 1: Passive + Active + Git exposure
// Module 2: Search engine dorking (Google/Bing/Shodan — all optional)

'use strict';
const _cfg = require('../config.cjs');

const { spawn }   = require('child_process');
const https       = require('https');
const http        = require('http');
const fs          = require('fs');
const path        = require('path');
const { URL }     = require('url');

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');
const FFUF_BIN      = _cfg.BINS.ffuf;

// ─── Risk config ─────────────────────────────────────────────────────────────

const PASSIVE_EXTENSIONS = [
  'sql','zip','tar','gz','bak','old','log','key','pem',
  'pfx','env','json','yml','yaml','conf','config','xml',
  'csv','xls','xlsx','doc','docx','pdf','db','sqlite',
];

const ACTIVE_WORDLIST = [
  '.env', '.env.local', '.env.backup', '.env.old', '.env.bak',
  'config.php', 'config.php.bak', 'config.php.old',
  'configuration.php', 'settings.php', 'database.php',
  'wp-config.php', 'wp-config.php.bak',
  'backup.sql', 'backup.zip', 'backup.tar.gz', 'backup.old',
  'database.sql', 'database.zip', 'db.sql', 'dump.sql',
  'backup/', 'backups/', 'backup.tar', 'site.tar.gz',
  '.git/config', '.git/HEAD', '.git/index',
  '.svn/entries', '.htaccess', '.htpasswd',
  'admin/', 'admin/config.php',
  'phpinfo.php', 'info.php', 'test.php',
  'robots.txt', 'sitemap.xml',
  'id_rsa', 'id_rsa.pub', 'private.key', 'server.key',
  'credentials.json', 'secrets.json', 'config.json',
  'docker-compose.yml', 'docker-compose.yaml',
  'Dockerfile', '.dockerenv',
  'package.json', 'composer.json', 'requirements.txt',
  'web.config', 'applicationHost.config',
  'app.config', 'appsettings.json',
  'log.txt', 'error.log', 'access.log', 'debug.log',
  'error_log', 'php_error.log',
  'readme.txt', 'README.md', 'CHANGELOG.md', 'INSTALL.md',
  '1.zip', '1.sql', '1.tar.gz',
  'old/', 'temp/', 'tmp/', 'bak/',
  'data.csv', 'export.csv', 'users.csv', 'emails.csv',
  'passwords.txt', 'creds.txt', 'accounts.txt',
];

// Add suffix variations to each wordlist entry
function expandWordlist(words) {
  const suffixes = ['.bak', '.old', '~', '.backup', '.tmp', '.1', '.orig'];
  const expanded = new Set(words);
  for (const w of words) {
    if (!w.endsWith('/')) {
      for (const s of suffixes) {
        expanded.add(w + s);
      }
    }
  }
  return [...expanded];
}

const DORK_EXTENSIONS = [
  'pdf','doc','docx','xls','xlsx','csv','sql',
  'zip','tar','gz','env','bak','log','conf','json','yml',
];

const DORK_KEYWORDS = [
  'confidential', 'internal use only', 'restricted',
  'password', 'credentials', 'secret', 'api key',
  'database dump', 'backup',
];

const GOOD_STATUS = new Set([200, 401, 403]);

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getConfidentialPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'confidential');
  return {
    base,
    status:    path.join(base, 'status.json'),
    findings:  path.join(base, 'findings.json'),
    dorks:     path.join(base, 'dorks.json'),
    wordlist:  path.join(base, '_wordlist.txt'),
  };
}

function writeStatus(f, d)  { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }
function readStatus(f)      {
  if (!fs.existsSync(f)) return null;
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; }
}

function getURLsMerged(target) {
  return path.join(WORKSPACE_DIR, target, 'urls', 'merged.txt');
}
function getLiveMerged(target) {
  return path.join(WORKSPACE_DIR, target, 'live', 'merged.txt');
}
function getLiveHosts(target) {
  return path.join(WORKSPACE_DIR, target, 'live', 'hosts.txt');
}

// HEAD request with timeout
function headURL(url, timeoutMs = 8000) {
  return new Promise((resolve) => {
    try {
      const parsed  = new URL(url);
      const mod     = parsed.protocol === 'https:' ? https : http;
      const options = {
        method:   'HEAD',
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        timeout:  timeoutMs,
        headers:  { 'User-Agent': 'Mozilla/5.0 (compatible; recon-tool/1.0)' },
      };
      const req = mod.request(options, (res) => {
        resolve({ status: res.statusCode, ok: GOOD_STATUS.has(res.statusCode) });
        res.resume();
      });
      req.on('timeout', () => { req.destroy(); resolve({ status: null, ok: false }); });
      req.on('error',   () => resolve({ status: null, ok: false }));
      req.end();
    } catch {
      resolve({ status: null, ok: false });
    }
  });
}

// ─── Module 1A: Passive ───────────────────────────────────────────────────────

async function runPassive(target, onFinding) {
  const urlFile = getURLsMerged(target);
  if (!fs.existsSync(urlFile)) {
    console.log('[confidential] passive: urls/merged.txt not found, skipping');
    return [];
  }

  const allURLs = fs.readFileSync(urlFile, 'utf8').split('\n').filter(Boolean);
  // Filter by risky extensions
  const risky = allURLs.filter(u => {
    try {
      const ext = new URL(u).pathname.split('.').pop()?.toLowerCase();
      return PASSIVE_EXTENSIONS.includes(ext || '');
    } catch { return false; }
  });

  console.log(`[confidential] passive: ${risky.length} risky URLs to validate`);

  const findings = [];
  // Batch with concurrency 5
  const BATCH = 5;
  for (let i = 0; i < risky.length; i += BATCH) {
    const batch = risky.slice(i, i + BATCH);
    const results = await Promise.all(batch.map(async (url) => {
      const { status, ok } = await headURL(url);
      if (!ok) return null;
      const ext = new URL(url).pathname.split('.').pop()?.toLowerCase() || '';
      return {
        host:          new URL(url).hostname,
        exposure_type: 'sensitive_file',
        file_path:     url,
        status_code:   status,
        extension:     ext,
        source:        'passive',
      };
    }));
    for (const r of results) {
      if (r) { findings.push(r); onFinding(r); }
    }
  }

  console.log(`[confidential] passive: ${findings.length} confirmed findings`);
  return findings;
}

// ─── Module 1B: Git exposure ──────────────────────────────────────────────────
// Uses GET + body verification — HEAD-only was causing soft-404 false positives
// (servers that return 200 for every URL including /.git/config)

// Body signatures that prove it is a real vcs file, not an HTML error page
const GIT_SIGNATURES = {
  '/.git/config':  [/\[core\]/i, /\[remote/i, /repositoryformatversion/i],
  '/.git/HEAD':    [/^ref: refs\/heads\//m, /^[0-9a-f]{40}$/m],
  '/.svn/entries': [/svn:\/\//i, /^10$/m, /^dir$/m],
  '/.hg/hgrc':     [/\[paths\]/i, /\[ui\]/i],
};

function isRealVcsFile(probe, body) {
  if (!body || body.length === 0 || /<html/i.test(body)) return false;
  const sigs = GIT_SIGNATURES[probe];
  return sigs ? sigs.some(re => re.test(body)) : body.length < 20000;
}

// Small GET — reads first 8KB only (enough for any git file)
function getSmall(url, timeoutMs = 8000) {
  return new Promise((resolve) => {
    try {
      const { URL: URLC } = require('url');
      const parsed = new URLC(url);
      const mod = parsed.protocol === 'https:' ? require('https') : require('http');
      const req = mod.get({
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname,
        timeout: timeoutMs,
        rejectUnauthorized: false,
        headers: { 'User-Agent': 'Mozilla/5.0' },
      }, (res) => {
        let body = '';
        res.on('data', d => { body += d; if (body.length > 8192) res.destroy(); });
        res.on('end',  () => resolve({ ok: true, status: res.statusCode, body }));
        res.on('close',() => resolve({ ok: true, status: res.statusCode, body }));
      });
      req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
      req.on('error',   () => resolve({ ok: false }));
    } catch { resolve({ ok: false }); }
  });
}

async function runGitCheck(target, onFinding) {
  const hostsFile = getLiveHosts(target);
  if (!fs.existsSync(hostsFile)) return [];

  const hosts  = fs.readFileSync(hostsFile, 'utf8').split('\n').filter(Boolean);
  const probes = ['/.git/config', '/.git/HEAD', '/.svn/entries', '/.hg/hgrc'];
  const findings = [];

  console.log(`[confidential] git check: ${hosts.length} hosts × ${probes.length} probes`);

  for (const host of hosts) {
    let confirmed = false;
    for (const scheme of ['https', 'http']) {
      if (confirmed) break;
      for (const probe of probes) {
        const url = `${scheme}://${host}${probe}`;
        const res = await getSmall(url);

        if (!res.ok || res.status !== 200) continue;

        // KEY CHECK: verify body actually looks like the git file, not HTML soft-404
        if (!isRealVcsFile(probe, res.body)) {
          console.log(`[confidential] git: ${url} → 200 but body is soft-404 HTML, skipping`);
          continue;
        }

        const f = {
          host,
          exposure_type: 'git_exposure',
          file_path:     url,
          status_code:   200,
          body_preview:  res.body.slice(0, 300),
          source:        'git',
          critical:      true,
        };
        findings.push(f);
        onFinding(f);
        confirmed = true;
        console.log(`[confidential] GIT CONFIRMED: ${url} — body verified`);
        break;
      }
    }
  }

  console.log(`[confidential] git check: ${findings.length} confirmed (body-verified)`);
  return findings;
}

// ─── Module 1C: Active (ffuf) ─────────────────────────────────────────────────

function runFFUF(host, wordlistFile, timeoutMs) {
  return new Promise((resolve) => {
    if (!fs.existsSync(FFUF_BIN)) {
      return resolve({ skipped: true, findings: [] });
    }

    // Try https first — ffuf handles redirects
    const url  = `https://${host}/FUZZ`;
    const args = [
      '-u', url,
      '-w', wordlistFile,
      '-mc', '200,401,403',
      '-t', '30',
      '-timeout', '10',
      '-of', 'json',
      '-o', '/dev/stdin', // output to stdout
      '-s',               // silent
    ];

    const proc    = spawn(FFUF_BIN, args, {
      env: { ...process.env, HOME: _cfg.HOME },
    });
    proc.stdin.end();

    let rawOut   = '';
    let finished = false;

    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        proc.kill('SIGKILL');
        resolve({ timedOut: true, findings: [] });
      }
    }, timeoutMs);

    proc.stdout.on('data', d => { rawOut += d.toString(); });
    proc.stderr.on('data', () => {});

    proc.on('close', () => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        const findings = [];
        try {
          const json = JSON.parse(rawOut);
          for (const r of (json.results || [])) {
            findings.push({
              host,
              exposure_type: 'active_discovery',
              file_path:     r.url || `https://${host}/${r.input?.FUZZ}`,
              status_code:   r.status,
              source:        'active',
            });
          }
        } catch {}
        resolve({ findings });
      }
    });

    proc.on('error', () => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        resolve({ findings: [] });
      }
    });
  });
}

async function runActive(target, wordlistFile, onFinding) {
  const hostsFile = getLiveHosts(target);
  if (!fs.existsSync(hostsFile)) return [];

  const hosts = fs.readFileSync(hostsFile, 'utf8').split('\n').filter(Boolean);
  console.log(`[confidential] active: ffuf on ${hosts.length} hosts`);

  const allFindings = [];
  for (const host of hosts) {
    console.log(`[confidential] active: scanning ${host}`);
    const { findings } = await runFFUF(host, wordlistFile, 120_000);
    for (const f of findings) {
      allFindings.push(f);
      onFinding(f);
    }
  }

  console.log(`[confidential] active: ${allFindings.length} findings`);
  return allFindings;
}

// ─── Module 2: Dork discovery ─────────────────────────────────────────────────

// Generic API GET helper
function apiGET(url, headers, timeoutMs = 15_000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const options = {
        hostname: parsed.hostname,
        path:     parsed.pathname + parsed.search,
        method:   'GET',
        timeout:  timeoutMs,
        headers:  { 'Accept': 'application/json', ...headers },
      };
      const req = https.request(options, (res) => {
        let raw = '';
        res.on('data', d => { raw += d; });
        res.on('end', () => {
          try { resolve({ ok: true, data: JSON.parse(raw) }); }
          catch { resolve({ ok: false, raw }); }
        });
      });
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
      req.on('error', (e) => resolve({ ok: false, error: e.message }));
      req.end();
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
}

// Sleep helper for rate limiting
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Google Custom Search
async function dorkGoogle(domain, apiKey, cx) {
  const results = [];
  const queries = [
    // Extension dorks
    ...DORK_EXTENSIONS.map(ext => `site:${domain} ext:${ext}`),
    // Keyword dorks
    ...DORK_KEYWORDS.map(kw => `site:${domain} "${kw}"`),
  ];

  for (const dork of queries) {
    const url = `https://www.googleapis.com/customsearch/v1?key=${apiKey}&cx=${cx}&q=${encodeURIComponent(dork)}&num=10`;
    const res = await apiGET(url, {});
    if (res.ok && res.data?.items) {
      for (const item of res.data.items) {
        results.push({
          domain,
          dork,
          discovered_url: item.link,
          title:          item.title || '',
          source_engine:  'google',
        });
      }
    }
    await sleep(1000); // rate limit: 1 req/sec
  }
  return results;
}

// Bing Search API
async function dorkBing(domain, apiKey) {
  const results = [];
  const queries = [
    ...DORK_EXTENSIONS.map(ext => `site:${domain} filetype:${ext}`),
    ...DORK_KEYWORDS.map(kw => `site:${domain} "${kw}"`),
  ];

  for (const dork of queries) {
    const url = `https://api.bing.microsoft.com/v7.0/search?q=${encodeURIComponent(dork)}&count=10&mkt=en-US`;
    const res = await apiGET(url, { 'Ocp-Apim-Subscription-Key': apiKey });
    if (res.ok && res.data?.webPages?.value) {
      for (const item of res.data.webPages.value) {
        results.push({
          domain,
          dork,
          discovered_url: item.url,
          title:          item.name || '',
          source_engine:  'bing',
        });
      }
    }
    await sleep(500);
  }
  return results;
}

// Shodan search
async function dorkShodan(domain, apiKey) {
  const results = [];
  const url = `https://api.shodan.io/shodan/host/search?key=${apiKey}&query=hostname:${domain}&facets=port,country`;
  const res = await apiGET(url, {});
  if (res.ok && res.data?.matches) {
    for (const match of res.data.matches) {
      results.push({
        domain,
        dork:           `hostname:${domain}`,
        discovered_url: `${match.ip_str}:${match.port}`,
        title:          (match.org || '') + ' ' + (match.product || ''),
        source_engine:  'shodan',
        extra: {
          ip:       match.ip_str,
          port:     match.port,
          org:      match.org,
          product:  match.product,
          hostnames: match.hostnames,
        },
      });
    }
  }
  return results;
}

// ─── Main Phase Runner ────────────────────────────────────────────────────────

async function runConfidential(target, options = {}) {
  const p = getConfidentialPaths(target);
  fs.mkdirSync(p.base, { recursive: true });

  const {
    passive   = true,
    active    = true,
    gitCheck  = true,
    googleKey = null,
    googleCX  = null,
    bingKey   = null,
    shodanKey = null,
  } = options;

  const allFindings = [];
  const allDorks    = [];

  const saveFindings = () => {
    fs.writeFileSync(p.findings, JSON.stringify(allFindings, null, 2));
  };
  const saveDorks = () => {
    fs.writeFileSync(p.dorks, JSON.stringify(allDorks, null, 2));
  };

  const onFinding = (f) => {
    allFindings.push(f);
    saveFindings();
    writeStatus(p.status, {
      status:   'running',
      findings: allFindings.length,
      dorks:    allDorks.length,
    });
  };

  writeStatus(p.status, { status: 'running', findings: 0, dorks: 0, startedAt: new Date().toISOString() });
  console.log('[confidential] starting for', target);

  // Build + write expanded wordlist
  const wordlist = expandWordlist(ACTIVE_WORDLIST);
  fs.writeFileSync(p.wordlist, wordlist.join('\n') + '\n');

  // ── Git check (fast, run first) ────────────────────────────────────────────
  if (gitCheck) {
    console.log('[confidential] running git exposure check');
    await runGitCheck(target, onFinding);
  }

  // ── Passive ────────────────────────────────────────────────────────────────
  if (passive) {
    console.log('[confidential] running passive mode');
    await runPassive(target, onFinding);
  }

  // ── Active (ffuf) ──────────────────────────────────────────────────────────
  if (active) {
    console.log('[confidential] running active mode (ffuf)');
    await runActive(target, p.wordlist, onFinding);
  }

  // ── Dork discovery ─────────────────────────────────────────────────────────
  const dorkEnabled = googleKey || bingKey || shodanKey;
  if (dorkEnabled) {
    console.log('[confidential] running dork discovery');

    if (googleKey && googleCX) {
      console.log('[confidential] dorking: Google');
      const gRes = await dorkGoogle(target, googleKey, googleCX);
      allDorks.push(...gRes);
      saveDorks();
    }

    if (bingKey) {
      console.log('[confidential] dorking: Bing');
      const bRes = await dorkBing(target, bingKey);
      allDorks.push(...bRes);
      saveDorks();
    }

    if (shodanKey) {
      console.log('[confidential] dorking: Shodan');
      const sRes = await dorkShodan(target, shodanKey);
      allDorks.push(...sRes);
      saveDorks();
    }
  }

  // Clean up temp wordlist
  try { fs.unlinkSync(p.wordlist); } catch {}

  const finalStatus = {
    status:       'done',
    findings:     allFindings.length,
    dorks:        allDorks.length,
    critical:     allFindings.filter(f => f.critical).length,
    bySource: {
      passive: allFindings.filter(f => f.source === 'passive').length,
      active:  allFindings.filter(f => f.source === 'active').length,
      git:     allFindings.filter(f => f.source === 'git').length,
    },
    dorksEnabled:  !!dorkEnabled,
    completedAt:  new Date().toISOString(),
  };

  console.log(`[confidential] done — ${allFindings.length} findings, ${allDorks.length} dorks`);
  writeStatus(p.status, finalStatus);
  return { success: true, ...finalStatus };
}

// ─── Status reader ────────────────────────────────────────────────────────────

function getConfidentialStatus(target) {
  const p      = getConfidentialPaths(target);
  const status = readStatus(p.status) || { status: 'not_started' };

  let findings = [];
  let dorks    = [];

  if (fs.existsSync(p.findings)) {
    try { findings = JSON.parse(fs.readFileSync(p.findings, 'utf8')); } catch {}
  }
  if (fs.existsSync(p.dorks)) {
    try { dorks = JSON.parse(fs.readFileSync(p.dorks, 'utf8')); } catch {}
  }

  return { ...status, findings, dorks };
}

module.exports = { runConfidential, getConfidentialStatus, getConfidentialPaths };
