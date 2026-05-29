// backend/phases/originip.cjs
// Phase 8 — Origin IP Detection
// Detects real server IPs behind CDN/proxy (Cloudflare, Akamai, Fastly, etc.)

'use strict';
const _cfg = require('../config.cjs');

const https   = require('https');
const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const dns     = require('dns').promises;
const { URL } = require('url');

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');

// ─── Known CDN/proxy IP ranges ───────────────────────────────────────────────
// These are the major CDN CIDR blocks. IPs in these ranges = behind CDN.

const CDN_RANGES = {
  cloudflare: [
    '103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
    '104.16.0.0/13','104.24.0.0/14','108.162.192.0/18',
    '131.0.72.0/22','141.101.64.0/18','162.158.0.0/15',
    '172.64.0.0/13','173.245.48.0/20','188.114.96.0/20',
    '190.93.240.0/20','197.234.240.0/22','198.41.128.0/17',
    '2400:cb00::/32','2606:4700::/32','2803:f800::/32',
    '2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32',
  ],
  akamai: [
    '23.32.0.0/11','23.64.0.0/14','23.192.0.0/11',
    '104.64.0.0/10','184.24.0.0/13','184.50.0.0/15',
    '2.16.0.0/13','2.22.0.0/15','2.23.0.0/16',
  ],
  fastly: [
    '23.235.32.0/20','43.249.72.0/22','103.244.50.0/24',
    '103.245.222.0/23','103.245.224.0/24','104.156.80.0/20',
    '151.101.0.0/16','157.52.64.0/18','167.82.0.0/17',
    '167.82.128.0/20','172.111.64.0/18','185.31.16.0/22',
    '199.27.72.0/21','199.232.0.0/16',
  ],
  sucuri: [
    '185.93.228.0/22','192.88.134.0/23','192.88.136.0/21',
    '66.248.200.0/22','208.109.0.0/22',
  ],
  incapsula: [
    '149.126.72.0/21','185.11.124.0/22','192.230.64.0/18',
    '45.64.64.0/22',
  ],
};

// ─── IP math helpers ──────────────────────────────────────────────────────────

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return null;
  return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

function cidrContains(cidr, ip) {
  if (cidr.includes(':')) return false; // skip IPv6 for now
  const [range, bits] = cidr.split('/');
  const mask   = ~((1 << (32 - parseInt(bits))) - 1);
  const rangeInt = ipToInt(range);
  const ipInt    = ipToInt(ip);
  if (rangeInt === null || ipInt === null) return false;
  return (rangeInt & mask) === (ipInt & mask);
}

function detectCDN(ip) {
  for (const [cdn, ranges] of Object.entries(CDN_RANGES)) {
    for (const cidr of ranges) {
      if (cidrContains(cidr, ip)) return cdn;
    }
  }
  return null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getOriginPaths(target) {
  const base = path.join(WORKSPACE_DIR, target, 'originip');
  return {
    base,
    status:  path.join(base, 'status.json'),
    results: path.join(base, 'results.json'),
  };
}

function writeStatus(f, d) { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }
function readStatus(f) {
  if (!fs.existsSync(f)) return null;
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; }
}

function getDNSRecords(target) {
  const dnsFile = path.join(WORKSPACE_DIR, target, 'dns', 'records.json');
  if (!fs.existsSync(dnsFile)) return {};
  try { return JSON.parse(fs.readFileSync(dnsFile, 'utf8')); } catch { return {}; }
}

function getLiveHosts(target) {
  const f = path.join(WORKSPACE_DIR, target, 'live', 'hosts.txt');
  if (!fs.existsSync(f)) return [];
  return fs.readFileSync(f, 'utf8').split('\n').filter(Boolean);
}

// HTTP GET helper
function httpGET(url, headers = {}, timeoutMs = 10000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const mod    = parsed.protocol === 'https:' ? https : http;
      const req    = mod.get({
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        timeout:  timeoutMs,
        headers:  { 'User-Agent': 'Mozilla/5.0', ...headers },
      }, (res) => {
        let raw = '';
        res.on('data', d => { raw += d; });
        res.on('end', () => resolve({ ok: true, status: res.statusCode, data: raw }));
      });
      req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
      req.on('error',   () => resolve({ ok: false }));
    } catch { resolve({ ok: false }); }
  });
}

// Fetch Cloudflare IP ranges fresh from their API
async function fetchCloudflareRanges() {
  const res = await httpGET('https://api.cloudflare.com/client/v4/ips');
  if (!res.ok) return null;
  try {
    const data = JSON.parse(res.data);
    if (data.result?.ipv4_cidrs) return data.result.ipv4_cidrs;
  } catch {}
  return null;
}

// ─── Origin discovery techniques ──────────────────────────────────────────────

// 1. Historical DNS — check SecurityTrails-like sources via cert history
async function checkCertHistory(domain) {
  const ips = [];
  // crt.sh sometimes exposes old IPs via SAN records - use as metadata only
  // We use Shodan internetdb (free, no key) for historical IPs
  const res = await httpGET(`https://internetdb.shodan.io/${domain}`);
  if (res.ok && res.data) {
    try {
      const data = JSON.parse(res.data);
      if (data.ip) ips.push(data.ip);
    } catch {}
  }
  return ips;
}

// 2. DNS A record lookup (already have from dns phase, but re-resolve for freshness)
async function resolveHost(hostname) {
  try {
    const result = await dns.resolve4(hostname);
    return result;
  } catch { return []; }
}

// 3. Probe IP directly with Host header — check if it responds like the real server
async function probeDirectIP(ip, hostname, scheme = 'https') {
  const url = `${scheme}://${ip}/`;
  const res = await httpGET(url, {
    'Host': hostname,
    'User-Agent': 'Mozilla/5.0',
  }, 8000);
  return res;
}

// 4. Check MX records — mail servers often reveal origin IPs
async function getMXIPs(domain) {
  const results = [];
  try {
    const mx = await dns.resolveMx(domain);
    for (const record of mx) {
      const ips = await resolveHost(record.exchange);
      for (const ip of ips) {
        results.push({ hostname: record.exchange, ip, source: 'mx' });
      }
    }
  } catch {}
  return results;
}

// 5. Check subdomains not behind CDN (direct IP subdomains)
async function findDirectSubdomains(target) {
  const dnsRecords = getDNSRecords(target);
  const direct = [];
  for (const [host, rec] of Object.entries(dnsRecords)) {
    for (const ip of (rec.a || [])) {
      const cdn = detectCDN(ip);
      if (!cdn) {
        direct.push({ host, ip, cdn: null });
      }
    }
  }
  return direct;
}

// 6. TLS certificate — check if cert SAN contains other hostnames
async function checkTLSCert(hostname) {
  return new Promise((resolve) => {
    const opts = {
      host:               hostname,
      port:               443,
      servername:         hostname,
      rejectUnauthorized: false,
      timeout:            8000,
    };
    const socket = require('tls').connect(opts, () => {
      try {
        const cert = socket.getPeerCertificate();
        const sans = cert?.subjectaltname?.split(', ')
          .filter(s => s.startsWith('DNS:'))
          .map(s => s.replace('DNS:', '')) || [];
        socket.destroy();
        resolve({ cn: cert?.subject?.CN, sans });
      } catch {
        socket.destroy();
        resolve({ cn: null, sans: [] });
      }
    });
    socket.on('error', () => resolve({ cn: null, sans: [] }));
    socket.on('timeout', () => { socket.destroy(); resolve({ cn: null, sans: [] }); });
  });
}

// 7. Favicon hash — check if same favicon appears on a direct IP (Shodan-style)
async function getFaviconHash(url) {
  const res = await httpGET(`${url}/favicon.ico`, {}, 6000);
  if (!res.ok || !res.data) return null;
  // Simple length-based fingerprint (not full murmurhash, but useful for comparison)
  return res.data.length;
}

// ─── Main Phase Runner ────────────────────────────────────────────────────────

async function runOriginIPDetection(target) {
  const p = getOriginPaths(target);
  fs.mkdirSync(p.base, { recursive: true });

  writeStatus(p.status, { status: 'running', startedAt: new Date().toISOString() });
  console.log('[originip] starting for', target);

  // Try to get fresh Cloudflare ranges
  console.log('[originip] fetching fresh Cloudflare IP ranges');
  const freshCF = await fetchCloudflareRanges();
  if (freshCF) {
    CDN_RANGES.cloudflare = freshCF;
    console.log('[originip] updated Cloudflare ranges:', freshCF.length, 'CIDRs');
  }

  const dnsRecords    = getDNSRecords(target);
  const liveHosts     = getLiveHosts(target);
  const allResults    = [];

  // ── Step 1: Classify all known IPs from DNS phase ─────────────────────────
  console.log('[originip] classifying DNS IPs');
  const ipMap = {}; // ip -> { hosts: [], cdn }

  for (const [host, rec] of Object.entries(dnsRecords)) {
    for (const ip of (rec.a || [])) {
      if (!ipMap[ip]) ipMap[ip] = { hosts: [], cdn: detectCDN(ip) };
      if (!ipMap[ip].hosts.includes(host)) ipMap[ip].hosts.push(host);
    }
  }

  for (const [ip, info] of Object.entries(ipMap)) {
    allResults.push({
      type:       'dns_ip',
      ip,
      hosts:      info.hosts,
      cdn:        info.cdn,
      behind_cdn: !!info.cdn,
      source:     'dns_records',
      confidence: 'high',
    });
  }

  // ── Step 2: Find subdomains NOT behind CDN ────────────────────────────────
  console.log('[originip] finding direct subdomains');
  const directSubs = await findDirectSubdomains(target);
  for (const d of directSubs) {
    console.log(`[originip] direct subdomain: ${d.host} → ${d.ip}`);
    allResults.push({
      type:       'direct_subdomain',
      ip:         d.ip,
      hosts:      [d.host],
      cdn:        null,
      behind_cdn: false,
      source:     'subdomain_scan',
      confidence: 'high',
      note:       'Subdomain not behind CDN — may be origin server',
    });
  }

  // ── Step 3: MX record IPs ─────────────────────────────────────────────────
  console.log('[originip] checking MX records');
  const mxIPs = await getMXIPs(target);
  for (const m of mxIPs) {
    const cdn = detectCDN(m.ip);
    if (!cdn) {
      console.log(`[originip] MX origin: ${m.hostname} → ${m.ip}`);
      allResults.push({
        type:       'mx_record',
        ip:         m.ip,
        hosts:      [m.hostname],
        cdn:        null,
        behind_cdn: false,
        source:     'mx_record',
        confidence: 'medium',
        note:       'Mail server IP — often same hosting as web server',
      });
    }
  }

  // ── Step 4: Historical IPs via Shodan internetdb (free) ───────────────────
  console.log('[originip] checking historical IPs (Shodan internetdb)');
  for (const host of liveHosts.slice(0, 20)) { // limit to avoid rate limits
    const ips = await checkCertHistory(host);
    for (const ip of ips) {
      const cdn = detectCDN(ip);
      if (!cdn) {
        console.log(`[originip] historical origin: ${host} → ${ip}`);
        allResults.push({
          type:       'historical_ip',
          ip,
          hosts:      [host],
          cdn:        null,
          behind_cdn: false,
          source:     'shodan_internetdb',
          confidence: 'medium',
          note:       'Historical IP — may be old origin before CDN migration',
        });
      }
    }
  }

  // ── Step 5: TLS cert SAN check on CDN-protected hosts ────────────────────
  console.log('[originip] checking TLS certificates');
  const cdnHosts = allResults
    .filter(r => r.behind_cdn)
    .flatMap(r => r.hosts)
    .filter((h, i, arr) => arr.indexOf(h) === i)
    .slice(0, 15);

  for (const host of cdnHosts) {
    const cert = await checkTLSCert(host);
    if (cert.sans.length > 0) {
      // Look for SANs that reveal internal hostnames
      const interesting = cert.sans.filter(s =>
        !s.startsWith('*.') &&
        !s.endsWith(target) &&
        s !== host
      );
      if (interesting.length > 0) {
        allResults.push({
          type:       'tls_san',
          ip:         null,
          hosts:      [host],
          cdn:        null,
          behind_cdn: false,
          source:     'tls_certificate',
          confidence: 'low',
          note:       `TLS cert reveals: ${interesting.join(', ')}`,
          sans:       cert.sans,
        });
      }
    }
  }

  // ── Step 6: Direct IP probe — try to connect to non-CDN IPs directly ──────
  console.log('[originip] probing direct IPs');
  const potentialOrigins = allResults.filter(r => !r.behind_cdn && r.ip);
  for (const result of potentialOrigins.slice(0, 20)) {
    const host    = result.hosts[0];
    const ip      = result.ip;
    if (!host || !ip) continue;

    const probeHTTPS = await probeDirectIP(ip, host, 'https');
    const probeHTTP  = probeHTTPS.ok ? null : await probeDirectIP(ip, host, 'http');
    const probe      = probeHTTPS.ok ? probeHTTPS : probeHTTP;

    if (probe?.ok) {
      result.direct_access  = true;
      result.direct_status  = probe.status;
      result.confidence     = 'high';
      console.log(`[originip] confirmed direct access: ${ip} (${host}) → ${probe.status}`);
    } else {
      result.direct_access = false;
    }
  }

  // Deduplicate IPs
  const seen    = new Set();
  const deduped = allResults.filter(r => {
    const key = `${r.type}-${r.ip}-${r.hosts?.[0]}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const summary = {
    totalIPs:      deduped.filter(r => r.ip).length,
    behindCDN:     deduped.filter(r => r.behind_cdn).length,
    directExposed: deduped.filter(r => !r.behind_cdn && r.ip).length,
    confirmed:     deduped.filter(r => r.direct_access).length,
    cdnBreakdown:  {},
  };

  // CDN breakdown
  for (const r of deduped.filter(r => r.cdn)) {
    summary.cdnBreakdown[r.cdn] = (summary.cdnBreakdown[r.cdn] || 0) + 1;
  }

  fs.writeFileSync(p.results, JSON.stringify(deduped, null, 2));

  const finalStatus = {
    status: 'done',
    ...summary,
    completedAt: new Date().toISOString(),
  };

  console.log(`[originip] done — ${summary.totalIPs} IPs, ${summary.directExposed} direct, ${summary.confirmed} confirmed`);
  writeStatus(p.status, finalStatus);
  return { success: true, ...finalStatus };
}

// ─── Status reader ────────────────────────────────────────────────────────────

function getOriginIPStatus(target) {
  const p      = getOriginPaths(target);
  const status = readStatus(p.status) || { status: 'not_started' };

  let results = [];
  if (fs.existsSync(p.results)) {
    try { results = JSON.parse(fs.readFileSync(p.results, 'utf8')); } catch {}
  }

  return { ...status, results };
}

module.exports = { runOriginIPDetection, getOriginIPStatus, getOriginPaths };
