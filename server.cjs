// server.cjs — RECON Framework Backend
'use strict';

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const runSubdomainPhase = require('./phases/subdomain.cjs');

const app = express();
app.use(cors());
app.use(express.json());

const WORKSPACE = path.join(__dirname, 'workspace');
if (!fs.existsSync(WORKSPACE)) fs.mkdirSync(WORKSPACE);

// ── Targets ───────────────────────────────────────────────────────────────────
app.post('/api/scan', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target required' });
  const targetPath = path.join(WORKSPACE, target);
  const statusFile = path.join(targetPath, 'status.json');
  if (fs.existsSync(statusFile)) {
    const s = JSON.parse(fs.readFileSync(statusFile));
    if (s.status === 'running') return res.json({ message: 'Scan already running' });
  }
  if (!fs.existsSync(targetPath)) fs.mkdirSync(targetPath, { recursive: true });
  fs.writeFileSync(statusFile, JSON.stringify({ status: 'running' }, null, 2));
  runSubdomainPhase(target, targetPath)
    .then(() => fs.writeFileSync(statusFile, JSON.stringify({ status: 'completed' }, null, 2)))
    .catch((err) => { console.error(err); fs.writeFileSync(statusFile, JSON.stringify({ status: 'failed' }, null, 2)); });
  res.json({ message: 'Scan started' });
});

app.get('/api/status/:target', (req, res) => {
  const file = path.join(WORKSPACE, req.params.target, 'status.json');
  if (!fs.existsSync(file)) return res.json({ status: 'not_started' });
  res.json(JSON.parse(fs.readFileSync(file)));
});

app.get('/api/targets', (req, res) => {
  if (!fs.existsSync(WORKSPACE)) return res.json([]);
  const targets = fs.readdirSync(WORKSPACE).filter(f => fs.statSync(path.join(WORKSPACE, f)).isDirectory());
  res.json(targets);
});

// ── Subdomains ────────────────────────────────────────────────────────────────
app.get('/api/subdomains/:target', (req, res) => {
  const targetPath = path.join(WORKSPACE, req.params.target, 'subdomain');
  const filtered   = path.join(targetPath, 'filtered.txt');
  const merged     = path.join(targetPath, 'merged.txt');
  const file = fs.existsSync(filtered) ? filtered : merged;
  if (!fs.existsSync(file)) return res.json([]);
  const rows = fs.readFileSync(file, 'utf-8').split('\n').filter(Boolean).map((s, i) => ({ id: i + 1, subdomain: s }));
  res.json(rows);
});

app.get('/api/subdomains/:target/oos', (req, res) => {
  const file = path.join(WORKSPACE, req.params.target, 'subdomain', 'oos.txt');
  if (!fs.existsSync(file)) return res.json({ oos: [] });
  res.json({ oos: fs.readFileSync(file, 'utf-8').split('\n').filter(Boolean) });
});

app.post('/api/subdomains/:target/oos', (req, res) => {
  const { oos } = req.body;
  if (!Array.isArray(oos)) return res.status(400).json({ error: 'oos must be an array' });
  const targetPath  = path.join(WORKSPACE, req.params.target, 'subdomain');
  const mergedFile  = path.join(targetPath, 'merged.txt');
  if (!fs.existsSync(mergedFile)) return res.status(404).json({ error: 'No subdomains found' });
  fs.writeFileSync(path.join(targetPath, 'oos.txt'), oos.join('\n'));
  const allSubs  = fs.readFileSync(mergedFile, 'utf-8').split('\n').filter(Boolean);
  const oosLower = oos.map(o => o.trim().toLowerCase()).filter(Boolean);
  const kept     = allSubs.filter(s => { const sl = s.trim().toLowerCase(); return !oosLower.some(o => sl === o || sl.endsWith('.' + o) || sl === o.replace(/^\*\./, '')); });
  fs.writeFileSync(path.join(targetPath, 'filtered.txt'), kept.join('\n'));
  res.json({ total: allSubs.length, filtered: kept.length, removed: allSubs.length - kept.length, rows: kept.map((s, i) => ({ id: i + 1, subdomain: s })) });
});

// ── All phase routes ──────────────────────────────────────────────────────────
app.use('/api/live',          require('./routes/liveRoutes.cjs'));
app.use('/api/dns',           require('./routes/dnsRoutes.cjs'));
app.use('/api/ports',         require('./routes/portsRoutes.cjs'));
app.use('/api/urls',          require('./routes/urlsRoutes.cjs'));
app.use('/api/screenshots',   require('./routes/screenshotsRoutes.cjs'));
app.use('/api/confidential',  require('./routes/confidentialRoutes.cjs'));
app.use('/api/originip',      require('./routes/originipRoutes.cjs'));
app.use('/api/bypass403',     require('./routes/bypass403Routes.cjs'));
app.use('/api/intelligence',  require('./routes/intelligenceRoutes.cjs'));
app.use('/api/nuclei',        require('./routes/nucleiRoutes.cjs'));

app.listen(8000, () => console.log('[RECON] Backend running → http://localhost:8000'));
