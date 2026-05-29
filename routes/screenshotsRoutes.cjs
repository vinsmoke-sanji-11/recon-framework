// backend/routes/screenshotsRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const fs      = require('fs');
const path    = require('path');
const { runScreenshots, getScreenshotsStatus, getScreenshotsPaths } = require('../phases/screenshots.cjs');

const WORKSPACE_DIR = path.resolve(__dirname, '../workspace');
const activeRuns    = new Set();

// POST /api/screenshots/:target — trigger
router.post('/:target', async (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'Screenshots already running' });
  }
  res.json({ message: 'Screenshots started', target });
  activeRuns.add(target);
  try {
    await runScreenshots(target);
  } catch (err) {
    console.error('[screenshotsRoutes] error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/screenshots/:target — status + index
router.get('/:target', (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  try {
    res.json(getScreenshotsStatus(target));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/screenshots/:target/img/:filename — serve PNG
router.get('/:target/img/:filename', (req, res) => {
  const { target, filename } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target' });
  }
  // Sanitize filename — no path traversal
  const safe = path.basename(filename);
  const file = path.join(WORKSPACE_DIR, target, 'screenshots', 'imgs', safe);
  if (!fs.existsSync(file)) {
    return res.status(404).json({ error: 'Image not found' });
  }
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  fs.createReadStream(file).pipe(res);
});

module.exports = router;
