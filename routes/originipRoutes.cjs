// backend/routes/originipRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runOriginIPDetection, getOriginIPStatus } = require('../phases/originip.cjs');

const activeRuns = new Set();

// POST /api/originip/:target
router.post('/:target', async (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'Origin IP detection already running' });
  }
  res.json({ message: 'Origin IP detection started', target });
  activeRuns.add(target);
  try {
    await runOriginIPDetection(target);
  } catch (err) {
    console.error('[originipRoutes] error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/originip/:target
router.get('/:target', (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  try {
    res.json(getOriginIPStatus(target));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
