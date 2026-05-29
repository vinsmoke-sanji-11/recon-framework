// backend/routes/liveRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runLiveDetection, getLiveStatus } = require('../phases/live.cjs');

// Track active runs in memory — resets on server restart
const activeRuns = new Set();

// POST /api/live/:target — trigger Phase 2
router.post('/:target', async (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'Live detection already running for this target' });
  }

  // Respond immediately so the frontend doesn't wait
  res.json({ message: 'Live host detection started', target });

  activeRuns.add(target);
  try {
    await runLiveDetection(target);
  } catch (err) {
    console.error('[liveRoutes] unexpected error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/live/:target — get current status + results
router.get('/:target', (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  try {
    const data = getLiveStatus(target);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
