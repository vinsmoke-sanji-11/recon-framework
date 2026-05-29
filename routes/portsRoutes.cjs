// backend/routes/portsRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runPortScan, getPortsStatus } = require('../phases/ports.cjs');

const activeRuns = new Set();

// POST /api/ports/:target
router.post('/:target', async (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'Port scan already running for this target' });
  }

  res.json({ message: 'Port scan started', target });

  activeRuns.add(target);
  try {
    await runPortScan(target);
  } catch (err) {
    console.error('[portsRoutes] unexpected error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/ports/:target
router.get('/:target', (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  try {
    res.json(getPortsStatus(target));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
