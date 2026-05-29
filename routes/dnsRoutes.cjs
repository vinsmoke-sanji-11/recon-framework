// backend/routes/dnsRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runDNSResolution, getDNSStatus } = require('../phases/dns.cjs');

const activeRuns = new Set();

// POST /api/dns/:target — trigger Phase 2
router.post('/:target', async (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'DNS resolution already running for this target' });
  }

  res.json({ message: 'DNS resolution started', target });

  activeRuns.add(target);
  try {
    await runDNSResolution(target);
  } catch (err) {
    console.error('[dnsRoutes] unexpected error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/dns/:target — get status + results
router.get('/:target', (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  try {
    res.json(getDNSStatus(target));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
