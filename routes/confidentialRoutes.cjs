// backend/routes/confidentialRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runConfidential, getConfidentialStatus } = require('../phases/confidential.cjs');

const activeRuns = new Set();

// POST /api/confidential/:target
// Body: { passive, active, gitCheck, googleKey, googleCX, bingKey, shodanKey }
router.post('/:target', async (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'Scan already running for this target' });
  }

  const options = {
    passive:   req.body.passive   !== false,
    active:    req.body.active    !== false,
    gitCheck:  req.body.gitCheck  !== false,
    googleKey: req.body.googleKey || null,
    googleCX:  req.body.googleCX  || null,
    bingKey:   req.body.bingKey   || null,
    shodanKey: req.body.shodanKey || null,
  };

  res.json({ message: 'Confidential surface scan started', target, options });

  activeRuns.add(target);
  try {
    await runConfidential(target, options);
  } catch (err) {
    console.error('[confidentialRoutes] error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/confidential/:target
router.get('/:target', (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  try {
    res.json(getConfidentialStatus(target));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
