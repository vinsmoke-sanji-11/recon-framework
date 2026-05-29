// backend/routes/intelligenceRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runIntelligence, getIntelligenceStatus } = require('../phases/intelligence.cjs');

const activeRuns = new Set();

// POST /api/intelligence/:target
router.post('/:target', async (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target' });
  }
  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'Intelligence scan already running' });
  }

  const options = {
    jsAnalysis:        req.body.jsAnalysis        !== false,
    paramAnalysis:     req.body.paramAnalysis      !== false,
    headerAnalysis:    req.body.headerAnalysis     !== false,
    portIntelligence:  req.body.portIntelligence   !== false,
    confidentialIntel: req.body.confidentialIntel  !== false,
    subdomainTakeover: req.body.subdomainTakeover  !== false,
    s3Discovery:       req.body.s3Discovery        !== false,
    s3Concurrency:     parseInt(req.body.s3Concurrency)   || 15,
    s3MaxCandidates:   parseInt(req.body.s3MaxCandidates) || 3000,
  };

  res.json({ message: 'Intelligence scan started', target, options });

  activeRuns.add(target);
  try {
    await runIntelligence(target, options);
  } catch (err) {
    console.error('[intelligenceRoutes] error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/intelligence/:target
router.get('/:target', (req, res) => {
  const { target } = req.params;
  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target' });
  }
  try {
    res.json(getIntelligenceStatus(target));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
