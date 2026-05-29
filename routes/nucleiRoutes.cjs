// backend/routes/nucleiRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runNuclei, getNucleiStatus } = require('../phases/nuclei.cjs');

const activeRuns = new Set();

// POST /api/nuclei/:target
// Body (all optional):
// {
//   severity:    ['critical','high','medium','low','info'],
//   tags:        ['cve','misconfig','exposure'],
//   excludeTags: ['dos','fuzz'],
//   templates:   ['/path/to/custom-template.yaml'],
//   rateLimit:   150,
//   concurrency: 25,
//   timeout:     10,
//   retries:     1
// }
router.post('/:target', async (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'Nuclei scan already running for this target' });
  }

  const options = {
    severity:    req.body.severity    || ['critical', 'high', 'medium', 'low', 'info'],
    tags:        req.body.tags        || [],
    excludeTags: req.body.excludeTags || [],
    templates:   req.body.templates   || [],
    rateLimit:   req.body.rateLimit   || 150,
    concurrency: req.body.concurrency || 25,
    timeout:     req.body.timeout     || 10,
    retries:     req.body.retries     || 1,
  };

  res.json({ message: 'Nuclei scan started', target, options });

  activeRuns.add(target);
  try {
    await runNuclei(target, options);
  } catch (err) {
    console.error('[nucleiRoutes] error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/nuclei/:target
// Returns status + all findings
router.get('/:target', (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }
  try {
    res.json(getNucleiStatus(target));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
