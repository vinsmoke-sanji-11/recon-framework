// backend/routes/urlsRoutes.cjs

'use strict';

const express = require('express');
const router  = express.Router();
const { runURLDiscovery, getURLsStatus } = require('../phases/urls.cjs');

const activeRuns = new Set();

// POST /api/urls/:target
router.post('/:target', async (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  if (activeRuns.has(target)) {
    return res.status(409).json({ error: 'URL discovery already running for this target' });
  }

  res.json({ message: 'URL discovery started', target });

  activeRuns.add(target);
  try {
    await runURLDiscovery(target);
  } catch (err) {
    console.error('[urlsRoutes] unexpected error:', err.message);
  } finally {
    activeRuns.delete(target);
  }
});

// GET /api/urls/:target
router.get('/:target', (req, res) => {
  const { target } = req.params;

  if (!target || !/^[\w.\-]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target name' });
  }

  try {
    const data   = getURLsStatus(target);
    const page   = parseInt(req.query.page   || '0');
    const limit  = parseInt(req.query.limit  || '200');
    const filter = (req.query.filter || '').toLowerCase();

    let urls = data.urls || [];
    if (filter) urls = urls.filter(u => u.toLowerCase().includes(filter));
    const total     = urls.length;
    const paginated = urls.slice(page * limit, (page + 1) * limit);

    res.json({ ...data, urls: paginated, totalFiltered: total, page, limit });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
