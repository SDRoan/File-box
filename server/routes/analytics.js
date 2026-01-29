const express = require('express');
const auth = require('../middleware/auth');
const analytics = require('../services/analytics');
const router = express.Router();

/**
 * Get file access statistics
 */
router.get('/access-stats', auth, async (req, res) => {
  try {
    const { timeRange = '30d' } = req.query;
    const stats = await analytics.getFileAccessStats(req.user._id, timeRange);
    res.json(stats);
  } catch (error) {
    console.error('Error getting access stats:', error);
    res.status(500).json({ message: 'Failed to get access stats', error: error.message });
  }
});

/**
 * Get access heatmap data
 */
router.get('/heatmap', auth, async (req, res) => {
  try {
    const { timeRange = '30d' } = req.query;
    const heatmap = await analytics.getAccessHeatmap(req.user._id, timeRange);
    res.json(heatmap);
  } catch (error) {
    console.error('Error getting heatmap:', error);
    res.status(500).json({ message: 'Failed to get heatmap', error: error.message });
  }
});

/**
 * Get unused files
 */
router.get('/unused-files', auth, async (req, res) => {
  try {
    const { daysUnused = 90 } = req.query;
    const unusedFiles = await analytics.getUnusedFiles(req.user._id, parseInt(daysUnused));
    res.json(unusedFiles);
  } catch (error) {
    console.error('Error getting unused files:', error);
    res.status(500).json({ message: 'Failed to get unused files', error: error.message });
  }
});

/**
 * Get storage breakdown
 */
router.get('/storage-breakdown', auth, async (req, res) => {
  try {
    const breakdown = await analytics.getStorageBreakdown(req.user._id);
    res.json(breakdown);
  } catch (error) {
    console.error('Error getting storage breakdown:', error);
    res.status(500).json({ message: 'Failed to get storage breakdown', error: error.message });
  }
});

/**
 * Get activity timeline
 */
router.get('/timeline', auth, async (req, res) => {
  try {
    const { timeRange = '7d' } = req.query;
    const timeline = await analytics.getActivityTimeline(req.user._id, timeRange);
    res.json(timeline);
  } catch (error) {
    console.error('Error getting timeline:', error);
    res.status(500).json({ message: 'Failed to get timeline', error: error.message });
  }
});

/**
 * Get top file types
 */
router.get('/top-types', auth, async (req, res) => {
  try {
    const { timeRange = '30d' } = req.query;
    const topTypes = await analytics.getTopFileTypes(req.user._id, timeRange);
    res.json(topTypes);
  } catch (error) {
    console.error('Error getting top types:', error);
    res.status(500).json({ message: 'Failed to get top types', error: error.message });
  }
});

/**
 * Get storage optimization suggestions
 */
router.get('/suggestions', auth, async (req, res) => {
  try {
    const suggestions = await analytics.getStorageSuggestions(req.user._id);
    res.json(suggestions);
  } catch (error) {
    console.error('Error getting suggestions:', error);
    res.status(500).json({ message: 'Failed to get suggestions', error: error.message });
  }
});

module.exports = router;










