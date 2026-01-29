const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const File = require('../models/File');
const Folder = require('../models/Folder');
const predictiveOrgService = require('../services/predictiveOrganization');

// Get organization suggestions for a file
router.get('/suggestions/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check permissions
    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const context = {
      actionBefore: req.query.actionBefore || 'uploaded',
      projectContext: req.query.projectContext || null
    };

    const suggestions = await predictiveOrgService.getSuggestions(
      req.user._id,
      file,
      context
    );

    res.json({ suggestions });
  } catch (error) {
    console.error('Error getting suggestions:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get all patterns for user
router.get('/patterns', auth, async (req, res) => {
  try {
    const patterns = await predictiveOrgService.getUserPatterns(req.user._id);
    res.json({ patterns });
  } catch (error) {
    console.error('Error getting patterns:', error);
    res.status(500).json({ message: error.message });
  }
});

// Record feedback on a suggestion
router.post('/feedback/:patternId', auth, async (req, res) => {
  try {
    const { action } = req.body; // 'accepted', 'rejected', 'ignored'
    
    if (!['accepted', 'rejected', 'ignored'].includes(action)) {
      return res.status(400).json({ message: 'Invalid action' });
    }

    const pattern = await predictiveOrgService.recordFeedback(
      req.user._id,
      req.params.patternId,
      action
    );

    res.json({ pattern });
  } catch (error) {
    console.error('Error recording feedback:', error);
    res.status(500).json({ message: error.message });
  }
});

// Manually trigger pattern recording (for testing)
router.post('/record-pattern', auth, async (req, res) => {
  try {
    const { fileId, sourceFolderId, destinationFolderId, context } = req.body;
    
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const pattern = await predictiveOrgService.recordPattern(
      req.user._id,
      file,
      sourceFolderId,
      destinationFolderId,
      context || {}
    );

    res.json({ pattern });
  } catch (error) {
    console.error('Error recording pattern:', error);
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

