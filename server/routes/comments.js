const express = require('express');
const auth = require('../middleware/auth');
const Comment = require('../models/Comment');
const File = require('../models/File');
const Activity = require('../models/Activity');
const router = express.Router();

// Helper function to log activity
const logActivity = async (user, action, fileId = null, folderId = null, details = '') => {
  try {
    const activity = new Activity({
      user: user._id || user,
      file: fileId,
      folder: folderId,
      action,
      details
    });
    await activity.save();
  } catch (error) {
    console.error('Error logging activity:', error);
  }
};

// Get comments for a file
router.get('/file/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check if user has access (owner or shared with)
    const hasAccess = file.owner.toString() === req.user._id.toString() ||
      file.sharedWith.some(s => s.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const comments = await Comment.find({ file: req.params.fileId })
      .populate('user', 'name email')
      .populate('replies.user', 'name email')
      .sort({ createdAt: -1 });

    res.json(comments);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Add comment
router.post('/file/:fileId', auth, async (req, res) => {
  try {
    const { text } = req.body;
    
    if (!text || !text.trim()) {
      return res.status(400).json({ message: 'Comment text is required' });
    }

    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check if user has access
    const hasAccess = file.owner.toString() === req.user._id.toString() ||
      file.sharedWith.some(s => s.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const comment = new Comment({
      file: req.params.fileId,
      user: req.user._id,
      text: text.trim()
    });

    await comment.save();
    await comment.populate('user', 'name email');

    // Log activity
    await logActivity(req.user._id, 'commented', req.params.fileId, null, 'Added a comment');

    res.status(201).json(comment);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update comment
router.patch('/:commentId', auth, async (req, res) => {
  try {
    const { text } = req.body;
    const comment = await Comment.findById(req.params.commentId);

    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    if (comment.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only edit your own comments' });
    }

    comment.text = text.trim();
    comment.updatedAt = new Date();
    await comment.save();

    res.json(comment);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete comment
router.delete('/:commentId', auth, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.commentId);

    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    if (comment.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only delete your own comments' });
    }

    await comment.deleteOne();
    res.json({ message: 'Comment deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Add reply to comment
router.post('/:commentId/reply', auth, async (req, res) => {
  try {
    const { text } = req.body;
    const comment = await Comment.findById(req.params.commentId);

    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    // Check if user has access to the file
    const file = await File.findById(comment.file);
    const hasAccess = file.owner.toString() === req.user._id.toString() ||
      file.sharedWith.some(s => s.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    comment.replies.push({
      user: req.user._id,
      text: text.trim()
    });

    await comment.save();
    await comment.populate('replies.user', 'name email');

    res.json(comment);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

