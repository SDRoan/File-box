const express = require('express');
const auth = require('../middleware/auth');
const Annotation = require('../models/Annotation');
const File = require('../models/File');
const router = express.Router();

// Get annotations for a file
router.get('/file/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check if user has access
    const hasAccess = file.owner.toString() === req.user._id.toString() ||
      file.sharedWith.some(s => s.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'No access to this file' });
    }

    const annotations = await Annotation.find({ file: req.params.fileId })
      .populate('user', 'name email')
      .sort({ page: 1, createdAt: 1 })
      .lean();

    res.json({ annotations });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create annotation
router.post('/', auth, async (req, res) => {
  try {
    const {
      file,
      type,
      page,
      position,
      content,
      color,
      strokeWidth,
      points
    } = req.body;

    if (!file || !type || page === undefined) {
      return res.status(400).json({ message: 'File, type, and page are required' });
    }

    const fileDoc = await File.findById(file);
    if (!fileDoc) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check if user has access
    const hasAccess = fileDoc.owner.toString() === req.user._id.toString() ||
      fileDoc.sharedWith.some(s => s.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'No access to this file' });
    }

    const annotation = new Annotation({
      file,
      user: req.user._id,
      type,
      page,
      position: position || {},
      content: content || '',
      color: color || '#ffff00',
      strokeWidth: strokeWidth || 2,
      points: points || []
    });

    await annotation.save();
    await annotation.populate('user', 'name email');

    res.status(201).json({ annotation });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update annotation
router.put('/:id', auth, async (req, res) => {
  try {
    const annotation = await Annotation.findById(req.params.id);

    if (!annotation) {
      return res.status(404).json({ message: 'Annotation not found' });
    }

    if (annotation.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only edit your own annotations' });
    }

    const { content, color, position, points } = req.body;

    if (content !== undefined) annotation.content = content;
    if (color) annotation.color = color;
    if (position) annotation.position = position;
    if (points) annotation.points = points;

    await annotation.save();
    await annotation.populate('user', 'name email');

    res.json({ annotation });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete annotation
router.delete('/:id', auth, async (req, res) => {
  try {
    const annotation = await Annotation.findById(req.params.id);

    if (!annotation) {
      return res.status(404).json({ message: 'Annotation not found' });
    }

    if (annotation.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only delete your own annotations' });
    }

    await annotation.deleteOne();
    res.json({ message: 'Annotation deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;








