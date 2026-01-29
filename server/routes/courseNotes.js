const express = require('express');
const auth = require('../middleware/auth');
const CourseNote = require('../models/CourseNote');
const router = express.Router();

// Get all notes for a course
router.get('/course/:courseId', auth, async (req, res) => {
  try {
    const notes = await CourseNote.find({
      course: req.params.courseId,
      user: req.user._id
    })
      .sort({ isPinned: -1, updatedAt: -1 })
      .populate('relatedFiles', 'originalName _id')
      .lean();

    res.json({ notes });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single note
router.get('/:id', auth, async (req, res) => {
  try {
    const note = await CourseNote.findOne({
      _id: req.params.id,
      user: req.user._id
    })
      .populate('relatedFiles', 'originalName _id')
      .lean();

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    res.json({ note });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create note
router.post('/', auth, async (req, res) => {
  try {
    const { course, title, content, tags, topic, relatedFiles, isPinned } = req.body;

    if (!course || !title) {
      return res.status(400).json({ message: 'Course and title are required' });
    }

    const note = new CourseNote({
      course,
      user: req.user._id,
      title,
      content: content || '',
      tags: tags || [],
      topic: topic || '',
      relatedFiles: relatedFiles || [],
      isPinned: isPinned || false
    });

    await note.save();
    await note.populate('relatedFiles', 'originalName _id');

    res.status(201).json({ note });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update note
router.put('/:id', auth, async (req, res) => {
  try {
    const note = await CourseNote.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    const { title, content, tags, topic, relatedFiles, isPinned } = req.body;

    if (title !== undefined) note.title = title;
    if (content !== undefined) note.content = content;
    if (tags !== undefined) note.tags = tags;
    if (topic !== undefined) note.topic = topic;
    if (relatedFiles !== undefined) note.relatedFiles = relatedFiles;
    if (isPinned !== undefined) note.isPinned = isPinned;

    await note.save();
    await note.populate('relatedFiles', 'originalName _id');

    res.json({ note });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete note
router.delete('/:id', auth, async (req, res) => {
  try {
    const note = await CourseNote.findOneAndDelete({
      _id: req.params.id,
      user: req.user._id
    });

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    res.json({ message: 'Note deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Search notes
router.get('/search/:courseId', auth, async (req, res) => {
  try {
    const { q, tag, topic } = req.query;
    const query = {
      course: req.params.courseId,
      user: req.user._id
    };

    if (q) {
      query.$or = [
        { title: { $regex: q, $options: 'i' } },
        { content: { $regex: q, $options: 'i' } }
      ];
    }

    if (tag) {
      query.tags = tag;
    }

    if (topic) {
      query.topic = topic;
    }

    const notes = await CourseNote.find(query)
      .sort({ updatedAt: -1 })
      .populate('relatedFiles', 'originalName _id')
      .lean();

    res.json({ notes });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
