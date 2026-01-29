const express = require('express');
const auth = require('../middleware/auth');
const StudySession = require('../models/StudySession');
const router = express.Router();

// Get all study sessions for a course
router.get('/course/:courseId', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const query = {
      course: req.params.courseId,
      user: req.user._id
    };

    if (startDate && endDate) {
      query.startTime = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    const sessions = await StudySession.find(query)
      .sort({ startTime: -1 })
      .populate('filesAccessed', 'originalName _id')
      .lean();

    // Calculate statistics
    const totalDuration = sessions.reduce((sum, s) => sum + (s.duration || 0), 0);
    const totalSessions = sessions.length;
    const avgDuration = totalSessions > 0 ? totalDuration / totalSessions : 0;

    res.json({
      sessions,
      statistics: {
        totalDuration,
        totalSessions,
        avgDuration: Math.round(avgDuration),
        totalHours: Math.round((totalDuration / 60) * 100) / 100
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Start a study session
router.post('/start', auth, async (req, res) => {
  try {
    const { course, topic, filesAccessed } = req.body;

    if (!course) {
      return res.status(400).json({ message: 'Course is required' });
    }

    const session = new StudySession({
      course,
      user: req.user._id,
      startTime: new Date(),
      topic: topic || '',
      filesAccessed: filesAccessed || []
    });

    await session.save();

    res.status(201).json({ session });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// End a study session
router.put('/:id/end', auth, async (req, res) => {
  try {
    const { notes, productivity, notesCreated } = req.body;

    const session = await StudySession.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    session.endTime = new Date();
    if (notes !== undefined) session.notes = notes;
    if (productivity !== undefined) session.productivity = productivity;
    if (notesCreated !== undefined) session.notesCreated = notesCreated;

    await session.save();

    res.json({ session });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update session
router.put('/:id', auth, async (req, res) => {
  try {
    const session = await StudySession.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    const { topic, filesAccessed, notes, productivity, notesCreated } = req.body;

    if (topic !== undefined) session.topic = topic;
    if (filesAccessed !== undefined) session.filesAccessed = filesAccessed;
    if (notes !== undefined) session.notes = notes;
    if (productivity !== undefined) session.productivity = productivity;
    if (notesCreated !== undefined) session.notesCreated = notesCreated;

    await session.save();
    await session.populate('filesAccessed', 'originalName _id');

    res.json({ session });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete session
router.delete('/:id', auth, async (req, res) => {
  try {
    const session = await StudySession.findOneAndDelete({
      _id: req.params.id,
      user: req.user._id
    });

    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    res.json({ message: 'Session deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
