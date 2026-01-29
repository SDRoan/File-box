const express = require('express');
const auth = require('../middleware/auth');
const StudySchedule = require('../models/StudySchedule');
const router = express.Router();

// Get all study schedules for a course
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

    const schedules = await StudySchedule.find(query)
      .sort({ startTime: 1 })
      .lean();

    res.json({ schedules });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single schedule
router.get('/:id', auth, async (req, res) => {
  try {
    const schedule = await StudySchedule.findOne({
      _id: req.params.id,
      user: req.user._id
    }).lean();

    if (!schedule) {
      return res.status(404).json({ message: 'Schedule not found' });
    }

    res.json({ schedule });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create schedule
router.post('/', auth, async (req, res) => {
  try {
    const {
      course,
      title,
      description,
      startTime,
      endTime,
      type,
      location,
      isRecurring,
      recurringPattern,
      reminderMinutes
    } = req.body;

    if (!course || !title || !startTime || !endTime) {
      return res.status(400).json({ message: 'Course, title, startTime, and endTime are required' });
    }

    const schedule = new StudySchedule({
      course,
      user: req.user._id,
      title,
      description: description || '',
      startTime: new Date(startTime),
      endTime: new Date(endTime),
      type: type || 'study_session',
      location: location || '',
      isRecurring: isRecurring || false,
      recurringPattern: recurringPattern || null,
      reminderMinutes: reminderMinutes || 15
    });

    await schedule.save();

    res.status(201).json({ schedule });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update schedule
router.put('/:id', auth, async (req, res) => {
  try {
    const schedule = await StudySchedule.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!schedule) {
      return res.status(404).json({ message: 'Schedule not found' });
    }

    const {
      title,
      description,
      startTime,
      endTime,
      type,
      location,
      isRecurring,
      recurringPattern,
      completed,
      reminderMinutes
    } = req.body;

    if (title !== undefined) schedule.title = title;
    if (description !== undefined) schedule.description = description;
    if (startTime !== undefined) schedule.startTime = new Date(startTime);
    if (endTime !== undefined) schedule.endTime = new Date(endTime);
    if (type !== undefined) schedule.type = type;
    if (location !== undefined) schedule.location = location;
    if (isRecurring !== undefined) schedule.isRecurring = isRecurring;
    if (recurringPattern !== undefined) schedule.recurringPattern = recurringPattern;
    if (completed !== undefined) schedule.completed = completed;
    if (reminderMinutes !== undefined) schedule.reminderMinutes = reminderMinutes;

    await schedule.save();

    res.json({ schedule });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete schedule
router.delete('/:id', auth, async (req, res) => {
  try {
    const schedule = await StudySchedule.findOneAndDelete({
      _id: req.params.id,
      user: req.user._id
    });

    if (!schedule) {
      return res.status(404).json({ message: 'Schedule not found' });
    }

    res.json({ message: 'Schedule deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
