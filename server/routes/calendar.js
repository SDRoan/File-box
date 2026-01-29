const express = require('express');
const auth = require('../middleware/auth');
const CalendarEvent = require('../models/CalendarEvent');
const Assignment = require('../models/Assignment');
const router = express.Router();

// Get calendar events
router.get('/', auth, async (req, res) => {
  try {
    const { startDate, endDate, type, courseCode } = req.query;
    const query = { owner: req.user._id };

    if (startDate && endDate) {
      query.$or = [
        {
          startDate: { $gte: new Date(startDate), $lte: new Date(endDate) }
        },
        {
          endDate: { $gte: new Date(startDate), $lte: new Date(endDate) }
        },
        {
          startDate: { $lte: new Date(startDate) },
          endDate: { $gte: new Date(endDate) }
        }
      ];
    }

    if (type) query.type = type;
    if (courseCode) query.courseCode = courseCode;

    const events = await CalendarEvent.find(query)
      .populate('assignment', 'title status')
      .sort({ startDate: 1 })
      .lean();

    res.json({ events });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get upcoming events
router.get('/upcoming', auth, async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const events = await CalendarEvent.find({
      owner: req.user._id,
      startDate: { $gte: new Date() }
    })
      .populate('assignment', 'title status')
      .sort({ startDate: 1 })
      .limit(parseInt(limit))
      .lean();

    res.json({ events });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single event
router.get('/:id', auth, async (req, res) => {
  try {
    const event = await CalendarEvent.findOne({
      _id: req.params.id,
      owner: req.user._id
    })
      .populate('assignment')
      .lean();

    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    res.json({ event });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create event
router.post('/', auth, async (req, res) => {
  try {
    const {
      title,
      description,
      type,
      course,
      courseCode,
      startDate,
      endDate,
      allDay,
      location,
      color,
      reminder,
      assignment,
      recurring
    } = req.body;

    if (!title || !startDate) {
      return res.status(400).json({ message: 'Title and start date are required' });
    }

    // Verify assignment belongs to user if provided
    if (assignment) {
      const assignmentDoc = await Assignment.findOne({
        _id: assignment,
        owner: req.user._id
      });
      if (!assignmentDoc) {
        return res.status(400).json({ message: 'Assignment not found' });
      }
    }

    const event = new CalendarEvent({
      title,
      description,
      type: type || 'other',
      course,
      courseCode,
      owner: req.user._id,
      startDate,
      endDate: endDate || startDate,
      allDay: allDay || false,
      location,
      color: color || '#6366f1',
      reminder: reminder || { enabled: true, minutesBefore: 15 },
      assignment: assignment || null,
      recurring: recurring || { enabled: false }
    });

    await event.save();
    await event.populate('assignment', 'title status');

    res.status(201).json({ event });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update event
router.put('/:id', auth, async (req, res) => {
  try {
    const event = await CalendarEvent.findOne({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    const {
      title,
      description,
      type,
      course,
      courseCode,
      startDate,
      endDate,
      allDay,
      location,
      color,
      reminder,
      recurring
    } = req.body;

    if (title) event.title = title;
    if (description !== undefined) event.description = description;
    if (type) event.type = type;
    if (course) event.course = course;
    if (courseCode) event.courseCode = courseCode;
    if (startDate) event.startDate = startDate;
    if (endDate) event.endDate = endDate;
    if (allDay !== undefined) event.allDay = allDay;
    if (location !== undefined) event.location = location;
    if (color) event.color = color;
    if (reminder) event.reminder = reminder;
    if (recurring) event.recurring = recurring;

    await event.save();
    await event.populate('assignment', 'title status');

    res.json({ event });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete event
router.delete('/:id', auth, async (req, res) => {
  try {
    const event = await CalendarEvent.findOneAndDelete({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    res.json({ message: 'Event deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Auto-create events from assignments
router.post('/sync-assignments', auth, async (req, res) => {
  try {
    const assignments = await Assignment.find({
      owner: req.user._id,
      status: { $ne: 'Graded' }
    });

    const createdEvents = [];

    for (const assignment of assignments) {
      // Check if event already exists
      const existingEvent = await CalendarEvent.findOne({
        assignment: assignment._id
      });

      if (!existingEvent) {
        const event = new CalendarEvent({
          title: assignment.title,
          description: assignment.description,
          type: 'assignment',
          course: assignment.course,
          courseCode: assignment.courseCode,
          owner: req.user._id,
          startDate: assignment.dueDate,
          endDate: assignment.dueDate,
          allDay: true,
          color: assignment.priority === 'Urgent' ? '#ef4444' : 
                 assignment.priority === 'High' ? '#f59e0b' : '#6366f1',
          reminder: { enabled: true, minutesBefore: 1440 }, // 24 hours before
          assignment: assignment._id
        });

        await event.save();
        createdEvents.push(event);
      }
    }

    res.json({ message: `Created ${createdEvents.length} events from assignments` });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;








