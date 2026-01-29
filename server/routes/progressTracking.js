const express = require('express');
const auth = require('../middleware/auth');
const ProgressEntry = require('../models/ProgressEntry');
const router = express.Router();

// Get all progress entries for a course
router.get('/course/:courseId', auth, async (req, res) => {
  try {
    const entries = await ProgressEntry.find({
      course: req.params.courseId,
      user: req.user._id
    })
      .sort({ dateCompleted: -1 })
      .lean();

    // Calculate overall statistics
    const totalPointsEarned = entries.reduce((sum, e) => sum + (e.pointsEarned || 0), 0);
    const totalPointsPossible = entries.reduce((sum, e) => sum + (e.pointsPossible || 0), 0);
    const overallPercentage = totalPointsPossible > 0 
      ? (totalPointsEarned / totalPointsPossible) * 100 
      : 0;

    // Calculate by category
    const byCategory = {};
    entries.forEach(entry => {
      const cat = entry.category || 'other';
      if (!byCategory[cat]) {
        byCategory[cat] = { earned: 0, possible: 0, count: 0 };
      }
      byCategory[cat].earned += entry.pointsEarned || 0;
      byCategory[cat].possible += entry.pointsPossible || 0;
      byCategory[cat].count += 1;
    });

    Object.keys(byCategory).forEach(cat => {
      if (byCategory[cat].possible > 0) {
        byCategory[cat].percentage = (byCategory[cat].earned / byCategory[cat].possible) * 100;
      }
    });

    res.json({
      entries,
      statistics: {
        totalPointsEarned,
        totalPointsPossible,
        overallPercentage: Math.round(overallPercentage * 100) / 100,
        byCategory,
        totalEntries: entries.length
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single entry
router.get('/:id', auth, async (req, res) => {
  try {
    const entry = await ProgressEntry.findOne({
      _id: req.params.id,
      user: req.user._id
    }).lean();

    if (!entry) {
      return res.status(404).json({ message: 'Entry not found' });
    }

    res.json({ entry });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create entry
router.post('/', auth, async (req, res) => {
  try {
    const {
      course,
      assignmentName,
      pointsEarned,
      pointsPossible,
      category,
      weight,
      dateCompleted,
      notes
    } = req.body;

    if (!course || !assignmentName || pointsPossible === undefined) {
      return res.status(400).json({ message: 'Course, assignmentName, and pointsPossible are required' });
    }

    const entry = new ProgressEntry({
      course,
      user: req.user._id,
      assignmentName,
      pointsEarned: pointsEarned || 0,
      pointsPossible,
      category: category || 'homework',
      weight: weight || 1,
      dateCompleted: dateCompleted ? new Date(dateCompleted) : new Date(),
      notes: notes || ''
    });

    await entry.save();

    res.status(201).json({ entry });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update entry
router.put('/:id', auth, async (req, res) => {
  try {
    const entry = await ProgressEntry.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!entry) {
      return res.status(404).json({ message: 'Entry not found' });
    }

    const {
      assignmentName,
      pointsEarned,
      pointsPossible,
      category,
      weight,
      dateCompleted,
      notes
    } = req.body;

    if (assignmentName !== undefined) entry.assignmentName = assignmentName;
    if (pointsEarned !== undefined) entry.pointsEarned = pointsEarned;
    if (pointsPossible !== undefined) entry.pointsPossible = pointsPossible;
    if (category !== undefined) entry.category = category;
    if (weight !== undefined) entry.weight = weight;
    if (dateCompleted !== undefined) entry.dateCompleted = new Date(dateCompleted);
    if (notes !== undefined) entry.notes = notes;

    await entry.save();

    res.json({ entry });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete entry
router.delete('/:id', auth, async (req, res) => {
  try {
    const entry = await ProgressEntry.findOneAndDelete({
      _id: req.params.id,
      user: req.user._id
    });

    if (!entry) {
      return res.status(404).json({ message: 'Entry not found' });
    }

    res.json({ message: 'Entry deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
