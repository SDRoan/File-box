const express = require('express');
const auth = require('../middleware/auth');
const Course = require('../models/Course');
const Folder = require('../models/Folder');
const router = express.Router();

// Get all courses
router.get('/', auth, async (req, res) => {
  try {
    const { semester, year } = req.query;
    const query = { owner: req.user._id };
    
    if (semester) query.semester = semester;
    if (year) query.year = year;

    const courses = await Course.find(query)
      .sort({ code: 1 })
      .populate('folder', 'name _id')
      .lean();

    // Ensure all course folders are marked as course folders
    for (const course of courses) {
      if (course.folder && course.folder._id) {
        await Folder.findByIdAndUpdate(course.folder._id, { isCourseFolder: true });
      }
    }

    res.json({ courses });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single course
router.get('/:id', auth, async (req, res) => {
  try {
    const course = await Course.findOne({
      _id: req.params.id,
      owner: req.user._id
    })
      .populate('folder')
      .lean();

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    res.json({ course });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create course
router.post('/', auth, async (req, res) => {
  try {
    const {
      name,
      code,
      semester,
      year,
      instructor,
      color,
      schedule
    } = req.body;

    if (!name || !code) {
      return res.status(400).json({ message: 'Name and code are required' });
    }

    // Check if course already exists
    const existing = await Course.findOne({
      owner: req.user._id,
      code: code.toUpperCase()
    });

    if (existing) {
      return res.status(400).json({ message: 'Course with this code already exists' });
    }

    // Create folder for course (marked as course folder)
    const folder = new Folder({
      name: `${code} - ${name}`,
      owner: req.user._id,
      parentFolder: null,
      isCourseFolder: true
    });
    await folder.save();

    const course = new Course({
      name,
      code: code.toUpperCase(),
      owner: req.user._id,
      semester,
      year,
      instructor,
      color: color || '#6366f1',
      folder: folder._id,
      schedule: schedule || []
    });

    await course.save();
    await course.populate('folder', 'name _id');

    res.status(201).json({ course });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update course
router.put('/:id', auth, async (req, res) => {
  try {
    const course = await Course.findOne({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    const {
      name,
      code,
      semester,
      year,
      instructor,
      color,
      schedule
    } = req.body;

    if (name) course.name = name;
    if (code) course.code = code.toUpperCase();
    if (semester !== undefined) course.semester = semester;
    if (year !== undefined) course.year = year;
    if (instructor !== undefined) course.instructor = instructor;
    if (color) course.color = color;
    if (schedule) course.schedule = schedule;

    // Update folder name if course name or code changed
    if ((name || code) && course.folder) {
      const folder = await Folder.findById(course.folder);
      if (folder) {
        folder.name = `${course.code} - ${course.name}`;
        await folder.save();
      }
    }

    await course.save();
    await course.populate('folder', 'name _id');

    res.json({ course });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete course
router.delete('/:id', auth, async (req, res) => {
  try {
    const course = await Course.findOneAndDelete({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Delete the associated folder if it exists
    if (course.folder) {
      await Folder.findByIdAndDelete(course.folder);
    }
    
    res.json({ message: 'Course deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

