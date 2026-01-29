const express = require('express');
const auth = require('../middleware/auth');
const Assignment = require('../models/Assignment');
const File = require('../models/File');
const Folder = require('../models/Folder');
const router = express.Router();

// Get all assignments
router.get('/', auth, async (req, res) => {
  try {
    const { status, course, upcoming } = req.query;
    const query = { owner: req.user._id };
    
    if (status) query.status = status;
    if (course) query.course = course;
    if (upcoming === 'true') {
      query.dueDate = { $gte: new Date() };
    }

    const assignments = await Assignment.find(query)
      .sort({ dueDate: 1 })
      .populate('attachedFiles', 'name originalName')
      .populate('attachedFolders', 'name')
      .lean();

    res.json({ assignments });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single assignment
router.get('/:id', auth, async (req, res) => {
  try {
    const assignment = await Assignment.findOne({
      _id: req.params.id,
      owner: req.user._id
    })
      .populate('attachedFiles')
      .populate('attachedFolders')
      .lean();

    if (!assignment) {
      return res.status(404).json({ message: 'Assignment not found' });
    }

    res.json({ assignment });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create assignment
router.post('/', auth, async (req, res) => {
  try {
    const {
      title,
      description,
      course,
      courseCode,
      dueDate,
      priority,
      attachedFiles,
      attachedFolders,
      tags
    } = req.body;

    if (!title || !course || !dueDate) {
      return res.status(400).json({ message: 'Title, course, and due date are required' });
    }

    // Verify files/folders belong to user
    if (attachedFiles && attachedFiles.length > 0) {
      const files = await File.find({ _id: { $in: attachedFiles }, owner: req.user._id });
      if (files.length !== attachedFiles.length) {
        return res.status(400).json({ message: 'Some files not found or not owned by you' });
      }
    }

    if (attachedFolders && attachedFolders.length > 0) {
      const folders = await Folder.find({ _id: { $in: attachedFolders }, owner: req.user._id });
      if (folders.length !== attachedFolders.length) {
        return res.status(400).json({ message: 'Some folders not found or not owned by you' });
      }
    }

    const assignment = new Assignment({
      title,
      description,
      course,
      courseCode,
      owner: req.user._id,
      dueDate,
      priority: priority || 'Medium',
      attachedFiles: attachedFiles || [],
      attachedFolders: attachedFolders || [],
      tags: tags || []
    });

    await assignment.save();
    await assignment.populate('attachedFiles', 'name originalName');
    await assignment.populate('attachedFolders', 'name');

    res.status(201).json({ assignment });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update assignment
router.put('/:id', auth, async (req, res) => {
  try {
    const assignment = await Assignment.findOne({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!assignment) {
      return res.status(404).json({ message: 'Assignment not found' });
    }

    const {
      title,
      description,
      course,
      courseCode,
      dueDate,
      priority,
      status,
      grade,
      maxPoints,
      attachedFiles,
      attachedFolders,
      tags
    } = req.body;

    if (title) assignment.title = title;
    if (description !== undefined) assignment.description = description;
    if (course) assignment.course = course;
    if (courseCode) assignment.courseCode = courseCode;
    if (dueDate) assignment.dueDate = dueDate;
    if (priority) assignment.priority = priority;
    if (status) {
      assignment.status = status;
      if (status === 'Submitted' && !assignment.submittedAt) {
        assignment.submittedAt = new Date();
      }
    }
    if (grade !== undefined) assignment.grade = grade;
    if (maxPoints !== undefined) assignment.maxPoints = maxPoints;
    if (attachedFiles) assignment.attachedFiles = attachedFiles;
    if (attachedFolders) assignment.attachedFolders = attachedFolders;
    if (tags) assignment.tags = tags;

    await assignment.save();
    await assignment.populate('attachedFiles', 'name originalName');
    await assignment.populate('attachedFolders', 'name');

    res.json({ assignment });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Attach file to assignment
router.post('/:id/attach-file', auth, async (req, res) => {
  try {
    const assignment = await Assignment.findOne({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!assignment) {
      return res.status(404).json({ message: 'Assignment not found' });
    }

    const { fileId } = req.body;
    if (!fileId) {
      return res.status(400).json({ message: 'File ID is required' });
    }

    // Verify file belongs to user
    const file = await File.findOne({ _id: fileId, owner: req.user._id });
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Add file if not already attached
    if (!assignment.attachedFiles.includes(fileId)) {
      assignment.attachedFiles.push(fileId);
      await assignment.save();
    }

    await assignment.populate('attachedFiles', 'name originalName');
    await assignment.populate('attachedFolders', 'name');

    res.json({ assignment });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Remove file from assignment
router.delete('/:id/attach-file/:fileId', auth, async (req, res) => {
  try {
    const assignment = await Assignment.findOne({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!assignment) {
      return res.status(404).json({ message: 'Assignment not found' });
    }

    assignment.attachedFiles = assignment.attachedFiles.filter(
      id => id.toString() !== req.params.fileId
    );
    await assignment.save();

    await assignment.populate('attachedFiles', 'name originalName');
    await assignment.populate('attachedFolders', 'name');

    res.json({ assignment });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete assignment
router.delete('/:id', auth, async (req, res) => {
  try {
    const assignment = await Assignment.findOneAndDelete({
      _id: req.params.id,
      owner: req.user._id
    });

    if (!assignment) {
      return res.status(404).json({ message: 'Assignment not found' });
    }

    res.json({ message: 'Assignment deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

