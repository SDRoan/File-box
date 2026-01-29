const express = require('express');
const auth = require('../middleware/auth');
const FileMemory = require('../models/FileMemory');
const File = require('../models/File');
const Folder = require('../models/Folder');
const router = express.Router();

// Get memory for a specific file
router.get('/file/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check permissions
    if (file.owner.toString() !== req.user._id.toString() &&
        !file.sharedWith.some(s => s.user.toString() === req.user._id.toString())) {
      return res.status(403).json({ message: 'Access denied' });
    }

    let memory = await FileMemory.findOne({ 
      file: req.params.fileId, 
      owner: req.user._id 
    }).populate('creationContext.relatedFiles', 'originalName').populate('creationContext.relatedFolders', 'name');

    // If no memory exists, create a basic one
    if (!memory) {
      memory = new FileMemory({
        file: req.params.fileId,
        owner: req.user._id,
        creationContext: {
          timestamp: file.createdAt,
          source: 'upload',
          userAction: '',
          relatedFiles: [],
          relatedFolders: file.parentFolder ? [file.parentFolder] : [],
          projectContext: '',
          meetingContext: '',
          deadlineContext: null
        }
      });
      await memory.save();
    }

    await memory.populate('file', 'originalName mimeType size createdAt');
    res.json(memory);
  } catch (error) {
    console.error('Error fetching file memory:', error);
    res.status(500).json({ message: error.message });
  }
});

// Update file memory context
router.put('/file/:fileId', auth, async (req, res) => {
  try {
    const { userAction, projectContext, meetingContext, deadlineContext, notes } = req.body;
    
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    let memory = await FileMemory.findOne({ 
      file: req.params.fileId, 
      owner: req.user._id 
    });

    if (!memory) {
      memory = new FileMemory({
        file: req.params.fileId,
        owner: req.user._id,
        creationContext: {
          timestamp: file.createdAt,
          source: 'upload',
          relatedFolders: file.parentFolder ? [file.parentFolder] : []
        }
      });
    }

    if (userAction) memory.creationContext.userAction = userAction;
    if (projectContext) memory.creationContext.projectContext = projectContext;
    if (meetingContext) memory.creationContext.meetingContext = meetingContext;
    if (deadlineContext) memory.creationContext.deadlineContext = new Date(deadlineContext);
    if (notes) {
      memory.userNotes.push({
        content: notes,
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    await memory.save();
    await memory.populate('file', 'originalName mimeType size');
    
    res.json(memory);
  } catch (error) {
    console.error('Error updating file memory:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get all memories for user (with filters)
router.get('/', auth, async (req, res) => {
  try {
    const { project, search, sortBy = 'updatedAt' } = req.query;
    
    const query = { owner: req.user._id };
    
    if (project) {
      query.$or = [
        { 'creationContext.projectContext': { $regex: project, $options: 'i' } },
        { 'linkedEntities.projects': { $in: [project] } }
      ];
    }

    if (search) {
      query.$or = [
        { 'creationContext.userAction': { $regex: search, $options: 'i' } },
        { 'creationContext.projectContext': { $regex: search, $options: 'i' } },
        { 'aiInsights.purpose': { $regex: search, $options: 'i' } }
      ];
    }

    const memories = await FileMemory.find(query)
      .populate('file', 'originalName mimeType size createdAt')
      .populate('creationContext.relatedFiles', 'originalName')
      .sort({ [sortBy]: -1 })
      .limit(100);

    res.json(memories);
  } catch (error) {
    console.error('Error fetching memories:', error);
    res.status(500).json({ message: error.message });
  }
});

// Ask a question about file context (for AI assistant)
router.post('/file/:fileId/ask', auth, async (req, res) => {
  try {
    const { question } = req.body;
    
    if (!question) {
      return res.status(400).json({ message: 'Question is required' });
    }

    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    let memory = await FileMemory.findOne({ 
      file: req.params.fileId, 
      owner: req.user._id 
    }).populate('file', 'originalName mimeType size createdAt')
      .populate('creationContext.relatedFiles', 'originalName')
      .populate('creationContext.relatedFolders', 'name');

    if (!memory) {
      return res.json({
        answer: `I don't have much context about this file yet. It was created on ${file.createdAt.toLocaleDateString()}. You can add context by updating the file memory.`,
        memory: null
      });
    }

    // Generate answer based on memory context
    let answer = `Based on the context I have:\n\n`;
    
    if (memory.creationContext.userAction) {
      answer += `**Why you saved it:** ${memory.creationContext.userAction}\n\n`;
    }
    
    if (memory.creationContext.projectContext) {
      answer += `**Project:** ${memory.creationContext.projectContext}\n\n`;
    }
    
    if (memory.creationContext.meetingContext) {
      answer += `**Meeting/Context:** ${memory.creationContext.meetingContext}\n\n`;
    }
    
    if (memory.creationContext.deadlineContext) {
      answer += `**Deadline:** ${new Date(memory.creationContext.deadlineContext).toLocaleDateString()}\n\n`;
    }
    
    if (memory.aiInsights.purpose) {
      answer += `**Purpose:** ${memory.aiInsights.purpose}\n\n`;
    }
    
    if (memory.creationContext.relatedFiles && memory.creationContext.relatedFiles.length > 0) {
      answer += `**Related files:** ${memory.creationContext.relatedFiles.map(f => f.originalName).join(', ')}\n\n`;
    }
    
    if (memory.userNotes && memory.userNotes.length > 0) {
      answer += `**Your notes:** ${memory.userNotes[memory.userNotes.length - 1].content}\n\n`;
    }

    // Store Q&A
    memory.contextualQA.push({
      question,
      answer,
      createdAt: new Date()
    });
    await memory.save();

    res.json({
      answer,
      memory
    });
  } catch (error) {
    console.error('Error answering question:', error);
    res.status(500).json({ message: error.message });
  }
});

// Link file to project/course/study group
router.post('/file/:fileId/link', auth, async (req, res) => {
  try {
    const { project, courseId, studyGroupId, assignmentId } = req.body;
    
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    if (file.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    let memory = await FileMemory.findOne({ 
      file: req.params.fileId, 
      owner: req.user._id 
    });

    if (!memory) {
      memory = new FileMemory({
        file: req.params.fileId,
        owner: req.user._id,
        creationContext: {
          timestamp: file.createdAt,
          source: 'upload',
          relatedFolders: file.parentFolder ? [file.parentFolder] : []
        }
      });
    }

    if (project && !memory.linkedEntities.projects.includes(project)) {
      memory.linkedEntities.projects.push(project);
    }
    if (courseId && !memory.linkedEntities.courses.includes(courseId)) {
      memory.linkedEntities.courses.push(courseId);
    }
    if (studyGroupId && !memory.linkedEntities.studyGroups.includes(studyGroupId)) {
      memory.linkedEntities.studyGroups.push(studyGroupId);
    }
    if (assignmentId && !memory.linkedEntities.assignments.includes(assignmentId)) {
      memory.linkedEntities.assignments.push(assignmentId);
    }

    await memory.save();
    await memory.populate('file', 'originalName mimeType size');
    
    res.json(memory);
  } catch (error) {
    console.error('Error linking file:', error);
    res.status(500).json({ message: error.message });
  }
});

// Update usage patterns (called when file is accessed)
router.patch('/file/:fileId/usage', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    let memory = await FileMemory.findOne({ 
      file: req.params.fileId, 
      owner: req.user._id 
    });

    if (!memory) {
      memory = new FileMemory({
        file: req.params.fileId,
        owner: req.user._id,
        creationContext: {
          timestamp: file.createdAt,
          source: 'upload',
          relatedFolders: file.parentFolder ? [file.parentFolder] : []
        }
      });
    }

    const now = new Date();
    const dayOfWeek = now.getDay();
    const hour = now.getHours();

    if (!memory.usagePatterns.firstAccess) {
      memory.usagePatterns.firstAccess = now;
    }
    memory.usagePatterns.lastAccess = now;

    // Update typical access days
    if (!memory.usagePatterns.typicalAccessDays.includes(dayOfWeek)) {
      memory.usagePatterns.typicalAccessDays.push(dayOfWeek);
    }

    // Update typical access times
    const timeEntry = memory.usagePatterns.typicalAccessTimes.find(t => t.hour === hour);
    if (timeEntry) {
      timeEntry.frequency += 1;
    } else {
      memory.usagePatterns.typicalAccessTimes.push({ hour, frequency: 1 });
    }

    await memory.save();
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating usage patterns:', error);
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

