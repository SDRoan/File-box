const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const LearningResource = require('../models/LearningResource');

// Get all learning resources
router.get('/', auth, async (req, res) => {
  try {
    const { category, type, difficulty, search, tags } = req.query;
    const query = { isPublished: true };

    if (category) {
      query.category = category;
    }

    if (type) {
      query.type = type;
    }

    if (difficulty) {
      query.difficulty = difficulty;
    }

    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : [tags];
      query.tags = { $in: tagArray };
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const resources = await LearningResource.find(query)
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 });

    res.json(resources);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get resource by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const resource = await LearningResource.findById(req.params.id)
      .populate('createdBy', 'name email');

    if (!resource || !resource.isPublished) {
      return res.status(404).json({ message: 'Resource not found' });
    }

    // Increment views
    resource.views += 1;
    await resource.save();

    res.json(resource);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Rate resource
router.post('/:id/rate', auth, async (req, res) => {
  try {
    const { rating } = req.body;
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    const resource = await LearningResource.findById(req.params.id);
    if (!resource) {
      return res.status(404).json({ message: 'Resource not found' });
    }

    // Update rating
    const currentTotal = resource.rating * resource.ratingCount;
    resource.ratingCount += 1;
    resource.rating = (currentTotal + rating) / resource.ratingCount;

    await resource.save();
    res.json({ rating: resource.rating, ratingCount: resource.ratingCount });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create resource (admin only)
router.post('/', auth, async (req, res) => {
  try {
    const User = require('../models/User');
    const user = await User.findById(req.user._id);
    
    // Only admins can create resources
    if (user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { title, description, type, category, content, videoUrl, externalUrl, tags, difficulty, duration } = req.body;

    if (!title || !description || !type) {
      return res.status(400).json({ message: 'Title, description, and type are required' });
    }

    const resource = new LearningResource({
      title,
      description,
      type,
      category: category || 'getting-started',
      content: content || '',
      videoUrl: videoUrl || null,
      externalUrl: externalUrl || null,
      tags: tags || [],
      difficulty: difficulty || 'beginner',
      duration: duration || 0,
      createdBy: req.user._id
    });

    await resource.save();
    res.json(resource);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update resource (admin only)
router.put('/:id', auth, async (req, res) => {
  try {
    const User = require('../models/User');
    const user = await User.findById(req.user._id);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const resource = await LearningResource.findById(req.params.id);
    if (!resource) {
      return res.status(404).json({ message: 'Resource not found' });
    }

    const { title, description, type, category, content, videoUrl, externalUrl, tags, difficulty, duration, isPublished } = req.body;
    if (title) resource.title = title;
    if (description) resource.description = description;
    if (type) resource.type = type;
    if (category) resource.category = category;
    if (content !== undefined) resource.content = content;
    if (videoUrl !== undefined) resource.videoUrl = videoUrl;
    if (externalUrl !== undefined) resource.externalUrl = externalUrl;
    if (tags) resource.tags = tags;
    if (difficulty) resource.difficulty = difficulty;
    if (duration !== undefined) resource.duration = duration;
    if (isPublished !== undefined) resource.isPublished = isPublished;
    resource.updatedAt = new Date();

    await resource.save();
    res.json(resource);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

