const mongoose = require('mongoose');

const learningResourceSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['tutorial', 'guide', 'video', 'article', 'documentation', 'faq'],
    required: true
  },
  category: {
    type: String,
    enum: ['getting-started', 'file-management', 'sharing', 'collaboration', 'security', 'advanced', 'api'],
    default: 'getting-started'
  },
  content: {
    type: String, // HTML or markdown content
    default: ''
  },
  videoUrl: {
    type: String,
    default: null
  },
  externalUrl: {
    type: String,
    default: null
  },
  thumbnail: {
    type: String,
    default: null
  },
  tags: [{
    type: String
  }],
  difficulty: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced'],
    default: 'beginner'
  },
  duration: {
    type: Number, // in minutes
    default: 0
  },
  views: {
    type: Number,
    default: 0
  },
  rating: {
    type: Number,
    default: 0,
    min: 0,
    max: 5
  },
  ratingCount: {
    type: Number,
    default: 0
  },
  isPublished: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null // null for system resources
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

learningResourceSchema.index({ category: 1, type: 1 });
learningResourceSchema.index({ tags: 1 });
learningResourceSchema.index({ isPublished: 1 });

module.exports = mongoose.model('LearningResource', learningResourceSchema);

