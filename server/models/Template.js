const mongoose = require('mongoose');

const templateSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  category: {
    type: String,
    enum: ['business', 'academic', 'personal', 'legal', 'creative', 'other'],
    default: 'other'
  },
  content: {
    type: String, // For text-based templates (DOCX, TXT)
    default: ''
  },
  filePath: {
    type: String, // Path to template file if it's a file-based template
    default: null
  },
  mimeType: {
    type: String,
    default: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' // DOCX default
  },
  thumbnail: {
    type: String, // URL or path to thumbnail image
    default: null
  },
  tags: [{
    type: String
  }],
  isPublic: {
    type: Boolean,
    default: true // Templates can be public or private
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null // null for system templates
  },
  usageCount: {
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
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

templateSchema.index({ category: 1, isPublic: 1 });
templateSchema.index({ tags: 1 });
templateSchema.index({ createdBy: 1 });

module.exports = mongoose.model('Template', templateSchema);

