const mongoose = require('mongoose');

const FileContentSchema = new mongoose.Schema({
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true,
    unique: true
  },
  extractedText: {
    type: String,
    default: ''
  },
  embedding: {
    type: [Number], // Vector embedding for semantic search
    default: []
  },
  extractedAt: {
    type: Date,
    default: Date.now
  },
  extractionStatus: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'not_supported'],
    default: 'pending'
  },
  summary: {
    type: String,
    default: ''
  },
  summaryGeneratedAt: {
    type: Date
  },
  summaryModel: {
    type: String,
    default: ''
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('FileContent', FileContentSchema);

