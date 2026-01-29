const mongoose = require('mongoose');

const fileSummarySchema = new mongoose.Schema({
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true,
    unique: true
  },
  summary: {
    type: String,
    required: true
  },
  keyPoints: [{
    type: String
  }],
  extractedData: {
    dates: [{
      type: String
    }],
    people: [{
      type: String
    }],
    topics: [{
      type: String
    }],
    amounts: [{
      type: String
    }],
    locations: [{
      type: String
    }]
  },
  wordCount: {
    type: Number
  },
  readingTime: {
    type: Number // in minutes
  },
  language: {
    type: String
  },
  generatedAt: {
    type: Date,
    default: Date.now
  },
  model: {
    type: String,
    default: 'ai-summary'
  }
});

fileSummarySchema.index({ file: 1 });

module.exports = mongoose.model('FileSummary', fileSummarySchema);








