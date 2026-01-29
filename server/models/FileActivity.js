const mongoose = require('mongoose');

const FileActivitySchema = new mongoose.Schema({
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  action: {
    type: String,
    enum: ['view', 'download', 'preview', 'edit', 'share', 'delete', 'restore', 'star', 'unstar', 'move', 'copy'],
    required: true
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true // Index for faster queries
  }
}, {
  timestamps: true
});

// Compound index for efficient queries
FileActivitySchema.index({ file: 1, timestamp: -1 });
FileActivitySchema.index({ user: 1, timestamp: -1 });
FileActivitySchema.index({ action: 1, timestamp: -1 });

module.exports = mongoose.model('FileActivity', FileActivitySchema);










