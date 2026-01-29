const mongoose = require('mongoose');

const cloudBackupSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  sourcePath: {
    type: String,
    required: true // e.g., '/Users/username/Desktop' or '/Users/username/Documents'
  },
  sourceType: {
    type: String,
    enum: ['desktop', 'documents', 'custom'],
    required: true
  },
  enabled: {
    type: Boolean,
    default: true
  },
  lastBackupAt: {
    type: Date,
    default: null
  },
  nextBackupAt: {
    type: Date,
    default: null
  },
  backupFrequency: {
    type: String,
    enum: ['hourly', 'daily', 'weekly'],
    default: 'daily'
  },
  backupCount: {
    type: Number,
    default: 0
  },
  totalFilesBackedUp: {
    type: Number,
    default: 0
  },
  totalSizeBackedUp: {
    type: Number,
    default: 0 // in bytes
  },
  status: {
    type: String,
    enum: ['idle', 'backing_up', 'completed', 'failed'],
    default: 'idle'
  },
  lastError: {
    type: String,
    default: null
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

cloudBackupSchema.index({ user: 1, sourceType: 1 });
cloudBackupSchema.index({ user: 1, enabled: 1 });

module.exports = mongoose.model('CloudBackup', cloudBackupSchema);

