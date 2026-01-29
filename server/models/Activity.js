const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    default: null
  },
  folder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    default: null
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  action: {
    type: String,
    enum: [
      'uploaded',
      'downloaded',
      'deleted',
      'restored',
      'renamed',
      'moved',
      'copied',
      'shared',
      'starred',
      'unstarred',
      'version_created',
      'version_restored',
      'commented'
    ],
    required: true
  },
  details: {
    type: String,
    default: ''
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

activitySchema.index({ file: 1, createdAt: -1 });
activitySchema.index({ folder: 1, createdAt: -1 });
activitySchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model('Activity', activitySchema);










