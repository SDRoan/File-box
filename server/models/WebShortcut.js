const mongoose = require('mongoose');

const webShortcutSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true
  },
  url: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  favicon: {
    type: String, // URL to favicon
    default: null
  },
  tags: [{
    type: String
  }],
  folder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    default: null // Can organize shortcuts in folders
  },
  isStarred: {
    type: Boolean,
    default: false
  },
  clickCount: {
    type: Number,
    default: 0
  },
  lastAccessedAt: {
    type: Date,
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

webShortcutSchema.index({ user: 1, folder: 1 });
webShortcutSchema.index({ user: 1, isStarred: 1 });
webShortcutSchema.index({ user: 1, tags: 1 });

module.exports = mongoose.model('WebShortcut', webShortcutSchema);

