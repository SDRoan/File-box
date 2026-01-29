const mongoose = require('mongoose');

const reactionSchema = new mongoose.Schema({
  emoji: {
    type: String,
    required: true
  },
  users: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  count: {
    type: Number,
    default: 0
  }
}, { _id: false });

const teamFolderMessageSchema = new mongoose.Schema({
  teamFolder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'TeamFolder',
    required: true,
    index: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['text', 'file', 'system', 'thread'],
    default: 'text'
  },
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    default: null
  },
  threadParent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'TeamFolderMessage',
    default: null
  },
  mentions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  reactions: [reactionSchema],
  isEdited: {
    type: Boolean,
    default: false
  },
  editedAt: {
    type: Date,
    default: null
  },
  isPinned: {
    type: Boolean,
    default: false
  },
  pinnedAt: {
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

teamFolderMessageSchema.index({ teamFolder: 1, createdAt: -1 });
teamFolderMessageSchema.index({ threadParent: 1 });
teamFolderMessageSchema.index({ sender: 1 });
teamFolderMessageSchema.index({ 'mentions': 1 });

module.exports = mongoose.model('TeamFolderMessage', teamFolderMessageSchema);
