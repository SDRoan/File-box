const mongoose = require('mongoose');

const teamFolderSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  members: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    role: {
      type: String,
      enum: ['admin', 'editor', 'viewer'],
      default: 'viewer'
    },
    joinedAt: {
      type: Date,
      default: Date.now
    }
  }],
  parentFolder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'TeamFolder',
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

teamFolderSchema.index({ owner: 1 });
teamFolderSchema.index({ 'members.user': 1 });

module.exports = mongoose.model('TeamFolder', teamFolderSchema);










