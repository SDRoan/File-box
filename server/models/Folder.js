const mongoose = require('mongoose');

const folderSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  parentFolder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    default: null
  },
  isStarred: {
    type: Boolean,
    default: false
  },
  isTrashed: {
    type: Boolean,
    default: false
  },
  deletedAt: {
    type: Date,
    default: null
  },
  recoveryPeriodDays: {
    type: Number,
    default: 30 // Default 30 days recovery period
  },
  isCourseFolder: {
    type: Boolean,
    default: false
  },
  sharedWith: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    permission: {
      type: String,
      enum: ['view', 'edit'],
      default: 'view'
    }
  }],
  dataClassification: {
    type: String,
    enum: ['Public', 'Internal', 'Confidential', 'Top Secret'],
    default: 'Internal'
  },
  encryptionEnabled: {
    type: Boolean,
    default: true
  },
  accessLog: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    action: {
      type: String,
      enum: ['view', 'edit', 'delete']
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    ipAddress: String
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

folderSchema.index({ owner: 1, parentFolder: 1 });
folderSchema.index({ owner: 1, isTrashed: 1 });

module.exports = mongoose.model('Folder', folderSchema);



