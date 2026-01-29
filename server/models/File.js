const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  path: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  mimeType: {
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
  isFolder: {
    type: Boolean,
    default: false
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
  sharedWith: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    permission: {
      type: String,
      enum: ['view', 'edit'],
      default: 'view'
    },
    password: {
      type: String,
      default: null
    },
    expiresAt: {
      type: Date,
      default: null
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
  watermarkEnabled: {
    type: Boolean,
    default: false
  },
  accessLog: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    action: {
      type: String,
      enum: ['view', 'download', 'edit', 'delete']
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

fileSchema.index({ owner: 1, parentFolder: 1 });
fileSchema.index({ owner: 1, isTrashed: 1 });

module.exports = mongoose.model('File', fileSchema);



