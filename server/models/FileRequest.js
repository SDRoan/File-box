const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const fileRequestSchema = new mongoose.Schema({
  requestId: {
    type: String,
    default: () => uuidv4(),
    unique: true
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  requester: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  folder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    default: null
  },
  status: {
    type: String,
    enum: ['open', 'fulfilled', 'closed'],
    default: 'open'
  },
  uploadedFiles: [{
    file: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'File'
    },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  expiresAt: {
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

fileRequestSchema.index({ requester: 1, createdAt: -1 });
fileRequestSchema.index({ requestId: 1 });

module.exports = mongoose.model('FileRequest', fileRequestSchema);










