const mongoose = require('mongoose');

const fileCollectionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  files: [{
    file: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'File'
    },
    folder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Folder'
    },
    addedAt: {
      type: Date,
      default: Date.now
    },
    note: {
      type: String,
      trim: true
    }
  }],
  isPublic: {
    type: Boolean,
    default: false
  },
  tags: [{
    type: String,
    trim: true
  }],
  coverImage: {
    type: String
  },
  viewCount: {
    type: Number,
    default: 0
  },
  likeCount: {
    type: Number,
    default: 0
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
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

fileCollectionSchema.index({ owner: 1, createdAt: -1 });
fileCollectionSchema.index({ isPublic: 1, viewCount: -1 });
fileCollectionSchema.index({ tags: 1 });

module.exports = mongoose.model('FileCollection', fileCollectionSchema);








