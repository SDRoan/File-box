const mongoose = require('mongoose');

const socialPostSchema = new mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
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
  description: {
    type: String,
    default: '',
    maxlength: 500
  },
  likes: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  comments: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    text: {
      type: String,
      required: true,
      maxlength: 500
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  downloadCount: {
    type: Number,
    default: 0
  },
  viewCount: {
    type: Number,
    default: 0
  },
  isPublic: {
    type: Boolean,
    default: true
  },
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Group',
    default: null,
    index: true
  },
  originalPost: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SocialPost',
    default: null
  },
  repostedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  repostCount: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes for performance
socialPostSchema.index({ owner: 1, createdAt: -1 });
socialPostSchema.index({ createdAt: -1 });
socialPostSchema.index({ 'likes.user': 1 });

module.exports = mongoose.model('SocialPost', socialPostSchema);

