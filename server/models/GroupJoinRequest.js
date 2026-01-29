const mongoose = require('mongoose');

const groupJoinRequestSchema = new mongoose.Schema({
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Group',
    required: true,
    index: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  message: {
    type: String,
    maxlength: 200,
    default: ''
  },
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  reviewedAt: {
    type: Date,
    default: null
  },
  invitedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index to prevent duplicate pending requests (but allow invitations)
// Note: We don't make this unique because invitations can coexist with join requests
groupJoinRequestSchema.index({ group: 1, user: 1, status: 1 });

module.exports = mongoose.model('GroupJoinRequest', groupJoinRequestSchema);









