const mongoose = require('mongoose');

const followSchema = new mongoose.Schema({
  follower: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  following: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Prevent duplicate follows
followSchema.index({ follower: 1, following: 1 }, { unique: true });

// Prevent self-follow
followSchema.pre('save', function(next) {
  if (this.follower.toString() === this.following.toString()) {
    return next(new Error('Cannot follow yourself'));
  }
  next();
});

module.exports = mongoose.model('Follow', followSchema);









