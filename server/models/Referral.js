const mongoose = require('mongoose');

const referralSchema = new mongoose.Schema({
  referrer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  referred: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true // Each user can only be referred once
  },
  referralCode: {
    type: String,
    required: true,
    unique: true
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'rewarded'],
    default: 'pending'
  },
  rewardGiven: {
    type: Boolean,
    default: false
  },
  rewardType: {
    type: String,
    enum: ['storage', 'premium', 'credit'],
    default: 'storage'
  },
  rewardAmount: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  completedAt: {
    type: Date,
    default: null
  }
});

referralSchema.index({ referrer: 1 });
referralSchema.index({ referralCode: 1 });

module.exports = mongoose.model('Referral', referralSchema);

