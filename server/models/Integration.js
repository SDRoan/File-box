const mongoose = require('mongoose');

const integrationSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  provider: {
    type: String,
    enum: ['microsoft_teams', 'zoom', 'slack', 'google_drive', 'dropbox'],
    required: true
  },
  accessToken: {
    type: String,
    required: true
  },
  refreshToken: {
    type: String,
    default: null
  },
  tokenExpiresAt: {
    type: Date,
    default: null
  },
  providerUserId: {
    type: String,
    default: null
  },
  providerEmail: {
    type: String,
    default: null
  },
  enabled: {
    type: Boolean,
    default: true
  },
  settings: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: {}
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

integrationSchema.index({ user: 1, provider: 1 }, { unique: true });

module.exports = mongoose.model('Integration', integrationSchema);

