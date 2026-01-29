const mongoose = require('mongoose');

const securitySettingsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  mfaSecret: {
    type: String,
    default: null
  },
  mfaBackupCodes: [{
    type: String
  }],
  sessionTimeout: {
    type: Number, // in minutes
    default: 60
  },
  ipWhitelist: [{
    type: String
  }],
  requireIpWhitelist: {
    type: Boolean,
    default: false
  },
  lastPasswordChange: {
    type: Date,
    default: Date.now
  },
  passwordExpiryDays: {
    type: Number,
    default: 90
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  accountLockedUntil: {
    type: Date,
    default: null
  },
  encryptionEnabled: {
    type: Boolean,
    default: true
  },
  encryptionKey: {
    type: String,
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

securitySettingsSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('SecuritySettings', securitySettingsSchema);








