const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const shareSchema = new mongoose.Schema({
  shareId: {
    type: String,
    default: () => uuidv4(),
    unique: true
  },
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  accessType: {
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
  },
  allowDownload: {
    type: Boolean,
    default: true // By default, downloads are allowed
  },
  downloadCount: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Share', shareSchema);










