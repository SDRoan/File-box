const mongoose = require('mongoose');

const fileVersionSchema = new mongoose.Schema({
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true
  },
  versionNumber: {
    type: Number,
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
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  changeDescription: {
    type: String,
    default: ''
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

fileVersionSchema.index({ file: 1, versionNumber: -1 });

module.exports = mongoose.model('FileVersion', fileVersionSchema);










