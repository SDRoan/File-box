const mongoose = require('mongoose');

const studyNoteSchema = new mongoose.Schema({
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'StudyGroup',
    required: true,
    index: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  content: {
    type: String,
    default: ''
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  tags: [{
    type: String,
    trim: true
  }],
  isPublic: {
    type: Boolean,
    default: true
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

studyNoteSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

studyNoteSchema.index({ group: 1, createdAt: -1 });
studyNoteSchema.index({ author: 1 });

module.exports = mongoose.model('StudyNote', studyNoteSchema);

