const mongoose = require('mongoose');

const studySessionSchema = new mongoose.Schema({
  course: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true,
    index: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  startTime: {
    type: Date,
    required: true
  },
  endTime: {
    type: Date,
    default: null
  },
  duration: {
    type: Number, // Duration in minutes
    default: 0
  },
  topic: {
    type: String,
    trim: true
  },
  filesAccessed: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File'
  }],
  notesCreated: {
    type: Number,
    default: 0
  },
  productivity: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  notes: {
    type: String,
    default: ''
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

studySessionSchema.index({ course: 1, user: 1, startTime: -1 });
studySessionSchema.index({ user: 1, startTime: -1 });

studySessionSchema.pre('save', function(next) {
  if (this.endTime && this.startTime) {
    this.duration = Math.round((this.endTime - this.startTime) / (1000 * 60)); // Convert to minutes
  }
  next();
});

module.exports = mongoose.model('StudySession', studySessionSchema);
