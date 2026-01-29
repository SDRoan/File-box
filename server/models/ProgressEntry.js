const mongoose = require('mongoose');

const progressEntrySchema = new mongoose.Schema({
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
  assignmentName: {
    type: String,
    required: true,
    trim: true
  },
  pointsEarned: {
    type: Number,
    default: 0
  },
  pointsPossible: {
    type: Number,
    required: true
  },
  percentage: {
    type: Number,
    default: 0
  },
  category: {
    type: String,
    enum: ['homework', 'quiz', 'exam', 'project', 'participation', 'lab', 'other'],
    default: 'homework'
  },
  weight: {
    type: Number,
    default: 1 // Weight in grade calculation
  },
  dateCompleted: {
    type: Date,
    default: Date.now
  },
  notes: {
    type: String,
    default: ''
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

progressEntrySchema.index({ course: 1, user: 1, dateCompleted: -1 });
progressEntrySchema.index({ user: 1, course: 1 });

progressEntrySchema.pre('save', function(next) {
  if (this.pointsPossible > 0) {
    this.percentage = (this.pointsEarned / this.pointsPossible) * 100;
  }
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('ProgressEntry', progressEntrySchema);
