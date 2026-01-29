const mongoose = require('mongoose');

const assignmentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ''
  },
  course: {
    type: String,
    required: true,
    trim: true
  },
  courseCode: {
    type: String,
    trim: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  dueDate: {
    type: Date,
    required: true
  },
  priority: {
    type: String,
    enum: ['Low', 'Medium', 'High', 'Urgent'],
    default: 'Medium'
  },
  status: {
    type: String,
    enum: ['Not Started', 'In Progress', 'Submitted', 'Graded'],
    default: 'Not Started'
  },
  attachedFiles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File'
  }],
  attachedFolders: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder'
  }],
  grade: {
    type: Number,
    default: null
  },
  maxPoints: {
    type: Number,
    default: null
  },
  submittedAt: {
    type: Date,
    default: null
  },
  reminderSent: {
    type: Boolean,
    default: false
  },
  tags: [{
    type: String
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

assignmentSchema.index({ owner: 1, dueDate: 1 });
assignmentSchema.index({ owner: 1, status: 1 });
assignmentSchema.index({ owner: 1, course: 1 });

assignmentSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Assignment', assignmentSchema);








