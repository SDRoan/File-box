const mongoose = require('mongoose');

const courseNoteSchema = new mongoose.Schema({
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
  title: {
    type: String,
    required: true,
    trim: true
  },
  content: {
    type: String,
    default: ''
  },
  tags: [{
    type: String,
    trim: true
  }],
  topic: {
    type: String,
    trim: true
  },
  relatedFiles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File'
  }],
  isPinned: {
    type: Boolean,
    default: false
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

courseNoteSchema.index({ course: 1, user: 1, createdAt: -1 });
courseNoteSchema.index({ user: 1, tags: 1 });

courseNoteSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('CourseNote', courseNoteSchema);
