const mongoose = require('mongoose');

const courseSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  code: {
    type: String,
    required: true,
    trim: true,
    uppercase: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  semester: {
    type: String,
    trim: true
  },
  year: {
    type: Number
  },
  instructor: {
    type: String,
    trim: true
  },
  color: {
    type: String,
    default: '#6366f1'
  },
  folder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    default: null
  },
  schedule: [{
    day: {
      type: String,
      enum: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    },
    startTime: String,
    endTime: String,
    location: String
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

courseSchema.index({ owner: 1, code: 1 });
courseSchema.index({ owner: 1, semester: 1, year: 1 });

module.exports = mongoose.model('Course', courseSchema);








