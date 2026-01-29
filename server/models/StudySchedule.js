const mongoose = require('mongoose');

const studyScheduleSchema = new mongoose.Schema({
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
  description: {
    type: String,
    default: ''
  },
  startTime: {
    type: Date,
    required: true
  },
  endTime: {
    type: Date,
    required: true
  },
  type: {
    type: String,
    enum: ['study_session', 'review', 'assignment_work', 'exam_prep', 'project_work', 'other'],
    default: 'study_session'
  },
  location: {
    type: String,
    trim: true
  },
  isRecurring: {
    type: Boolean,
    default: false
  },
  recurringPattern: {
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'biweekly'],
      default: 'weekly'
    },
    daysOfWeek: [{
      type: Number // 0-6 (Sunday-Saturday)
    }],
    endDate: Date
  },
  completed: {
    type: Boolean,
    default: false
  },
  reminderMinutes: {
    type: Number,
    default: 15 // Remind 15 minutes before
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

studyScheduleSchema.index({ course: 1, user: 1, startTime: 1 });
studyScheduleSchema.index({ user: 1, startTime: 1 });

studyScheduleSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('StudySchedule', studyScheduleSchema);
