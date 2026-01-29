const mongoose = require('mongoose');

const calendarEventSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ''
  },
  type: {
    type: String,
    enum: ['assignment', 'exam', 'class', 'study', 'personal', 'other'],
    default: 'other'
  },
  course: {
    type: String,
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
  startDate: {
    type: Date,
    required: true
  },
  endDate: {
    type: Date,
    default: null
  },
  allDay: {
    type: Boolean,
    default: false
  },
  location: {
    type: String,
    trim: true
  },
  color: {
    type: String,
    default: '#6366f1'
  },
  reminder: {
    enabled: {
      type: Boolean,
      default: true
    },
    minutesBefore: {
      type: Number,
      default: 15
    }
  },
  assignment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Assignment',
    default: null
  },
  recurring: {
    enabled: {
      type: Boolean,
      default: false
    },
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly'],
      default: 'weekly'
    },
    endDate: {
      type: Date,
      default: null
    }
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

calendarEventSchema.index({ owner: 1, startDate: 1 });
calendarEventSchema.index({ owner: 1, type: 1 });
calendarEventSchema.index({ assignment: 1 });

calendarEventSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('CalendarEvent', calendarEventSchema);








