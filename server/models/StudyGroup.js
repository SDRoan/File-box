const mongoose = require('mongoose');

const studyGroupSchema = new mongoose.Schema({
  name: {
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
    trim: true
  },
  courseCode: {
    type: String,
    trim: true
  },
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  members: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    role: {
      type: String,
      enum: ['member', 'admin'],
      default: 'member'
    },
    joinedAt: {
      type: Date,
      default: Date.now
    }
  }],
  folder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    default: null
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  maxMembers: {
    type: Number,
    default: 50
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  // Study tools
  notes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'StudyNote'
  }],
  flashcards: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Flashcard'
  }],
  whiteboards: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Whiteboard'
  }],
  chatMessages: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ChatMessage'
  }]
});

studyGroupSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

studyGroupSchema.index({ creator: 1 });
studyGroupSchema.index({ 'members.user': 1 });
studyGroupSchema.index({ courseCode: 1 });

module.exports = mongoose.model('StudyGroup', studyGroupSchema);








