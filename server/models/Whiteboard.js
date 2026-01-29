const mongoose = require('mongoose');

const whiteboardSchema = new mongoose.Schema({
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'StudyGroup',
    required: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    trim: true,
    default: 'Untitled Whiteboard'
  },
  content: {
    type: String,
    default: '{}' // JSON string for whiteboard data
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
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

whiteboardSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

whiteboardSchema.index({ group: 1, createdAt: -1 });
whiteboardSchema.index({ author: 1 });

module.exports = mongoose.model('Whiteboard', whiteboardSchema);

