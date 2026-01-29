const mongoose = require('mongoose');

const chatMessageSchema = new mongoose.Schema({
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'StudyGroup',
    required: true,
    index: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['text', 'file', 'system'],
    default: 'text'
  },
  fileUrl: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

chatMessageSchema.index({ group: 1, createdAt: -1 });
chatMessageSchema.index({ sender: 1 });

module.exports = mongoose.model('ChatMessage', chatMessageSchema);

