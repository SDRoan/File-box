const mongoose = require('mongoose');

const flashcardSchema = new mongoose.Schema({
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'StudyGroup',
    required: true,
    index: true
  },
  front: {
    type: String,
    required: true,
    trim: true
  },
  back: {
    type: String,
    required: true,
    trim: true
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  deck: {
    type: String,
    default: 'default',
    trim: true
  },
  difficulty: {
    type: String,
    enum: ['easy', 'medium', 'hard'],
    default: 'medium'
  },
  lastReviewed: {
    type: Date,
    default: null
  },
  reviewCount: {
    type: Number,
    default: 0
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

flashcardSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

flashcardSchema.index({ group: 1, deck: 1 });
flashcardSchema.index({ author: 1 });

module.exports = mongoose.model('Flashcard', flashcardSchema);

