const mongoose = require('mongoose');

const annotationSchema = new mongoose.Schema({
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['highlight', 'comment', 'drawing', 'text', 'sticky'],
    required: true
  },
  page: {
    type: Number,
    required: true
  },
  position: {
    x: Number,
    y: Number,
    width: Number,
    height: Number
  },
  content: {
    type: String,
    default: ''
  },
  color: {
    type: String,
    default: '#ffff00'
  },
  strokeWidth: {
    type: Number,
    default: 2
  },
  points: [{
    x: Number,
    y: Number
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

annotationSchema.index({ file: 1, page: 1 });
annotationSchema.index({ user: 1 });

annotationSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Annotation', annotationSchema);








