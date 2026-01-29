const mongoose = require('mongoose');

const FileRelationshipSchema = new mongoose.Schema({
  sourceFile: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true,
    index: true
  },
  targetFile: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true,
    index: true
  },
  relationshipType: {
    type: String,
    enum: ['related', 'depends_on', 'references', 'part_of', 'version_of', 'duplicate_of', 'custom'],
    default: 'related'
  },
  customLabel: {
    type: String,
    default: ''
  },
  description: {
    type: String,
    default: ''
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Prevent duplicate relationships
FileRelationshipSchema.index({ sourceFile: 1, targetFile: 1, owner: 1 }, { unique: true });

// Prevent self-relationships
FileRelationshipSchema.pre('save', function(next) {
  if (this.sourceFile.toString() === this.targetFile.toString()) {
    return next(new Error('A file cannot be related to itself'));
  }
  next();
});

module.exports = mongoose.model('FileRelationship', FileRelationshipSchema);










