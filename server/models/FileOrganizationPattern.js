const mongoose = require('mongoose');

const fileOrganizationPatternSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Pattern details
  patternType: {
    type: String,
    enum: ['file_type_to_folder', 'file_name_pattern_to_folder', 'source_folder_to_destination', 'time_based', 'project_based'],
    required: true
  },
  // What triggers this pattern
  trigger: {
    fileType: String, // e.g., 'application/pdf', 'image/png'
    fileExtension: String, // e.g., 'pdf', 'docx'
    fileNamePattern: String, // regex pattern
    sourceFolder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Folder'
    },
    projectContext: String,
    timeOfDay: Number, // 0-23
    dayOfWeek: Number // 0-6
  },
  // Where files typically go
  destinationFolder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Folder',
    required: true
  },
  destinationFolderName: String, // Cache for quick access
  // Pattern strength/confidence
  confidence: {
    type: Number,
    default: 0.5,
    min: 0,
    max: 1
  },
  // Pattern statistics
  occurrences: {
    type: Number,
    default: 1
  },
  lastOccurrence: {
    type: Date,
    default: Date.now
  },
  firstSeen: {
    type: Date,
    default: Date.now
  },
  // Context around the pattern
  context: {
    actionBefore: String, // e.g., 'viewed', 'downloaded', 'shared'
    timeAfterUpload: Number, // minutes after upload
    fileSizeRange: {
      min: Number,
      max: Number
    }
  },
  // AI-generated explanation
  aiExplanation: {
    type: String,
    default: ''
  },
  // User feedback
  userFeedback: [{
    action: {
      type: String,
      enum: ['accepted', 'rejected', 'ignored']
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  // Pattern status
  isActive: {
    type: Boolean,
    default: true
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

fileOrganizationPatternSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Indexes for efficient queries
fileOrganizationPatternSchema.index({ user: 1, isActive: 1 });
fileOrganizationPatternSchema.index({ user: 1, 'trigger.fileType': 1 });
fileOrganizationPatternSchema.index({ user: 1, 'trigger.fileExtension': 1 });
fileOrganizationPatternSchema.index({ user: 1, 'trigger.sourceFolder': 1 });
fileOrganizationPatternSchema.index({ user: 1, confidence: -1 }); // For sorting by confidence

module.exports = mongoose.model('FileOrganizationPattern', fileOrganizationPatternSchema);

