const mongoose = require('mongoose');

const fileMemorySchema = new mongoose.Schema({
  file: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    required: true,
    index: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Context captured at creation/upload
  creationContext: {
    timestamp: {
      type: Date,
      default: Date.now
    },
    source: {
      type: String,
      enum: ['upload', 'download', 'share', 'create', 'import', 'convert'],
      default: 'upload'
    },
    userAction: {
      type: String, // What the user was doing: "working on project X", "preparing presentation", etc.
      default: ''
    },
    relatedFiles: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'File'
    }],
    relatedFolders: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Folder'
    }],
    projectContext: {
      type: String, // Project name or context
      default: ''
    },
    meetingContext: {
      type: String, // Meeting name or context
      default: ''
    },
    deadlineContext: {
      type: Date, // Associated deadline
      default: null
    }
  },
  // AI-generated insights
  aiInsights: {
    purpose: {
      type: String, // AI-detected purpose: "research document", "presentation draft", etc.
      default: ''
    },
    keyTopics: [{
      type: String
    }],
    importance: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium'
    },
    suggestedTags: [{
      type: String
    }]
  },
  // Usage patterns over time
  usagePatterns: {
    firstAccess: {
      type: Date,
      default: null
    },
    lastAccess: {
      type: Date,
      default: null
    },
    accessFrequency: {
      type: String,
      enum: ['rare', 'occasional', 'regular', 'frequent'],
      default: 'occasional'
    },
    typicalAccessDays: [{
      type: Number // 0-6 (Sunday-Saturday)
    }],
    typicalAccessTimes: [{
      hour: Number, // 0-23
      frequency: Number
    }]
  },
  // User notes and reminders
  userNotes: [{
    content: String,
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  }],
  // Automatic links to other entities
  linkedEntities: {
    projects: [{
      type: String
    }],
    courses: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Course'
    }],
    studyGroups: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'StudyGroup'
    }],
    assignments: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Assignment'
    }]
  },
  // Contextual questions and answers (for AI assistant)
  contextualQA: [{
    question: String,
    answer: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
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

fileMemorySchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

fileMemorySchema.index({ file: 1, owner: 1 }, { unique: true });
fileMemorySchema.index({ owner: 1, 'creationContext.projectContext': 1 });
fileMemorySchema.index({ owner: 1, 'linkedEntities.projects': 1 });

module.exports = mongoose.model('FileMemory', fileMemorySchema);

