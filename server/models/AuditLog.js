const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'login', 'logout', 'login_failed',
      'file_upload', 'file_download', 'file_delete', 'file_share', 'file_move', 'file_copy',
      'folder_create', 'folder_delete', 'folder_share', 'folder_move',
      'user_create', 'user_update', 'user_delete',
      'permission_grant', 'permission_revoke',
      'security_settings_change', 'mfa_enabled', 'mfa_disabled',
      'data_classification_change', 'access_denied'
    ]
  },
  resourceType: {
    type: String,
    enum: ['file', 'folder', 'user', 'system', null],
    default: null
  },
  resourceId: {
    type: mongoose.Schema.Types.ObjectId,
    default: null
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  ipAddress: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  },
  status: {
    type: String,
    enum: ['success', 'failure', 'denied'],
    default: 'success'
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for efficient queries
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ resourceType: 1, resourceId: 1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);








