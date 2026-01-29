const mongoose = require('mongoose');

const studyGroupInvitationSchema = new mongoose.Schema({
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'StudyGroup',
    required: true,
    index: true
  },
  inviter: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  invitee: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending'
  },
  message: {
    type: String,
    default: ''
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  respondedAt: {
    type: Date,
    default: null
  }
});

studyGroupInvitationSchema.index({ group: 1, invitee: 1, status: 1 });
studyGroupInvitationSchema.index({ invitee: 1, status: 1 });

module.exports = mongoose.model('StudyGroupInvitation', studyGroupInvitationSchema);

