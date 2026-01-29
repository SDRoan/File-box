const mongoose = require('mongoose');

const signatureSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  signatureData: {
    type: String, // Base64 encoded image data
    required: true
  },
  isDefault: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Ensure only one default signature per user
signatureSchema.pre('save', async function(next) {
  if (this.isDefault && this.isNew) {
    // Unset other default signatures for this user
    await mongoose.model('Signature').updateMany(
      { user: this.user, _id: { $ne: this._id } },
      { isDefault: false }
    );
  }
  next();
});

signatureSchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model('Signature', signatureSchema);






