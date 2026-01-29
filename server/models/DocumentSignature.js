const mongoose = require('mongoose');

const documentSignatureSchema = new mongoose.Schema({
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
  signature: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Signature',
    required: true
  },
  pageNumber: {
    type: Number,
    required: true,
    default: 1
  },
  position: {
    x: { type: Number, required: true }, // X coordinate (0-1 normalized)
    y: { type: Number, required: true }, // Y coordinate (0-1 normalized)
    width: { type: Number, required: true }, // Width (0-1 normalized)
    height: { type: Number, required: true } // Height (0-1 normalized)
  },
  signedAt: {
    type: Date,
    default: Date.now
  },
  signedDocumentPath: {
    type: String, // Path to the signed PDF
    required: false
  }
});

documentSignatureSchema.index({ file: 1, user: 1 });
documentSignatureSchema.index({ file: 1, pageNumber: 1 });

module.exports = mongoose.model('DocumentSignature', documentSignatureSchema);






