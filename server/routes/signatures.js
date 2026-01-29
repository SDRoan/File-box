const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Signature = require('../models/Signature');
const DocumentSignature = require('../models/DocumentSignature');
const File = require('../models/File');
const fs = require('fs-extra');
const path = require('path');

// Get all user signatures
router.get('/', auth, async (req, res) => {
  try {
    const signatures = await Signature.find({ user: req.user._id })
      .sort({ isDefault: -1, createdAt: -1 });
    res.json(signatures);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get a specific signature
router.get('/:signatureId', auth, async (req, res) => {
  try {
    const signature = await Signature.findById(req.params.signatureId);
    
    if (!signature) {
      return res.status(404).json({ message: 'Signature not found' });
    }
    
    if (signature.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    res.json(signature);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create a new signature
router.post('/', auth, async (req, res) => {
  try {
    const { name, signatureData, isDefault } = req.body;
    
    if (!name || !signatureData) {
      return res.status(400).json({ message: 'Name and signature data are required' });
    }
    
    // Validate base64 image data
    if (!signatureData.startsWith('data:image/')) {
      return res.status(400).json({ message: 'Invalid signature format. Must be base64 image data.' });
    }
    
    // If this is set as default, unset other defaults
    if (isDefault) {
      await Signature.updateMany(
        { user: req.user._id },
        { isDefault: false }
      );
    }
    
    const signature = new Signature({
      user: req.user._id,
      name: name.trim(),
      signatureData,
      isDefault: isDefault || false
    });
    
    await signature.save();
    res.status(201).json(signature);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update signature
router.put('/:signatureId', auth, async (req, res) => {
  try {
    const { name, isDefault } = req.body;
    const signature = await Signature.findById(req.params.signatureId);
    
    if (!signature) {
      return res.status(404).json({ message: 'Signature not found' });
    }
    
    if (signature.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    if (name) {
      signature.name = name.trim();
    }
    
    if (isDefault !== undefined) {
      signature.isDefault = isDefault;
      // If setting as default, unset other defaults
      if (isDefault) {
        await Signature.updateMany(
          { user: req.user._id, _id: { $ne: signature._id } },
          { isDefault: false }
        );
      }
    }
    
    await signature.save();
    res.json(signature);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete signature
router.delete('/:signatureId', auth, async (req, res) => {
  try {
    const signature = await Signature.findById(req.params.signatureId);
    
    if (!signature) {
      return res.status(404).json({ message: 'Signature not found' });
    }
    
    if (signature.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    // Check if signature is used in any documents
    const documentSignatures = await DocumentSignature.find({ signature: signature._id });
    if (documentSignatures.length > 0) {
      return res.status(400).json({ 
        message: 'Cannot delete signature that is used in documents',
        usedInDocuments: documentSignatures.length
      });
    }
    
    await signature.deleteOne();
    res.json({ message: 'Signature deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Apply signature to a document
router.post('/apply/:fileId', auth, async (req, res) => {
  try {
    const { signatureId, pageNumber, position } = req.body;
    
    if (!signatureId || !pageNumber || !position) {
      return res.status(400).json({ 
        message: 'Signature ID, page number, and position are required' 
      });
    }
    
    // Verify file exists and user has access
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    if (file.owner.toString() !== req.user._id.toString() &&
        !file.sharedWith.some(s => s.user.toString() === req.user._id.toString())) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    // Verify signature exists and belongs to user
    const signature = await Signature.findById(signatureId);
    if (!signature) {
      return res.status(404).json({ message: 'Signature not found' });
    }
    
    if (signature.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    // Only allow PDFs for now
    if (!file.mimeType.includes('pdf')) {
      return res.status(400).json({ message: 'Signatures can only be applied to PDF files' });
    }
    
    // Check if file exists on disk
    const filePath = path.isAbsolute(file.path) 
      ? file.path 
      : path.join(__dirname, '..', file.path);
    
    if (!await fs.pathExists(filePath)) {
      return res.status(404).json({ message: 'File not found on disk' });
    }
    
    // Apply signature to PDF
    const signedPdfPath = await applySignatureToPDF(
      filePath,
      signature.signatureData,
      pageNumber,
      position,
      file.owner.toString()
    );
    
    // Create document signature record
    const documentSignature = new DocumentSignature({
      file: file._id,
      user: req.user._id,
      signature: signature._id,
      pageNumber,
      position,
      signedDocumentPath: signedPdfPath
    });
    
    await documentSignature.save();
    
    // Update file path to point to signed version
    file.path = signedPdfPath;
    await file.save();
    
    res.status(201).json({
      message: 'Signature applied successfully',
      documentSignature,
      signedFile: {
        id: file._id,
        path: signedPdfPath
      }
    });
  } catch (error) {
    console.error('Error applying signature:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get signatures applied to a document
router.get('/document/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    if (file.owner.toString() !== req.user._id.toString() &&
        !file.sharedWith.some(s => s.user.toString() === req.user._id.toString())) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    const documentSignatures = await DocumentSignature.find({ file: file._id })
      .populate('signature', 'name')
      .populate('user', 'name email')
      .sort({ signedAt: -1 });
    
    res.json(documentSignatures);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Helper function to apply signature to PDF
// Note: For now, we store signature positions and render them as overlays in the frontend
// This is more efficient and doesn't modify the original PDF
async function applySignatureToPDF(pdfPath, signatureData, pageNumber, position, userId) {
  try {
    // Validate PDF exists
    const fileExists = await fs.pathExists(pdfPath);
    if (!fileExists) {
      throw new Error('PDF file not found');
    }
    
    // For now, we skip PDF validation to avoid pdf-parse issues
    // The frontend will handle signature placement and validation
    // If you need page count validation, uncomment below:
    /*
    const pdfParse = require('pdf-parse');
    const originalPdfBuffer = await fs.readFile(pdfPath);
    const pdfData = await pdfParse(originalPdfBuffer);
    const totalPages = pdfData.numpages || 1;
    
    if (pageNumber < 1 || pageNumber > totalPages) {
      throw new Error(`Invalid page number. PDF has ${totalPages} pages.`);
    }
    */
    
    // Return original path - signature overlay will be handled in frontend
    // This approach is more efficient and preserves the original document
    return pdfPath;
  } catch (error) {
    console.error('Error validating PDF:', error);
    // If validation fails, still return the path - frontend will handle it
    return pdfPath;
  }
}

module.exports = router;

