const express = require('express');
const auth = require('../middleware/auth');
const File = require('../models/File');
const FileContent = require('../models/FileContent');
const router = express.Router();

/**
 * Debug endpoint to check extraction status
 */
router.get('/extraction-status', auth, async (req, res) => {
  try {
    console.log('[Debug] User ID:', req.user._id);
    
    // Check all files first (including deleted)
    const allFiles = await File.find({ owner: req.user._id });
    console.log('[Debug] All files (including deleted):', allFiles.length);
    
    const files = await File.find({
      owner: req.user._id,
      isTrashed: { $ne: true }
    });
    
    console.log('[Debug] Files (not deleted):', files.length);
    console.log('[Debug] File IDs:', files.map(f => ({ id: f._id, name: f.originalName, deleted: f.isDeleted })));

    const fileContents = await FileContent.find({
      file: { $in: files.map(f => f._id) }
    });
    
    console.log('[Debug] File contents found:', fileContents.length);

    const status = files.map(file => {
      const content = fileContents.find(fc => fc.file.toString() === file._id.toString());
      return {
        filename: file.originalName,
        mimeType: file.mimeType,
        hasContent: !!content,
        extractionStatus: content?.extractionStatus || 'not_extracted',
        textLength: content?.extractedText?.length || 0,
        hasEmbedding: content?.embedding?.length > 0 || false,
        embeddingLength: content?.embedding?.length || 0
      };
    });

    res.json({
      totalFiles: files.length,
      filesWithContent: fileContents.length,
      status: status
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

