const express = require('express');
const auth = require('../middleware/auth');
const File = require('../models/File');
const Folder = require('../models/Folder');
const smartOrganization = require('../services/smartOrganization');
const router = express.Router();

/**
 * Analyze a single file and get organization suggestions
 */
router.post('/analyze/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    const suggestion = await smartOrganization.analyzeFile(file, file.path);
    res.json(suggestion);
  } catch (error) {
    console.error('Error analyzing file:', error);
    res.status(500).json({ message: 'Failed to analyze file', error: error.message });
  }
});

/**
 * Get bulk organization suggestions for multiple files
 */
router.post('/analyze-bulk', auth, async (req, res) => {
  try {
    const { fileIds } = req.body;

    if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
      return res.status(400).json({ message: 'fileIds array is required' });
    }

    // Get files
    const files = await File.find({
      _id: { $in: fileIds },
      owner: req.user._id,
      isTrashed: { $ne: true }
    });

    if (files.length === 0) {
      return res.status(404).json({ message: 'No files found' });
    }

    const result = await smartOrganization.getBulkSuggestions(files, req.user._id);
    res.json(result);
  } catch (error) {
    console.error('Error analyzing files:', error);
    res.status(500).json({ message: 'Failed to analyze files', error: error.message });
  }
});

/**
 * Get organization suggestions for all unorganized files in current folder
 */
router.get('/suggest/:folderId?', auth, async (req, res) => {
  try {
    const folderId = req.params.folderId || 'root';
    
    // Get all files in the folder
    const files = await File.find({
      owner: req.user._id,
      parentFolder: folderId === 'root' ? null : folderId,
      isTrashed: { $ne: true }
    }).limit(50); // Limit to 50 files for performance

    if (files.length === 0) {
      return res.json({
        suggestions: [],
        folderGroups: {},
        totalFiles: 0,
        message: 'No files to organize'
      });
    }

    const result = await smartOrganization.getBulkSuggestions(files, req.user._id);
    res.json(result);
  } catch (error) {
    console.error('Error getting suggestions:', error);
    res.status(500).json({ message: 'Failed to get suggestions', error: error.message });
  }
});

/**
 * Create folder and move files based on suggestions
 */
router.post('/organize', auth, async (req, res) => {
  try {
    const { folderName, fileIds, parentFolderId } = req.body;

    if (!folderName || !fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
      return res.status(400).json({ message: 'folderName and fileIds array are required' });
    }

    // Check if folder already exists
    let folder = await Folder.findOne({
      name: folderName,
      owner: req.user._id,
      parentFolder: parentFolderId || null,
      isTrashed: { $ne: true }
    });

    // Create folder if it doesn't exist
    if (!folder) {
      folder = new Folder({
        name: folderName,
        owner: req.user._id,
        parentFolder: parentFolderId || null
      });
      await folder.save();
    }

    // Move files to the folder
    const result = await File.updateMany(
      {
        _id: { $in: fileIds },
        owner: req.user._id
      },
      {
        $set: { parentFolder: folder._id }
      }
    );

    res.json({
      message: `Organized ${result.modifiedCount} files into "${folderName}"`,
      folderId: folder._id,
      folderName: folder.name,
      filesMoved: result.modifiedCount
    });
  } catch (error) {
    console.error('Error organizing files:', error);
    res.status(500).json({ message: 'Failed to organize files', error: error.message });
  }
});

module.exports = router;










