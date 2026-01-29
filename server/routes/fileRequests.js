const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const auth = require('../middleware/auth');
const FileRequest = require('../models/FileRequest');
const File = require('../models/File');
const Folder = require('../models/Folder');
const User = require('../models/User');
const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const userId = req.user._id.toString();
    const uploadPath = path.join(__dirname, '..', 'uploads', userId);
    await fs.ensureDir(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Get all file requests (user's requests)
router.get('/', auth, async (req, res) => {
  try {
    const requests = await FileRequest.find({ requester: req.user._id })
      .populate('folder')
      .sort({ createdAt: -1 });

    res.json(requests);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create file request
router.post('/', auth, async (req, res) => {
  try {
    const { title, description, folderId, expiresAt } = req.body;

    if (!title) {
      return res.status(400).json({ message: 'Title is required' });
    }

    const fileRequest = new FileRequest({
      title,
      description: description || '',
      requester: req.user._id,
      folder: folderId && folderId !== 'root' ? folderId : null,
      expiresAt: expiresAt ? new Date(expiresAt) : null
    });

    await fileRequest.save();
    await fileRequest.populate('folder');

    res.status(201).json(fileRequest);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get file request by ID
router.get('/:requestId', async (req, res) => {
  try {
    const fileRequest = await FileRequest.findOne({ requestId: req.params.requestId })
      .populate('requester', 'name email')
      .populate('folder')
      .populate('uploadedFiles.file')
      .populate('uploadedFiles.uploadedBy', 'name email');

    if (!fileRequest) {
      return res.status(404).json({ message: 'File request not found' });
    }

    // Check expiration
    if (fileRequest.expiresAt && new Date() > fileRequest.expiresAt) {
      fileRequest.status = 'closed';
      await fileRequest.save();
    }

    res.json(fileRequest);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Upload file to request
router.post('/:requestId/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const fileRequest = await FileRequest.findOne({ requestId: req.params.requestId });
    if (!fileRequest) {
      await fs.remove(req.file.path);
      return res.status(404).json({ message: 'File request not found' });
    }

    // Check expiration
    if (fileRequest.expiresAt && new Date() > fileRequest.expiresAt) {
      await fs.remove(req.file.path);
      return res.status(410).json({ message: 'File request has expired' });
    }

    if (fileRequest.status !== 'open') {
      await fs.remove(req.file.path);
      return res.status(400).json({ message: 'File request is not open' });
    }

    // Allow anonymous uploads - uploaderId can be null
    // If anonymous upload, assign to requester
    const uploaderId = req.user ? req.user._id : null;
    const targetFolder = fileRequest.folder || null;
    const fileOwner = uploaderId || fileRequest.requester;
    
    const file = new File({
      name: req.file.filename,
      originalName: req.file.originalname,
      path: req.file.path,
      size: req.file.size,
      mimeType: req.file.mimetype,
      owner: fileOwner,
      parentFolder: targetFolder
    });

    await file.save();

    // Update requester's storage if anonymous upload
    if (!uploaderId) {
      const requester = await User.findById(fileRequest.requester);
      if (requester) {
        requester.storageUsed += req.file.size;
        await requester.save();
      }
    }

    // Update requester's storage if anonymous upload
    if (!uploaderId) {
      const requester = await User.findById(fileRequest.requester);
      if (requester) {
        requester.storageUsed += req.file.size;
        await requester.save();
      }
    }

    // Add to request
    fileRequest.uploadedFiles.push({
      file: file._id,
      uploadedBy: uploaderId,
      uploadedAt: new Date()
    });

    fileRequest.status = 'fulfilled';
    fileRequest.updatedAt = new Date();
    await fileRequest.save();

    await fileRequest.populate('uploadedFiles.file');
    await fileRequest.populate('uploadedFiles.uploadedBy', 'name email');

    res.status(201).json(fileRequest);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Close file request
router.patch('/:requestId/close', auth, async (req, res) => {
  try {
    const fileRequest = await FileRequest.findOne({ requestId: req.params.requestId });

    if (!fileRequest) {
      return res.status(404).json({ message: 'File request not found' });
    }

    if (fileRequest.requester.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Only the requester can close the request' });
    }

    fileRequest.status = 'closed';
    fileRequest.updatedAt = new Date();
    await fileRequest.save();

    res.json(fileRequest);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete file request
router.delete('/:requestId', auth, async (req, res) => {
  try {
    const fileRequest = await FileRequest.findOne({ requestId: req.params.requestId })
      .populate('uploadedFiles.file');

    if (!fileRequest) {
      return res.status(404).json({ message: 'File request not found' });
    }

    if (fileRequest.requester.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Only the requester can delete the request' });
    }

    // Delete associated files if any
    if (fileRequest.uploadedFiles && fileRequest.uploadedFiles.length > 0) {
      for (const uploadedFile of fileRequest.uploadedFiles) {
        if (uploadedFile.file && uploadedFile.file.path) {
          try {
            await fs.remove(uploadedFile.file.path);
          } catch (err) {
            console.error('Error deleting file:', err);
          }
        }
        if (uploadedFile.file && uploadedFile.file._id) {
          try {
            await File.findByIdAndDelete(uploadedFile.file._id);
          } catch (err) {
            console.error('Error removing file from database:', err);
          }
        }
      }
    }

    // Delete the file request
    await fileRequest.deleteOne();

    res.json({ message: 'File request deleted successfully' });
  } catch (error) {
    console.error('Error deleting file request:', error);
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

