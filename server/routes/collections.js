const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const FileCollection = require('../models/FileCollection');
const File = require('../models/File');
const Folder = require('../models/Folder');

// Get all collections for user
router.get('/', auth, async (req, res) => {
  try {
    const { public: isPublic } = req.query;
    const query = isPublic === 'true' 
      ? { isPublic: true }
      : { owner: req.user._id };
    
    const collections = await FileCollection.find(query)
      .populate('owner', 'name email')
      .populate('files.file', 'originalName mimeType size')
      .populate('files.folder', 'name')
      .sort({ createdAt: -1 });
    
    res.json(collections);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single collection
router.get('/:id', auth, async (req, res) => {
  try {
    const collection = await FileCollection.findOne({
      _id: req.params.id,
      $or: [
        { owner: req.user._id },
        { isPublic: true },
        { sharedWith: { $elemMatch: { user: req.user._id } } }
      ]
    })
      .populate('owner', 'name email')
      .populate('files.file', 'originalName mimeType size')
      .populate('files.folder', 'name');
    
    if (!collection) {
      return res.status(404).json({ message: 'Collection not found' });
    }
    
    // Increment view count
    collection.viewCount += 1;
    await collection.save();
    
    res.json(collection);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create collection
router.post('/', auth, async (req, res) => {
  try {
    const { name, description, files, isPublic, tags } = req.body;
    
    if (!name) {
      return res.status(400).json({ message: 'Collection name is required' });
    }
    
    const collection = new FileCollection({
      name,
      description,
      owner: req.user._id,
      files: files || [],
      isPublic: isPublic || false,
      tags: tags || []
    });
    
    await collection.save();
    
    const populated = await FileCollection.findById(collection._id)
      .populate('owner', 'name email')
      .populate('files.file', 'originalName mimeType size')
      .populate('files.folder', 'name');
    
    res.status(201).json(populated);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update collection
router.put('/:id', auth, async (req, res) => {
  try {
    const collection = await FileCollection.findOne({
      _id: req.params.id,
      owner: req.user._id
    });
    
    if (!collection) {
      return res.status(404).json({ message: 'Collection not found' });
    }
    
    const { name, description, files, isPublic, tags } = req.body;
    
    if (name) collection.name = name;
    if (description !== undefined) collection.description = description;
    if (files !== undefined) collection.files = files;
    if (isPublic !== undefined) collection.isPublic = isPublic;
    if (tags !== undefined) collection.tags = tags;
    
    collection.updatedAt = new Date();
    await collection.save();
    
    const populated = await FileCollection.findById(collection._id)
      .populate('owner', 'name email')
      .populate('files.file', 'originalName mimeType size')
      .populate('files.folder', 'name');
    
    res.json(populated);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Add file to collection
router.post('/:id/files', auth, async (req, res) => {
  try {
    const { fileId, folderId, note } = req.body;
    
    if (!fileId && !folderId) {
      return res.status(400).json({ message: 'File or folder ID is required' });
    }
    
    const collection = await FileCollection.findOne({
      _id: req.params.id,
      $or: [
        { owner: req.user._id },
        { sharedWith: { $elemMatch: { user: req.user._id, permission: 'edit' } } }
      ]
    });
    
    if (!collection) {
      return res.status(404).json({ message: 'Collection not found' });
    }
    
    // Check if already in collection
    const exists = collection.files.some(
      f => (fileId && f.file?.toString() === fileId) || 
           (folderId && f.folder?.toString() === folderId)
    );
    
    if (exists) {
      return res.status(400).json({ message: 'File/folder already in collection' });
    }
    
    collection.files.push({
      file: fileId || null,
      folder: folderId || null,
      note: note || ''
    });
    
    collection.updatedAt = new Date();
    await collection.save();
    
    const populated = await FileCollection.findById(collection._id)
      .populate('owner', 'name email')
      .populate('files.file', 'originalName mimeType size')
      .populate('files.folder', 'name');
    
    res.json(populated);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Remove file from collection
router.delete('/:id/files/:fileIndex', auth, async (req, res) => {
  try {
    const collection = await FileCollection.findOne({
      _id: req.params.id,
      $or: [
        { owner: req.user._id },
        { sharedWith: { $elemMatch: { user: req.user._id, permission: 'edit' } } }
      ]
    });
    
    if (!collection) {
      return res.status(404).json({ message: 'Collection not found' });
    }
    
    const index = parseInt(req.params.fileIndex);
    if (index < 0 || index >= collection.files.length) {
      return res.status(400).json({ message: 'Invalid file index' });
    }
    
    collection.files.splice(index, 1);
    collection.updatedAt = new Date();
    await collection.save();
    
    res.json(collection);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete collection
router.delete('/:id', auth, async (req, res) => {
  try {
    const collection = await FileCollection.findOne({
      _id: req.params.id,
      owner: req.user._id
    });
    
    if (!collection) {
      return res.status(404).json({ message: 'Collection not found' });
    }
    
    await collection.deleteOne();
    res.json({ message: 'Collection deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Like collection
router.post('/:id/like', auth, async (req, res) => {
  try {
    const collection = await FileCollection.findById(req.params.id);
    
    if (!collection) {
      return res.status(404).json({ message: 'Collection not found' });
    }
    
    collection.likeCount += 1;
    await collection.save();
    
    res.json({ likeCount: collection.likeCount });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;








