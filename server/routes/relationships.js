const express = require('express');
const auth = require('../middleware/auth');
const FileRelationship = require('../models/FileRelationship');
const File = require('../models/File');
const router = express.Router();

/**
 * Create a relationship between two files
 */
router.post('/', auth, async (req, res) => {
  try {
    const { sourceFileId, targetFileId, relationshipType, customLabel, description } = req.body;

    if (!sourceFileId || !targetFileId) {
      return res.status(400).json({ message: 'Source and target file IDs are required' });
    }

    if (sourceFileId === targetFileId) {
      return res.status(400).json({ message: 'A file cannot be related to itself' });
    }

    // Verify both files exist and belong to the user
    const [sourceFile, targetFile] = await Promise.all([
      File.findOne({ _id: sourceFileId, owner: req.user._id, isTrashed: { $ne: true } }),
      File.findOne({ _id: targetFileId, owner: req.user._id, isTrashed: { $ne: true } })
    ]);

    if (!sourceFile) {
      return res.status(404).json({ message: 'Source file not found' });
    }

    if (!targetFile) {
      return res.status(404).json({ message: 'Target file not found' });
    }

    // Check if relationship already exists
    const existing = await FileRelationship.findOne({
      sourceFile: sourceFileId,
      targetFile: targetFileId,
      owner: req.user._id
    });

    if (existing) {
      return res.status(400).json({ message: 'Relationship already exists' });
    }

    // Create relationship
    const relationship = new FileRelationship({
      sourceFile: sourceFileId,
      targetFile: targetFileId,
      relationshipType: relationshipType || 'related',
      customLabel: customLabel || '',
      description: description || '',
      owner: req.user._id
    });

    await relationship.save();

    // Populate file details
    await relationship.populate('sourceFile', 'originalName mimeType size');
    await relationship.populate('targetFile', 'originalName mimeType size');

    res.status(201).json(relationship);
  } catch (error) {
    console.error('Error creating relationship:', error);
    res.status(500).json({ message: 'Failed to create relationship', error: error.message });
  }
});

/**
 * Get all relationships for a file
 */
router.get('/file/:fileId', auth, async (req, res) => {
  try {
    const { fileId } = req.params;

    // Verify file exists and belongs to user
    const file = await File.findOne({ _id: fileId, owner: req.user._id });
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Get all relationships where this file is source or target
    const relationships = await FileRelationship.find({
      $or: [
        { sourceFile: fileId, owner: req.user._id },
        { targetFile: fileId, owner: req.user._id }
      ]
    })
      .populate('sourceFile', 'originalName mimeType size createdAt')
      .populate('targetFile', 'originalName mimeType size createdAt')
      .sort({ createdAt: -1 });

    // Separate into outgoing and incoming relationships
    const outgoing = relationships.filter(r => r.sourceFile._id.toString() === fileId);
    const incoming = relationships.filter(r => r.targetFile._id.toString() === fileId);

    res.json({
      file: {
        _id: file._id,
        originalName: file.originalName
      },
      outgoing,
      incoming,
      all: relationships
    });
  } catch (error) {
    console.error('Error fetching relationships:', error);
    res.status(500).json({ message: 'Failed to fetch relationships', error: error.message });
  }
});

/**
 * Get all relationships for the user (for graph view)
 */
router.get('/graph', auth, async (req, res) => {
  try {
    console.log('[Relationships] Fetching graph for user:', req.user._id);
    const relationships = await FileRelationship.find({ owner: req.user._id })
      .populate('sourceFile', 'originalName mimeType size')
      .populate('targetFile', 'originalName mimeType size')
      .sort({ createdAt: -1 });

    console.log('[Relationships] Found', relationships.length, 'relationships');

    // Filter out relationships where files don't exist or are null
    const validRelationships = relationships.filter(rel => 
      rel.sourceFile && rel.targetFile && 
      rel.sourceFile._id && rel.targetFile._id
    );

    console.log('[Relationships] Valid relationships:', validRelationships.length);

    // Get all unique files involved in relationships
    const fileIds = new Set();
    validRelationships.forEach(rel => {
      if (rel.sourceFile && rel.sourceFile._id) {
        fileIds.add(rel.sourceFile._id.toString());
      }
      if (rel.targetFile && rel.targetFile._id) {
        fileIds.add(rel.targetFile._id.toString());
      }
    });

    console.log('[Relationships] Unique file IDs:', Array.from(fileIds));

    const files = await File.find({
      _id: { $in: Array.from(fileIds) },
      owner: req.user._id,
      isTrashed: { $ne: true }
    }).select('originalName mimeType size createdAt');

    console.log('[Relationships] Found', files.length, 'files');

    const response = {
      nodes: files.map(file => ({
        id: file._id.toString(),
        name: file.originalName,
        type: file.mimeType,
        size: file.size
      })),
      edges: validRelationships.map(rel => ({
        id: rel._id.toString(),
        source: rel.sourceFile._id.toString(),
        target: rel.targetFile._id.toString(),
        type: rel.relationshipType,
        label: rel.customLabel || rel.relationshipType,
        description: rel.description
      }))
    };

    console.log('[Relationships] Sending response:', {
      nodes: response.nodes.length,
      edges: response.edges.length
    });

    res.json(response);
  } catch (error) {
    console.error('Error fetching relationship graph:', error);
    res.status(500).json({ message: 'Failed to fetch relationship graph', error: error.message });
  }
});

/**
 * Update a relationship
 */
router.put('/:relationshipId', auth, async (req, res) => {
  try {
    const { relationshipId } = req.params;
    const { relationshipType, customLabel, description } = req.body;

    const relationship = await FileRelationship.findOne({
      _id: relationshipId,
      owner: req.user._id
    });

    if (!relationship) {
      return res.status(404).json({ message: 'Relationship not found' });
    }

    if (relationshipType) {
      relationship.relationshipType = relationshipType;
    }
    if (customLabel !== undefined) {
      relationship.customLabel = customLabel;
    }
    if (description !== undefined) {
      relationship.description = description;
    }

    await relationship.save();

    // Populate file details
    await relationship.populate('sourceFile', 'originalName mimeType size');
    await relationship.populate('targetFile', 'originalName mimeType size');

    res.json(relationship);
  } catch (error) {
    console.error('Error updating relationship:', error);
    res.status(500).json({ message: 'Failed to update relationship', error: error.message });
  }
});

/**
 * Delete a relationship
 */
router.delete('/:relationshipId', auth, async (req, res) => {
  try {
    const { relationshipId } = req.params;

    const relationship = await FileRelationship.findOne({
      _id: relationshipId,
      owner: req.user._id
    });

    if (!relationship) {
      return res.status(404).json({ message: 'Relationship not found' });
    }

    await FileRelationship.deleteOne({ _id: relationshipId });
    res.json({ message: 'Relationship deleted successfully' });
  } catch (error) {
    console.error('Error deleting relationship:', error);
    res.status(500).json({ message: 'Failed to delete relationship', error: error.message });
  }
});

/**
 * Get suggested relationships (files that might be related)
 */
router.get('/suggestions/:fileId', auth, async (req, res) => {
  try {
    const { fileId } = req.params;
    const file = await File.findOne({ _id: fileId, owner: req.user._id });

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Get files with similar names or in the same folder
    const suggestions = await File.find({
      _id: { $ne: fileId },
      owner: req.user._id,
      isTrashed: { $ne: true },
      $or: [
        { parentFolder: file.parentFolder },
        { originalName: { $regex: file.originalName.split('.')[0], $options: 'i' } }
      ]
    })
      .limit(10)
      .select('originalName mimeType size createdAt parentFolder');

    res.json({ suggestions });
  } catch (error) {
    console.error('Error fetching suggestions:', error);
    res.status(500).json({ message: 'Failed to fetch suggestions', error: error.message });
  }
});

module.exports = router;







