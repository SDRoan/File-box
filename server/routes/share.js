const express = require('express');
const auth = require('../middleware/auth');
const Share = require('../models/Share');
const File = require('../models/File');
const Folder = require('../models/Folder');
const User = require('../models/User');
const FileActivity = require('../models/FileActivity');
const analytics = require('../services/analytics');
const router = express.Router();

// Create share link
router.post('/create', auth, async (req, res) => {
  try {
    const { fileId, accessType, password, expiresAt, allowDownload } = req.body;
    
    console.log('[Share] Creating share link:', { fileId, accessType, hasPassword: !!password, expiresAt });
    
    const file = await File.findById(fileId);
    if (!file) {
      console.log('[Share] File not found:', fileId);
      return res.status(404).json({ message: 'File not found' });
    }
    
    if (file.owner.toString() !== req.user._id.toString()) {
      console.log('[Share] Access denied - user is not owner');
      return res.status(403).json({ message: 'You can only share files you own' });
    }

    const shareData = {
      file: fileId,
      owner: req.user._id,
      accessType: accessType || 'view',
      allowDownload: allowDownload !== undefined ? allowDownload : true
    };
    
    if (password) {
      shareData.password = password;
    }
    
    if (expiresAt) {
      try {
        const expiryDate = new Date(expiresAt);
        if (isNaN(expiryDate.getTime())) {
          return res.status(400).json({ message: 'Invalid expiration date format' });
        }
        shareData.expiresAt = expiryDate;
      } catch (err) {
        return res.status(400).json({ message: 'Invalid expiration date format' });
      }
    }

    const share = new Share(shareData);
    await share.save();
    
    console.log('[Share] Share created successfully:', {
      shareId: share.shareId,
      fileId: share.file,
      accessType: share.accessType
    });
    
    // Return the share with shareId
    res.json({
      _id: share._id.toString(),
      shareId: share.shareId,
      file: fileId,
      owner: req.user._id.toString(),
      accessType: share.accessType,
      expiresAt: share.expiresAt,
      createdAt: share.createdAt
    });
  } catch (error) {
    console.error('[Share] Error creating share:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get share info
router.get('/:shareId', async (req, res) => {
  try {
    const share = await Share.findOne({ shareId: req.params.shareId })
      .populate('file')
      .populate('owner', 'name email');
    
    if (!share) {
      return res.status(404).json({ message: 'Share not found' });
    }

    // Check expiration
    if (share.expiresAt && new Date() > share.expiresAt) {
      return res.status(410).json({ message: 'Share link has expired' });
    }

    // Don't send password in response
    const shareData = share.toObject();
    delete shareData.password;

    res.json(shareData);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Share file with user
router.post('/user', auth, async (req, res) => {
  try {
    const { fileId, userId, permission, password, expiresAt } = req.body;
    
    const file = await File.findById(fileId);
    if (!file || file.owner.toString() !== req.user._id.toString()) {
      return res.status(404).json({ message: 'File not found' });
    }

    const userToShare = await User.findById(userId);
    if (!userToShare) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if already shared
    const alreadyShared = file.sharedWith.find(
      s => s.user.toString() === userId
    );

    const shareData = {
      user: userId,
      permission: permission || 'view'
    };

    // Add password and expiration if provided
    if (password) {
      shareData.password = password;
    }
    if (expiresAt) {
      try {
        const expiryDate = new Date(expiresAt);
        if (!isNaN(expiryDate.getTime())) {
          shareData.expiresAt = expiryDate;
        }
      } catch (err) {
        // Invalid date, ignore
      }
    }

    if (alreadyShared) {
      alreadyShared.permission = shareData.permission;
      if (shareData.password !== undefined) alreadyShared.password = shareData.password;
      if (shareData.expiresAt !== undefined) alreadyShared.expiresAt = shareData.expiresAt;
    } else {
      file.sharedWith.push(shareData);
    }

    await file.save();
    
    // Record activity
    await analytics.recordActivity(fileId, req.user._id, 'share', {
      sharedWith: userId,
      permission: permission || 'view'
    });
    
    // Send real-time notification to the user being shared with
    const io = req.app.get('io');
    if (io) {
      io.to(`user-${userId}`).emit('file-shared-with-you', {
        file: {
          _id: file._id,
          originalName: file.originalName,
          mimeType: file.mimeType,
          size: file.size
        },
        sharedBy: {
          _id: req.user._id,
          name: req.user.name,
          email: req.user.email
        },
        permission: permission || 'view',
        timestamp: new Date()
      });
    }
    
    res.json({ message: 'File shared successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get shared files
router.get('/shared/with-me', auth, async (req, res) => {
  try {
    const files = await File.find({
      'sharedWith.user': req.user._id,
      isTrashed: false
    })
    .populate('owner', 'name email')
    .populate('sharedWith.user', 'name email')
    .sort({ createdAt: -1 });

    // Enrich with share metadata
    const enrichedFiles = files.map(file => {
      const shareInfo = file.sharedWith.find(
        s => s.user._id.toString() === req.user._id.toString()
      );
      return {
        ...file.toObject(),
        sharePermission: shareInfo?.permission || 'view',
        sharedAt: file.createdAt
      };
    });

    res.json(enrichedFiles);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get files shared by me
router.get('/shared/by-me', auth, async (req, res) => {
  try {
    const files = await File.find({
      owner: req.user._id,
      'sharedWith.0': { $exists: true },
      isTrashed: false
    })
    .populate('sharedWith.user', 'name email')
    .sort({ updatedAt: -1 });

    res.json(files);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get activity for a shared file (who accessed it, when)
router.get('/activity/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check if user owns the file or has access
    const isOwner = file.owner.toString() === req.user._id.toString();
    const hasAccess = file.sharedWith.some(
      s => s.user.toString() === req.user._id.toString()
    );

    if (!isOwner && !hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Get activity for this file
    const activities = await FileActivity.find({ file: req.params.fileId })
      .populate('user', 'name email')
      .sort({ timestamp: -1 })
      .limit(50);

    res.json(activities);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get access statistics for files you've shared
router.get('/shared/by-me/stats', auth, async (req, res) => {
  try {
    const files = await File.find({
      owner: req.user._id,
      'sharedWith.0': { $exists: true },
      isTrashed: false
    });

    const fileIds = files.map(f => f._id);
    
    // Get activity stats for all shared files
    const stats = await FileActivity.aggregate([
      {
        $match: {
          file: { $in: fileIds },
          action: { $in: ['view', 'download', 'preview'] }
        }
      },
      {
        $group: {
          _id: '$file',
          viewCount: {
            $sum: { $cond: [{ $eq: ['$action', 'view'] }, 1, 0] }
          },
          downloadCount: {
            $sum: { $cond: [{ $eq: ['$action', 'download'] }, 1, 0] }
          },
          previewCount: {
            $sum: { $cond: [{ $eq: ['$action', 'preview'] }, 1, 0] }
          },
          lastAccessed: { $max: '$timestamp' },
          uniqueUsers: { $addToSet: '$user' }
        }
      },
      {
        $project: {
          fileId: '$_id',
          viewCount: 1,
          downloadCount: 1,
          previewCount: 1,
          totalAccess: { $add: ['$viewCount', '$downloadCount', '$previewCount'] },
          lastAccessed: 1,
          uniqueUserCount: { $size: '$uniqueUsers' }
        }
      }
    ]);

    res.json(stats);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Download shared file
router.get('/:shareId/download', async (req, res) => {
  try {
    const { password } = req.query;
    const share = await Share.findOne({ shareId: req.params.shareId })
      .populate('file');

    if (!share) {
      return res.status(404).json({ message: 'Share not found' });
    }

    // Check expiration
    if (share.expiresAt && new Date() > share.expiresAt) {
      return res.status(410).json({ message: 'Share link has expired' });
    }

    // Check password
    if (share.password && share.password !== password) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Check download permission
    if (share.allowDownload === false) {
      return res.status(403).json({ message: 'Downloads are not allowed for this share' });
    }

    const file = share.file;
    const fs = require('fs-extra');

    if (!await fs.pathExists(file.path)) {
      return res.status(404).json({ message: 'File not found on disk' });
    }

    // Update download count
    share.downloadCount += 1;
    await share.save();

    res.download(file.path, file.originalName);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Remove share
router.delete('/:shareId', auth, async (req, res) => {
  try {
    const share = await Share.findOne({ shareId: req.params.shareId });
    
    if (!share || share.owner.toString() !== req.user._id.toString()) {
      return res.status(404).json({ message: 'Share not found' });
    }

    await share.deleteOne();
    res.json({ message: 'Share removed' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;










