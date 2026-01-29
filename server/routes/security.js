const express = require('express');
const auth = require('../middleware/auth');
const AuditLog = require('../models/AuditLog');
const SecuritySettings = require('../models/SecuritySettings');
const User = require('../models/User');
const File = require('../models/File');
const Folder = require('../models/Folder');
const router = express.Router();

// Helper function to create audit log
const createAuditLog = async (userId, action, resourceType, resourceId, details, ipAddress, userAgent, status = 'success') => {
  try {
    await AuditLog.create({
      userId,
      action,
      resourceType,
      resourceId,
      details,
      ipAddress,
      userAgent,
      status
    });
  } catch (error) {
    console.error('Error creating audit log:', error);
  }
};

// Get security dashboard data
router.get('/dashboard', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get recent audit logs
    const recentLogs = await AuditLog.find({ userId })
      .sort({ timestamp: -1 })
      .limit(50)
      .populate('userId', 'name email')
      .lean();

    // Get security settings
    let securitySettings = await SecuritySettings.findOne({ userId });
    if (!securitySettings) {
      securitySettings = await SecuritySettings.create({ userId });
    }

    // Get security stats
    const totalFiles = await File.countDocuments({ owner: userId });
    const confidentialFiles = await File.countDocuments({ 
      owner: userId, 
      dataClassification: { $in: ['Confidential', 'Top Secret'] } 
    });
    
    const recentAccess = await File.aggregate([
      { $match: { owner: userId } },
      { $unwind: '$accessLog' },
      { $sort: { 'accessLog.timestamp': -1 } },
      { $limit: 20 },
      { $lookup: {
        from: 'users',
        localField: 'accessLog.userId',
        foreignField: '_id',
        as: 'user'
      }},
      { $unwind: '$user' },
      { $project: {
        fileName: '$name',
        action: '$accessLog.action',
        timestamp: '$accessLog.timestamp',
        userName: '$user.name',
        userEmail: '$user.email',
        ipAddress: '$accessLog.ipAddress'
      }}
    ]);

    // Get failed login attempts
    const failedLogins = await AuditLog.find({
      userId,
      action: 'login_failed'
    })
      .sort({ timestamp: -1 })
      .limit(10)
      .lean();

    res.json({
      recentLogs,
      securitySettings: {
        mfaEnabled: securitySettings.mfaEnabled,
        sessionTimeout: securitySettings.sessionTimeout,
        encryptionEnabled: securitySettings.encryptionEnabled,
        requireIpWhitelist: securitySettings.requireIpWhitelist
      },
      stats: {
        totalFiles,
        confidentialFiles,
        recentAccessCount: recentAccess.length
      },
      recentAccess,
      failedLogins
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get audit logs
router.get('/audit-logs', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { page = 1, limit = 50, action, startDate, endDate } = req.query;
    
    const query = { userId };
    if (action) query.action = action;
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    const logs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .populate('userId', 'name email')
      .lean();

    const total = await AuditLog.countDocuments(query);

    res.json({
      logs,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit))
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update security settings
router.put('/settings', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { sessionTimeout, requireIpWhitelist, ipWhitelist } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('user-agent');

    let securitySettings = await SecuritySettings.findOne({ userId });
    if (!securitySettings) {
      securitySettings = new SecuritySettings({ userId });
    }

    if (sessionTimeout !== undefined) securitySettings.sessionTimeout = sessionTimeout;
    if (requireIpWhitelist !== undefined) securitySettings.requireIpWhitelist = requireIpWhitelist;
    if (ipWhitelist !== undefined) securitySettings.ipWhitelist = ipWhitelist;

    await securitySettings.save();

    await createAuditLog(
      userId,
      'security_settings_change',
      'system',
      null,
      { changes: req.body },
      ipAddress,
      userAgent
    );

    res.json({ message: 'Security settings updated', securitySettings });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update data classification for file/folder
router.put('/classification/:type/:id', auth, async (req, res) => {
  try {
    const { type, id } = req.params;
    const { dataClassification } = req.body;
    const userId = req.user._id;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('user-agent');

    if (!['Public', 'Internal', 'Confidential', 'Top Secret'].includes(dataClassification)) {
      return res.status(400).json({ message: 'Invalid classification level' });
    }

    let resource;
    if (type === 'file') {
      resource = await File.findById(id);
      if (!resource || resource.owner.toString() !== userId.toString()) {
        return res.status(404).json({ message: 'File not found' });
      }
      resource.dataClassification = dataClassification;
      await resource.save();
    } else if (type === 'folder') {
      resource = await Folder.findById(id);
      if (!resource || resource.owner.toString() !== userId.toString()) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      resource.dataClassification = dataClassification;
      await resource.save();
    } else {
      return res.status(400).json({ message: 'Invalid resource type' });
    }

    await createAuditLog(
      userId,
      'data_classification_change',
      type,
      id,
      { classification: dataClassification },
      ipAddress,
      userAgent
    );

    res.json({ message: 'Classification updated', resource });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Toggle watermark for file
router.put('/watermark/:fileId', auth, async (req, res) => {
  try {
    const { fileId } = req.params;
    const { enabled } = req.body;
    const userId = req.user._id;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('user-agent');

    const file = await File.findById(fileId);
    if (!file || file.owner.toString() !== userId.toString()) {
      return res.status(404).json({ message: 'File not found' });
    }

    file.watermarkEnabled = enabled;
    await file.save();

    await createAuditLog(
      userId,
      'security_settings_change',
      'file',
      fileId,
      { watermarkEnabled: enabled },
      ipAddress,
      userAgent
    );

    res.json({ message: 'Watermark setting updated', file });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;








