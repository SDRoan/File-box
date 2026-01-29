const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const cloudBackupService = require('../services/cloudBackup');

// Get all backups for the current user
router.get('/', auth, async (req, res) => {
  try {
    const backups = await cloudBackupService.getUserBackups(req.user._id);
    res.json(backups);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get default backup paths
router.get('/default-paths', auth, async (req, res) => {
  try {
    const paths = cloudBackupService.getDefaultBackupPaths();
    const availablePaths = {};
    
    // Check which paths exist
    for (const [key, path] of Object.entries(paths)) {
      if (path) {
        availablePaths[key] = {
          path: path,
          exists: await cloudBackupService.checkPathExists(path)
        };
      }
    }
    
    res.json(availablePaths);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create or update a backup configuration
router.post('/', auth, async (req, res) => {
  try {
    const { sourceType, sourcePath, enabled, backupFrequency } = req.body;
    
    if (!sourceType || !sourcePath) {
      return res.status(400).json({ message: 'sourceType and sourcePath are required' });
    }

    // Check if path exists and is accessible
    const pathExists = await cloudBackupService.checkPathExists(sourcePath);
    if (!pathExists) {
      return res.status(400).json({ 
        message: 'Source path does not exist or you do not have permission to access it. Please check the folder permissions.' 
      });
    }

    const backup = await cloudBackupService.createOrUpdateBackup(
      req.user._id,
      sourceType,
      sourcePath,
      { enabled, backupFrequency }
    );

    res.json(backup);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Perform a manual backup
router.post('/:backupId/backup', auth, async (req, res) => {
  try {
    const backup = await cloudBackupService.performBackup(req.params.backupId);
    res.json(backup);
  } catch (error) {
    // Check if it's a permission error
    if (error.message && (error.message.includes('Permission denied') || error.message.includes('EPERM') || error.message.includes('EACCES'))) {
      return res.status(403).json({ 
        message: error.message || 'Permission denied: Cannot access the backup folder. Please check folder permissions in System Preferences > Security & Privacy > Privacy > Full Disk Access.' 
      });
    }
    res.status(500).json({ message: error.message || 'Failed to perform backup' });
  }
});

// Update backup settings
router.put('/:backupId', auth, async (req, res) => {
  try {
    const { enabled, backupFrequency } = req.body;
    const CloudBackup = require('../models/CloudBackup');
    
    const backup = await CloudBackup.findOne({
      _id: req.params.backupId,
      user: req.user._id
    });

    if (!backup) {
      return res.status(404).json({ message: 'Backup not found' });
    }

    if (enabled !== undefined) backup.enabled = enabled;
    if (backupFrequency) backup.backupFrequency = backupFrequency;
    backup.updatedAt = new Date();
    
    await backup.save();
    res.json(backup);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete a backup configuration
router.delete('/:backupId', auth, async (req, res) => {
  try {
    await cloudBackupService.deleteBackup(req.params.backupId, req.user._id);
    res.json({ message: 'Backup configuration deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

