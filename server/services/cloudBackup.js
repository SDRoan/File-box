const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const File = require('../models/File');
const Folder = require('../models/Folder');
const CloudBackup = require('../models/CloudBackup');
const User = require('../models/User');

class CloudBackupService {
  /**
   * Get default backup paths for the current OS
   */
  getDefaultBackupPaths() {
    const platform = os.platform();
    const homeDir = os.homedir();
    
    const paths = {
      desktop: null,
      documents: null
    };
    
    if (platform === 'darwin') {
      // macOS
      paths.desktop = path.join(homeDir, 'Desktop');
      paths.documents = path.join(homeDir, 'Documents');
    } else if (platform === 'win32') {
      // Windows
      paths.desktop = path.join(homeDir, 'Desktop');
      paths.documents = path.join(homeDir, 'Documents');
    } else if (platform === 'linux') {
      // Linux
      paths.desktop = path.join(homeDir, 'Desktop');
      paths.documents = path.join(homeDir, 'Documents');
    }
    
    return paths;
  }

  /**
   * Check if a path exists and is accessible
   */
  async checkPathExists(sourcePath) {
    try {
      const stats = await fs.stat(sourcePath);
      if (!stats.isDirectory()) {
        return false;
      }
      // Try to read the directory to check permissions
      try {
        await fs.readdir(sourcePath);
        return true;
      } catch (readError) {
        // Path exists but we don't have permission to read it
        if (readError.code === 'EPERM' || readError.code === 'EACCES') {
          return false; // Return false for permission errors
        }
        throw readError; // Re-throw other errors
      }
    } catch (error) {
      return false;
    }
  }

  /**
   * Create or update a cloud backup configuration
   */
  async createOrUpdateBackup(userId, sourceType, sourcePath, options = {}) {
    const backup = await CloudBackup.findOne({ user: userId, sourceType });
    
    const backupData = {
      user: userId,
      sourceType,
      sourcePath,
      enabled: options.enabled !== undefined ? options.enabled : true,
      backupFrequency: options.backupFrequency || 'daily',
      ...options
    };
    
    if (backup) {
      Object.assign(backup, backupData);
      backup.updatedAt = new Date();
      await backup.save();
      return backup;
    } else {
      const newBackup = new CloudBackup(backupData);
      await newBackup.save();
      return newBackup;
    }
  }

  /**
   * Perform a backup of a source directory
   */
  async performBackup(backupId) {
    const backup = await CloudBackup.findById(backupId).populate('user');
    if (!backup || !backup.enabled) {
      throw new Error('Backup not found or disabled');
    }

    // Check if source path exists
    const pathExists = await this.checkPathExists(backup.sourcePath);
    if (!pathExists) {
      backup.status = 'failed';
      backup.lastError = `Source path does not exist: ${backup.sourcePath}`;
      await backup.save();
      throw new Error(backup.lastError);
    }

    backup.status = 'backing_up';
    await backup.save();

    try {
      // Check if we can actually read the directory before starting backup
      try {
        await fs.readdir(backup.sourcePath);
      } catch (readError) {
        if (readError.code === 'EPERM' || readError.code === 'EACCES') {
          backup.status = 'failed';
          backup.lastError = `Permission denied: Cannot access ${backup.sourcePath}. Please check folder permissions.`;
          await backup.save();
          throw new Error(backup.lastError);
        }
        throw readError;
      }

      const userId = backup.user._id || backup.user;
      const user = await User.findById(userId);
      
      // Create a folder for this backup in the user's File Box
      const folderName = `Cloud Backup - ${backup.sourceType === 'desktop' ? 'Desktop' : backup.sourceType === 'documents' ? 'Documents' : path.basename(backup.sourcePath)}`;
      
      // Find or create backup folder
      let backupFolder = await Folder.findOne({
        owner: userId,
        name: folderName,
        isTrashed: false
      });

      if (!backupFolder) {
        backupFolder = new Folder({
          name: folderName,
          owner: userId,
          parentFolder: null
        });
        await backupFolder.save();
      }

      // Recursively backup files
      const backupResult = await this.backupDirectory(
        backup.sourcePath,
        userId,
        backupFolder._id,
        backup.lastBackupAt
      );

      // Update backup record
      backup.status = 'completed';
      backup.lastBackupAt = new Date();
      backup.backupCount += 1;
      backup.totalFilesBackedUp += backupResult.filesCount;
      backup.totalSizeBackedUp += backupResult.totalSize;
      backup.lastError = null;
      
      // Calculate next backup time
      backup.nextBackupAt = this.calculateNextBackupTime(backup.backupFrequency);
      
      await backup.save();

      return {
        success: true,
        filesBackedUp: backupResult.filesCount,
        totalSize: backupResult.totalSize,
        backupId: backup._id
      };
    } catch (error) {
      backup.status = 'failed';
      backup.lastError = error.message;
      await backup.save();
      throw error;
    }
  }

  /**
   * Recursively backup a directory
   */
  async backupDirectory(sourcePath, userId, parentFolderId, lastBackupTime) {
    const files = await fs.readdir(sourcePath);
    let filesCount = 0;
    let totalSize = 0;

    for (const item of files) {
      // Skip hidden files and system files
      if (item.startsWith('.')) continue;

      const itemPath = path.join(sourcePath, item);
      const stats = await fs.stat(itemPath);

      if (stats.isDirectory()) {
        // Create folder in File Box
        const folderName = item;
        let folder = await Folder.findOne({
          owner: userId,
          name: folderName,
          parentFolder: parentFolderId,
          isTrashed: false
        });

        if (!folder) {
          folder = new Folder({
            name: folderName,
            owner: userId,
            parentFolder: parentFolderId
          });
          await folder.save();
        }

        // Recursively backup subdirectory
        const subResult = await this.backupDirectory(
          itemPath,
          userId,
          folder._id,
          lastBackupTime
        );
        filesCount += subResult.filesCount;
        totalSize += subResult.totalSize;
      } else if (stats.isFile()) {
        // Check if file was modified since last backup
        if (lastBackupTime && stats.mtime < lastBackupTime) {
          // File hasn't changed, skip it
          continue;
        }

        // Check if file already exists
        const existingFile = await File.findOne({
          owner: userId,
          parentFolder: parentFolderId,
          originalName: item,
          isTrashed: false
        });

        if (existingFile) {
          // File exists, check if it needs updating
          const existingStats = await fs.stat(existingFile.path);
          if (existingStats.mtime >= stats.mtime) {
            // Existing file is newer or same, skip
            continue;
          }
        }

        // Copy file to File Box uploads directory
        const uploadsDir = path.join(__dirname, '..', 'uploads', userId.toString());
        await fs.ensureDir(uploadsDir);
        
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(item);
        const baseName = path.basename(item, ext);
        const destFileName = `${baseName}-${uniqueSuffix}${ext}`;
        const destPath = path.join(uploadsDir, destFileName);

        await fs.copy(itemPath, destPath);

        // Get MIME type
        const mimeType = this.getMimeType(item);

        // Create file record
        if (existingFile) {
          // Update existing file
          existingFile.path = destPath;
          existingFile.size = stats.size;
          existingFile.updatedAt = new Date();
          await existingFile.save();
        } else {
          // Create new file record
          const file = new File({
            name: destFileName,
            originalName: item,
            path: destPath,
            size: stats.size,
            mimeType: mimeType,
            owner: userId,
            parentFolder: parentFolderId
          });
          await file.save();
        }

        // Update user storage
        const user = await User.findById(userId);
        if (user) {
          user.storageUsed += stats.size;
          await user.save();
        }

        filesCount++;
        totalSize += stats.size;
      }
    }

    return { filesCount, totalSize };
  }

  /**
   * Get MIME type from file extension
   */
  getMimeType(filename) {
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
      '.pdf': 'application/pdf',
      '.doc': 'application/msword',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.txt': 'text/plain',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.mp4': 'video/mp4',
      '.mp3': 'audio/mpeg',
      '.zip': 'application/zip',
      '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    };
    return mimeTypes[ext] || 'application/octet-stream';
  }

  /**
   * Calculate next backup time based on frequency
   */
  calculateNextBackupTime(frequency) {
    const now = new Date();
    const next = new Date(now);

    switch (frequency) {
      case 'hourly':
        next.setHours(next.getHours() + 1);
        break;
      case 'daily':
        next.setDate(next.getDate() + 1);
        next.setHours(2, 0, 0, 0); // 2 AM
        break;
      case 'weekly':
        next.setDate(next.getDate() + 7);
        next.setHours(2, 0, 0, 0); // 2 AM
        break;
      default:
        next.setDate(next.getDate() + 1);
    }

    return next;
  }

  /**
   * Get all backups for a user
   */
  async getUserBackups(userId) {
    return await CloudBackup.find({ user: userId }).sort({ createdAt: -1 });
  }

  /**
   * Delete a backup configuration
   */
  async deleteBackup(backupId, userId) {
    const backup = await CloudBackup.findOne({ _id: backupId, user: userId });
    if (!backup) {
      throw new Error('Backup not found');
    }
    await backup.deleteOne();
    return true;
  }
}

module.exports = new CloudBackupService();

