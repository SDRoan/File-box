const FileActivity = require('../models/FileActivity');
const File = require('../models/File');
const Folder = require('../models/Folder');
const mongoose = require('mongoose');

class AnalyticsService {
  /**
   * Get file access statistics
   */
  async getFileAccessStats(userId, timeRange = '30d') {
    const dateRange = this.getDateRange(timeRange);
    
    const stats = await FileActivity.aggregate([
      {
        $match: {
          user: mongoose.Types.ObjectId.isValid(userId) ? new mongoose.Types.ObjectId(userId) : userId,
          timestamp: { $gte: dateRange.start }
        }
      },
      {
        $group: {
          _id: '$file',
          accessCount: { $sum: 1 },
          lastAccessed: { $max: '$timestamp' },
          actions: { $push: '$action' }
        }
      },
      {
        $lookup: {
          from: 'files',
          localField: '_id',
          foreignField: '_id',
          as: 'fileInfo'
        }
      },
      {
        $unwind: '$fileInfo'
      },
      {
        $project: {
          fileId: '$_id',
          fileName: '$fileInfo.originalName',
          fileSize: '$fileInfo.size',
          mimeType: '$fileInfo.mimeType',
          accessCount: 1,
          lastAccessed: 1,
          actions: 1
        }
      },
      {
        $sort: { accessCount: -1 }
      },
      {
        $limit: 100
      }
    ]);

    return stats;
  }

  /**
   * Get access heatmap data (by hour of day and day of week)
   */
  async getAccessHeatmap(userId, timeRange = '30d') {
    const dateRange = this.getDateRange(timeRange);
    
    const heatmapData = await FileActivity.aggregate([
      {
        $match: {
          user: mongoose.Types.ObjectId.isValid(userId) ? new mongoose.Types.ObjectId(userId) : userId,
          timestamp: { $gte: dateRange.start }
        }
      },
      {
        $project: {
          hour: { $hour: '$timestamp' },
          dayOfWeek: { $dayOfWeek: '$timestamp' },
          action: 1
        }
      },
      {
        $group: {
          _id: {
            hour: '$hour',
            dayOfWeek: '$dayOfWeek'
          },
          count: { $sum: 1 }
        }
      }
    ]);

    // Format for frontend
    const heatmap = {};
    heatmapData.forEach(item => {
      const key = `${item._id.dayOfWeek}-${item._id.hour}`;
      heatmap[key] = item.count;
    });

    return heatmap;
  }

  /**
   * Get unused files (not accessed in specified time)
   */
  async getUnusedFiles(userId, daysUnused = 90) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysUnused);

    // Get all files
    const allFiles = await File.find({
      owner: userId,
      isTrashed: { $ne: true }
    });

    // Get files with recent activity
    const activeFileIds = await FileActivity.distinct('file', {
      user: userId,
      timestamp: { $gte: cutoffDate }
    });

    // Find unused files
    const unusedFiles = allFiles.filter(file => 
      !activeFileIds.some(id => id.toString() === file._id.toString())
    );

    // Sort by size (largest first)
    unusedFiles.sort((a, b) => b.size - a.size);

    return unusedFiles.map(file => ({
      fileId: file._id,
      fileName: file.originalName,
      fileSize: file.size,
      mimeType: file.mimeType,
      createdAt: file.createdAt,
      daysUnused: Math.floor((new Date() - file.createdAt) / (1000 * 60 * 60 * 24))
    }));
  }

  /**
   * Get storage breakdown by file type
   */
  async getStorageBreakdown(userId) {
    const breakdown = await File.aggregate([
      {
        $match: {
          owner: mongoose.Types.ObjectId.isValid(userId) ? new mongoose.Types.ObjectId(userId) : userId,
          isTrashed: { $ne: true }
        }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $regexMatch: { input: '$mimeType', regex: /^image\// } },
              'Images',
              {
                $cond: [
                  { $regexMatch: { input: '$mimeType', regex: /^video\// } },
                  'Videos',
                  {
                    $cond: [
                      { $regexMatch: { input: '$mimeType', regex: /^audio\// } },
                      'Audio',
                      {
                        $cond: [
                          { $regexMatch: { input: '$mimeType', regex: /application\/pdf/ } },
                          'PDFs',
                          {
                            $cond: [
                              { $regexMatch: { input: '$mimeType', regex: /(word|document)/ } },
                              'Documents',
                              {
                                $cond: [
                                  { $regexMatch: { input: '$mimeType', regex: /(javascript|json|text|code)/ } },
                                  'Code/Text',
                                  'Other'
                                ]
                              }
                            ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            ]
          },
          totalSize: { $sum: '$size' },
          fileCount: { $sum: 1 }
        }
      },
      {
        $sort: { totalSize: -1 }
      }
    ]);

    return breakdown;
  }

  /**
   * Get activity timeline
   */
  async getActivityTimeline(userId, timeRange = '7d') {
    const dateRange = this.getDateRange(timeRange);
    
    const timeline = await FileActivity.aggregate([
      {
        $match: {
          user: mongoose.Types.ObjectId.isValid(userId) ? new mongoose.Types.ObjectId(userId) : userId,
          timestamp: { $gte: dateRange.start }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$timestamp'
            }
          },
          count: { $sum: 1 },
          actions: {
            $push: {
              action: '$action',
              file: '$file',
              timestamp: '$timestamp'
            }
          }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    return timeline;
  }

  /**
   * Get top file types accessed
   */
  async getTopFileTypes(userId, timeRange = '30d') {
    const dateRange = this.getDateRange(timeRange);
    
    const topTypes = await FileActivity.aggregate([
      {
        $match: {
          user: mongoose.Types.ObjectId.isValid(userId) ? new mongoose.Types.ObjectId(userId) : userId,
          timestamp: { $gte: dateRange.start }
        }
      },
      {
        $lookup: {
          from: 'files',
          localField: 'file',
          foreignField: '_id',
          as: 'fileInfo'
        }
      },
      {
        $unwind: '$fileInfo'
      },
      {
        $group: {
          _id: '$fileInfo.mimeType',
          accessCount: { $sum: 1 }
        }
      },
      {
        $sort: { accessCount: -1 }
      },
      {
        $limit: 10
      }
    ]);

    return topTypes;
  }

  /**
   * Get storage optimization suggestions
   */
  async getStorageSuggestions(userId) {
    const suggestions = [];
    
    // Get unused files
    const unusedFiles = await this.getUnusedFiles(userId, 90);
    if (unusedFiles.length > 0) {
      const totalUnusedSize = unusedFiles.reduce((sum, file) => sum + file.fileSize, 0);
      suggestions.push({
        type: 'unused_files',
        title: 'Unused Files',
        description: `${unusedFiles.length} files haven't been accessed in 90+ days`,
        potentialSavings: totalUnusedSize,
        action: 'delete_unused',
        files: unusedFiles.slice(0, 10) // Top 10 largest
      });
    }

    // Get large files
    const largeFiles = await File.find({
      owner: userId,
      isTrashed: { $ne: true },
      size: { $gte: 100 * 1024 * 1024 } // 100MB+
    })
      .sort({ size: -1 })
      .limit(10);

    if (largeFiles.length > 0) {
      suggestions.push({
        type: 'large_files',
        title: 'Large Files',
        description: `${largeFiles.length} files are over 100MB`,
        action: 'review_large',
        files: largeFiles.map(f => ({
          fileId: f._id,
          fileName: f.originalName,
          fileSize: f.size
        }))
      });
    }

    return suggestions;
  }

  /**
   * Helper: Get date range from time range string
   */
  getDateRange(timeRange) {
    const now = new Date();
    const start = new Date();

    switch (timeRange) {
      case '7d':
        start.setDate(now.getDate() - 7);
        break;
      case '30d':
        start.setDate(now.getDate() - 30);
        break;
      case '90d':
        start.setDate(now.getDate() - 90);
        break;
      case '1y':
        start.setFullYear(now.getFullYear() - 1);
        break;
      default:
        start.setDate(now.getDate() - 30);
    }

    return { start, end: now };
  }

  /**
   * Record file activity
   */
  async recordActivity(fileId, userId, action, metadata = {}) {
    try {
      const activity = new FileActivity({
        file: fileId,
        user: userId,
        action,
        metadata,
        timestamp: new Date()
      });
      await activity.save();
    } catch (error) {
      console.error('[Analytics] Error recording activity:', error);
      // Don't throw - analytics shouldn't break main functionality
    }
  }
}

module.exports = new AnalyticsService();

