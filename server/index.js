const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
require('dotenv').config();
const appConfig = require('./config/appConfig');

// Import open package for auto-opening browser
const open = require('open');

const authRoutes = require('./routes/auth');
const fileRoutes = require('./routes/files');
const shareRoutes = require('./routes/share');
const userRoutes = require('./routes/users');
const commentRoutes = require('./routes/comments');
const teamFolderRoutes = require('./routes/teamFolders');
const fileRequestRoutes = require('./routes/fileRequests');
const searchRoutes = require('./routes/search');
const debugRoutes = require('./routes/debug');
const relationshipRoutes = require('./routes/relationships');
const summarizationRoutes = require('./routes/summarization');
const smartOrganizationRoutes = require('./routes/smartOrganization');
const analyticsRoutes = require('./routes/analytics');
const socialRoutes = require('./routes/social');

// Import learning resource scheduler
const learningResourceScheduler = require('./services/learningResourceScheduler');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: appConfig.server.clientUrl,
    methods: ["GET", "POST"]
  }
});

// Middleware - CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',')
  : [appConfig.server.clientUrl || 'http://localhost:3000'];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV !== 'production') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create uploads directory if it doesn't exist
const fs = require('fs-extra');
const uploadsDir = path.join(__dirname, 'uploads');
fs.ensureDirSync(uploadsDir);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/share', shareRoutes);
app.use('/api/users', userRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api/team-folders', teamFolderRoutes);
app.use('/api/file-requests', fileRequestRoutes);
app.use('/api/search', searchRoutes);
app.use('/api/debug', debugRoutes);
app.use('/api/relationships', relationshipRoutes);
app.use('/api/summarization', summarizationRoutes);
app.use('/api/smart-org', smartOrganizationRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/social', socialRoutes);
app.use('/api/groups', require('./routes/groups'));
app.use('/api/security', require('./routes/security'));
app.use('/api/assignments', require('./routes/assignments'));
app.use('/api/courses', require('./routes/courses'));
app.use('/api/study-groups', require('./routes/studyGroups'));
app.use('/api/annotations', require('./routes/annotations'));
app.use('/api/calendar', require('./routes/calendar'));
app.use('/api/collections', require('./routes/collections'));
app.use('/api/summaries', require('./routes/summaries'));
app.use('/api/signatures', require('./routes/signatures'));
app.use('/api/ai-assistant', require('./routes/aiAssistant'));
app.use('/api/file-memory', require('./routes/fileMemory'));
app.use('/api/predictive-org', require('./routes/predictiveOrganization'));
app.use('/api/cloud-backup', require('./routes/cloudBackup'));
app.use('/api/templates', require('./routes/templates'));
app.use('/api/web-shortcuts', require('./routes/webShortcuts'));
app.use('/api/secured-links', require('./routes/securedLinks'));
app.use('/api/integrations', require('./routes/integrations'));
app.use('/api/referrals', require('./routes/referrals'));
app.use('/api/forums', require('./routes/forums'));
app.use('/api/learning', require('./routes/learning'));
app.use('/api/course-notes', require('./routes/courseNotes'));
app.use('/api/study-schedule', require('./routes/studySchedule'));
app.use('/api/progress-tracking', require('./routes/progressTracking'));
app.use('/api/study-sessions', require('./routes/studySessions'));

// Socket.io for real-time updates
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-user-room', (userId) => {
    socket.join(`user-${userId}`);
  });

  socket.on('join-team-folder', (teamFolderId) => {
    socket.join(`team-folder-${teamFolderId}`);
    console.log(`User ${socket.id} joined team folder ${teamFolderId}`);
  });

  socket.on('leave-team-folder', (teamFolderId) => {
    socket.leave(`team-folder-${teamFolderId}`);
    console.log(`User ${socket.id} left team folder ${teamFolderId}`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Make io available to routes
app.set('io', io);

// Database connection
mongoose.connect(appConfig.database.uri)
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Cleanup job: Permanently delete files/folders after recovery period (30 days)
const cleanupTrash = async () => {
  try {
    const File = require('./models/File');
    const Folder = require('./models/Folder');
    const User = require('./models/User');
    const fs = require('fs-extra');
    
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    // Find files deleted more than 30 days ago
    const expiredFiles = await File.find({
      isTrashed: true,
      deletedAt: { $lte: thirtyDaysAgo }
    });
    
    // Find folders deleted more than 30 days ago
    const expiredFolders = await Folder.find({
      isTrashed: true,
      deletedAt: { $lte: thirtyDaysAgo }
    });
    
    let deletedFilesCount = 0;
    let deletedFoldersCount = 0;
    
    // Permanently delete expired files
    for (const file of expiredFiles) {
      try {
        // Delete physical file
        if (await fs.pathExists(file.path)) {
          await fs.remove(file.path);
        }
        
        // Update user storage
        const user = await User.findById(file.owner);
        if (user) {
          user.storageUsed = Math.max(0, user.storageUsed - file.size);
          await user.save();
        }
        
        await file.deleteOne();
        deletedFilesCount++;
      } catch (error) {
        console.error(`Error permanently deleting file ${file._id}:`, error.message);
      }
    }
    
    // Permanently delete expired folders
    for (const folder of expiredFolders) {
      try {
        // Delete all files and subfolders in this folder
        await File.deleteMany({ parentFolder: folder._id });
        await Folder.deleteMany({ parentFolder: folder._id });
        
        await folder.deleteOne();
        deletedFoldersCount++;
      } catch (error) {
        console.error(`Error permanently deleting folder ${folder._id}:`, error.message);
      }
    }
    
    if (deletedFilesCount > 0 || deletedFoldersCount > 0) {
      console.log(`[Cleanup] Permanently deleted ${deletedFilesCount} files and ${deletedFoldersCount} folders after 30-day recovery period`);
    }
  } catch (error) {
    console.error('[Cleanup] Error in trash cleanup job:', error);
  }
};

// Run cleanup job every 24 hours
setInterval(cleanupTrash, 24 * 60 * 60 * 1000); // 24 hours in milliseconds
// Also run immediately on server start
setTimeout(cleanupTrash, 60000); // Run after 1 minute of server startup

// Cloud Backup Scheduler
const runCloudBackups = async () => {
  try {
    const CloudBackup = require('./models/CloudBackup');
    const cloudBackupService = require('./services/cloudBackup');
    
    const now = new Date();
    const backupsToRun = await CloudBackup.find({
      enabled: true,
      $or: [
        { nextBackupAt: { $lte: now } },
        { nextBackupAt: null }
      ]
    });

    for (const backup of backupsToRun) {
      try {
        console.log(`[Cloud Backup] Running backup for ${backup.sourceType} (${backup._id})`);
        await cloudBackupService.performBackup(backup._id);
        console.log(`[Cloud Backup] ✅ Backup completed for ${backup.sourceType}`);
      } catch (error) {
        console.error(`[Cloud Backup] ❌ Backup failed for ${backup.sourceType}:`, error.message);
      }
    }
  } catch (error) {
    console.error('[Cloud Backup] Error in backup scheduler:', error);
  }
};

// Run cloud backups every hour
setInterval(runCloudBackups, 60 * 60 * 1000); // 1 hour
// Also run after 2 minutes of server startup
setTimeout(runCloudBackups, 120000); // Run after 2 minutes

const PORT = appConfig.server.port;
const CLIENT_URL = appConfig.server.clientUrl;
const CLIENT_PORT = CLIENT_URL.includes(':') 
  ? CLIENT_URL.split(':').pop().replace('/', '') 
  : '3000';

server.listen(PORT, '127.0.0.1', () => {
  console.log('\n' + '═'.repeat(70));
  console.log('🚀  SERVER STARTED SUCCESSFULLY!');
  console.log('═'.repeat(70));
  console.log(`📡 Backend API:  http://localhost:${PORT}`);
  console.log(`🌐 Frontend App: http://localhost:${CLIENT_PORT}`);
  console.log('═'.repeat(70));
  
  // Start learning resource scheduler (updates resources every 24 hours)
  try {
    learningResourceScheduler.start();
  } catch (error) {
    console.error('Failed to start learning resource scheduler:', error);
  }
  console.log(`\n✨  👉  OPEN YOUR BROWSER: http://localhost:${CLIENT_PORT}  👈  ✨\n`);
  console.log('═'.repeat(70) + '\n');
  
  // Automatically open browser in Google Chrome after a short delay
  const frontendUrl = `http://localhost:${CLIENT_PORT}`;
  setTimeout(() => {
    // Open specifically in Google Chrome
    const isMac = process.platform === 'darwin';
    
    if (isMac) {
      // On macOS, use 'google chrome' as the app name
      open(frontendUrl, { app: 'google chrome' }).catch(err => {
        // Fallback: try alternative Chrome paths
        console.log(`⚠️  Could not open in Chrome, trying alternative...`);
        open(frontendUrl, { app: '/Applications/Google Chrome.app' }).catch(fallbackErr => {
          console.log(`⚠️  Could not automatically open Chrome. Please manually open: ${frontendUrl}`);
          console.log(`   Error: ${fallbackErr.message}`);
        });
      });
    } else {
      // On other platforms, try 'chrome' or default browser
      open(frontendUrl, { app: 'chrome' }).catch(err => {
        open(frontendUrl).catch(fallbackErr => {
          console.log(`⚠️  Could not automatically open browser. Please manually open: ${frontendUrl}`);
        });
      });
    }
  }, 1000);
});

