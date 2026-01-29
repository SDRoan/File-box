require('dotenv').config();

module.exports = {
  // File Upload Configuration
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE_BYTES) || (100 * 1024 * 1024 * 1024), // Default 100GB
    allowedMimeTypes: process.env.ALLOWED_MIME_TYPES 
      ? process.env.ALLOWED_MIME_TYPES.split(',')
      : null, // null means all types allowed
  },

  // Server Configuration
  server: {
    port: parseInt(process.env.PORT) || 5001,
    clientUrl: process.env.CLIENT_URL || 'http://localhost:3000',
  },

  // Database Configuration
  database: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/dropbox-clone',
  },

  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },

  // Storage Configuration
  storage: {
    defaultLimit: parseInt(process.env.DEFAULT_STORAGE_LIMIT_BYTES) || (10 * 1024 * 1024 * 1024), // Default 10GB
  }
};










