const mongoose = require('mongoose');
const crypto = require('crypto');

const securedLinkSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  url: {
    type: String,
    required: true
  },
  // Encrypted URL for sensitive links
  encryptedUrl: {
    type: String,
    default: null
  },
  // Password to access the link (hashed)
  password: {
    type: String,
    default: null // null means no password required
  },
  // Password hint (optional)
  passwordHint: {
    type: String,
    default: ''
  },
  description: {
    type: String,
    default: ''
  },
  category: {
    type: String,
    default: 'general'
  },
  tags: [{
    type: String,
    trim: true
  }],
  // Whether the link requires password to view
  isPasswordProtected: {
    type: Boolean,
    default: false
  },
  // Whether the URL should be encrypted
  isEncrypted: {
    type: Boolean,
    default: false
  },
  // Access tracking
  accessCount: {
    type: Number,
    default: 0
  },
  lastAccessedAt: {
    type: Date,
    default: null
  },
  // Expiration date (optional)
  expiresAt: {
    type: Date,
    default: null
  },
  // Notes/remarks
  notes: {
    type: String,
    default: ''
  },
  isStarred: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for efficient queries
securedLinkSchema.index({ user: 1, category: 1 });
securedLinkSchema.index({ user: 1, isStarred: 1 });
securedLinkSchema.index({ user: 1, tags: 1 });
securedLinkSchema.index({ user: 1, createdAt: -1 });

// Method to encrypt URL
securedLinkSchema.methods.encryptUrl = function(masterPassword) {
  if (!this.isEncrypted || !masterPassword) return;
  
  const algorithm = 'aes-256-cbc';
  const key = crypto.scryptSync(masterPassword, 'salt', 32);
  const iv = crypto.randomBytes(16);
  
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(this.url, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  this.encryptedUrl = iv.toString('hex') + ':' + encrypted;
  this.url = ''; // Clear original URL
};

// Method to decrypt URL
securedLinkSchema.methods.decryptUrl = function(masterPassword) {
  if (!this.isEncrypted || !this.encryptedUrl || !masterPassword) {
    return this.url;
  }
  
  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(masterPassword, 'salt', 32);
    const parts = this.encryptedUrl.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error('Failed to decrypt URL');
  }
};

// Pre-save hook to update updatedAt
securedLinkSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('SecuredLink', securedLinkSchema);
