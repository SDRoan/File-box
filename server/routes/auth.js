const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Folder = require('../models/Folder');
const AuditLog = require('../models/AuditLog');
const SecuritySettings = require('../models/SecuritySettings');
const appConfig = require('../config/appConfig');
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

// Register
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ message: 'Please provide all fields' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const user = new User({ email, password, name });
    await user.save();

    // Create root folder for user
    const rootFolder = new Folder({
      name: 'My Files',
      owner: user._id,
      parentFolder: null
    });
    await rootFolder.save();

    const token = jwt.sign(
      { userId: user._id },
      appConfig.jwt.secret,
      { expiresIn: appConfig.jwt.expiresIn }
    );

    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    const userAgent = req.get('user-agent') || 'unknown';

    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      await createAuditLog(null, 'login_failed', null, null, { email, reason: 'User not found' }, ipAddress, userAgent, 'failure');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if account is locked
    const securitySettings = await SecuritySettings.findOne({ userId: user._id });
    if (securitySettings && securitySettings.accountLockedUntil && securitySettings.accountLockedUntil > new Date()) {
      await createAuditLog(user._id, 'login_failed', null, null, { email, reason: 'Account locked' }, ipAddress, userAgent, 'denied');
      return res.status(403).json({ message: 'Account is temporarily locked. Please try again later.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      // Increment failed login attempts
      if (securitySettings) {
        securitySettings.failedLoginAttempts += 1;
        if (securitySettings.failedLoginAttempts >= 5) {
          securitySettings.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 minutes
        }
        await securitySettings.save();
      }
      
      await createAuditLog(user._id, 'login_failed', null, null, { email, reason: 'Invalid password' }, ipAddress, userAgent, 'failure');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Reset failed login attempts on successful login
    if (securitySettings) {
      securitySettings.failedLoginAttempts = 0;
      securitySettings.accountLockedUntil = null;
      await securitySettings.save();
    }

    // Update user last login
    user.lastLogin = new Date();
    user.lastLoginIp = ipAddress;
    await user.save();

    const token = jwt.sign(
      { userId: user._id },
      appConfig.jwt.secret,
      { expiresIn: appConfig.jwt.expiresIn }
    );

    // Create successful login audit log
    await createAuditLog(user._id, 'login', null, null, { email }, ipAddress, userAgent, 'success');

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit,
        role: user.role,
        securityClearance: user.securityClearance
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get current user
router.get('/me', async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, appConfig.jwt.secret);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    res.json({
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit
      }
    });
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

module.exports = router;

