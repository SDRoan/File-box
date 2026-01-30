const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const Folder = require('../models/Folder');
const AuditLog = require('../models/AuditLog');
const SecuritySettings = require('../models/SecuritySettings');
const EmailVerification = require('../models/EmailVerification');
const emailService = require('../services/emailService');
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

// Generate verification code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
}

// Step 1: Register - Send verification code
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ message: 'Please provide all fields' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Check if there's a pending verification for this email
    const existingVerification = await EmailVerification.findOne({ 
      email, 
      verified: false,
      expiresAt: { $gt: new Date() }
    });

    // Hash password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    const verificationCode = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    if (existingVerification) {
      // Update existing verification
      existingVerification.code = verificationCode;
      existingVerification.registrationData = {
        name,
        password: hashedPassword,
        email
      };
      existingVerification.expiresAt = expiresAt;
      existingVerification.attempts = 0;
      await existingVerification.save();
    } else {
      // Create new verification
      await EmailVerification.create({
        email,
        code: verificationCode,
        registrationData: {
          name,
          password: hashedPassword,
          email
        },
        expiresAt
      });
    }

    // Send verification email
    try {
      await emailService.sendVerificationCode(email, verificationCode, name);
      res.status(200).json({ 
        message: 'Verification code sent to your email. Please check your inbox.',
        email: email // Return email for frontend to use in verification step
      });
    } catch (emailError) {
      console.error('Error sending verification email:', emailError);
      // If email service is not configured, allow registration without verification
      if (!emailService.isConfigured()) {
        // Fallback: Create user directly if email service is not configured
        const user = new User({ email, password: hashedPassword, name });
        await user.save();

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

        return res.status(201).json({
          token,
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            storageUsed: user.storageUsed,
            storageLimit: user.storageLimit
          }
        });
      }
      return res.status(500).json({ 
        message: 'Failed to send verification email. Please try again later.' 
      });
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Step 2: Verify code and complete registration
router.post('/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ message: 'Email and verification code are required' });
    }

    // Find verification record
    const verification = await EmailVerification.findOne({ 
      email: email.toLowerCase(),
      verified: false
    });

    if (!verification) {
      return res.status(400).json({ message: 'No pending verification found. Please register again.' });
    }

    // Check if expired
    if (verification.expiresAt < new Date()) {
      return res.status(400).json({ message: 'Verification code has expired. Please register again.' });
    }

    // Check attempts
    if (verification.attempts >= verification.maxAttempts) {
      return res.status(400).json({ message: 'Too many failed attempts. Please register again.' });
    }

    // Verify code
    if (verification.code !== code) {
      verification.attempts += 1;
      await verification.save();
      const remainingAttempts = verification.maxAttempts - verification.attempts;
      return res.status(400).json({ 
        message: `Invalid verification code. ${remainingAttempts > 0 ? `${remainingAttempts} attempt(s) remaining.` : 'Please register again.'}` 
      });
    }

    // Code is correct - create user
    const { name, password: hashedPassword } = verification.registrationData;

    // Double-check user doesn't exist
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      verification.verified = true;
      await verification.save();
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create user
    const user = new User({ 
      email: email.toLowerCase(), 
      password: hashedPassword, 
      name 
    });
    await user.save();

    // Create root folder for user
    const rootFolder = new Folder({
      name: 'My Files',
      owner: user._id,
      parentFolder: null
    });
    await rootFolder.save();

    // Mark verification as verified
    verification.verified = true;
    await verification.save();

    // Generate token
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
    console.error('Verification error:', error);
    res.status(500).json({ message: error.message });
  }
});

// Resend verification code
router.post('/resend-code', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const verification = await EmailVerification.findOne({ 
      email: email.toLowerCase(),
      verified: false
    });

    if (!verification) {
      return res.status(400).json({ message: 'No pending verification found. Please register again.' });
    }

    const verificationCode = generateVerificationCode();
    verification.code = verificationCode;
    verification.expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    verification.attempts = 0;
    await verification.save();

    try {
      await emailService.sendVerificationCode(
        email.toLowerCase(), 
        verificationCode, 
        verification.registrationData.name
      );
      res.json({ message: 'Verification code resent to your email.' });
    } catch (emailError) {
      console.error('Error sending verification email:', emailError);
      res.status(500).json({ message: 'Failed to send verification email. Please try again later.' });
    }
  } catch (error) {
    console.error('Resend code error:', error);
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

