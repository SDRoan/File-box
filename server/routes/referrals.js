const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Referral = require('../models/Referral');
const User = require('../models/User');
const { v4: uuidv4 } = require('uuid');

// Generate referral code for user
router.post('/generate-code', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate unique referral code
    if (!user.referralCode) {
      const baseCode = user.name.replace(/\s+/g, '').toUpperCase().substring(0, 6) + 
                       Math.floor(Math.random() * 10000).toString().padStart(4, '0');
      user.referralCode = baseCode;
      await user.save();
    }

    res.json({ referralCode: user.referralCode });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get user's referral code
router.get('/my-code', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate if doesn't exist
    if (!user.referralCode) {
      const baseCode = user.name.replace(/\s+/g, '').toUpperCase().substring(0, 6) + 
                       Math.floor(Math.random() * 10000).toString().padStart(4, '0');
      user.referralCode = baseCode;
      await user.save();
    }

    res.json({ referralCode: user.referralCode });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get referral stats
router.get('/stats', auth, async (req, res) => {
  try {
    const referrals = await Referral.find({ referrer: req.user._id });
    const completed = referrals.filter(r => r.status === 'completed').length;
    const rewarded = referrals.filter(r => r.rewardGiven).length;

    res.json({
      totalReferrals: referrals.length,
      completedReferrals: completed,
      rewardedReferrals: rewarded,
      pendingReferrals: referrals.length - completed
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get all referrals
router.get('/', auth, async (req, res) => {
  try {
    const referrals = await Referral.find({ referrer: req.user._id })
      .populate('referred', 'name email createdAt')
      .sort({ createdAt: -1 });

    res.json(referrals);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Use referral code during registration (called from auth route)
router.post('/use-code', async (req, res) => {
  try {
    const { referralCode, userId } = req.body;

    if (!referralCode || !userId) {
      return res.status(400).json({ message: 'Referral code and user ID are required' });
    }

    // Find referrer by code
    const referrer = await User.findOne({ referralCode });
    if (!referrer) {
      return res.status(404).json({ message: 'Invalid referral code' });
    }

    // Check if user was already referred
    const existingReferral = await Referral.findOne({ referred: userId });
    if (existingReferral) {
      return res.status(400).json({ message: 'User already used a referral code' });
    }

    // Create referral record
    const referral = new Referral({
      referrer: referrer._id,
      referred: userId,
      referralCode: referralCode,
      status: 'completed', // User has signed up
      rewardType: 'storage',
      rewardAmount: 1024 * 1024 * 1024 // 1GB storage bonus
    });

    await referral.save();

    // Update referrer's referral count
    referrer.referralCount += 1;
    await referrer.save();

    // Update referred user
    const referredUser = await User.findById(userId);
    if (referredUser) {
      referredUser.referredBy = referrer._id;
      // Give storage bonus
      referredUser.storageLimit += referral.rewardAmount;
      await referredUser.save();
    }

    // Give reward to referrer (after 3 successful referrals)
    if (referrer.referralCount >= 3 && referrer.referralCount % 3 === 0) {
      referrer.storageLimit += 5 * 1024 * 1024 * 1024; // 5GB bonus
      await referrer.save();
      
      referral.rewardGiven = true;
      await referral.save();
    }

    res.json({ message: 'Referral code applied successfully', referral });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

