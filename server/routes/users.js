const express = require('express');
const auth = require('../middleware/auth');
const User = require('../models/User');
const router = express.Router();

// Get user profile
router.get('/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update user profile
router.patch('/profile', auth, async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = await User.findById(req.user._id);

    if (name) user.name = name;
    if (email) {
      const existingUser = await User.findOne({ email });
      if (existingUser && existingUser._id.toString() !== user._id.toString()) {
        return res.status(400).json({ message: 'Email already in use' });
      }
      user.email = email;
    }

    await user.save();
    res.json({
      id: user._id,
      email: user.email,
      name: user.name,
      storageUsed: user.storageUsed,
      storageLimit: user.storageLimit
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Search users
router.get('/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.json([]);
    }

    const users = await User.find({
      $or: [
        { name: { $regex: q, $options: 'i' } },
        { email: { $regex: q, $options: 'i' } }
      ],
      _id: { $ne: req.user._id }
    }).select('name email').limit(10);

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get all users (for sharing)
router.get('/all', auth, async (req, res) => {
  try {
    const users = await User.find({
      _id: { $ne: req.user._id }
    })
    .select('name email')
    .sort({ name: 1 })
    .limit(100);

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;










