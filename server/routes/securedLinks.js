const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const SecuredLink = require('../models/SecuredLink');
const bcrypt = require('bcryptjs');

// Get all secured links for user
router.get('/', auth, async (req, res) => {
  try {
    const { category, starred, tags, search } = req.query;
    const query = { user: req.user._id };

    if (category && category !== 'all') {
      query.category = category;
    }

    if (starred === 'true') {
      query.isStarred = true;
    }

    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : [tags];
      query.tags = { $in: tagArray };
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { notes: { $regex: search, $options: 'i' } },
        { tags: { $regex: search, $options: 'i' } }
      ];
    }

    const links = await SecuredLink.find(query)
      .select('-password -encryptedUrl') // Don't send sensitive data by default
      .sort({ createdAt: -1 });

    res.json(links);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get secured link by ID (without sensitive data)
router.get('/:id', auth, async (req, res) => {
  try {
    const link = await SecuredLink.findOne({
      _id: req.params.id,
      user: req.user._id
    }).select('-password -encryptedUrl');

    if (!link) {
      return res.status(404).json({ message: 'Secured link not found' });
    }

    res.json(link);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get decrypted URL (requires password if protected)
router.post('/:id/access', auth, async (req, res) => {
  try {
    const { password } = req.body;
    const link = await SecuredLink.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!link) {
      return res.status(404).json({ message: 'Secured link not found' });
    }

    // Check if password is required
    if (link.isPasswordProtected) {
      if (!password) {
        return res.status(401).json({ 
          message: 'Password required',
          hasPasswordHint: !!link.passwordHint,
          passwordHint: link.passwordHint || null
        });
      }

      // Verify password
      if (!link.password || !(await bcrypt.compare(password, link.password))) {
        return res.status(401).json({ message: 'Invalid password' });
      }
    }

    // Update access tracking
    link.accessCount += 1;
    link.lastAccessedAt = new Date();
    await link.save();

    // Return URL (decrypt if needed)
    let url = link.url;
    if (link.isEncrypted && link.encryptedUrl) {
      // For encrypted URLs, we'd need a master password
      // For now, return a message that decryption is needed client-side
      url = link.encryptedUrl; // Return encrypted version for client-side decryption
    }

    res.json({ 
      url,
      isEncrypted: link.isEncrypted,
      title: link.title
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create secured link
router.post('/', auth, async (req, res) => {
  try {
    const { 
      title, 
      url, 
      description, 
      category, 
      tags, 
      password, 
      passwordHint,
      isPasswordProtected,
      isEncrypted,
      notes,
      expiresAt
    } = req.body;

    if (!url) {
      return res.status(400).json({ message: 'URL is required' });
    }

    // Validate URL
    try {
      new URL(url);
    } catch (e) {
      return res.status(400).json({ message: 'Invalid URL format' });
    }

    // Hash password if provided
    let hashedPassword = null;
    if (isPasswordProtected && password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    const link = new SecuredLink({
      user: req.user._id,
      title: title || new URL(url).hostname,
      url: isEncrypted ? '' : url, // Clear URL if encrypted
      encryptedUrl: null, // Will be set client-side or via separate endpoint
      password: hashedPassword,
      passwordHint: passwordHint || '',
      description: description || '',
      category: category || 'general',
      tags: tags || [],
      isPasswordProtected: isPasswordProtected || false,
      isEncrypted: isEncrypted || false,
      notes: notes || '',
      expiresAt: expiresAt || null
    });

    await link.save();

    // Return link without sensitive data
    const linkResponse = link.toObject();
    delete linkResponse.password;
    delete linkResponse.encryptedUrl;

    res.json(linkResponse);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update secured link
router.put('/:id', auth, async (req, res) => {
  try {
    const link = await SecuredLink.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!link) {
      return res.status(404).json({ message: 'Secured link not found' });
    }

    const { 
      title, 
      url, 
      description, 
      category, 
      tags, 
      password, 
      passwordHint,
      isPasswordProtected,
      isEncrypted,
      notes,
      isStarred,
      expiresAt
    } = req.body;

    if (title) link.title = title;
    if (description !== undefined) link.description = description;
    if (category) link.category = category;
    if (tags) link.tags = tags;
    if (notes !== undefined) link.notes = notes;
    if (isStarred !== undefined) link.isStarred = isStarred;
    if (expiresAt !== undefined) link.expiresAt = expiresAt;
    if (passwordHint !== undefined) link.passwordHint = passwordHint;

    // Update password if provided
    if (isPasswordProtected !== undefined) {
      link.isPasswordProtected = isPasswordProtected;
      if (password) {
        link.password = await bcrypt.hash(password, 10);
      } else if (!isPasswordProtected) {
        link.password = null;
      }
    }

    // Update URL
    if (url) {
      try {
        new URL(url);
        if (isEncrypted) {
          link.url = '';
          // Encrypted URL should be set separately
        } else {
          link.url = url;
          link.encryptedUrl = null;
        }
      } catch (e) {
        return res.status(400).json({ message: 'Invalid URL format' });
      }
    }

    if (isEncrypted !== undefined) {
      link.isEncrypted = isEncrypted;
    }

    await link.save();

    // Return link without sensitive data
    const linkResponse = link.toObject();
    delete linkResponse.password;
    delete linkResponse.encryptedUrl;

    res.json(linkResponse);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete secured link
router.delete('/:id', auth, async (req, res) => {
  try {
    const link = await SecuredLink.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!link) {
      return res.status(404).json({ message: 'Secured link not found' });
    }

    await link.deleteOne();
    res.json({ message: 'Secured link deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Toggle star
router.patch('/:id/star', auth, async (req, res) => {
  try {
    const link = await SecuredLink.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!link) {
      return res.status(404).json({ message: 'Secured link not found' });
    }

    link.isStarred = !link.isStarred;
    await link.save();

    res.json({ isStarred: link.isStarred });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
