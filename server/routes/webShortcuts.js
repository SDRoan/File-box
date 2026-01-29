const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const WebShortcut = require('../models/WebShortcut');
const axios = require('axios');

// Optional dependency - cheerio for fetching page titles
let cheerio;
try {
  cheerio = require('cheerio');
} catch (e) {
  console.log('[Web Shortcuts] cheerio not installed - page title fetching disabled');
}

// Get all shortcuts for user
router.get('/', auth, async (req, res) => {
  try {
    const { folder, starred, tags, search } = req.query;
    const query = { user: req.user._id };

    if (folder) {
      query.folder = folder === 'null' ? null : folder;
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
        { url: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const shortcuts = await WebShortcut.find(query)
      .populate('folder', 'name')
      .sort({ createdAt: -1 });

    res.json(shortcuts);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get shortcut by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const shortcut = await WebShortcut.findOne({
      _id: req.params.id,
      user: req.user._id
    }).populate('folder', 'name');

    if (!shortcut) {
      return res.status(404).json({ message: 'Shortcut not found' });
    }

    res.json(shortcut);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create shortcut
router.post('/', auth, async (req, res) => {
  try {
    const { title, url, description, tags, folder, favicon } = req.body;

    if (!url) {
      return res.status(400).json({ message: 'URL is required' });
    }

    // Validate URL
    try {
      new URL(url);
    } catch (e) {
      return res.status(400).json({ message: 'Invalid URL format' });
    }

    // Try to fetch favicon if not provided
    let finalFavicon = favicon;
    if (!finalFavicon) {
      try {
        finalFavicon = await fetchFavicon(url);
      } catch (error) {
        console.log('Could not fetch favicon:', error.message);
      }
    }

    // Auto-generate title if not provided
    let finalTitle = title;
    if (!finalTitle) {
      try {
        finalTitle = await fetchPageTitle(url);
      } catch (error) {
        finalTitle = new URL(url).hostname;
      }
    }

    const shortcut = new WebShortcut({
      user: req.user._id,
      title: finalTitle || url,
      url,
      description: description || '',
      tags: tags || [],
      folder: folder && folder !== 'null' ? folder : null,
      favicon: finalFavicon
    });

    await shortcut.save();
    res.json(shortcut);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update shortcut
router.put('/:id', auth, async (req, res) => {
  try {
    const shortcut = await WebShortcut.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!shortcut) {
      return res.status(404).json({ message: 'Shortcut not found' });
    }

    const { title, url, description, tags, folder, isStarred, favicon } = req.body;
    if (title) shortcut.title = title;
    if (url) {
      try {
        new URL(url);
        shortcut.url = url;
      } catch (e) {
        return res.status(400).json({ message: 'Invalid URL format' });
      }
    }
    if (description !== undefined) shortcut.description = description;
    if (tags) shortcut.tags = tags;
    if (folder !== undefined) shortcut.folder = folder === 'null' ? null : folder;
    if (isStarred !== undefined) shortcut.isStarred = isStarred;
    if (favicon) shortcut.favicon = favicon;
    shortcut.updatedAt = new Date();

    await shortcut.save();
    res.json(shortcut);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Track click/access
router.post('/:id/access', auth, async (req, res) => {
  try {
    const shortcut = await WebShortcut.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!shortcut) {
      return res.status(404).json({ message: 'Shortcut not found' });
    }

    shortcut.clickCount += 1;
    shortcut.lastAccessedAt = new Date();
    await shortcut.save();

    res.json({ clickCount: shortcut.clickCount });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete shortcut
router.delete('/:id', auth, async (req, res) => {
  try {
    const shortcut = await WebShortcut.findOne({
      _id: req.params.id,
      user: req.user._id
    });

    if (!shortcut) {
      return res.status(404).json({ message: 'Shortcut not found' });
    }

    await shortcut.deleteOne();
    res.json({ message: 'Shortcut deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Helper function to fetch favicon
async function fetchFavicon(url) {
  try {
    const urlObj = new URL(url);
    return `${urlObj.protocol}//${urlObj.host}/favicon.ico`;
  } catch (error) {
    return null;
  }
}

// Helper function to fetch page title
async function fetchPageTitle(url) {
  try {
    if (!cheerio) {
      return new URL(url).hostname;
    }
    const response = await axios.get(url, {
      timeout: 5000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    const $ = cheerio.load(response.data);
    return $('title').text().trim() || new URL(url).hostname;
  } catch (error) {
    return new URL(url).hostname;
  }
}

module.exports = router;

