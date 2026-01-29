const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const ForumPost = require('../models/ForumPost');

// Get all forum posts
router.get('/', auth, async (req, res) => {
  try {
    const { category, search, sortBy = 'createdAt', order = 'desc' } = req.query;
    const query = {};

    if (category) {
      query.category = category;
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { content: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const sortOptions = {};
    if (sortBy === 'popular') {
      sortOptions.upvotes = order === 'desc' ? -1 : 1;
    } else if (sortBy === 'replies') {
      sortOptions.replyCount = order === 'desc' ? -1 : 1;
    } else {
      sortOptions[sortBy] = order === 'desc' ? -1 : 1;
    }

    // Pin posts first
    sortOptions.isPinned = -1;

    const posts = await ForumPost.find(query)
      .populate('author', 'name email')
      .sort(sortOptions)
      .limit(50);

    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get post by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const post = await ForumPost.findById(req.params.id)
      .populate('author', 'name email')
      .populate('replies.author', 'name email');

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Increment views
    post.views += 1;
    await post.save();

    res.json(post);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create post
router.post('/', auth, async (req, res) => {
  try {
    const { title, content, category, tags } = req.body;

    if (!title || !content) {
      return res.status(400).json({ message: 'Title and content are required' });
    }

    const post = new ForumPost({
      title,
      content,
      author: req.user._id,
      category: category || 'general',
      tags: tags || []
    });

    await post.save();
    await post.populate('author', 'name email');
    res.json(post);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Reply to post
router.post('/:id/reply', auth, async (req, res) => {
  try {
    const { content } = req.body;
    const post = await ForumPost.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (post.isLocked) {
      return res.status(403).json({ message: 'Post is locked' });
    }

    post.replies.push({
      author: req.user._id,
      content
    });

    post.replyCount += 1;
    post.lastActivityAt = new Date();
    await post.save();

    await post.populate('replies.author', 'name email');
    res.json(post);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Vote on post
router.post('/:id/vote', auth, async (req, res) => {
  try {
    const { vote } = req.body; // 'up' or 'down'
    const post = await ForumPost.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (vote === 'up') {
      post.upvotes += 1;
    } else if (vote === 'down') {
      post.downvotes += 1;
    }

    await post.save();
    res.json({ upvotes: post.upvotes, downvotes: post.downvotes });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update post
router.put('/:id', auth, async (req, res) => {
  try {
    const post = await ForumPost.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (post.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { title, content, tags } = req.body;
    if (title) post.title = title;
    if (content) post.content = content;
    if (tags) post.tags = tags;
    post.updatedAt = new Date();

    await post.save();
    res.json(post);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete post
router.delete('/:id', auth, async (req, res) => {
  try {
    const post = await ForumPost.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (post.author.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    await post.deleteOne();
    res.json({ message: 'Post deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

