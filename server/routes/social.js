const express = require('express');
const auth = require('../middleware/auth');
const SocialPost = require('../models/SocialPost');
const Follow = require('../models/Follow');
const File = require('../models/File');
const Folder = require('../models/Folder');
const User = require('../models/User');
const Notification = require('../models/Notification');
const router = express.Router();

// Helper function to create notification
const createNotification = async (req, userId, type, fromUserId, postId = null, commentId = null) => {
  try {
    // Don't notify if user is notifying themselves
    if (userId.toString() === fromUserId.toString()) return;
    
    const notification = new Notification({
      user: userId,
      type,
      fromUser: fromUserId,
      post: postId,
      comment: commentId
    });
    await notification.save();
    
    // Emit socket event if available
    const io = req.app.get('io');
    if (io) {
      io.to(`user-${userId}`).emit('new-notification', notification);
    }
  } catch (error) {
    console.error('Error creating notification:', error);
  }
};

// Create a social post (share file/folder to feed)
router.post('/post', auth, async (req, res) => {
  try {
    const { fileId, folderId, description, isPublic, groupId } = req.body;

    if (!fileId && !folderId) {
      return res.status(400).json({ message: 'Either fileId or folderId is required' });
    }

    // Verify ownership
    if (fileId) {
      const file = await File.findById(fileId);
      if (!file || file.owner.toString() !== req.user._id.toString()) {
        return res.status(404).json({ message: 'File not found' });
      }
    }

    if (folderId) {
      const folder = await Folder.findById(folderId);
      if (!folder || folder.owner.toString() !== req.user._id.toString()) {
        return res.status(404).json({ message: 'Folder not found' });
      }
    }

    // If posting to a group, verify membership
    if (groupId) {
      const Group = require('../models/Group');
      const group = await Group.findById(groupId);
      if (!group) {
        return res.status(404).json({ message: 'Group not found' });
      }
      const isMember = group.members.some(
        m => m.user.toString() === req.user._id.toString()
      );
      if (!isMember) {
        return res.status(403).json({ message: 'You must be a member to post in this group' });
      }
    }

    const post = new SocialPost({
      owner: req.user._id,
      file: fileId || null,
      folder: folderId || null,
      description: description || '',
      isPublic: isPublic !== undefined ? isPublic : true,
      group: groupId || null
    });

    await post.save();
    await post.populate('owner', 'name email');
    await post.populate('file', 'originalName mimeType size _id');
    await post.populate('folder', 'name _id');
    await post.populate('group', 'name');

    res.status(201).json(post);
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get social feed (posts from followed users + public posts)
router.get('/feed', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Get users that the current user follows
    const follows = await Follow.find({ follower: req.user._id });
    const followingIds = follows.map(f => f.following);

    // Get posts from followed users and public posts
    const query = {
      $or: [
        { owner: { $in: followingIds } },
        { isPublic: true }
      ]
    };

    const posts = await SocialPost.find(query)
      .populate('owner', 'name email')
      .populate('file')
      .populate('folder')
      .populate('likes.user', 'name email')
      .populate('comments.user', 'name email')
      .populate({
        path: 'originalPost',
        populate: {
          path: 'owner',
          select: 'name email'
        }
      })
      .populate('repostedBy', 'name email')
      .populate('group', 'name')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await SocialPost.countDocuments(query);

    res.json({
      posts,
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      hasMore: skip + posts.length < total
    });
  } catch (error) {
    console.error('Error fetching feed:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get posts by a specific user
router.get('/user/:userId/posts', auth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const query = { owner: userId };
    
    // If viewing own posts or following the user, show all. Otherwise only public
    const isFollowing = await Follow.findOne({ 
      follower: req.user._id, 
      following: userId 
    });
    
    if (userId !== req.user._id.toString() && !isFollowing) {
      query.isPublic = true;
    }

    const posts = await SocialPost.find(query)
      .populate('owner', 'name email')
      .populate('file')
      .populate('folder')
      .populate('likes.user', 'name email')
      .populate('comments.user', 'name email')
      .populate({
        path: 'originalPost',
        populate: {
          path: 'owner',
          select: 'name email'
        }
      })
      .populate('repostedBy', 'name email')
      .populate('group', 'name')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await SocialPost.countDocuments(query);

    res.json({
      posts,
      total,
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('Error fetching user posts:', error);
    res.status(500).json({ message: error.message });
  }
});

// Like/unlike a post
router.post('/post/:postId/like', auth, async (req, res) => {
  try {
    const post = await SocialPost.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const likeIndex = post.likes.findIndex(
      like => like.user.toString() === req.user._id.toString()
    );

    if (likeIndex > -1) {
      // Unlike
      post.likes.splice(likeIndex, 1);
    } else {
      // Like
      post.likes.push({ user: req.user._id });
    }

      await post.save();
      await post.populate('likes.user', 'name email');

      // Create notification if liked
      if (likeIndex === -1) {
        await createNotification(req, post.owner._id, 'like', req.user._id, post._id);
      }

      res.json({ likes: post.likes, isLiked: likeIndex === -1 });
  } catch (error) {
    console.error('Error liking post:', error);
    res.status(500).json({ message: error.message });
  }
});

// Add comment to post
router.post('/post/:postId/comment', auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || text.trim().length === 0) {
      return res.status(400).json({ message: 'Comment text is required' });
    }

    const post = await SocialPost.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    post.comments.push({
      user: req.user._id,
      text: text.trim()
    });

    await post.save();
    await post.populate('comments.user', 'name email');

    const newComment = post.comments[post.comments.length - 1];
    
    // Create notification
    await createNotification(req, post.owner._id, 'comment', req.user._id, post._id, newComment._id);

    res.status(201).json(newComment);
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ message: error.message });
  }
});

// Delete own post
router.delete('/post/:postId', auth, async (req, res) => {
  try {
    const post = await SocialPost.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (post.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized to delete this post' });
    }

    await post.deleteOne();
    res.json({ message: 'Post deleted' });
  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({ message: error.message });
  }
});

// Follow a user
router.post('/follow/:userId', auth, async (req, res) => {
  try {
    const { userId } = req.params;

    if (userId === req.user._id.toString()) {
      return res.status(400).json({ message: 'Cannot follow yourself' });
    }

    const userToFollow = await User.findById(userId);
    if (!userToFollow) {
      return res.status(404).json({ message: 'User not found' });
    }

    const existingFollow = await Follow.findOne({
      follower: req.user._id,
      following: userId
    });

    if (existingFollow) {
      await existingFollow.deleteOne();
      res.json({ following: false, message: 'Unfollowed user' });
    } else {
      const follow = new Follow({
        follower: req.user._id,
        following: userId
      });
      await follow.save();
      
      // Create notification
      await createNotification(req, userId, 'follow', req.user._id);
      
      res.json({ following: true, message: 'Following user' });
    }
  } catch (error) {
    console.error('Error following user:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get follow status
router.get('/follow/:userId', auth, async (req, res) => {
  try {
    const { userId } = req.params;

    const follow = await Follow.findOne({
      follower: req.user._id,
      following: userId
    });

    res.json({ following: !!follow });
  } catch (error) {
    console.error('Error checking follow status:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get user's followers and following counts
router.get('/user/:userId/stats', auth, async (req, res) => {
  try {
    const { userId } = req.params;

    const followersCount = await Follow.countDocuments({ following: userId });
    const followingCount = await Follow.countDocuments({ follower: userId });
    const postsCount = await SocialPost.countDocuments({ owner: userId });

    res.json({
      followers: followersCount,
      following: followingCount,
      posts: postsCount
    });
  } catch (error) {
    console.error('Error fetching user stats:', error);
    res.status(500).json({ message: error.message });
  }
});

// Discover users (users to follow)
router.get('/discover', auth, async (req, res) => {
  try {
    const { limit = 10 } = req.query;

    // Get users that current user already follows
    const follows = await Follow.find({ follower: req.user._id });
    const followingIds = follows.map(f => f.following);
    followingIds.push(req.user._id); // Exclude self

    // Get users with most posts who aren't already followed
    const activeUsers = await SocialPost.aggregate([
      { $match: { owner: { $nin: followingIds } } },
      { $group: { _id: '$owner', postCount: { $sum: 1 } } },
      { $sort: { postCount: -1 } },
      { $limit: parseInt(limit) }
    ]);

    const userIds = activeUsers.map(u => u._id);
    const users = await User.find({ _id: { $in: userIds } })
      .select('name email')
      .limit(parseInt(limit));

    // Get stats for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const followers = await Follow.countDocuments({ following: user._id });
        const posts = await SocialPost.countDocuments({ owner: user._id });
        return {
          ...user.toObject(),
          followers,
          posts
        };
      })
    );

    res.json(usersWithStats);
  } catch (error) {
    console.error('Error discovering users:', error);
    res.status(500).json({ message: error.message });
  }
});

// Repost/Share a post
router.post('/post/:postId/repost', auth, async (req, res) => {
  try {
    const originalPost = await SocialPost.findById(req.params.postId)
      .populate('owner', 'name email')
      .populate('file')
      .populate('folder');
    
    if (!originalPost) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Don't allow reposting your own posts
    if (originalPost.owner._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Cannot repost your own post' });
    }

    // Check if already reposted
    const existingRepost = await SocialPost.findOne({
      originalPost: originalPost._id,
      repostedBy: req.user._id
    });

    if (existingRepost) {
      await existingRepost.deleteOne();
      // Decrease repost count
      originalPost.repostCount = Math.max(0, originalPost.repostCount - 1);
      await originalPost.save();
      res.json({ reposted: false, message: 'Repost removed' });
    } else {
      // Create repost
      const repost = new SocialPost({
        owner: req.user._id,
        file: originalPost.file,
        folder: originalPost.folder,
        description: originalPost.description,
        isPublic: true,
        originalPost: originalPost._id,
        repostedBy: req.user._id
      });

      await repost.save();
      
      // Increase repost count
      originalPost.repostCount = (originalPost.repostCount || 0) + 1;
      await originalPost.save();

      // Create notification
      await createNotification(req, originalPost.owner._id, 'repost', req.user._id, originalPost._id);

      await repost.populate('owner', 'name email');
      await repost.populate('file', 'originalName mimeType size _id');
      await repost.populate('folder', 'name _id');
      await repost.populate({
        path: 'originalPost',
        populate: [
          {
            path: 'owner',
            select: 'name email'
          },
          {
            path: 'file',
            select: 'originalName mimeType size _id'
          },
          {
            path: 'folder',
            select: 'name _id'
          }
        ]
      });
      await repost.populate('repostedBy', 'name email');

      res.status(201).json(repost);
    }
  } catch (error) {
    console.error('Error reposting:', error);
    res.status(500).json({ message: error.message });
  }
});

// Save/Unsave a post
router.post('/post/:postId/save', auth, async (req, res) => {
  try {
    const post = await SocialPost.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const user = await User.findById(req.user._id);
    const savedIndex = user.savedPosts.findIndex(
      p => p.toString() === post._id.toString()
    );

    if (savedIndex > -1) {
      user.savedPosts.splice(savedIndex, 1);
      await user.save();
      res.json({ saved: false, message: 'Post unsaved' });
    } else {
      user.savedPosts.push(post._id);
      await user.save();
      res.json({ saved: true, message: 'Post saved' });
    }
  } catch (error) {
    console.error('Error saving post:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get saved posts
router.get('/saved', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate({
      path: 'savedPosts',
      populate: [
        { path: 'owner', select: 'name email' },
        { path: 'file' },
        { path: 'folder' },
        { 
          path: 'originalPost', 
          populate: { 
            path: 'owner', 
            select: 'name email' 
          } 
        },
        { path: 'repostedBy', select: 'name email' }
      ]
    });

    const savedPosts = user.savedPosts.sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );

    res.json({ posts: savedPosts });
  } catch (error) {
    console.error('Error fetching saved posts:', error);
    res.status(500).json({ message: error.message });
  }
});

// Search users
router.get('/search/users', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length === 0) {
      return res.json({ users: [] });
    }

    const searchRegex = new RegExp(q.trim(), 'i');
    const users = await User.find({
      $or: [
        { name: searchRegex },
        { email: searchRegex }
      ],
      _id: { $ne: req.user._id }
    })
      .select('name email')
      .limit(20);

    // Get stats for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const followers = await Follow.countDocuments({ following: user._id });
        const posts = await SocialPost.countDocuments({ owner: user._id });
        const isFollowing = await Follow.findOne({
          follower: req.user._id,
          following: user._id
        });
        return {
          ...user.toObject(),
          followers,
          posts,
          isFollowing: !!isFollowing
        };
      })
    );

    res.json({ users: usersWithStats });
  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get user posts
router.get('/user/:userId/posts', auth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const posts = await SocialPost.find({ owner: userId })
      .populate('owner', 'name email')
      .populate('file', 'originalName mimeType size _id')
      .populate('folder', 'name _id')
      .populate('likes.user', 'name email')
      .populate('comments.user', 'name email')
      .populate({
        path: 'originalPost',
        populate: [
          {
            path: 'owner',
            select: 'name email'
          },
          {
            path: 'file',
            select: 'originalName mimeType size _id'
          },
          {
            path: 'folder',
            select: 'name _id'
          }
        ]
      })
      .populate('repostedBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    const total = await SocialPost.countDocuments({ owner: userId });

    res.json({
      posts,
      hasMore: skip + posts.length < total,
      total
    });
  } catch (error) {
    console.error('Error fetching user posts:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get user profile
router.get('/user/:userId/profile', auth, async (req, res) => {
  try {
    const { userId } = req.params;
    const profileUser = await User.findById(userId).select('name email bio createdAt');
    
    if (!profileUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    const followersCount = await Follow.countDocuments({ following: userId });
    const followingCount = await Follow.countDocuments({ follower: userId });
    const postsCount = await SocialPost.countDocuments({ owner: userId });
    const isFollowing = await Follow.findOne({
      follower: req.user._id,
      following: userId
    });

    res.json({
      user: profileUser,
      stats: {
        followers: followersCount,
        following: followingCount,
        posts: postsCount
      },
      isFollowing: !!isFollowing,
      isOwnProfile: userId === req.user._id.toString()
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ message: error.message });
  }
});

// Update user profile
router.patch('/profile', auth, async (req, res) => {
  try {
    const { bio } = req.body;
    const user = await User.findById(req.user._id);
    
    if (bio !== undefined) {
      user.bio = bio.substring(0, 200);
    }

    await user.save();
    res.json({ user: { ...user.toObject(), password: undefined } });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get notifications
router.get('/notifications', auth, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const notifications = await Notification.find({ user: req.user._id })
      .populate('fromUser', 'name email')
      .populate('post')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    const unreadCount = await Notification.countDocuments({
      user: req.user._id,
      read: false
    });

    res.json({ notifications, unreadCount });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: error.message });
  }
});

// Mark notification as read
router.patch('/notifications/:notificationId/read', auth, async (req, res) => {
  try {
    const notification = await Notification.findOne({
      _id: req.params.notificationId,
      user: req.user._id
    });

    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }

    notification.read = true;
    await notification.save();

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ message: error.message });
  }
});

// Mark all notifications as read
router.patch('/notifications/read-all', auth, async (req, res) => {
  try {
    await Notification.updateMany(
      { user: req.user._id, read: false },
      { read: true }
    );

    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

