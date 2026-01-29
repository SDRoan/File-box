const express = require('express');
const auth = require('../middleware/auth');
const TeamFolder = require('../models/TeamFolder');
const TeamFolderMessage = require('../models/TeamFolderMessage');
const File = require('../models/File');
const Folder = require('../models/Folder');
const User = require('../models/User');
const multer = require('multer');
const fs = require('fs-extra');
const path = require('path');
const router = express.Router();

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// Get all team folders user has access to
router.get('/', auth, async (req, res) => {
  try {
    const teamFolders = await TeamFolder.find({
      $or: [
        { owner: req.user._id },
        { 'members.user': req.user._id }
      ]
    })
    .populate('owner', 'name email')
    .populate('members.user', 'name email')
    .sort({ createdAt: -1 });

    res.json(teamFolders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create team folder
router.post('/', auth, async (req, res) => {
  try {
    const { name, parentFolder } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Team folder name is required' });
    }

    const teamFolder = new TeamFolder({
      name,
      owner: req.user._id,
      parentFolder: parentFolder && parentFolder !== 'root' ? parentFolder : null,
      members: [{
        user: req.user._id,
        role: 'admin',
        joinedAt: new Date()
      }]
    });

    await teamFolder.save();
    await teamFolder.populate('owner', 'name email');
    await teamFolder.populate('members.user', 'name email');

    res.status(201).json(teamFolder);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ========== MESSAGING ROUTES (Slack-like features) - Must be before /:id route ==========

// Get messages for a team folder
router.get('/:id/messages', auth, async (req, res) => {
  try {
    const { limit = 50, before } = req.query;
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const query = { teamFolder: req.params.id, threadParent: null };
    if (before) {
      query.createdAt = { $lt: new Date(before) };
    }

    const messages = await TeamFolderMessage.find(query)
      .populate('sender', 'name email')
      .populate('file', 'originalName size mimeType')
      .populate('mentions', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();

    // Get thread counts for each message
    for (const message of messages) {
      const threadCount = await TeamFolderMessage.countDocuments({ threadParent: message._id });
      message.threadCount = threadCount;
    }

    res.json(messages.reverse()); // Reverse to show oldest first
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Send a message
router.post('/:id/messages', auth, async (req, res) => {
  try {
    const { message, threadParent, fileId } = req.body;
    const teamFolder = await TeamFolder.findById(req.params.id).populate('members.user');

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access - owner always has access
    const isOwner = teamFolder.owner.toString() === req.user._id.toString();
    // Check if user is a member (handle both populated and unpopulated cases)
    const isMember = teamFolder.members.some(m => {
      if (!m.user) return false;
      const userId = m.user._id ? m.user._id.toString() : m.user.toString();
      return userId === req.user._id.toString();
    });
    const hasAccess = isOwner || isMember;

    console.log('Message access check:', {
      userId: req.user._id.toString(),
      isOwner,
      isMember,
      hasAccess,
      membersCount: teamFolder.members.length
    });

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied. You must be a member of this team folder.' });
    }

    if (!message && !fileId) {
      return res.status(400).json({ message: 'Message or file is required' });
    }

    // Extract @mentions
    const mentionRegex = /@(\w+)/g;
    const mentions = [];
    let match;
    if (message) {
      while ((match = mentionRegex.exec(message)) !== null) {
        // Find user by name or email
        const user = await User.findOne({
          $or: [
            { name: { $regex: match[1], $options: 'i' } },
            { email: { $regex: match[1], $options: 'i' } }
          ]
        });
        if (user && !mentions.includes(user._id)) {
          mentions.push(user._id);
        }
      }
    }

    const teamMessage = new TeamFolderMessage({
      teamFolder: req.params.id,
      sender: req.user._id,
      message: message || '',
      type: fileId ? 'file' : (threadParent ? 'thread' : 'text'),
      file: fileId || null,
      threadParent: threadParent || null,
      mentions
    });

    await teamMessage.save();
    await teamMessage.populate('sender', 'name email');
    await teamMessage.populate('file', 'originalName size mimeType');
    await teamMessage.populate('mentions', 'name email');

    // Emit real-time update
    const io = req.app.get('io');
    const room = `team-folder-${req.params.id}`;
    io.to(room).emit('new-message', teamMessage);

    // Notify mentioned users
    mentions.forEach(userId => {
      io.to(`user-${userId}`).emit('mention', {
        teamFolder: teamFolder.name,
        message: teamMessage.message,
        sender: req.user.name
      });
    });

    res.status(201).json(teamMessage);
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: error.message || 'Failed to send message' });
  }
});

// Get thread replies for a message
router.get('/:id/messages/:messageId/thread', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const replies = await TeamFolderMessage.find({ threadParent: req.params.messageId })
      .populate('sender', 'name email')
      .populate('file', 'originalName size mimeType')
      .populate('mentions', 'name email')
      .sort({ createdAt: 1 })
      .lean();

    res.json(replies);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Edit a message
router.patch('/:id/messages/:messageId', auth, async (req, res) => {
  try {
    const { message } = req.body;
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const teamMessage = await TeamFolderMessage.findById(req.params.messageId);

    if (!teamMessage) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Only sender can edit their own message
    if (teamMessage.sender.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'You can only edit your own messages' });
    }

    teamMessage.message = message || teamMessage.message;
    teamMessage.isEdited = true;
    teamMessage.editedAt = new Date();
    await teamMessage.save();
    await teamMessage.populate('sender', 'name email');
    await teamMessage.populate('file', 'originalName size mimeType');
    await teamMessage.populate('mentions', 'name email');

    // Emit real-time update
    const io = req.app.get('io');
    const room = `team-folder-${req.params.id}`;
    io.to(room).emit('message-updated', teamMessage);

    res.json(teamMessage);
  } catch (error) {
    console.error('Error editing message:', error);
    res.status(500).json({ message: error.message || 'Failed to edit message' });
  }
});

// Delete a message
router.delete('/:id/messages/:messageId', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const teamMessage = await TeamFolderMessage.findById(req.params.messageId);

    if (!teamMessage) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Only sender or admin/owner can delete messages
    const isSender = teamMessage.sender.toString() === req.user._id.toString();
    const isOwner = teamFolder.owner.toString() === req.user._id.toString();
    const isAdmin = teamFolder.members.some(m => 
      m.user.toString() === req.user._id.toString() && m.role === 'admin'
    );

    if (!isSender && !isOwner && !isAdmin) {
      return res.status(403).json({ message: 'You can only delete your own messages or you must be an admin' });
    }

    // Delete the message and all its thread replies
    await TeamFolderMessage.deleteMany({ 
      $or: [
        { _id: req.params.messageId },
        { threadParent: req.params.messageId }
      ]
    });

    // Emit real-time update
    const io = req.app.get('io');
    const room = `team-folder-${req.params.id}`;
    io.to(room).emit('message-deleted', { messageId: req.params.messageId });

    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ message: error.message || 'Failed to delete message' });
  }
});

// Add reaction to a message
router.post('/:id/messages/:messageId/reactions', auth, async (req, res) => {
  try {
    const { emoji } = req.body;
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const teamMessage = await TeamFolderMessage.findById(req.params.messageId);

    if (!teamMessage) {
      return res.status(404).json({ message: 'Message not found' });
    }

    if (!teamMessage.reactions) {
      teamMessage.reactions = [];
    }

    // Find or create reaction
    let reaction = teamMessage.reactions.find(r => r.emoji === emoji);
    if (reaction) {
      // Toggle user in reaction
      const userIndex = reaction.users.indexOf(req.user._id.toString());
      if (userIndex > -1) {
        reaction.users.splice(userIndex, 1);
        reaction.count = Math.max(0, reaction.count - 1);
        if (reaction.count === 0) {
          teamMessage.reactions = teamMessage.reactions.filter(r => r.emoji !== emoji);
        }
      } else {
        reaction.users.push(req.user._id.toString());
        reaction.count += 1;
      }
    } else {
      teamMessage.reactions.push({
        emoji,
        users: [req.user._id.toString()],
        count: 1
      });
    }

    await teamMessage.save();

    // Emit real-time update
    const io = req.app.get('io');
    const room = `team-folder-${req.params.id}`;
    if (reaction && reaction.count > 0) {
      io.to(room).emit('reaction-added', { messageId: req.params.messageId, reactions: teamMessage.reactions });
    } else {
      io.to(room).emit('reaction-removed', { messageId: req.params.messageId, reactions: teamMessage.reactions });
    }

    res.json(teamMessage);
  } catch (error) {
    console.error('Error adding reaction:', error);
    res.status(500).json({ message: error.message || 'Failed to add reaction' });
  }
});

// Remove reaction from a message
router.delete('/:id/messages/:messageId/reactions/:emoji', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const teamMessage = await TeamFolderMessage.findById(req.params.messageId);

    if (!teamMessage) {
      return res.status(404).json({ message: 'Message not found' });
    }

    if (!teamMessage.reactions) {
      return res.json(teamMessage);
    }

    const reaction = teamMessage.reactions.find(r => r.emoji === req.params.emoji);
    if (reaction) {
      const userIndex = reaction.users.indexOf(req.user._id.toString());
      if (userIndex > -1) {
        reaction.users.splice(userIndex, 1);
        reaction.count = Math.max(0, reaction.count - 1);
        if (reaction.count === 0) {
          teamMessage.reactions = teamMessage.reactions.filter(r => r.emoji !== req.params.emoji);
        }
      }
    }

    await teamMessage.save();

    // Emit real-time update
    const io = req.app.get('io');
    const room = `team-folder-${req.params.id}`;
    io.to(room).emit('reaction-removed', { messageId: req.params.messageId, reactions: teamMessage.reactions });

    res.json(teamMessage);
  } catch (error) {
    console.error('Error removing reaction:', error);
    res.status(500).json({ message: error.message || 'Failed to remove reaction' });
  }
});

// Pin/unpin a message
router.post('/:id/messages/:messageId/pin', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const teamMessage = await TeamFolderMessage.findById(req.params.messageId);

    if (!teamMessage) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Toggle pin status
    teamMessage.isPinned = !teamMessage.isPinned;
    teamMessage.pinnedAt = teamMessage.isPinned ? new Date() : null;
    await teamMessage.save();

    // Emit real-time update
    const io = req.app.get('io');
    const room = `team-folder-${req.params.id}`;
    io.to(room).emit('message-pinned', { messageId: req.params.messageId, isPinned: teamMessage.isPinned });

    res.json(teamMessage);
  } catch (error) {
    console.error('Error pinning message:', error);
    res.status(500).json({ message: error.message || 'Failed to pin message' });
  }
});

// Get team folder details (must be after /:id/messages routes)
router.get('/:id', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id)
      .populate('owner', 'name email')
      .populate('members.user', 'name email');

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user._id.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    res.json(teamFolder);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Add member to team folder
router.post('/:id/members', auth, async (req, res) => {
  try {
    const { userId, role } = req.body;
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check if user is admin or owner
    const isAdmin = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => 
        m.user.toString() === req.user._id.toString() && m.role === 'admin'
      );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can add members' });
    }

    // Check if user exists
    const userToAdd = await User.findById(userId);
    if (!userToAdd) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if already a member
    const existingMember = teamFolder.members.find(
      m => m.user.toString() === userId
    );

    if (existingMember) {
      existingMember.role = role || 'viewer';
    } else {
      teamFolder.members.push({
        user: userId,
        role: role || 'viewer'
      });
    }

    await teamFolder.save();
    await teamFolder.populate('members.user', 'name email');

    res.json(teamFolder);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Remove member from team folder
router.delete('/:id/members/:userId', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check if user is admin or owner
    const isAdmin = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => 
        m.user.toString() === req.user._id.toString() && m.role === 'admin'
      );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can remove members' });
    }

    teamFolder.members = teamFolder.members.filter(
      m => m.user.toString() !== req.params.userId
    );

    await teamFolder.save();

    res.json({ message: 'Member removed' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get files in team folder
router.get('/:id/files', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access
    const hasAccess = teamFolder.owner.toString() === req.user._id.toString() ||
      teamFolder.members.some(m => m.user._id.toString() === req.user._id.toString());

    if (!hasAccess) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Find files and folders where parentFolder matches the team folder ID
    const files = await File.find({ 
      parentFolder: req.params.id, 
      isTrashed: { $ne: true } 
    })
      .populate('owner', 'name email')
      .sort({ createdAt: -1 });
    
    const folders = await Folder.find({ 
      parentFolder: req.params.id, 
      isTrashed: { $ne: true } 
    })
      .populate('owner', 'name email')
      .sort({ createdAt: -1 });

    res.json({ files, folders });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Upload file to team folder
router.post('/:id/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const teamFolder = await TeamFolder.findById(req.params.id);
    if (!teamFolder) {
      await fs.remove(req.file.path);
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access and permissions
    const member = teamFolder.members.find(m => m.user.toString() === req.user._id.toString());
    const isOwner = teamFolder.owner.toString() === req.user._id.toString();
    const isAdmin = isOwner || (member && member.role === 'admin');
    const isEditor = isAdmin || (member && member.role === 'editor');

    if (!isOwner && !member) {
      await fs.remove(req.file.path);
      return res.status(403).json({ message: 'Access denied' });
    }

    if (!isEditor) {
      await fs.remove(req.file.path);
      return res.status(403).json({ message: 'Only editors and admins can upload files' });
    }

    const user = await User.findById(req.user._id);
    const fileSize = req.file.size;

    // Check storage limit
    if (user.storageUsed + fileSize > user.storageLimit) {
      await fs.remove(req.file.path);
      return res.status(400).json({ message: 'Storage limit exceeded' });
    }

    const file = new File({
      name: req.file.filename,
      originalName: req.file.originalname,
      path: req.file.path,
      size: fileSize,
      mimeType: req.file.mimetype,
      owner: req.user._id,
      parentFolder: req.params.id
    });

    await file.save();
    user.storageUsed += fileSize;
    await user.save();

    // Emit real-time update
    const io = req.app.get('io');
    teamFolder.members.forEach(member => {
      io.to(`user-${member.user}`).emit('file-uploaded', file);
    });
    io.to(`user-${teamFolder.owner}`).emit('file-uploaded', file);

    await file.populate('owner', 'name email');
    res.status(201).json(file);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create folder in team folder
router.post('/:id/folders', auth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ message: 'Folder name is required' });
    }

    const teamFolder = await TeamFolder.findById(req.params.id);
    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Check access and permissions
    const member = teamFolder.members.find(m => m.user.toString() === req.user._id.toString());
    const isOwner = teamFolder.owner.toString() === req.user._id.toString();
    const isAdmin = isOwner || (member && member.role === 'admin');
    const isEditor = isAdmin || (member && member.role === 'editor');

    if (!isOwner && !member) {
      return res.status(403).json({ message: 'Access denied' });
    }

    if (!isEditor) {
      return res.status(403).json({ message: 'Only editors and admins can create folders' });
    }

    const folder = new Folder({
      name,
      owner: req.user._id,
      parentFolder: req.params.id
    });

    await folder.save();

    // Emit real-time update
    const io = req.app.get('io');
    teamFolder.members.forEach(member => {
      io.to(`user-${member.user}`).emit('folder-created', folder);
    });
    io.to(`user-${teamFolder.owner}`).emit('folder-created', folder);

    await folder.populate('owner', 'name email');
    res.status(201).json(folder);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete team folder
router.delete('/:id', auth, async (req, res) => {
  try {
    const teamFolder = await TeamFolder.findById(req.params.id);

    if (!teamFolder) {
      return res.status(404).json({ message: 'Team folder not found' });
    }

    // Only owner can delete the team folder
    if (teamFolder.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Only the owner can delete the team folder' });
    }

    // Delete all files in the team folder
    const files = await File.find({ parentFolder: req.params.id });
    for (const file of files) {
      try {
        if (await fs.pathExists(file.path)) {
          await fs.remove(file.path);
        }
        await File.findByIdAndDelete(file._id);
      } catch (err) {
        console.error('Error deleting file:', err);
      }
    }

    // Delete all folders in the team folder
    const folders = await Folder.find({ parentFolder: req.params.id });
    for (const folder of folders) {
      await Folder.findByIdAndDelete(folder._id);
    }

    // Delete all messages
    await TeamFolderMessage.deleteMany({ teamFolder: req.params.id });

    // Delete the team folder itself
    await TeamFolder.findByIdAndDelete(req.params.id);

    // Emit real-time update
    const io = req.app.get('io');
    teamFolder.members.forEach(member => {
      io.to(`user-${member.user}`).emit('team-folder-deleted', { folderId: req.params.id });
    });
    io.to(`user-${teamFolder.owner}`).emit('team-folder-deleted', { folderId: req.params.id });

    res.json({ message: 'Team folder deleted successfully' });
  } catch (error) {
    console.error('Error deleting team folder:', error);
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;



