const express = require('express');
const auth = require('../middleware/auth');
const StudyGroup = require('../models/StudyGroup');
const Folder = require('../models/Folder');
const User = require('../models/User');
const StudyNote = require('../models/StudyNote');
const Flashcard = require('../models/Flashcard');
const Whiteboard = require('../models/Whiteboard');
const ChatMessage = require('../models/ChatMessage');
const StudyGroupInvitation = require('../models/StudyGroupInvitation');
const router = express.Router();

// Get all study groups (user is member or creator)
router.get('/', auth, async (req, res) => {
  try {
    const { courseCode } = req.query;
    const query = {
      $or: [
        { creator: req.user._id },
        { 'members.user': req.user._id }
      ]
    };
    
    if (courseCode) query.courseCode = courseCode;

    const groups = await StudyGroup.find(query)
      .populate('creator', 'name email')
      .populate('members.user', 'name email')
      .populate('folder', 'name _id')
      .sort({ createdAt: -1 })
      .lean();

    res.json({ groups });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single study group
router.get('/:id', auth, async (req, res) => {
  try {
    const group = await StudyGroup.findOne({
      _id: req.params.id,
      $or: [
        { creator: req.user._id },
        { 'members.user': req.user._id }
      ]
    })
      .populate('creator', 'name email')
      .populate('members.user', 'name email')
      .populate('folder')
      .lean();

    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    res.json({ group });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create study group
router.post('/', auth, async (req, res) => {
  try {
    const {
      name,
      description,
      course,
      courseCode,
      isPublic,
      maxMembers
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Name is required' });
    }

    // Create folder for study group
    const folder = new Folder({
      name: `Study Group: ${name}`,
      owner: req.user._id,
      parentFolder: null
    });
    await folder.save();

    const group = new StudyGroup({
      name,
      description,
      course,
      courseCode,
      creator: req.user._id,
      folder: folder._id,
      isPublic: isPublic || false,
      maxMembers: maxMembers || 50,
      members: [{
        user: req.user._id,
        role: 'admin'
      }]
    });

    await group.save();
    await group.populate('creator', 'name email');
    await group.populate('members.user', 'name email');
    await group.populate('folder', 'name _id');

    res.status(201).json({ group });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Join study group
router.post('/:id/join', auth, async (req, res) => {
  try {
    const group = await StudyGroup.findById(req.params.id);

    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    // Check if already a member
    const isMember = group.members.some(
      m => m.user.toString() === req.user._id.toString()
    );

    if (isMember) {
      return res.status(400).json({ message: 'Already a member' });
    }

    // Check if group is full
    if (group.members.length >= group.maxMembers) {
      return res.status(400).json({ message: 'Study group is full' });
    }

    group.members.push({
      user: req.user._id,
      role: 'member'
    });

    await group.save();
    await group.populate('creator', 'name email');
    await group.populate('members.user', 'name email');
    await group.populate('folder', 'name _id');

    res.json({ group });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Leave study group
router.post('/:id/leave', auth, async (req, res) => {
  try {
    const group = await StudyGroup.findById(req.params.id);

    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    // Can't leave if you're the creator
    if (group.creator.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Creator cannot leave the group' });
    }

    group.members = group.members.filter(
      m => m.user.toString() !== req.user._id.toString()
    );

    await group.save();
    res.json({ message: 'Left study group' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update study group
router.put('/:id', auth, async (req, res) => {
  try {
    const group = await StudyGroup.findById(req.params.id);

    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    // Only creator or admin can update
    const isAdmin = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => 
        m.user.toString() === req.user._id.toString() && m.role === 'admin'
      );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can update the group' });
    }

    const { name, description, course, courseCode, isPublic, maxMembers } = req.body;

    if (name) group.name = name;
    if (description !== undefined) group.description = description;
    if (course) group.course = course;
    if (courseCode) group.courseCode = courseCode;
    if (isPublic !== undefined) group.isPublic = isPublic;
    if (maxMembers) group.maxMembers = maxMembers;

    await group.save();
    await group.populate('creator', 'name email');
    await group.populate('members.user', 'name email');
    await group.populate('folder', 'name _id');

    res.json({ group });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete study group
router.delete('/:id', auth, async (req, res) => {
  try {
    const group = await StudyGroup.findOne({
      _id: req.params.id,
      creator: req.user._id
    });

    if (!group) {
      return res.status(404).json({ message: 'Study group not found or you are not the creator' });
    }

    await group.deleteOne();
    res.json({ message: 'Study group deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Invite user to study group
router.post('/:id/invite', auth, async (req, res) => {
  try {
    const { userId, message } = req.body;
    const group = await StudyGroup.findById(req.params.id);

    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    // Check if user is admin or creator
    const isAdmin = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => 
        m.user.toString() === req.user._id.toString() && m.role === 'admin'
      );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can invite users' });
    }

    // Check if user exists
    const invitee = await User.findById(userId);
    if (!invitee) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if already a member
    const isMember = group.members.some(
      m => m.user.toString() === userId
    );

    if (isMember) {
      return res.status(400).json({ message: 'User is already a member' });
    }

    // Check if invitation already exists
    const existingInvitation = await StudyGroupInvitation.findOne({
      group: group._id,
      invitee: userId,
      status: 'pending'
    });

    if (existingInvitation) {
      return res.status(400).json({ message: 'Invitation already sent' });
    }

    // Create invitation
    const invitation = new StudyGroupInvitation({
      group: group._id,
      inviter: req.user._id,
      invitee: userId,
      message: message || ''
    });

    await invitation.save();
    await invitation.populate('inviter', 'name email');
    await invitation.populate('invitee', 'name email');
    await invitation.populate('group', 'name');

    // Send real-time notification
    const io = req.app.get('io');
    if (io) {
      io.to(`user-${userId}`).emit('study-group-invitation', {
        invitation: {
          _id: invitation._id,
          group: {
            _id: group._id,
            name: group.name
          },
          inviter: {
            _id: req.user._id,
            name: req.user.name,
            email: req.user.email
          },
          message: message || ''
        }
      });
    }

    res.json({ invitation });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Accept/Reject invitation
router.post('/invitations/:id/respond', auth, async (req, res) => {
  try {
    const { action } = req.body; // 'accept' or 'reject'
    const invitation = await StudyGroupInvitation.findById(req.params.id)
      .populate('group');

    if (!invitation) {
      return res.status(404).json({ message: 'Invitation not found' });
    }

    if (invitation.invitee.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    if (invitation.status !== 'pending') {
      return res.status(400).json({ message: 'Invitation already responded to' });
    }

    if (action === 'accept') {
      const group = await StudyGroup.findById(invitation.group._id);
      
      // Check if group is full
      if (group.members.length >= group.maxMembers) {
        return res.status(400).json({ message: 'Study group is full' });
      }

      // Add user to group
      group.members.push({
        user: req.user._id,
        role: 'member'
      });

      await group.save();
      invitation.status = 'accepted';
    } else {
      invitation.status = 'rejected';
    }

    invitation.respondedAt = new Date();
    await invitation.save();

    res.json({ message: `Invitation ${action}ed`, invitation });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get invitations for user
router.get('/invitations/my', auth, async (req, res) => {
  try {
    const invitations = await StudyGroupInvitation.find({
      invitee: req.user._id,
      status: 'pending'
    })
      .populate('group', 'name description course courseCode')
      .populate('inviter', 'name email')
      .sort({ createdAt: -1 });

    res.json({ invitations });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Study Notes routes
router.get('/:id/notes', auth, async (req, res) => {
  try {
    const group = await StudyGroup.findById(req.params.id);
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const notes = await StudyNote.find({ group: group._id })
      .populate('author', 'name email')
      .sort({ updatedAt: -1 });

    res.json({ notes });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post('/:id/notes', auth, async (req, res) => {
  try {
    const { title, content, tags, isPublic } = req.body;
    const group = await StudyGroup.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const note = new StudyNote({
      group: group._id,
      title,
      content: content || '',
      tags: tags || [],
      isPublic: isPublic !== undefined ? isPublic : true,
      author: req.user._id
    });

    await note.save();
    group.notes.push(note._id);
    await group.save();

    await note.populate('author', 'name email');
    res.json({ note });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update note
router.put('/notes/:noteId', auth, async (req, res) => {
  try {
    const { title, content, tags, isPublic } = req.body;
    const note = await StudyNote.findById(req.params.noteId)
      .populate('group');

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    const group = note.group;
    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Only author or admin can edit
    const isAuthor = note.author.toString() === req.user._id.toString();
    const isAdmin = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => 
        m.user.toString() === req.user._id.toString() && m.role === 'admin'
      );

    if (!isAuthor && !isAdmin) {
      return res.status(403).json({ message: 'Only the author or admins can edit notes' });
    }

    if (title) note.title = title;
    if (content !== undefined) note.content = content;
    if (tags !== undefined) note.tags = tags;
    if (isPublic !== undefined) note.isPublic = isPublic;

    await note.save();
    await note.populate('author', 'name email');
    res.json({ note });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete note
router.delete('/notes/:noteId', auth, async (req, res) => {
  try {
    const note = await StudyNote.findById(req.params.noteId)
      .populate('group');

    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    const group = note.group;
    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Only author or admin can delete
    const isAuthor = note.author.toString() === req.user._id.toString();
    const isAdmin = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => 
        m.user.toString() === req.user._id.toString() && m.role === 'admin'
      );

    if (!isAuthor && !isAdmin) {
      return res.status(403).json({ message: 'Only the author or admins can delete notes' });
    }

    // Remove note from group's notes array
    group.notes = group.notes.filter(n => n.toString() !== note._id.toString());
    await group.save();

    await note.deleteOne();
    res.json({ message: 'Note deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Flashcards routes
router.get('/:id/flashcards', auth, async (req, res) => {
  try {
    const { deck } = req.query;
    const group = await StudyGroup.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const query = { group: group._id };
    if (deck) query.deck = deck;

    const flashcards = await Flashcard.find(query)
      .populate('author', 'name email')
      .sort({ createdAt: -1 });

    res.json({ flashcards });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post('/:id/flashcards', auth, async (req, res) => {
  try {
    const { front, back, deck, difficulty } = req.body;
    const group = await StudyGroup.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const flashcard = new Flashcard({
      group: group._id,
      front,
      back,
      deck: deck || 'default',
      difficulty: difficulty || 'medium',
      author: req.user._id
    });

    await flashcard.save();
    group.flashcards.push(flashcard._id);
    await group.save();

    await flashcard.populate('author', 'name email');
    res.json({ flashcard });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Whiteboards routes
router.get('/:id/whiteboards', auth, async (req, res) => {
  try {
    const group = await StudyGroup.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const whiteboards = await Whiteboard.find({ group: group._id })
      .populate('author', 'name email')
      .sort({ updatedAt: -1 });

    res.json({ whiteboards });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post('/:id/whiteboards', auth, async (req, res) => {
  try {
    const { name } = req.body;
    const group = await StudyGroup.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const whiteboard = new Whiteboard({
      group: group._id,
      name: name || 'Untitled Whiteboard',
      content: '{}',
      author: req.user._id
    });

    await whiteboard.save();
    group.whiteboards.push(whiteboard._id);
    await group.save();

    await whiteboard.populate('author', 'name email');
    res.json({ whiteboard });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.put('/whiteboards/:id', auth, async (req, res) => {
  try {
    const { name, content } = req.body;
    const whiteboard = await Whiteboard.findById(req.params.id)
      .populate('group');

    if (!whiteboard) {
      return res.status(404).json({ message: 'Whiteboard not found' });
    }

    const group = whiteboard.group;
    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    if (name) whiteboard.name = name;
    if (content !== undefined) whiteboard.content = content;

    await whiteboard.save();
    res.json({ whiteboard });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Chat messages routes
router.get('/:id/chat', auth, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const group = await StudyGroup.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const messages = await ChatMessage.find({ group: group._id })
      .populate('sender', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();

    res.json({ messages: messages.reverse() });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post('/:id/chat', auth, async (req, res) => {
  try {
    const { message, type, fileUrl } = req.body;
    const group = await StudyGroup.findById(req.params.id);
    
    if (!group) {
      return res.status(404).json({ message: 'Study group not found' });
    }

    const isMember = group.creator.toString() === req.user._id.toString() ||
      group.members.some(m => m.user.toString() === req.user._id.toString());

    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const chatMessage = new ChatMessage({
      group: group._id,
      sender: req.user._id,
      message,
      type: type || 'text',
      fileUrl: fileUrl || null
    });

    await chatMessage.save();
    group.chatMessages.push(chatMessage._id);
    await group.save();

    await chatMessage.populate('sender', 'name email');

    // Broadcast to all group members
    const io = req.app.get('io');
    if (io) {
      group.members.forEach(member => {
        io.to(`user-${member.user}`).emit('study-group-message', {
          groupId: group._id,
          message: chatMessage
        });
      });
      io.to(`user-${group.creator}`).emit('study-group-message', {
        groupId: group._id,
        message: chatMessage
      });
    }

    res.json({ message: chatMessage });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;








