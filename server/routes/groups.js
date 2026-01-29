const express = require('express');
const auth = require('../middleware/auth');
const Group = require('../models/Group');
const SocialPost = require('../models/SocialPost');
const User = require('../models/User');
const Notification = require('../models/Notification');
const GroupJoinRequest = require('../models/GroupJoinRequest');
const router = express.Router();

// Helper function to create notification
const createNotification = async (req, userId, type, fromUserId, postId = null, groupId = null) => {
  try {
    if (userId.toString() === fromUserId.toString()) return;
    
    const notification = new Notification({
      user: userId,
      type,
      fromUser: fromUserId,
      post: postId,
      group: groupId
    });
    await notification.save();
    
    const io = req.app.get('io');
    if (io) {
      io.to(`user-${userId}`).emit('new-notification', notification);
    }
  } catch (error) {
    console.error('Error creating notification:', error);
  }
};

// Create a new group
router.post('/', auth, async (req, res) => {
  try {
    const { name, description, privacy } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ message: 'Group name is required' });
    }

    const group = new Group({
      name: name.trim(),
      description: description || '',
      creator: req.user._id,
      admins: [req.user._id],
      members: [{
        user: req.user._id,
        role: 'admin'
      }],
      privacy: privacy || 'public'
    });

    await group.save();
    await group.populate('creator', 'name email');
    await group.populate('members.user', 'name email');
    await group.populate('admins', 'name email');

    res.status(201).json(group);
  } catch (error) {
    console.error('Error creating group:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get all groups (public + user's groups)
router.get('/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, search } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Get user's group IDs
    const userGroups = await Group.find({
      'members.user': req.user._id
    }).select('_id');
    const userGroupIds = userGroups.map(g => g._id);

    // Build search condition if provided
    let searchCondition = {};
    if (search && search.trim().length > 0) {
      const searchRegex = new RegExp(search.trim(), 'i');
      searchCondition = {
        $or: [
          { name: searchRegex },
          { description: searchRegex }
        ]
      };
    }

    // Build query - show:
    // 1. Public groups (matching search if provided)
    // 2. User's groups (public or private, matching search if provided)
    // 3. Private groups matching search (so they can be discovered and joined)
    let query;
    if (Object.keys(searchCondition).length > 0) {
      // When searching, show all groups that match (public + user's groups + private groups for discovery)
      query = {
        $and: [
          searchCondition,
          {
            $or: [
              { privacy: 'public' },
              { _id: { $in: userGroupIds } },
              { privacy: 'private' } // Allow private groups to be discovered via search
            ]
          }
        ]
      };
    } else {
      // Without search, only show public groups and user's groups
      query = {
        $or: [
          { privacy: 'public' },
          { _id: { $in: userGroupIds } }
        ]
      };
    }

    const groups = await Group.find(query)
      .populate('creator', 'name email')
      .populate('admins', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    // Check membership status for each group
    const groupsWithMembership = await Promise.all(
      groups.map(async (group) => {
        const isMember = group.members.some(
          m => m.user.toString() === req.user._id.toString()
        );
        const isAdmin = group.admins.some(
          a => a.toString() === req.user._id.toString()
        );
        return {
          ...group.toObject(),
          isMember,
          isAdmin,
          isCreator: group.creator._id.toString() === req.user._id.toString()
        };
      })
    );

    const total = await Group.countDocuments(query);

    res.json({
      groups: groupsWithMembership,
      hasMore: skip + groups.length < total,
      total
    });
  } catch (error) {
    console.error('Error fetching groups:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get a specific group
router.get('/:groupId', auth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId)
      .populate('creator', 'name email')
      .populate('members.user', 'name email')
      .populate('admins', 'name email');

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user can view (public or member)
    const isMember = group.members.some(
      m => m.user._id.toString() === req.user._id.toString()
    );
    const isAdmin = group.admins.some(
      a => a.toString() === req.user._id.toString()
    );

    if (group.privacy === 'private' && !isMember) {
      return res.status(403).json({ message: 'This is a private group' });
    }

    const isCreator = group.creator._id.toString() === req.user._id.toString();
    
    res.json({
      ...group.toObject(),
      isMember,
      isAdmin: isAdmin || isCreator, // Creator is always admin
      isCreator
    });
  } catch (error) {
    console.error('Error fetching group:', error);
    res.status(500).json({ message: error.message });
  }
});

// Join a group (public) or request to join (private)
router.post('/:groupId/join', auth, async (req, res) => {
  try {
    const { message } = req.body;
    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if already a member
    const isMember = group.members.some(
      m => m.user.toString() === req.user._id.toString()
    );

    if (isMember) {
      return res.status(400).json({ message: 'Already a member of this group' });
    }

    // Check if there's already a pending request
    const existingRequest = await GroupJoinRequest.findOne({
      group: group._id,
      user: req.user._id,
      status: 'pending'
    });

    if (existingRequest) {
      return res.status(400).json({ message: 'Join request already pending' });
    }

    // If group is public, join directly
    if (group.privacy === 'public') {
      group.members.push({
        user: req.user._id,
        role: 'member'
      });

      await group.save();
      await group.populate('members.user', 'name email');

      // Create notification for group admins
      for (const adminId of group.admins) {
        if (adminId.toString() !== req.user._id.toString()) {
          await createNotification(req, adminId, 'group_join', req.user._id, null, group._id);
        }
      }

      res.json({ message: 'Joined group successfully', group, joined: true });
    } else {
      // If group is private, create a join request
      const joinRequest = new GroupJoinRequest({
        group: group._id,
        user: req.user._id,
        message: message || '',
        status: 'pending'
      });

      await joinRequest.save();
      await joinRequest.populate('user', 'name email');
      await joinRequest.populate('group', 'name');

      // Create notification for group admins
      for (const adminId of group.admins) {
        await createNotification(req, adminId, 'group_join_request', req.user._id, null, group._id);
      }

      res.json({ message: 'Join request sent successfully', request: joinRequest, joined: false });
    }
  } catch (error) {
    console.error('Error joining/requesting to join group:', error);
    res.status(500).json({ message: error.message });
  }
});

// Leave a group
router.post('/:groupId/leave', auth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if creator (can't leave)
    if (group.creator.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Group creator cannot leave the group' });
    }

    // Remove from members
    group.members = group.members.filter(
      m => m.user.toString() !== req.user._id.toString()
    );

    // Remove from admins if admin
    group.admins = group.admins.filter(
      a => a.toString() !== req.user._id.toString()
    );

    await group.save();

    res.json({ message: 'Left group successfully' });
  } catch (error) {
    console.error('Error leaving group:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get group posts
router.get('/:groupId/posts', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user can view (public or member)
    const isMember = group.members.some(
      m => m.user.toString() === req.user._id.toString()
    );

    if (group.privacy === 'private' && !isMember) {
      return res.status(403).json({ message: 'This is a private group' });
    }

    const posts = await SocialPost.find({ group: req.params.groupId })
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

    const total = await SocialPost.countDocuments({ group: req.params.groupId });

    res.json({
      posts,
      hasMore: skip + posts.length < total,
      total
    });
  } catch (error) {
    console.error('Error fetching group posts:', error);
    res.status(500).json({ message: error.message });
  }
});

// Add/remove admin
router.post('/:groupId/admin/:userId', auth, async (req, res) => {
  try {
    const { action } = req.body; // 'add' or 'remove'
    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if requester is creator or admin
    const isCreator = group.creator.toString() === req.user._id.toString();
    const isAdmin = group.admins.some(
      a => a.toString() === req.user._id.toString()
    );

    if (!isCreator && !isAdmin) {
      return res.status(403).json({ message: 'Only admins can manage admins' });
    }

    const userId = req.params.userId;

    // Check if user is a member
    const isMember = group.members.some(
      m => m.user.toString() === userId
    );

    if (!isMember) {
      return res.status(400).json({ message: 'User is not a member of this group' });
    }

    if (action === 'add') {
      if (group.admins.some(a => a.toString() === userId)) {
        return res.status(400).json({ message: 'User is already an admin' });
      }
      group.admins.push(userId);
      // Update member role
      const member = group.members.find(m => m.user.toString() === userId);
      if (member) {
        member.role = 'admin';
      }
    } else if (action === 'remove') {
      if (group.creator.toString() === userId) {
        return res.status(400).json({ message: 'Cannot remove creator as admin' });
      }
      group.admins = group.admins.filter(a => a.toString() !== userId);
      // Update member role
      const member = group.members.find(m => m.user.toString() === userId);
      if (member) {
        member.role = 'member';
      }
    } else {
      return res.status(400).json({ message: 'Invalid action. Use "add" or "remove"' });
    }

    await group.save();

    res.json({ message: `Admin ${action}ed successfully`, group });
  } catch (error) {
    console.error('Error managing admin:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get join requests for a group (admin only)
router.get('/:groupId/requests', auth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user is admin or creator
    const isAdmin = group.admins.some(
      a => a.toString() === req.user._id.toString()
    );
    const isCreator = group.creator.toString() === req.user._id.toString();

    if (!isAdmin && !isCreator) {
      return res.status(403).json({ message: 'Only admins can view join requests' });
    }

    const requests = await GroupJoinRequest.find({
      group: group._id,
      status: 'pending'
    })
      .populate('user', 'name email')
      .sort({ createdAt: -1 });

    res.json({ requests });
  } catch (error) {
    console.error('Error fetching join requests:', error);
    res.status(500).json({ message: error.message });
  }
});

// Accept a join request
router.post('/:groupId/requests/:requestId/accept', auth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user is admin
    const isAdmin = group.admins.some(
      a => a.toString() === req.user._id.toString()
    );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can accept join requests' });
    }

    const request = await GroupJoinRequest.findById(req.params.requestId)
      .populate('user', 'name email');

    if (!request || request.group.toString() !== group._id.toString()) {
      return res.status(404).json({ message: 'Join request not found' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ message: 'Request already processed' });
    }

    // Add user to group
    group.members.push({
      user: request.user._id,
      role: 'member'
    });

    // Update request status
    request.status = 'approved';
    request.reviewedBy = req.user._id;
    request.reviewedAt = Date.now();

    await Promise.all([group.save(), request.save()]);

    // Create notification for the user
    await createNotification(req, request.user._id, 'group_join', req.user._id, null, group._id);

    res.json({ message: 'Join request accepted', group });
  } catch (error) {
    console.error('Error accepting join request:', error);
    res.status(500).json({ message: error.message });
  }
});

// Reject a join request
router.post('/:groupId/requests/:requestId/reject', auth, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user is admin
    const isAdmin = group.admins.some(
      a => a.toString() === req.user._id.toString()
    );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can reject join requests' });
    }

    const request = await GroupJoinRequest.findById(req.params.requestId);

    if (!request || request.group.toString() !== group._id.toString()) {
      return res.status(404).json({ message: 'Join request not found' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ message: 'Request already processed' });
    }

    // Update request status
    request.status = 'rejected';
    request.reviewedBy = req.user._id;
    request.reviewedAt = Date.now();

    await request.save();

    res.json({ message: 'Join request rejected' });
  } catch (error) {
    console.error('Error rejecting join request:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get user's pending join requests
router.get('/requests/my', auth, async (req, res) => {
  try {
    const requests = await GroupJoinRequest.find({
      user: req.user._id,
      status: 'pending'
    })
      .populate('group', 'name privacy')
      .sort({ createdAt: -1 });

    res.json({ requests });
  } catch (error) {
    console.error('Error fetching user join requests:', error);
    res.status(500).json({ message: error.message });
  }
});

// Invite users to a group
router.post('/:groupId/invite', auth, async (req, res) => {
  try {
    const { userIds } = req.body; // Array of user IDs to invite
    const group = await Group.findById(req.params.groupId);

    if (!group) {
      return res.status(404).json({ message: 'Group not found' });
    }

    // Check if user is admin or creator
    const isAdmin = group.admins.some(
      a => a.toString() === req.user._id.toString()
    );
    const isCreator = group.creator.toString() === req.user._id.toString();

    if (!isAdmin && !isCreator) {
      return res.status(403).json({ message: 'Only admins can invite users' });
    }

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: 'User IDs array is required' });
    }

    const invitedUsers = [];
    const errors = [];

    for (const userId of userIds) {
      try {
        // Check if user exists
        const userToInvite = await User.findById(userId);
        if (!userToInvite) {
          errors.push({ userId, error: 'User not found' });
          continue;
        }

        // Check if already a member
        const isMember = group.members.some(
          m => m.user.toString() === userId
        );

        if (isMember) {
          errors.push({ userId, error: 'User is already a member' });
          continue;
        }

        // Check if there's already a pending invitation or join request
        const existingRequest = await GroupJoinRequest.findOne({
          group: group._id,
          user: userId,
          status: 'pending'
        });

        if (existingRequest) {
          errors.push({ userId, error: 'Invitation or join request already pending' });
          continue;
        }

        // Create invitation (as a join request with invitedBy field)
        const invitation = new GroupJoinRequest({
          group: group._id,
          user: userId,
          message: `You've been invited to join "${group.name}"`,
          status: 'pending',
          invitedBy: req.user._id,
          createdAt: Date.now()
        });

        await invitation.save();
        await invitation.populate('user', 'name email');

        // Create notification for the invited user
        await createNotification(req, userId, 'group_invite', req.user._id, null, group._id);

        invitedUsers.push(invitation);
      } catch (error) {
        errors.push({ userId, error: error.message });
      }
    }

    res.json({
      message: `Invited ${invitedUsers.length} user(s)`,
      invited: invitedUsers,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    console.error('Error inviting users to group:', error);
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

