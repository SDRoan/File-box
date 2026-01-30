import React, { useState, useEffect } from 'react';
import { groupsAPI, usersAPI } from '../services/api';
import { UsersIcon, SearchIcon, CheckIcon, CloseIcon, UserIcon } from './Icons';
import './InviteUsersModal.css';

interface InviteUsersModalProps {
  groupId: string;
  groupName: string;
  existingMemberIds: string[];
  onClose: () => void;
  onInviteSuccess: () => void;
}

const InviteUsersModal: React.FC<InviteUsersModalProps> = ({
  groupId,
  groupName,
  existingMemberIds,
  onClose,
  onInviteSuccess
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [users, setUsers] = useState<any[]>([]);
  const [selectedUsers, setSelectedUsers] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [inviting, setInviting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadUsers();
  }, []);

  useEffect(() => {
    if (searchQuery.trim()) {
      searchUsers(searchQuery);
    } else {
      loadUsers();
    }
  }, [searchQuery]);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const data = await usersAPI.getAllUsers();
      // Filter out existing members
      const filteredUsers = data.filter((user: any) => !existingMemberIds.includes(user._id));
      setUsers(filteredUsers);
    } catch (error) {
      console.error('Error loading users:', error);
      setError('Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const searchUsers = async (query: string) => {
    try {
      setLoading(true);
      const data = await usersAPI.getAllUsers();
      const filtered = data.filter((user: any) => {
        const matchesSearch = user.name.toLowerCase().includes(query.toLowerCase()) ||
                             user.email.toLowerCase().includes(query.toLowerCase());
        const notMember = !existingMemberIds.includes(user._id);
        return matchesSearch && notMember;
      });
      setUsers(filtered);
    } catch (error) {
      console.error('Error searching users:', error);
      setError('Failed to search users');
    } finally {
      setLoading(false);
    }
  };

  const toggleUserSelection = (userId: string) => {
    const newSelected = new Set(selectedUsers);
    if (newSelected.has(userId)) {
      newSelected.delete(userId);
    } else {
      newSelected.add(userId);
    }
    setSelectedUsers(newSelected);
  };

  const handleInvite = async () => {
    if (selectedUsers.size === 0) {
      alert('Please select at least one user to invite');
      return;
    }

    try {
      setInviting(true);
      setError(null);
      const userIds = Array.from(selectedUsers);
      const result = await groupsAPI.inviteUsers(groupId, userIds);
      
      if (result.errors && result.errors.length > 0) {
        const errorMessages = result.errors.map((e: any) => e.error).join(', ');
        alert(`Some invitations failed: ${errorMessages}`);
      } else {
        alert(`Successfully invited ${result.invited.length} user(s)!`);
      }
      
      onInviteSuccess();
      onClose();
    } catch (error: any) {
      console.error('Error inviting users:', error);
      setError(error.response?.data?.message || 'Failed to invite users');
    } finally {
      setInviting(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content invite-users-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>
            <UsersIcon size={20} color="currentColor" style={{ display: 'inline-block', marginRight: '0.5rem', verticalAlign: 'middle' }} />
            Invite Users to "{groupName}"
          </h3>
          <button className="close-btn" onClick={onClose}>
            <CloseIcon size={18} color="currentColor" />
          </button>
        </div>

        <div className="modal-body">
          <div className="search-section">
            <div className="search-box-invite">
              <SearchIcon size={18} color="#999" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input
                type="text"
                placeholder="Search users by name or email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input-invite"
              />
            </div>
          </div>

          {error && (
            <div className="error-message-invite">{error}</div>
          )}

          <div className="selected-count">
            {selectedUsers.size} user{selectedUsers.size !== 1 ? 's' : ''} selected
          </div>

          <div className="users-list-invite">
            {loading ? (
              <div className="loading-invite">Loading users...</div>
            ) : users.length === 0 ? (
              <div className="no-users-invite">
                <UserIcon size={48} color="#999" />
                <p>No users found</p>
              </div>
            ) : (
              users.map((user) => (
                <div
                  key={user._id}
                  className={`user-item-invite ${selectedUsers.has(user._id) ? 'selected' : ''}`}
                  onClick={() => toggleUserSelection(user._id)}
                >
                  <div className="user-avatar-invite">
                    {user.name.charAt(0).toUpperCase()}
                  </div>
                  <div className="user-info-invite">
                    <div className="user-name-invite">{user.name}</div>
                    <div className="user-email-invite">{user.email}</div>
                  </div>
                  <div className="checkmark-invite">
                    {selectedUsers.has(user._id) && (
                      <CheckIcon size={20} color="#6366f1" />
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="modal-footer-invite">
          <button className="cancel-btn-invite" onClick={onClose}>
            Cancel
          </button>
          <button
            className="invite-btn-invite"
            onClick={handleInvite}
            disabled={selectedUsers.size === 0 || inviting}
          >
            {inviting ? 'Inviting...' : `Invite ${selectedUsers.size} User${selectedUsers.size !== 1 ? 's' : ''}`}
          </button>
        </div>
      </div>
    </div>
  );
};

export default InviteUsersModal;

