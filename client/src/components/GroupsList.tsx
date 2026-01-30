import React, { useState, useEffect } from 'react';
import { groupsAPI } from '../services/api';
import CreateGroupModal from './CreateGroupModal';
import GroupView from './GroupView';
import { UsersIcon, PlusIcon, EyeIcon, LockIcon, MailIcon } from './Icons';
import './GroupsList.css';

interface Group {
  _id: string;
  name: string;
  description: string;
  creator: {
    _id: string;
    name: string;
    email: string;
  };
  memberCount: number;
  postCount: number;
  privacy: 'public' | 'private';
  isMember: boolean;
  isAdmin: boolean;
  isCreator: boolean;
  createdAt: string;
}

const GroupsList: React.FC = () => {
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadGroups();
  }, [searchQuery]);

  const loadGroups = async () => {
    try {
      setLoading(true);
      const data = await groupsAPI.getGroups(1, 50, searchQuery);
      setGroups(data.groups || []);
    } catch (error) {
      console.error('Error loading groups:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleJoinGroup = async (groupId: string) => {
    try {
      const group = groups.find(g => g._id === groupId);
      if (group?.privacy === 'private') {
        // For private groups, request to join
        const message = prompt('Optional message to group admin:') || '';
        const result = await groupsAPI.requestToJoin(groupId, message);
        if (result.joined) {
          alert('Joined group successfully!');
        } else {
          alert('Join request sent! The admin will review your request.');
        }
      } else {
        // For public groups, join directly
        await groupsAPI.joinGroup(groupId);
        alert('Joined group successfully!');
      }
      loadGroups();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to join/request to join group');
    }
  };

  const handleLeaveGroup = async (groupId: string) => {
    if (!window.confirm('Are you sure you want to leave this group?')) return;
    try {
      await groupsAPI.leaveGroup(groupId);
      loadGroups();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to leave group');
    }
  };

  if (selectedGroup) {
    return (
      <GroupView
        groupId={selectedGroup}
        onBack={() => setSelectedGroup(null)}
        onUpdate={loadGroups}
      />
    );
  }

  return (
    <div className="groups-list-container">
      <div className="groups-header">
        <h2>
          <UsersIcon size={28} color="currentColor" style={{ display: 'inline-block', marginRight: '0.5rem', verticalAlign: 'middle' }} />
          Groups
        </h2>
        <div className="groups-header-actions">
          <input
            type="text"
            placeholder="Search groups..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="groups-search-input"
          />
          <button
            className="create-group-btn"
            onClick={() => setShowCreateModal(true)}
          >
            <PlusIcon size={18} color="#ffffff" />
            <span>Create Group</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading">Loading groups...</div>
      ) : groups.length === 0 ? (
        <div className="empty-groups">
          <div className="empty-icon">
            <UsersIcon size={64} color="#999" />
          </div>
          <p>No groups found</p>
          <p className="hint">Create a group to get started!</p>
        </div>
      ) : (
        <div className="groups-grid">
          {groups.map(group => (
            <div key={group._id} className="group-card">
              <div className="group-header">
                <div className="group-avatar">
                  {group.name.charAt(0).toUpperCase()}
                </div>
                <div className="group-info">
                  <h3 className="group-name">{group.name}</h3>
                  <div className="group-meta">
                    <span>{group.memberCount} members</span>
                    <span>•</span>
                    <span>{group.postCount} posts</span>
                    {group.privacy === 'private' && (
                      <span>
                        • <LockIcon size={14} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} /> Private
                      </span>
                    )}
                  </div>
                </div>
              </div>
              {group.description && (
                <p className="group-description">{group.description}</p>
              )}
              <div className="group-footer">
                {group.isMember ? (
                  <>
                    <button
                      className="group-action-btn view-btn"
                      onClick={() => setSelectedGroup(group._id)}
                    >
                      <EyeIcon size={16} color="currentColor" />
                      <span>View Group</span>
                    </button>
                    {!group.isCreator && (
                      <button
                        className="group-action-btn leave-btn"
                        onClick={() => handleLeaveGroup(group._id)}
                      >
                        Leave
                      </button>
                    )}
                  </>
                ) : (
                  <button
                    className="group-action-btn join-btn"
                    onClick={() => handleJoinGroup(group._id)}
                  >
                    {group.privacy === 'private' ? (
                      <>
                        <MailIcon size={16} color="currentColor" />
                        <span>Request to Join</span>
                      </>
                    ) : (
                      <>
                        <PlusIcon size={16} color="currentColor" />
                        <span>Join Group</span>
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {showCreateModal && (
        <CreateGroupModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={(groupId) => {
            setShowCreateModal(false);
            setSelectedGroup(groupId);
            loadGroups();
          }}
        />
      )}
    </div>
  );
};

export default GroupsList;

