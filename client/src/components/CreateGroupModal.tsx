import React, { useState } from 'react';
import { groupsAPI } from '../services/api';
import './CreateGroupModal.css';

interface CreateGroupModalProps {
  onClose: () => void;
  onSuccess: (groupId: string) => void;
}

const CreateGroupModal: React.FC<CreateGroupModalProps> = ({ onClose, onSuccess }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [privacy, setPrivacy] = useState<'public' | 'private'>('public');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!name.trim()) {
      alert('Group name is required');
      return;
    }

    try {
      setLoading(true);
      const group = await groupsAPI.createGroup(name.trim(), description.trim(), privacy);
      onSuccess(group._id);
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create group');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content create-group-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Create New Group</h3>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            <div className="form-group">
              <label>Group Name *</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Enter group name"
                maxLength={100}
                required
              />
            </div>
            <div className="form-group">
              <label>Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What is this group about?"
                maxLength={500}
                rows={4}
              />
            </div>
            <div className="form-group">
              <label>Privacy</label>
              <div className="privacy-options">
                <label className="privacy-option">
                  <input
                    type="radio"
                    value="public"
                    checked={privacy === 'public'}
                    onChange={(e) => setPrivacy(e.target.value as 'public' | 'private')}
                  />
                  <div>
                    <strong>Public</strong>
                    <span>Anyone can see the group and join</span>
                  </div>
                </label>
                <label className="privacy-option">
                  <input
                    type="radio"
                    value="private"
                    checked={privacy === 'private'}
                    onChange={(e) => setPrivacy(e.target.value as 'public' | 'private')}
                  />
                  <div>
                    <strong>Private</strong>
                    <span>Only members can see the group</span>
                  </div>
                </label>
              </div>
            </div>
          </div>
          <div className="modal-footer">
            <button type="button" className="cancel-btn" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="submit-btn" disabled={loading}>
              {loading ? 'Creating...' : 'Create Group'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateGroupModal;









