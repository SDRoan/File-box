import React, { useState } from 'react';
import { filesAPI } from '../services/api';
import './CreateFolderModal.css';

interface CreateFolderModalProps {
  currentFolderId?: string;
  onClose: () => void;
  onCreated: () => void;
  isTeamFolder?: boolean;
  teamFolderId?: string;
}

const CreateFolderModal: React.FC<CreateFolderModalProps> = ({
  currentFolderId,
  onClose,
  onCreated,
  isTeamFolder = false,
  teamFolderId,
}) => {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    try {
      setLoading(true);
      if (isTeamFolder && teamFolderId) {
        const { teamFoldersAPI } = await import('../services/api');
        await teamFoldersAPI.createFolder(teamFolderId, name.trim());
      } else {
        await filesAPI.createFolder(name.trim(), currentFolderId);
      }
      onCreated();
    } catch (error) {
      console.error('Error creating folder:', error);
      alert('Failed to create folder');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Create New Folder</h2>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Folder Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            className="modal-input"
          />
          <div className="modal-actions">
            <button type="button" onClick={onClose} className="cancel-button">
              Cancel
            </button>
            <button type="submit" disabled={loading || !name.trim()} className="create-button">
              {loading ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateFolderModal;



