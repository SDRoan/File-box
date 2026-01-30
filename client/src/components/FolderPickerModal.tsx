import React, { useState, useEffect } from 'react';
import { filesAPI } from '../services/api';
import { Folder } from '../types';
import { FolderIcon, CloseIcon } from './Icons';
import './FolderPickerModal.css';

interface FolderPickerModalProps {
  onSelect: (folderId: string | null) => void;
  onClose: () => void;
  excludeFolderId?: string; // Don't show this folder (to prevent moving into itself)
  currentFolderId?: string;
}

const FolderPickerModal: React.FC<FolderPickerModalProps> = ({
  onSelect,
  onClose,
  excludeFolderId,
  currentFolderId,
}) => {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [loading, setLoading] = useState(true);
  const [folderStack, setFolderStack] = useState<string[]>([]);
  const [currentFolder, setCurrentFolder] = useState<string | null>(null);
  const [showCreateFolder, setShowCreateFolder] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [creatingFolder, setCreatingFolder] = useState(false);

  useEffect(() => {
    loadFolders();
  }, [currentFolder]);

  const loadFolders = async () => {
    try {
      setLoading(true);
      const data = await filesAPI.getFiles(
        currentFolder === 'root' || !currentFolder ? undefined : currentFolder
      );
      
      // Filter out the excluded folder and current folder
      const filteredFolders = (data.folders || []).filter(
        (f: Folder) => f._id !== excludeFolderId && f._id !== currentFolderId
      );
      
      setFolders(filteredFolders);
    } catch (error) {
      console.error('Error loading folders:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFolderClick = (folder: Folder) => {
    setFolderStack([...folderStack, folder._id]);
    setCurrentFolder(folder._id);
  };

  const handleNavigateUp = () => {
    if (folderStack.length > 0) {
      const newStack = [...folderStack];
      newStack.pop();
      setFolderStack(newStack);
      setCurrentFolder(newStack.length > 0 ? newStack[newStack.length - 1] : null);
    } else {
      setCurrentFolder(null);
    }
  };

  const handleSelectRoot = () => {
    onSelect(null);
    onClose();
  };

  const handleSelectFolder = (folderId: string) => {
    onSelect(folderId);
    onClose();
  };

  const handleCreateFolder = async () => {
    if (!newFolderName.trim()) {
      alert('Please enter a folder name');
      return;
    }

    try {
      setCreatingFolder(true);
      const newFolder = await filesAPI.createFolder(
        newFolderName.trim(),
        currentFolder === 'root' || !currentFolder ? undefined : currentFolder
      );
      
      // Reload folders to show the new one
      await loadFolders();
      
      // Reset form
      setNewFolderName('');
      setShowCreateFolder(false);
      
      // Optionally auto-select the newly created folder
      // onSelect(newFolder._id);
      // onClose();
    } catch (error: any) {
      console.error('Error creating folder:', error);
      alert(error.response?.data?.message || 'Failed to create folder');
    } finally {
      setCreatingFolder(false);
    }
  };

  const getBreadcrumbs = () => {
    const breadcrumbs = ['Root'];
    // We'd need to load folder names for breadcrumbs, but for now just show current
    return breadcrumbs.join(' / ');
  };

  return (
    <div className="folder-picker-overlay" onClick={onClose}>
      <div className="folder-picker-modal" onClick={(e) => e.stopPropagation()}>
        <div className="folder-picker-header">
          <h3>Select Destination Folder</h3>
          <button className="close-btn" onClick={onClose}>
            <CloseIcon size={18} color="currentColor" />
          </button>
        </div>

        <div className="folder-picker-content">
          {loading ? (
            <div className="folder-picker-loading">Loading folders...</div>
          ) : (
            <>
              <div className="folder-picker-nav">
                {currentFolder && (
                  <button className="nav-up-btn" onClick={handleNavigateUp}>
                    ← Back
                  </button>
                )}
                <span className="current-path">
                  {currentFolder ? 'Current Folder' : 'Root'}
                </span>
              </div>

              {showCreateFolder ? (
                <div className="create-folder-form">
                  <h4>Create New Folder</h4>
                  <input
                    type="text"
                    value={newFolderName}
                    onChange={(e) => setNewFolderName(e.target.value)}
                    placeholder="Enter folder name"
                    className="folder-name-input"
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        handleCreateFolder();
                      } else if (e.key === 'Escape') {
                        setShowCreateFolder(false);
                        setNewFolderName('');
                      }
                    }}
                    autoFocus
                  />
                  <div className="create-folder-actions">
                    <button
                      className="create-btn"
                      onClick={handleCreateFolder}
                      disabled={creatingFolder || !newFolderName.trim()}
                    >
                      {creatingFolder ? 'Creating...' : 'Create'}
                    </button>
                    <button
                      className="cancel-create-btn"
                      onClick={() => {
                        setShowCreateFolder(false);
                        setNewFolderName('');
                      }}
                      disabled={creatingFolder}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="folder-picker-actions-bar">
                    <button
                      className="create-folder-btn"
                      onClick={() => setShowCreateFolder(true)}
                    >
                      + New Folder
                    </button>
                  </div>
                  <div className="folder-list">
                <div
                  className="folder-item root-item"
                  onClick={handleSelectRoot}
                >
                  <FolderIcon size={20} color="currentColor" className="folder-icon" />
                  <span className="folder-name">Root (Home)</span>
                </div>

                {folders.map((folder) => (
                  <div
                    key={folder._id}
                    className="folder-item"
                    onClick={() => handleSelectFolder(folder._id)}
                    onDoubleClick={() => handleFolderClick(folder)}
                  >
                    <FolderIcon size={20} color="currentColor" className="folder-icon" />
                    <span className="folder-name">{folder.name}</span>
                    <span className="folder-arrow">→</span>
                  </div>
                ))}

                    {folders.length === 0 && (
                      <div className="no-folders">
                        No folders available in this location
                      </div>
                    )}
                  </div>
                </>
              )}
            </>
          )}
        </div>

        <div className="folder-picker-footer">
          <button className="cancel-btn" onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

export default FolderPickerModal;

