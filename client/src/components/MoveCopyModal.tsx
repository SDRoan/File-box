import React, { useState, useEffect } from 'react';
import { Folder } from '../types';
import { filesAPI } from '../services/api';
import './MoveCopyModal.css';

interface MoveCopyModalProps {
  itemId: string;
  itemName: string;
  itemType: 'file' | 'folder';
  operation: 'move' | 'copy';
  onClose: () => void;
  onSuccess: () => void;
}

const MoveCopyModal: React.FC<MoveCopyModalProps> = ({
  itemId,
  itemName,
  itemType,
  operation,
  onClose,
  onSuccess,
}) => {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [selectedFolderId, setSelectedFolderId] = useState<string>('root');
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);

  useEffect(() => {
    loadFolders();
  }, []);

  const loadFolders = async () => {
    try {
      const data = await filesAPI.getFiles();
      setFolders(data.folders || []);
    } catch (error) {
      console.error('Error loading folders:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setProcessing(true);

    try {
      if (operation === 'move') {
        if (itemType === 'file') {
          await filesAPI.moveFile(itemId, selectedFolderId === 'root' ? undefined : selectedFolderId);
        } else {
          await filesAPI.moveFolder(itemId, selectedFolderId === 'root' ? undefined : selectedFolderId);
        }
      } else {
        if (itemType === 'file') {
          await filesAPI.copyFile(itemId, selectedFolderId === 'root' ? undefined : selectedFolderId);
        } else {
          alert('Copying folders is not yet supported');
          setProcessing(false);
          return;
        }
      }
      onSuccess();
      onClose();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Operation failed');
    } finally {
      setProcessing(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content move-copy-modal" onClick={(e) => e.stopPropagation()}>
        <h2>{operation === 'move' ? 'Move' : 'Copy'} {itemType === 'file' ? 'File' : 'Folder'}</h2>
        <p className="modal-subtitle">{itemName}</p>

        <form onSubmit={handleSubmit}>
          <label className="modal-label">Destination Folder</label>
          <select
            value={selectedFolderId}
            onChange={(e) => setSelectedFolderId(e.target.value)}
            className="modal-select"
            disabled={loading || processing}
          >
            <option value="root">My Files (Root)</option>
            {folders.map((folder) => (
              <option key={folder._id} value={folder._id}>
                {folder.name}
              </option>
            ))}
          </select>

          <div className="modal-actions">
            <button
              type="button"
              onClick={onClose}
              className="cancel-button"
              disabled={processing}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || processing}
              className="action-button"
            >
              {processing ? 'Processing...' : operation === 'move' ? 'Move' : 'Copy'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default MoveCopyModal;










