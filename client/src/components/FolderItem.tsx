import React, { useState } from 'react';
import { Folder } from '../types';
import { filesAPI } from '../services/api';
import MoveCopyModal from './MoveCopyModal';
import ClassificationBadge from './ClassificationBadge';
import { FolderIcon, DownloadIcon, PackageIcon, StarredIcon, TrashIcon, RestoreIcon } from './Icons';
import './FolderItem.css';

interface FolderItemProps {
  folder: Folder;
  onClick: () => void;
  onDelete: () => void;
  onRestore: () => void;
  onPermanentDelete: () => void;
  onMove?: () => void;
  showTrash: boolean;
  isSelected?: boolean;
  selectionMode?: boolean;
}

const FolderItem: React.FC<FolderItemProps> = ({
  folder,
  onClick,
  onDelete,
  onRestore,
  onPermanentDelete,
  onMove,
  showTrash,
  isSelected = false,
  selectionMode = false,
}) => {
  const [showMoveModal, setShowMoveModal] = useState(false);

  const handleDownloadAsZip = async () => {
    try {
      const blob = await filesAPI.downloadFolderAsZip(folder._id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${folder.name}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error downloading folder:', error);
      alert('Failed to download folder');
    }
  };
  return (
    <div className={`folder-item ${isSelected ? 'selected' : ''}`} onClick={onClick}>
      {selectionMode && (
        <input
          type="checkbox"
          checked={isSelected}
          readOnly
          className="selection-checkbox"
          onClick={(e) => e.stopPropagation()}
        />
      )}
      <div className="folder-icon">
        <FolderIcon size={32} color="currentColor" />
      </div>
      <div className="folder-info">
        <div className="folder-name" title={folder.name}>
          {folder.name}
        </div>
          <div className="folder-meta">
            {new Date(folder.createdAt).toLocaleDateString()}
            {showTrash && folder.deletedAt && (
              <span className="recovery-info">
                {(() => {
                  const daysDeleted = Math.floor((Date.now() - new Date(folder.deletedAt).getTime()) / (1000 * 60 * 60 * 24));
                  const recoveryDays = folder.recoveryPeriodDays || 30;
                  const daysRemaining = recoveryDays - daysDeleted;
                  if (daysRemaining > 0) {
                    return ` • ${daysRemaining} day${daysRemaining !== 1 ? 's' : ''} until permanent deletion`;
                  } else {
                    return ' • Will be permanently deleted soon';
                  }
                })()}
              </span>
            )}
          {folder.dataClassification && (
            <div style={{ marginTop: '4px' }}>
              <ClassificationBadge classification={folder.dataClassification} size="small" />
            </div>
          )}
        </div>
      </div>
      <div className="folder-actions" onClick={(e) => e.stopPropagation()}>
        {!showTrash ? (
          <>
            <button onClick={handleDownloadAsZip} className="icon-button" title="Download as ZIP">
              <DownloadIcon size={18} color="currentColor" />
            </button>
            <button onClick={() => setShowMoveModal(true)} className="icon-button" title="Move">
              <PackageIcon size={18} color="currentColor" />
            </button>
            <button
              onClick={() => filesAPI.starFolder(folder._id)}
              className={`icon-button ${folder.isStarred ? 'starred' : ''}`}
              title="Star"
            >
              <StarredIcon size={18} color="currentColor" />
            </button>
            <button onClick={onDelete} className="icon-button" title="Delete">
              <TrashIcon size={18} color="currentColor" />
            </button>
          </>
        ) : (
          <>
            <button onClick={onRestore} className="icon-button" title="Restore">
              <RestoreIcon size={18} color="currentColor" />
            </button>
            <button
              onClick={onPermanentDelete}
              className="icon-button danger"
              title="Permanently Delete"
            >
              <TrashIcon size={18} color="currentColor" />
            </button>
          </>
        )}
      </div>
      {showMoveModal && (
        <MoveCopyModal
          itemId={folder._id}
          itemName={folder.name}
          itemType="folder"
          operation="move"
          onClose={() => setShowMoveModal(false)}
          onSuccess={() => {
            setShowMoveModal(false);
            onMove?.();
          }}
        />
      )}
    </div>
  );
};

export default FolderItem;

