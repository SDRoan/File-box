import React from 'react';
import { CloseIcon, FolderIcon } from './Icons';
import './SocialFeed.css';

interface FileItem {
  _id: string;
  originalName: string;
  mimeType: string;
  size: number;
}

interface Folder {
  _id: string;
  name: string;
}

interface CreatePostModalProps {
  files: FileItem[];
  folders: Folder[];
  selectedFileId: string;
  selectedFolderId: string;
  description: string;
  isPublic: boolean;
  onFileSelect: (id: string) => void;
  onFolderSelect: (id: string) => void;
  onDescriptionChange: (text: string) => void;
  onPublicChange: (isPublic: boolean) => void;
  onSubmit: () => void;
  onClose: () => void;
  formatSize: (bytes: number) => string;
  getFileIcon: (mimeType: string | undefined | null) => React.ReactNode;
}

const CreatePostModal: React.FC<CreatePostModalProps> = ({
  files,
  folders,
  selectedFileId,
  selectedFolderId,
  description,
  isPublic,
  onFileSelect,
  onFolderSelect,
  onDescriptionChange,
  onPublicChange,
  onSubmit,
  onClose,
  formatSize,
  getFileIcon
}) => {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Share to Feed</h3>
          <button className="close-btn" onClick={onClose}>
            <CloseIcon size={18} color="currentColor" />
          </button>
        </div>
        <div className="modal-body">
          <div className="form-group">
            <label>Select File:</label>
            {files.length === 0 ? (
              <p style={{ color: '#6b7280', fontSize: '0.875rem', padding: '0.5rem 0' }}>
                No files available. Upload files first from the Files section.
              </p>
            ) : (
              <div className="items-list">
                {files.slice(0, 10).map(file => (
                  <div
                    key={file._id}
                    className={`item-option ${selectedFileId === file._id ? 'selected' : ''}`}
                    onClick={() => {
                      onFileSelect(file._id);
                      onFolderSelect('');
                    }}
                  >
                    <span>{getFileIcon(file.mimeType)}</span>
                    <span>{file.originalName}</span>
                    <span className="item-size">{formatSize(file.size)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="form-group">
            <label>Select Folder:</label>
            <div className="items-list">
              {folders.slice(0, 10).map(folder => (
                <div
                  key={folder._id}
                  className={`item-option ${selectedFolderId === folder._id ? 'selected' : ''}`}
                  onClick={() => {
                    onFolderSelect(folder._id);
                    onFileSelect('');
                  }}
                >
                  <FolderIcon size={20} color="currentColor" />
                  <span>{folder.name}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="form-group">
            <label>Description (optional):</label>
            <textarea
              value={description}
              onChange={(e) => onDescriptionChange(e.target.value)}
              placeholder="What makes this file/folder valuable?"
              rows={3}
              maxLength={500}
            />
          </div>

          <div className="form-group">
            <label>
              <input
                type="checkbox"
                checked={isPublic}
                onChange={(e) => onPublicChange(e.target.checked)}
              />
              Make this post public
            </label>
          </div>
        </div>
        <div className="modal-footer">
          <button className="cancel-btn" onClick={onClose}>Cancel</button>
          <button 
            className="submit-btn" 
            onClick={onSubmit}
            disabled={!selectedFileId && !selectedFolderId}
          >
            Share
          </button>
        </div>
      </div>
    </div>
  );
};

export default CreatePostModal;









