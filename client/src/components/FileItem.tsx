import React, { useState, useEffect, useRef } from 'react';
import { FileItem as FileItemType } from '../types';
import { filesAPI } from '../services/api';
import FilePreview from './FilePreview';
import MoveCopyModal from './MoveCopyModal';
import ShareModal from './ShareModal';
import FileVersions from './FileVersions';
import FileComments from './FileComments';
import FileActivity from './FileActivity';
import FileRelationships from './FileRelationships';
import ClassificationBadge from './ClassificationBadge';
import { ImageIcon, VideoIcon, AudioIcon, DocumentIcon, SummaryIcon, AnalyticsIcon, EyeIcon, PackageIcon, CopyIcon, ShareIcon, ScrollIcon, CommentIcon, DownloadIcon, StarredIcon, TrashIcon, RestoreIcon, LinkIcon, EditIcon } from './Icons';
import './FileItem.css';

interface FileItemProps {
  file: FileItemType;
  onDelete: () => void;
  onRestore: () => void;
  onPermanentDelete: () => void;
  onMove?: () => void;
  onRename?: () => void;
  showTrash: boolean;
  isSelected?: boolean;
  selectionMode?: boolean;
  onSelect?: () => void;
}

const FileItem: React.FC<FileItemProps> = ({
  file,
  onDelete,
  onRestore,
  onPermanentDelete,
  onMove,
  onRename,
  showTrash,
  isSelected = false,
  selectionMode = false,
  onSelect,
}) => {
  const [showPreview, setShowPreview] = useState(false);
  const [showMoveModal, setShowMoveModal] = useState(false);
  const [showCopyModal, setShowCopyModal] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [showVersions, setShowVersions] = useState(false);
  const [showComments, setShowComments] = useState(false);
  const [showActivity, setShowActivity] = useState(false);
  const [showRelationships, setShowRelationships] = useState(false);
  const [isRenaming, setIsRenaming] = useState(false);
  const [renameValue, setRenameValue] = useState(file.originalName);
  const renameInputRef = useRef<HTMLInputElement>(null);
  const isSavingRef = useRef(false);

  useEffect(() => {
    if (!isRenaming) {
      setRenameValue(file.originalName);
    }
  }, [file.originalName, isRenaming]);

  useEffect(() => {
    if (isRenaming && renameInputRef.current) {
      renameInputRef.current.focus();
      renameInputRef.current.select();
    }
  }, [isRenaming]);

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getFileIcon = (mimeType: string) => {
    if (mimeType.startsWith('image/')) return <ImageIcon size={24} color="currentColor" />;
    if (mimeType.startsWith('video/')) return <VideoIcon size={24} color="currentColor" />;
    if (mimeType.startsWith('audio/')) return <AudioIcon size={24} color="currentColor" />;
    if (mimeType.includes('pdf')) return <DocumentIcon size={24} color="currentColor" />;
    if (mimeType.includes('word')) return <SummaryIcon size={24} color="currentColor" />;
    if (mimeType.includes('excel') || mimeType.includes('spreadsheet')) return <AnalyticsIcon size={24} color="currentColor" />;
    return <DocumentIcon size={24} color="currentColor" />;
  };

  const handleDownload = async () => {
    try {
      const blob = await filesAPI.downloadFile(file._id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.originalName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error downloading file:', error);
      alert('Failed to download file');
    }
  };

  const handleRename = async () => {
    if (isSavingRef.current) {
      console.log('Rename already in progress, skipping...');
      return; // Prevent multiple simultaneous saves
    }
    
    const trimmedName = renameValue.trim();
    console.log('Attempting to rename:', {
      currentName: file.originalName,
      newName: trimmedName,
      fileId: file._id
    });
    
    if (!trimmedName) {
      console.log('Empty name, cancelling rename');
      setIsRenaming(false);
      setRenameValue(file.originalName);
      return;
    }
    
    if (trimmedName === file.originalName) {
      console.log('Name unchanged, cancelling rename');
      setIsRenaming(false);
      setRenameValue(file.originalName);
      return;
    }

    // Preserve file extension if user didn't include one
    let finalName = trimmedName;
    const currentExt = file.originalName.includes('.') 
      ? '.' + file.originalName.split('.').pop() 
      : '';
    // Only add extension if the original had one and the new name doesn't have any extension
    if (currentExt && !finalName.includes('.')) {
      finalName = finalName + currentExt;
      console.log('Added extension:', finalName);
    }

    isSavingRef.current = true;
    try {
      console.log('Calling rename API with:', { fileId: file._id, name: finalName });
      const response = await filesAPI.renameFile(file._id, finalName);
      console.log('File renamed successfully:', response);
      setIsRenaming(false);
      // Immediately refresh the file list
      if (onRename) {
        console.log('Calling onRename callback to refresh file list');
        onRename();
      }
      // File will also be updated via socket event as backup
    } catch (error: any) {
      console.error('Error renaming file:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      const errorMessage = error.response?.data?.message || error.message || 'Failed to rename file';
      alert(errorMessage);
      setRenameValue(file.originalName);
      setIsRenaming(false);
    } finally {
      isSavingRef.current = false;
    }
  };

  const handleRenameKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      e.stopPropagation();
      handleRename();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      setRenameValue(file.originalName);
      setIsRenaming(false);
    }
  };

  const handleRenameBlur = async (e: React.FocusEvent) => {
    console.log('Blur event fired on rename input');
    // Use setTimeout to allow click events on buttons to fire first
    // Check if the new target is a button or action element
    const relatedTarget = e.relatedTarget as HTMLElement;
    if (relatedTarget && (relatedTarget.closest('.file-actions') || relatedTarget.closest('.icon-button'))) {
      console.log('Blur cancelled - clicking on action button');
      // Don't save if clicking on action buttons
      return;
    }
    
    // Store the current rename value to use in the timeout
    const currentRenameValue = renameValue;
    const wasRenaming = isRenaming;
    
    setTimeout(async () => {
      console.log('Blur timeout executing', { isSavingRef: isSavingRef.current, wasRenaming, currentRenameValue });
      if (!isSavingRef.current && wasRenaming) {
        console.log('Calling handleRename from blur handler');
        await handleRename();
      }
    }, 150);
  };

  const canPreview = () => {
    const mimeType = file.mimeType.toLowerCase();
    const extension = file.originalName.split('.').pop()?.toLowerCase() || '';
    
    // Code file extensions
    const codeExtensions = [
      'js', 'jsx', 'ts', 'tsx', 'py', 'java', 'cpp', 'c', 'cs', 'php', 'rb', 'go',
      'rs', 'swift', 'kt', 'scala', 'sh', 'bash', 'zsh', 'fish', 'ps1', 'sql',
      'html', 'css', 'scss', 'sass', 'less', 'json', 'xml', 'yaml', 'yml', 'toml',
      'ini', 'md', 'markdown', 'vue', 'svelte', 'r', 'm', 'mm', 'dart', 'lua',
      'pl', 'pm', 'vim', 'dockerfile', 'makefile', 'cmake', 'h', 'hpp', 'cc',
      'cxx', 'mjs', 'coffee', 'litcoffee', 'coffee.md'
    ];
    
    return (
      mimeType.startsWith('image/') ||
      mimeType.startsWith('video/') ||
      mimeType.includes('pdf') ||
      mimeType.startsWith('text/') ||
      mimeType.includes('json') ||
      mimeType.includes('xml') ||
      mimeType.includes('javascript') ||
      mimeType.includes('css') ||
      mimeType.includes('html') ||
      codeExtensions.includes(extension)
    );
  };

  return (
    <>
      <div className={`file-item ${isSelected ? 'selected' : ''}`}>
        {selectionMode && (
          <input
            type="checkbox"
            checked={isSelected}
            onChange={onSelect}
            className="selection-checkbox"
            onClick={(e) => e.stopPropagation()}
          />
        )}
        <div className="file-icon" onClick={() => !selectionMode && canPreview() && !showTrash && setShowPreview(true)} style={{ cursor: !selectionMode && canPreview() && !showTrash ? 'pointer' : 'default' }}>{getFileIcon(file.mimeType)}</div>
        <div className="file-info" onClick={() => !selectionMode && canPreview() && !showTrash && !isRenaming && setShowPreview(true)} style={{ cursor: !selectionMode && canPreview() && !showTrash && !isRenaming ? 'pointer' : 'default', flex: 1 }}>
          {isRenaming ? (
            <input
              ref={renameInputRef}
              type="text"
              className="file-name-input"
              value={renameValue}
              onChange={(e) => setRenameValue(e.target.value)}
              onBlur={handleRenameBlur}
              onKeyDown={handleRenameKeyDown}
              onClick={(e) => e.stopPropagation()}
              onMouseDown={(e) => e.stopPropagation()}
            />
          ) : (
            <div className="file-name" title={file.originalName} onDoubleClick={(e) => {
              if (!showTrash && !selectionMode) {
                e.stopPropagation();
                setIsRenaming(true);
                setRenameValue(file.originalName);
              }
            }}>
              {file.originalName}
            </div>
          )}
          <div className="file-meta">
            {formatSize(file.size)} • {new Date(file.createdAt).toLocaleDateString()}
            {showTrash && file.deletedAt && (
              <span className="recovery-info">
                {(() => {
                  const daysDeleted = Math.floor((Date.now() - new Date(file.deletedAt).getTime()) / (1000 * 60 * 60 * 24));
                  const recoveryDays = file.recoveryPeriodDays || 30;
                  const daysRemaining = recoveryDays - daysDeleted;
                  if (daysRemaining > 0) {
                    return ` • ${daysRemaining} day${daysRemaining !== 1 ? 's' : ''} until permanent deletion`;
                  } else {
                    return ' • Will be permanently deleted soon';
                  }
                })()}
              </span>
            )}
            {file.dataClassification && (
              <div style={{ marginTop: '4px' }}>
                <ClassificationBadge classification={file.dataClassification} size="small" />
              </div>
            )}
          </div>
        </div>
        <div className="file-actions" onClick={(e) => e.stopPropagation()}>
          {!showTrash ? (
            <>
              {canPreview() && (
                <button onClick={() => setShowPreview(true)} className="icon-button" title="Preview">
                  <EyeIcon size={18} color="currentColor" />
                </button>
              )}
              <button onClick={() => setShowMoveModal(true)} className="icon-button" title="Move">
                <PackageIcon size={18} color="currentColor" />
              </button>
              <button onClick={() => setShowCopyModal(true)} className="icon-button" title="Copy">
                <CopyIcon size={18} color="currentColor" />
              </button>
              <button onClick={() => setShowShareModal(true)} className="icon-button" title="Share">
                <ShareIcon size={18} color="currentColor" />
              </button>
              <button 
                onMouseDown={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  if (!isRenaming) {
                    setIsRenaming(true);
                    setRenameValue(file.originalName);
                  }
                }}
                onClick={(e) => {
                  e.stopPropagation();
                }}
                className="icon-button" 
                title="Rename"
              >
                <EditIcon size={18} color="currentColor" />
              </button>
              <button onClick={() => setShowVersions(true)} className="icon-button" title="Versions">
                <ScrollIcon size={18} color="currentColor" />
              </button>
              <button onClick={() => setShowComments(true)} className="icon-button" title="Comments">
                <CommentIcon size={18} color="currentColor" />
              </button>
              <button onClick={() => setShowActivity(true)} className="icon-button" title="Activity">
                <AnalyticsIcon size={18} color="currentColor" />
              </button>
              <button onClick={() => setShowRelationships(true)} className="icon-button" title="Connections">
                <LinkIcon size={18} color="currentColor" />
              </button>
              <button onClick={handleDownload} className="icon-button" title="Download">
                <DownloadIcon size={18} color="currentColor" />
              </button>
              <button
                onClick={async () => {
                  try {
                    await filesAPI.starFile(file._id);
                    // File will be updated via socket event
                  } catch (error) {
                    console.error('Error starring file:', error);
                  }
                }}
                className={`icon-button ${file.isStarred ? 'starred' : ''}`}
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
      </div>
      {showPreview && (
        <FilePreview file={file} onClose={() => setShowPreview(false)} />
      )}
      {showMoveModal && (
        <MoveCopyModal
          itemId={file._id}
          itemName={file.originalName}
          itemType="file"
          operation="move"
          onClose={() => setShowMoveModal(false)}
          onSuccess={() => {
            setShowMoveModal(false);
            onMove?.();
          }}
        />
      )}
      {showCopyModal && (
        <MoveCopyModal
          itemId={file._id}
          itemName={file.originalName}
          itemType="file"
          operation="copy"
          onClose={() => setShowCopyModal(false)}
          onSuccess={() => {
            setShowCopyModal(false);
            onMove?.();
          }}
        />
      )}
      {showShareModal && (
        <ShareModal
          fileId={file._id}
          fileName={file.originalName}
          onClose={() => setShowShareModal(false)}
          onShareCreated={() => {
            setShowShareModal(false);
          }}
        />
      )}
      {showVersions && (
        <FileVersions
          fileId={file._id}
          onClose={() => setShowVersions(false)}
          onUploadNewVersion={() => {
            setShowVersions(false);
            // Trigger file input for new version upload
            const input = document.createElement('input');
            input.type = 'file';
            input.onchange = async (e: any) => {
              const selectedFile = e.target.files[0];
              if (selectedFile) {
                const formData = new FormData();
                formData.append('file', selectedFile);
                formData.append('isNewVersion', 'true');
                formData.append('fileId', file._id);
                try {
                  await filesAPI.uploadFileVersion(file._id, selectedFile);
                  alert('New version uploaded successfully!');
                  setShowVersions(true);
                } catch (error) {
                  alert('Failed to upload new version');
                }
              }
            };
            input.click();
          }}
        />
      )}
      {showComments && (
        <FileComments
          fileId={file._id}
          onClose={() => setShowComments(false)}
        />
      )}
      {showActivity && (
        <FileActivity
          fileId={file._id}
          onClose={() => setShowActivity(false)}
        />
      )}
      {showRelationships && (
        <FileRelationships
          file={file}
          onClose={() => setShowRelationships(false)}
          onFileClick={(fileId) => {
            setShowRelationships(false);
            // Could navigate to file or show preview
            console.log('Navigate to file:', fileId);
          }}
        />
      )}
    </>
  );
};

export default FileItem;

