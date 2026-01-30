import React, { useState, useEffect, useRef, useMemo } from 'react';
import { io, Socket } from 'socket.io-client';
import { FileItem, Folder } from '../types';
import { filesAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import FileItemComponent from './FileItem';
import FolderItem from './FolderItem';
import UploadButton from './UploadButton';
import CreateFolderModal from './CreateFolderModal';
import FileSortFilter, { SortOption, SortOrder, FilterOption } from './FileSortFilter';
import SmartOrganization from './SmartOrganization';
import FolderPickerModal from './FolderPickerModal';
import Breadcrumb from './Breadcrumb';
import { FolderIcon, SmartOrganizeIcon, CheckIcon, TrashIcon } from './Icons';
import './FileBrowser.css';

interface FileBrowserProps {
  currentFolderId?: string;
  onFolderClick: (folderId: string) => void;
  onNavigateUp: () => void;
  showTrash?: boolean;
  showStarred?: boolean;
  isTeamFolder?: boolean;
  teamFolderId?: string;
  folderStack?: string[];
  folderPath?: Folder[];
}

const FileBrowser: React.FC<FileBrowserProps> = ({
  currentFolderId,
  onFolderClick,
  onNavigateUp,
  showTrash = false,
  showStarred = false,
  isTeamFolder = false,
  teamFolderId,
  folderStack = [],
  folderPath = [],
}) => {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [loading, setLoading] = useState(true);
  const [breadcrumbFolders, setBreadcrumbFolders] = useState<Folder[]>([]);
  const [showCreateFolder, setShowCreateFolder] = useState(false);
  const [showSmartOrg, setShowSmartOrg] = useState(false);
  const [showFolderPicker, setShowFolderPicker] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [selectionMode, setSelectionMode] = useState(false);
  const [sortBy, setSortBy] = useState<SortOption>('name');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [filterBy, setFilterBy] = useState<FilterOption>('all');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { user } = useAuth();
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    loadFiles();
  }, [currentFolderId, showTrash, showStarred]);

  // Load breadcrumb folders
  useEffect(() => {
    const loadBreadcrumbFolders = async () => {
      if (folderPath && folderPath.length > 0) {
        setBreadcrumbFolders(folderPath);
      } else if (folderStack && folderStack.length > 1) {
        // Load folder names for breadcrumb
        try {
          const folderIds = folderStack.slice(1); // Skip 'root'
          const loadedFolders: Folder[] = [];
          for (const folderId of folderIds) {
            try {
              // Try to get folder from the folders list first (already loaded)
              const existingFolder = folders.find(f => f._id === folderId);
              if (existingFolder) {
                loadedFolders.push(existingFolder);
              } else {
                // If not found, fetch it
                const folderData = await filesAPI.getFolder(folderId);
                if (folderData) {
                  loadedFolders.push(folderData);
                }
              }
            } catch (error) {
              console.error('Error loading folder for breadcrumb:', error);
            }
          }
          setBreadcrumbFolders(loadedFolders);
        } catch (error) {
          console.error('Error loading breadcrumb folders:', error);
        }
      } else {
        setBreadcrumbFolders([]);
      }
    };
    loadBreadcrumbFolders();
  }, [folderStack, folderPath, folders]);

  // Socket.io real-time updates
  useEffect(() => {
    if (!user) return;

    const socket = io(process.env.REACT_APP_API_URL?.replace('/api', '') || 'http://localhost:5001');
    socketRef.current = socket;

    socket.emit('join-user-room', user.id);

    socket.on('file-uploaded', (file: FileItem) => {
      if (!showTrash && (file.parentFolder === currentFolderId || (!file.parentFolder && currentFolderId === 'root'))) {
        loadFiles();
      }
    });

    socket.on('folder-created', (folder: Folder) => {
      if (!showTrash && (folder.parentFolder === currentFolderId || (!folder.parentFolder && currentFolderId === 'root'))) {
        loadFiles();
      }
    });

    socket.on('file-deleted', () => {
      loadFiles();
    });

    socket.on('folder-deleted', () => {
      loadFiles();
    });

    socket.on('file-restored', () => {
      loadFiles();
    });

    socket.on('folder-restored', () => {
      loadFiles();
    });

    socket.on('file-starred', () => {
      if (showStarred) {
        loadFiles();
      }
    });

    socket.on('file-unstarred', () => {
      if (showStarred) {
        loadFiles();
      }
    });

    socket.on('file-renamed', () => {
      loadFiles();
    });

    socket.on('folder-renamed', () => {
      loadFiles();
    });

    return () => {
      socket.disconnect();
    };
  }, [user, currentFolderId, showTrash, showStarred]);

  const loadFiles = async () => {
    try {
      setLoading(true);
      let data;
      if (isTeamFolder && teamFolderId) {
        // Load files from team folder
        const { teamFoldersAPI } = await import('../services/api');
        data = await teamFoldersAPI.getTeamFolderFiles(teamFolderId);
      } else {
        data = await filesAPI.getFiles(
          currentFolderId === 'root' ? undefined : currentFolderId,
          showTrash,
          showStarred
        );
      }
      setFiles(data.files || []);
      setFolders(data.folders || []);
    } catch (error) {
      console.error('Error loading files:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    try {
      if (isTeamFolder && teamFolderId) {
        // Upload to team folder
        const { teamFoldersAPI } = await import('../services/api');
        await teamFoldersAPI.uploadFile(teamFolderId, file);
      } else {
        await filesAPI.uploadFile(file, currentFolderId === 'root' ? undefined : currentFolderId);
      }
      loadFiles();
    } catch (error: any) {
      console.error('Error uploading file:', error);
      const errorMessage = error?.response?.data?.message || error?.message || 'Failed to upload file';
      alert(errorMessage);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const droppedFiles = Array.from(e.dataTransfer.files);
    if (droppedFiles.length === 0) return;

    for (const file of droppedFiles) {
      await handleFileUpload(file);
    }
  };

  const handleFolderCreated = () => {
    setShowCreateFolder(false);
    loadFiles();
  };

  const handleDelete = async (id: string, type: 'file' | 'folder') => {
    try {
      if (type === 'file') {
        await filesAPI.deleteFile(id);
      } else {
        await filesAPI.deleteFolder(id);
      }
      loadFiles();
    } catch (error) {
      console.error('Error deleting:', error);
      alert('Failed to delete');
    }
  };

  const handleRestore = async (id: string, type: 'file' | 'folder') => {
    try {
      if (type === 'file') {
        await filesAPI.restoreFile(id);
      } else {
        await filesAPI.restoreFolder(id);
      }
      loadFiles();
    } catch (error) {
      console.error('Error restoring:', error);
      alert('Failed to restore');
    }
  };

  const handlePermanentDelete = async (id: string, type: 'file' | 'folder') => {
    if (!window.confirm('Are you sure you want to permanently delete this item?')) {
      return;
    }
    try {
      if (type === 'file') {
        await filesAPI.permanentDeleteFile(id);
      } else {
        await filesAPI.permanentDeleteFolder(id);
      }
      loadFiles();
    } catch (error) {
      console.error('Error permanently deleting:', error);
      alert('Failed to delete');
    }
  };

  const toggleSelection = (id: string) => {
    const newSelection = new Set(selectedItems);
    if (newSelection.has(id)) {
      newSelection.delete(id);
    } else {
      newSelection.add(id);
    }
    setSelectedItems(newSelection);
    if (newSelection.size === 0) {
      setSelectionMode(false);
    }
  };

  const selectAll = () => {
    const allIds = new Set<string>();
    folders.forEach(f => allIds.add(`folder-${f._id}`));
    files.forEach(f => allIds.add(`file-${f._id}`));
    setSelectedItems(allIds);
    setSelectionMode(true);
  };

  const clearSelection = () => {
    setSelectedItems(new Set());
    setSelectionMode(false);
  };

  const handleBulkDelete = async () => {
    if (selectedItems.size === 0) return;
    
    const confirmMessage = showTrash 
      ? `Permanently delete ${selectedItems.size} item(s)? This action cannot be undone.`
      : `Delete ${selectedItems.size} item(s)?`;
    
    if (!window.confirm(confirmMessage)) return;

    try {
      const itemsArray = Array.from(selectedItems);
      const deletePromises = itemsArray.map(async (itemId) => {
        const [type, id] = itemId.split('-');
        if (showTrash) {
          // Permanent delete when in trash
          if (type === 'file') {
            await filesAPI.permanentDeleteFile(id);
          } else {
            await filesAPI.permanentDeleteFolder(id);
          }
        } else {
          // Regular delete (move to trash)
          if (type === 'file') {
            await filesAPI.deleteFile(id);
          } else {
            await filesAPI.deleteFolder(id);
          }
        }
      });
      
      await Promise.all(deletePromises);
      clearSelection();
      loadFiles();
    } catch (error) {
      console.error('Error deleting items:', error);
      alert('Failed to delete some items');
    }
  };

  const handleBulkMove = async (destinationFolderId: string | null) => {
    if (selectedItems.size === 0) return;

    try {
      const itemsArray = Array.from(selectedItems);
      const movePromises = itemsArray.map(async (itemId) => {
        const [type, id] = itemId.split('-');
        if (type === 'file') {
          await filesAPI.moveFile(id, destinationFolderId || undefined);
        } else {
          await filesAPI.moveFolder(id, destinationFolderId || undefined);
        }
      });

      await Promise.all(movePromises);
      clearSelection();
      loadFiles();
    } catch (error) {
      console.error('Error moving items:', error);
      alert('Failed to move some items');
    }
  };

  // Filter and sort files/folders
  const filteredAndSorted = useMemo(() => {
    let filteredFiles = [...files];
    let filteredFolders = [...folders];

    // Apply filters
    if (filterBy === 'folders') {
      filteredFiles = [];
    } else if (filterBy === 'images') {
      filteredFiles = filteredFiles.filter(f => f.mimeType.startsWith('image/'));
    } else if (filterBy === 'videos') {
      filteredFiles = filteredFiles.filter(f => f.mimeType.startsWith('video/'));
    } else if (filterBy === 'documents') {
      filteredFiles = filteredFiles.filter(f => 
        f.mimeType.includes('pdf') || 
        f.mimeType.includes('word') || 
        f.mimeType.includes('excel') ||
        f.mimeType.includes('text')
      );
    }

    // Sort function
    const sortItems = <T extends FileItem | Folder>(items: T[]): T[] => {
      return [...items].sort((a, b) => {
        let comparison = 0;
        
        if (sortBy === 'name') {
          const nameA = 'originalName' in a ? a.originalName : a.name;
          const nameB = 'originalName' in b ? b.originalName : b.name;
          comparison = nameA.localeCompare(nameB);
        } else if (sortBy === 'date') {
          comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
        } else if (sortBy === 'size') {
          const sizeA = 'size' in a ? a.size : 0;
          const sizeB = 'size' in b ? b.size : 0;
          comparison = sizeA - sizeB;
        } else if (sortBy === 'type') {
          const typeA = 'mimeType' in a ? a.mimeType : 'folder';
          const typeB = 'mimeType' in b ? b.mimeType : 'folder';
          comparison = typeA.localeCompare(typeB);
        }
        
        return sortOrder === 'asc' ? comparison : -comparison;
      });
    };

    return {
      files: sortItems(filteredFiles),
      folders: sortItems(filteredFolders)
    };
  }, [files, folders, filterBy, sortBy, sortOrder]);

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div
      className={`file-browser ${isDragging ? 'dragging' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {isDragging && (
        <div className="drag-overlay">
          <div className="drag-overlay-content">
            <div className="drag-icon">➜</div>
            <p>Drop files here to upload</p>
          </div>
        </div>
      )}
      <div className="file-browser-content">
        {breadcrumbFolders.length > 0 && (
          <Breadcrumb
            folders={breadcrumbFolders}
            onFolderClick={(folderId) => {
              // Navigate to the clicked folder in breadcrumb
              const index = breadcrumbFolders.findIndex(f => f._id === folderId);
              if (index !== -1 && folderStack) {
                // Calculate how many levels up we need to go
                const levelsUp = breadcrumbFolders.length - index - 1;
                for (let i = 0; i < levelsUp; i++) {
                  onNavigateUp();
                }
              }
            }}
            onRootClick={() => {
              // Navigate all the way up
              if (folderStack && folderStack.length > 1) {
                const levelsUp = folderStack.length - 1;
                for (let i = 0; i < levelsUp; i++) {
                  onNavigateUp();
                }
              }
            }}
          />
        )}
        <div className="file-browser-header">
        <FileSortFilter
          sortBy={sortBy}
          sortOrder={sortOrder}
          filterBy={filterBy}
          viewMode={viewMode}
          onSortChange={setSortBy}
          onSortOrderChange={setSortOrder}
          onFilterChange={setFilterBy}
          onViewModeChange={setViewMode}
        />
        <div className="file-browser-actions">
          {selectionMode ? (
            <>
              <span className="selection-count">{selectedItems.size} selected</span>
              <button className="action-button" onClick={selectAll}>
                Select All
              </button>
              <button className="action-button" onClick={clearSelection}>
                Clear
              </button>
              {!showTrash && (
                <button 
                  className="action-button primary" 
                  onClick={() => setShowFolderPicker(true)}
                  title="Move selected items to a folder"
                >
                   Move to Folder
                </button>
              )}
              {showTrash ? (
                <button className="action-button danger" onClick={handleBulkDelete}>
                  <TrashIcon size={18} color="currentColor" />
                  <span>Permanently Delete Selected</span>
                </button>
              ) : (
                <button className="action-button danger" onClick={handleBulkDelete}>
                  <TrashIcon size={18} color="currentColor" />
                  <span>Delete Selected</span>
                </button>
              )}
              <button className="action-button" onClick={() => setSelectionMode(false)}>
                Cancel
              </button>
            </>
          ) : (
            <>
              {!showStarred && (
                <>
                  <UploadButton onFileSelect={handleFileUpload} />
                  <button
                    className="action-button"
                    onClick={() => setShowCreateFolder(true)}
                    style={{ background: '#1e40af', color: '#ffffff', border: 'none' }}
                  >
                    <FolderIcon size={16} color="#ffffff" />
                    <span>New Folder</span>
                  </button>
                </>
              )}
              {!showTrash && !showStarred && (
                <button
                  className="action-button smart-org-btn"
                  onClick={() => setShowSmartOrg(true)}
                  title="AI-powered file organization"
                >
                  <SmartOrganizeIcon size={16} color="#ffffff" />
                  <span>Smart Organize</span>
                </button>
              )}
              <button
                className="action-button"
                onClick={() => setSelectionMode(true)}
                style={{ background: '#4b5563', color: '#ffffff', border: 'none' }}
              >
                <CheckIcon size={16} color="#ffffff" />
                <span>Select</span>
              </button>
            </>
          )}
        </div>
        </div>

        {filteredAndSorted.folders.length === 0 && filteredAndSorted.files.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-content">
              <div className="empty-state-icon">
              </div>
              <h3 className="empty-state-title">
                {showTrash 
                  ? 'Trash is empty' 
                  : showStarred 
                  ? 'No starred files' 
                  : 'No files here yet'}
              </h3>
              <p className="empty-state-description">
                {showTrash 
                  ? 'Files you delete will appear here. They\'ll be permanently deleted after 30 days.'
                  : showStarred 
                  ? 'Star files to quickly access them later.'
                  : 'Upload files or create folders to get started. You can drag and drop files here.'}
              </p>
              {!showTrash && !showStarred && (
                <div className="empty-state-actions">
                  <UploadButton onFileSelect={handleFileUpload} />
                  <button
                    className="action-button"
                    onClick={() => setShowCreateFolder(true)}
                    style={{ background: '#1e40af', color: '#ffffff', border: 'none' }}
                  >
                    <FolderIcon size={16} color="#ffffff" />
                    <span>New Folder</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className={`file-list ${viewMode === 'list' ? 'list-view' : 'grid-view'}`}>
            {filteredAndSorted.folders.map((folder) => (
              <FolderItem
                key={folder._id}
                folder={folder}
                onClick={() => selectionMode ? toggleSelection(`folder-${folder._id}`) : onFolderClick(folder._id)}
                onDelete={() => handleDelete(folder._id, 'folder')}
                onRestore={() => handleRestore(folder._id, 'folder')}
                onPermanentDelete={() => handlePermanentDelete(folder._id, 'folder')}
                onMove={loadFiles}
                showTrash={showTrash}
                isSelected={selectionMode && selectedItems.has(`folder-${folder._id}`)}
                selectionMode={selectionMode}
              />
            ))}
            {filteredAndSorted.files.map((file) => (
              <FileItemComponent
                key={file._id}
                file={file}
                onDelete={() => handleDelete(file._id, 'file')}
                onRestore={() => handleRestore(file._id, 'file')}
                onPermanentDelete={() => handlePermanentDelete(file._id, 'file')}
                onRename={loadFiles}
                onMove={loadFiles}
                showTrash={showTrash}
                isSelected={selectionMode && selectedItems.has(`file-${file._id}`)}
                selectionMode={selectionMode}
                onSelect={() => toggleSelection(`file-${file._id}`)}
              />
            ))}
          </div>
        )}
      </div>

      {showCreateFolder && (
        <CreateFolderModal
          currentFolderId={isTeamFolder ? undefined : (currentFolderId === 'root' ? undefined : currentFolderId)}
          onClose={() => setShowCreateFolder(false)}
          onCreated={async () => {
            if (isTeamFolder && teamFolderId) {
              // For team folders, we'll handle creation differently
              // The modal will call the API directly
            }
            loadFiles();
            setShowCreateFolder(false);
          }}
          isTeamFolder={isTeamFolder}
          teamFolderId={teamFolderId}
        />
      )}
      {showSmartOrg && (
        <SmartOrganization
          folderId={currentFolderId === 'root' ? undefined : currentFolderId}
          onClose={() => setShowSmartOrg(false)}
          onOrganized={loadFiles}
        />
      )}
      {showFolderPicker && (
        <FolderPickerModal
          onSelect={(folderId: string | null) => {
            handleBulkMove(folderId);
            setShowFolderPicker(false);
          }}
          onClose={() => setShowFolderPicker(false)}
          currentFolderId={currentFolderId === 'root' ? undefined : currentFolderId}
        />
      )}
    </div>
  );
};

export default FileBrowser;

