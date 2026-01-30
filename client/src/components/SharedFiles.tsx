import React, { useState, useEffect, useMemo, useRef } from 'react';
import { FileItem } from '../types';
import { shareAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { io, Socket } from 'socket.io-client';
import FileSortFilter, { SortOption, SortOrder, FilterOption } from './FileSortFilter';
import FilePreview from './FilePreview';
import { UsersIcon, ArrowUpIcon, BellIcon, SearchIcon, AnalyticsIcon, FolderIcon, UserIcon, ImageIcon, DocumentIcon, SummaryIcon, VideoIcon, AudioIcon, PaperclipIcon, EditIcon, EyeIcon, DownloadIcon, TrashIcon, AnalyticsIcon as ActivityIcon } from './Icons';
import './SharedFiles.css';

// SharedFile extends FileItem but allows owner to be optional and have backend shape
type SharedFile = Omit<FileItem, 'owner'> & {
  sharePermission?: 'view' | 'edit';
  sharedAt?: string;
  // owner can be User, string, or backend shape (with _id) - all optional
  owner?: FileItem['owner'] | {
    _id: string;
    name: string;
    email: string;
  };
  sharedWith?: Array<{
    user: {
      _id: string;
      name: string;
      email: string;
    };
    permission: 'view' | 'edit';
  }>;
}

const SharedFiles: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'with-me' | 'by-me'>('with-me');
  const [files, setFiles] = useState<SharedFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState<SharedFile | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<SortOption>('name');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [filterBy, setFilterBy] = useState<FilterOption>('all');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [groupBySharer, setGroupBySharer] = useState(false);
  const [permissionFilter, setPermissionFilter] = useState<'all' | 'view' | 'edit'>('all');
  const [fileStats, setFileStats] = useState<{ [key: string]: any }>({});
  const [notifications, setNotifications] = useState<any[]>([]);
  const [showActivity, setShowActivity] = useState<string | null>(null);
  const [fileActivity, setFileActivity] = useState<{ [key: string]: any[] }>({});
  const { user } = useAuth();
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    loadFiles();
    if (activeTab === 'by-me') {
      loadStats();
    }
  }, [activeTab]);

  // Socket.io for real-time notifications
  useEffect(() => {
    if (!user) return;

    const socket = io(process.env.REACT_APP_API_URL?.replace('/api', '') || 'http://localhost:5001');
    socketRef.current = socket;

    socket.emit('join-user-room', user.id);

    // Listen for files shared with you
    socket.on('file-shared-with-you', (data: any) => {
      setNotifications(prev => [data, ...prev.slice(0, 9)]);
      if (activeTab === 'with-me') {
        loadFiles();
      }
    });

    // Listen for activity on files you shared
    socket.on('shared-file-accessed', (data: any) => {
      setNotifications(prev => [data, ...prev.slice(0, 9)]);
      if (activeTab === 'by-me') {
        loadFiles();
        loadStats();
        // Refresh activity for this file if it's currently shown
        if (showActivity === data.file._id) {
          loadFileActivity(data.file._id);
        }
      }
    });

    return () => {
      socket.disconnect();
    };
  }, [user, activeTab, showActivity]);

  const loadFiles = async () => {
    try {
      setLoading(true);
      const data = activeTab === 'with-me' 
        ? await shareAPI.getSharedWithMe()
        : await shareAPI.getSharedByMe();
      setFiles(data || []);
    } catch (error) {
      console.error('Error loading shared files:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const stats = await shareAPI.getSharedFilesStats();
      const statsMap: { [key: string]: any } = {};
      stats.forEach((stat: any) => {
        statsMap[stat.fileId] = stat;
      });
      setFileStats(statsMap);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const loadFileActivity = async (fileId: string) => {
    try {
      const activity = await shareAPI.getSharedFileActivity(fileId);
      setFileActivity(prev => ({ ...prev, [fileId]: activity }));
    } catch (error) {
      console.error('Error loading file activity:', error);
    }
  };

  const handleShowActivity = (fileId: string) => {
    if (showActivity === fileId) {
      setShowActivity(null);
    } else {
      setShowActivity(fileId);
      if (!fileActivity[fileId]) {
        loadFileActivity(fileId);
      }
    }
  };

  const handleFileClick = (file: SharedFile) => {
    setSelectedFile(file);
    setShowPreview(true);
  };

  const handleFileDelete = () => {
    loadFiles();
    setShowPreview(false);
    setSelectedFile(null);
  };

  const handleRemoveAccess = async (file: SharedFile) => {
    if (activeTab === 'by-me') {
      // Remove share from a specific user
      // This would require additional API endpoint
      alert('Remove share functionality - to be implemented');
    } else {
      // Remove yourself from shared files (stop receiving)
      alert('Stop receiving shared file - to be implemented');
    }
  };

  // Filter files based on search and filters
  const filteredFiles = useMemo(() => {
    let filtered = [...files];

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(file => 
        file.originalName.toLowerCase().includes(query) ||
        (file.owner && typeof file.owner === 'object' && file.owner.name?.toLowerCase().includes(query)) ||
        (file.owner && typeof file.owner === 'object' && file.owner.email?.toLowerCase().includes(query))
      );
    }

    // Permission filter
    if (permissionFilter !== 'all') {
      filtered = filtered.filter(file => file.sharePermission === permissionFilter);
    }

    // Type filter
    if (filterBy === 'images') {
      filtered = filtered.filter(file => file.mimeType.startsWith('image/'));
    } else if (filterBy === 'documents') {
      filtered = filtered.filter(file => 
        file.mimeType.includes('pdf') ||
        file.mimeType.includes('word') ||
        file.mimeType.includes('document') ||
        file.mimeType.includes('text')
      );
    } else if (filterBy === 'videos') {
      filtered = filtered.filter(file => file.mimeType.startsWith('video/'));
    }

    // Sort
    filtered.sort((a, b) => {
      let comparison = 0;
      
      switch (sortBy) {
        case 'name':
          comparison = a.originalName.localeCompare(b.originalName);
          break;
        case 'size':
          comparison = a.size - b.size;
          break;
        case 'date':
          comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
          break;
        case 'type':
          comparison = a.mimeType.localeCompare(b.mimeType);
          break;
        default:
          comparison = 0;
      }
      
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [files, searchQuery, filterBy, sortBy, sortOrder, permissionFilter]);

  // Group files by sharer (for "Shared with Me" tab)
  const groupedFiles = useMemo(() => {
    if (!groupBySharer || activeTab !== 'with-me') {
      return { 'All Files': filteredFiles };
    }

    const groups: { [key: string]: SharedFile[] } = {};
    
    filteredFiles.forEach(file => {
      const owner = file.owner && typeof file.owner === 'object' 
        ? file.owner.name || file.owner.email || 'Unknown'
        : 'Unknown';
      
      if (!groups[owner]) {
        groups[owner] = [];
      }
      groups[owner].push(file);
    });

    return groups;
  }, [filteredFiles, groupBySharer, activeTab]);

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
    return date.toLocaleDateString();
  };

  if (loading) {
    return (
      <div className="shared-files-container">
        <div className="shared-files-loading">
          <div className="loading-spinner"></div>
          <p>Loading shared files...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="shared-files-container">
      <div className="shared-files-header">
        <div className="shared-files-title-section">
          <h2>Shared Files</h2>
          <div className="shared-files-tabs">
            <button
              className={`tab-button ${activeTab === 'with-me' ? 'active' : ''}`}
              onClick={() => setActiveTab('with-me')}
            >
              <UsersIcon size={18} color="currentColor" /> Shared with Me
            </button>
            <button
              className={`tab-button ${activeTab === 'by-me' ? 'active' : ''}`}
              onClick={() => setActiveTab('by-me')}
            >
              <ArrowUpIcon size={18} color="currentColor" /> Shared by Me
            </button>
          </div>
        </div>

        {notifications.length > 0 && (
          <div className="notifications-badge" title={`${notifications.length} new notifications`}>
            <BellIcon size={18} color="currentColor" /> {notifications.length}
          </div>
        )}

        <div className="shared-files-controls">
          <div className="search-box">
            <input
              type="text"
              placeholder="Search shared files..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
            />
            <span className="search-icon"><SearchIcon size={18} color="currentColor" /></span>
          </div>

          {activeTab === 'with-me' && (
            <div className="permission-filter">
              <select
                value={permissionFilter}
                onChange={(e) => setPermissionFilter(e.target.value as 'all' | 'view' | 'edit')}
                className="filter-select"
              >
                <option value="all">All Permissions</option>
                <option value="view">View Only</option>
                <option value="edit">Can Edit</option>
              </select>
            </div>
          )}

          {activeTab === 'with-me' && (
            <button
              className={`group-toggle ${groupBySharer ? 'active' : ''}`}
              onClick={() => setGroupBySharer(!groupBySharer)}
              title="Group by sharer"
            >
              <AnalyticsIcon size={18} color="currentColor" /> {groupBySharer ? 'Ungroup' : 'Group by Sharer'}
            </button>
          )}

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
        </div>
      </div>

      <div className="shared-files-content">
        {Object.keys(groupedFiles).length === 0 || filteredFiles.length === 0 ? (
          <div className="shared-files-empty">
            <div className="empty-icon"><FolderIcon size={48} color="#999" /></div>
            <h3>
              {activeTab === 'with-me' 
                ? 'No files shared with you yet' 
                : "You haven't shared any files"}
            </h3>
            <p>
              {activeTab === 'with-me'
                ? 'Files that others share with you will appear here'
                : 'Files you share with others will appear here'}
            </p>
          </div>
        ) : (
          <>
            {Object.entries(groupedFiles).map(([groupName, groupFiles]) => (
              <div key={groupName} className="shared-files-group">
                {groupBySharer && activeTab === 'with-me' && (
                  <h3 className="group-header">
                    <span className="group-icon"><UserIcon size={18} color="currentColor" /></span>
                    {groupName}
                    <span className="group-count">({groupFiles.length})</span>
                  </h3>
                )}
                
                <div className={`files-grid ${viewMode === 'list' ? 'list-view' : ''}`}>
                  {groupFiles.map((file) => (
                    <div key={file._id} className="shared-file-item">
                      <div className="shared-file-card" onClick={() => handleFileClick(file)}>
                        <div className="file-icon-wrapper">
                          <div className="file-icon">
                            {file.mimeType.startsWith('image/') && <ImageIcon size={32} color="currentColor" />}
                            {file.mimeType.includes('pdf') && <DocumentIcon size={32} color="currentColor" />}
                            {file.mimeType.includes('word') && <SummaryIcon size={32} color="currentColor" />}
                            {file.mimeType.includes('video') && <VideoIcon size={32} color="currentColor" />}
                            {file.mimeType.includes('audio') && <AudioIcon size={32} color="currentColor" />}
                            {!file.mimeType.startsWith('image/') && 
                             !file.mimeType.includes('pdf') &&
                             !file.mimeType.includes('word') &&
                             !file.mimeType.includes('video') &&
                             !file.mimeType.includes('audio') && <PaperclipIcon size={32} color="currentColor" />}
                          </div>
                          {file.sharePermission && (
                            <div className={`permission-badge ${file.sharePermission}`}>
                              {file.sharePermission === 'edit' ? (
                                <>
                                  <EditIcon size={14} color="currentColor" /> Edit
                                </>
                              ) : (
                                <>
                                  <EyeIcon size={14} color="currentColor" /> View
                                </>
                              )}
                            </div>
                          )}
                        </div>
                        
                        <div className="file-info">
                          <h4 className="file-name" title={file.originalName}>
                            {file.originalName}
                          </h4>
                          
                          <div className="file-meta">
                            <span className="file-size">{formatFileSize(file.size)}</span>
                            <span className="file-date">{formatDate(file.createdAt)}</span>
                          </div>

                          {activeTab === 'with-me' && file.owner && typeof file.owner === 'object' && (
                            <div className="sharer-info">
                              <span className="sharer-label">Shared by:</span>
                              <span className="sharer-name">{file.owner.name || file.owner.email}</span>
                            </div>
                          )}

                          {activeTab === 'by-me' && file.sharedWith && file.sharedWith.length > 0 && (
                            <div className="shared-with-info">
                              <span className="shared-with-label">
                                Shared with {file.sharedWith.length} {file.sharedWith.length === 1 ? 'person' : 'people'}
                              </span>
                              <div className="shared-with-list">
                                {file.sharedWith.slice(0, 3).map((share, idx) => (
                                  <span key={idx} className="shared-user-tag">
                                    {share.user.name || share.user.email}
                                    <span className={`permission-indicator ${share.permission}`}>
                                      {share.permission === 'edit' ? <EditIcon size={14} color="currentColor" /> : <EyeIcon size={14} color="currentColor" />}
                                    </span>
                                  </span>
                                ))}
                                {file.sharedWith.length > 3 && (
                                  <span className="more-users">+{file.sharedWith.length - 3} more</span>
                                )}
                              </div>
                            </div>
                          )}
                        </div>

                        <div className="file-actions">
                          {activeTab === 'by-me' && (
                            <button
                              className={`action-button activity-btn ${showActivity === file._id ? 'active' : ''}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                handleShowActivity(file._id);
                              }}
                              title="View Activity"
                            >
                              <ActivityIcon size={18} color="currentColor" />
                            </button>
                          )}
                          <button
                            className="action-button preview-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleFileClick(file);
                            }}
                            title="Preview"
                          >
                            <EyeIcon size={18} color="currentColor" />
                          </button>
                          <button
                            className="action-button download-btn"
                            onClick={(e) => {
                              e.stopPropagation();
                              window.open(`http://localhost:5001/api/files/${file._id}/download`, '_blank');
                            }}
                            title="Download"
                          >
                            <DownloadIcon size={18} color="currentColor" />
                          </button>
                          {activeTab === 'by-me' && (
                            <button
                              className="action-button remove-btn"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleRemoveAccess(file);
                              }}
                              title="Remove Share"
                            >
                              <TrashIcon size={18} color="currentColor" />
                            </button>
                          )}
                        </div>
                      </div>

                      {showActivity === file._id && fileActivity[file._id] && (
                        <div className="activity-panel">
                          <h4>Recent Activity</h4>
                          {fileActivity[file._id].length === 0 ? (
                            <p className="no-activity">No activity yet</p>
                          ) : (
                            <div className="activity-list">
                              {fileActivity[file._id].slice(0, 10).map((activity: any, idx: number) => (
                                <div key={idx} className="activity-item">
                                  <span className="activity-user">
                                    {activity.user?.name || activity.user?.email || 'Unknown'}
                                  </span>
                                  <span className="activity-action">
                                    {activity.action === 'view' && (
                                      <>
                                        <EyeIcon size={14} color="currentColor" /> viewed
                                      </>
                                    )}
                                    {activity.action === 'download' && (
                                      <>
                                        <DownloadIcon size={14} color="currentColor" /> downloaded
                                      </>
                                    )}
                                    {activity.action === 'preview' && (
                                      <>
                                        <EyeIcon size={14} color="currentColor" /> previewed
                                      </>
                                    )}
                                  </span>
                                  <span className="activity-time">
                                    {formatDate(activity.timestamp)}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </>
        )}
      </div>

      {showPreview && selectedFile && (
        <FilePreview
          file={selectedFile as FileItem}
          onClose={() => {
            setShowPreview(false);
            setSelectedFile(null);
          }}
        />
      )}
    </div>
  );
};

export default SharedFiles;

