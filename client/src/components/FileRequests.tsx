import React, { useState, useEffect } from 'react';
import { fileRequestsAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './FileRequests.css';

interface UploadedFile {
  file: {
    _id: string;
    originalName: string;
    size: number;
  };
  uploadedBy: {
    name: string;
    email: string;
  };
  uploadedAt: string;
}

interface FileRequest {
  _id: string;
  requestId: string;
  title: string;
  description: string;
  status: 'open' | 'fulfilled' | 'closed';
  uploadedFiles: UploadedFile[];
  expiresAt?: string;
  createdAt: string;
}

interface FileRequestsProps {
  onClose: () => void;
}

const FileRequests: React.FC<FileRequestsProps> = ({ onClose }) => {
  const { user } = useAuth();
  const [requests, setRequests] = useState<FileRequest[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [loading, setLoading] = useState(true);
  const [selectedRequest, setSelectedRequest] = useState<FileRequest | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'open' | 'fulfilled' | 'closed'>('all');
  const [sortBy, setSortBy] = useState<'date' | 'title' | 'files'>('date');
  const [showRequestDetails, setShowRequestDetails] = useState<string | null>(null);
  const [showRequestMenu, setShowRequestMenu] = useState<string | null>(null);

  useEffect(() => {
    loadRequests();
  }, []);

  const loadRequests = async () => {
    try {
      setLoading(true);
      const data = await fileRequestsAPI.getFileRequests();
      setRequests(data);
    } catch (error) {
      console.error('Error loading file requests:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;

    try {
      await fileRequestsAPI.createFileRequest(
        title.trim(),
        description.trim(),
        undefined,
        expiresAt || undefined
      );
      setTitle('');
      setDescription('');
      setExpiresAt('');
      setShowCreateModal(false);
      loadRequests();
    } catch (error) {
      alert('Failed to create file request');
    }
  };

  const handleCloseRequest = async (requestId: string) => {
    if (!window.confirm('Close this file request?')) return;

    try {
      await fileRequestsAPI.closeFileRequest(requestId);
      loadRequests();
    } catch (error) {
      alert('Failed to close request');
    }
  };

  const copyRequestLink = (requestId: string) => {
    const link = `${window.location.origin}/file-request/${requestId}`;
    navigator.clipboard.writeText(link);
    alert('Request link copied to clipboard!');
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return '#6b7280';
      case 'fulfilled': return '#27ae60';
      case 'closed': return '#999';
      default: return '#999';
    }
  };

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
    
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    return date.toLocaleDateString();
  };

  const isExpired = (expiresAt?: string) => {
    if (!expiresAt) return false;
    return new Date() > new Date(expiresAt);
  };

  const getDaysUntilExpiry = (expiresAt?: string) => {
    if (!expiresAt) return null;
    const expiry = new Date(expiresAt);
    const now = new Date();
    const diffTime = expiry.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  const getTotalFileSize = (request: FileRequest) => {
    return request.uploadedFiles.reduce((sum, upload) => sum + (upload.file.size || 0), 0);
  };

  // Filter and sort requests
  const filteredAndSortedRequests = requests
    .filter(request => {
      // Status filter
      if (statusFilter !== 'all' && request.status !== statusFilter) return false;
      
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return request.title.toLowerCase().includes(query) ||
          request.description.toLowerCase().includes(query) ||
          request.uploadedFiles.some(u => u.file.originalName.toLowerCase().includes(query));
      }
      
      return true;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'title':
          return a.title.localeCompare(b.title);
        case 'files':
          return b.uploadedFiles.length - a.uploadedFiles.length;
        case 'date':
        default:
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      }
    });

  const handleDownloadFile = (fileId: string) => {
    window.open(`http://localhost:5001/api/files/${fileId}/download`, '_blank');
  };

  const handleDeleteRequest = async (requestId: string) => {
    if (!window.confirm('Delete this file request? This action cannot be undone.')) return;
    try {
      await fileRequestsAPI.deleteFileRequest(requestId);
      setShowRequestMenu(null); // Close the menu
      loadRequests();
    } catch (error: any) {
      console.error('Error deleting file request:', error);
      alert(error.response?.data?.message || 'Failed to delete request');
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content file-requests-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>File Requests</h2>
          <button onClick={onClose} className="close-btn">×</button>
        </div>

        <div className="file-requests-actions">
          <div className="file-requests-header-controls">
            <div className="search-box-request">
              <input
                type="text"
                placeholder="Search file requests..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input-request"
              />
              <span className="search-icon-request"></span>
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="filter-select-request"
            >
              <option value="all">All Status</option>
              <option value="open">Open</option>
              <option value="fulfilled">Fulfilled</option>
              <option value="closed">Closed</option>
            </select>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="sort-select-request"
            >
              <option value="date">Sort by Date</option>
              <option value="title">Sort by Title</option>
              <option value="files">Sort by Files</option>
            </select>
            <button onClick={() => setShowCreateModal(true)} className="action-button">
              + Create File Request
            </button>
          </div>
        </div>

        {loading ? (
          <div className="loading">Loading...</div>
        ) : (
          <div className="file-requests-list">
            {filteredAndSortedRequests.length === 0 ? (
              <div className="empty-state">
                {searchQuery || statusFilter !== 'all' 
                  ? 'No requests match your filters' 
                  : 'No file requests yet'}
              </div>
            ) : (
              filteredAndSortedRequests.map((request) => {
                const totalSize = getTotalFileSize(request);
                const daysUntilExpiry = getDaysUntilExpiry(request.expiresAt);
                const expired = isExpired(request.expiresAt);
                
                return (
                  <div key={request._id} className="file-request-item">
                    <div className="request-header">
                      <div className="request-title-section">
                        <h3>{request.title}</h3>
                        <span
                          className="status-badge"
                          style={{ backgroundColor: getStatusColor(request.status) }}
                        >
                          {request.status.toUpperCase()}
                        </span>
                        {expired && request.status === 'open' && (
                          <span className="expired-badge">EXPIRED</span>
                        )}
                        {daysUntilExpiry !== null && daysUntilExpiry > 0 && daysUntilExpiry <= 3 && (
                          <span className="expiring-soon-badge">
                            Expires in {daysUntilExpiry} day{daysUntilExpiry !== 1 ? 's' : ''}
                          </span>
                        )}
                      </div>
                      <div className="request-actions">
                        <button
                          onClick={() => copyRequestLink(request.requestId)}
                          className="icon-btn"
                          title="Copy Link"
                        >
                          
                        </button>
                        <div className="request-menu-wrapper">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setShowRequestMenu(showRequestMenu === request._id ? null : request._id);
                            }}
                            className="icon-btn menu-btn"
                            title="More Options"
                          >
                            ⋮
                          </button>
                          {showRequestMenu === request._id && (
                            <div className="request-menu" onClick={(e) => e.stopPropagation()}>
                              <button
                                onClick={() => {
                                  copyRequestLink(request.requestId);
                                  setShowRequestMenu(null);
                                }}
                                className="menu-item"
                              >
                                 Copy Link
                              </button>
                              {request.status === 'open' && (
                                <button
                                  onClick={() => {
                                    handleCloseRequest(request.requestId);
                                    setShowRequestMenu(null);
                                  }}
                                  className="menu-item"
                                >
                                  × Close Request
                                </button>
                              )}
                              <button
                                onClick={() => {
                                  handleDeleteRequest(request.requestId);
                                  setShowRequestMenu(null);
                                }}
                                className="menu-item delete"
                              >
                                Delete Delete
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                    {request.description && (
                      <p className="request-description">{request.description}</p>
                    )}
                    <div className="request-stats">
                      <div className="stat-item">
                        <span className="stat-icon"></span>
                        <span className="stat-value">{request.uploadedFiles.length}</span>
                        <span className="stat-label">file{request.uploadedFiles.length !== 1 ? 's' : ''}</span>
                      </div>
                      {totalSize > 0 && (
                        <div className="stat-item">
                          <span className="stat-icon"></span>
                          <span className="stat-value">{formatFileSize(totalSize)}</span>
                        </div>
                      )}
                      <div className="stat-item">
                        <span className="stat-icon"></span>
                        <span className="stat-label">Created {formatDate(request.createdAt)}</span>
                      </div>
                      {request.expiresAt && (
                        <div className="stat-item">
                          <span className="stat-icon">⏰</span>
                          <span className={`stat-label ${expired ? 'expired-text' : ''}`}>
                            {expired ? 'Expired' : `Expires ${formatDate(request.expiresAt)}`}
                          </span>
                        </div>
                      )}
                    </div>
                    {request.uploadedFiles.length > 0 && (
                      <div className="uploaded-files">
                        <div className="uploaded-files-header">
                          <strong>Uploaded Files ({request.uploadedFiles.length})</strong>
                          <button
                            onClick={() => setShowRequestDetails(
                              showRequestDetails === request._id ? null : request._id
                            )}
                            className="toggle-details-btn"
                          >
                            {showRequestDetails === request._id ? '▲ Hide' : '▼ Show'}
                          </button>
                        </div>
                        {showRequestDetails === request._id && (
                          <div className="uploaded-files-list">
                            {request.uploadedFiles.map((upload, idx) => (
                              <div key={idx} className="uploaded-file-item-enhanced">
                                <div className="file-info-enhanced">
                                  <span className="file-icon-enhanced"></span>
                                  <div className="file-details-enhanced">
                                    <span className="file-name-enhanced">{upload.file.originalName}</span>
                                    <span className="file-size-enhanced">{formatFileSize(upload.file.size)}</span>
                                  </div>
                                </div>
                                <div className="file-actions-enhanced">
                                  <span className="upload-meta-enhanced">
                                    {upload.uploadedBy?.name || 'Anonymous'} • {formatDate(upload.uploadedAt)}
                                  </span>
                                  <button
                                    onClick={() => handleDownloadFile(upload.file._id)}
                                    className="download-file-btn"
                                    title="Download"
                                  >
                                    
                                  </button>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                    {request.uploadedFiles.length === 0 && request.status === 'open' && (
                      <div className="no-files-yet">
                        <span className="no-files-icon"></span>
                        <span>No files uploaded yet</span>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {showCreateModal && (
          <div className="modal-overlay-inner" onClick={() => setShowCreateModal(false)}>
            <div className="modal-content-small" onClick={(e) => e.stopPropagation()}>
              <h3>Create File Request</h3>
              <form onSubmit={handleCreateRequest}>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Request Title *"
                  className="form-input"
                  required
                  autoFocus
                />
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Description (optional)"
                  className="form-textarea"
                  rows={4}
                />
                <input
                  type="date"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                  placeholder="Expiration Date (optional)"
                  className="form-input"
                  min={new Date().toISOString().split('T')[0]}
                />
                <div className="modal-actions">
                  <button type="button" onClick={() => setShowCreateModal(false)} className="cancel-button">
                    Cancel
                  </button>
                  <button type="submit" className="action-button">Create</button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default FileRequests;










