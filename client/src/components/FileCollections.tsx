import React, { useState, useEffect } from 'react';
import { collectionsAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './FileCollections.css';

interface FileCollection {
  _id: string;
  name: string;
  description?: string;
  owner: {
    _id: string;
    name: string;
    email: string;
  };
  files: Array<{
    file?: {
      _id: string;
      originalName: string;
      mimeType: string;
      size: number;
    };
    folder?: {
      _id: string;
      name: string;
    };
    note?: string;
    addedAt: string;
  }>;
  isPublic: boolean;
  tags: string[];
  viewCount: number;
  likeCount: number;
  createdAt: string;
}

const FileCollections: React.FC = () => {
  const { user } = useAuth();
  const [collections, setCollections] = useState<FileCollection[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedCollection, setSelectedCollection] = useState<FileCollection | null>(null);
  const [newCollection, setNewCollection] = useState({
    name: '',
    description: '',
    isPublic: false,
    tags: ''
  });

  useEffect(() => {
    loadCollections();
  }, []);

  const loadCollections = async () => {
    try {
      setLoading(true);
      const data = await collectionsAPI.getCollections();
      setCollections(data);
    } catch (error) {
      console.error('Error loading collections:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCollection = async () => {
    if (!newCollection.name.trim()) {
      alert('Please enter a collection name');
      return;
    }

    try {
      const tags = newCollection.tags.split(',').map(t => t.trim()).filter(t => t);
      await collectionsAPI.createCollection({
        name: newCollection.name,
        description: newCollection.description,
        isPublic: newCollection.isPublic,
        tags
      });
      setShowCreateModal(false);
      setNewCollection({ name: '', description: '', isPublic: false, tags: '' });
      loadCollections();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create collection');
    }
  };

  const handleLike = async (id: string) => {
    try {
      await collectionsAPI.likeCollection(id);
      loadCollections();
    } catch (error) {
      console.error('Error liking collection:', error);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  if (loading) {
    return <div className="collections-loading">Loading collections...</div>;
  }

  if (selectedCollection) {
    return (
      <div className="collections-container">
        <div className="collection-header">
          <button onClick={() => setSelectedCollection(null)} className="back-btn">
            ← Back to Collections
          </button>
          <h2>{selectedCollection.name}</h2>
          {selectedCollection.description && <p>{selectedCollection.description}</p>}
        </div>
        <div className="collection-content">
          <div className="collection-stats">
            <span> {selectedCollection.files.length} items</span>
            <span> {selectedCollection.viewCount} views</span>
            <span> {selectedCollection.likeCount} likes</span>
          </div>
          <div className="collection-files">
            {selectedCollection.files.map((item, index) => (
              <div key={index} className="collection-item">
                {item.file ? (
                  <div className="file-item-card">
                    <div className="file-icon"></div>
                    <div className="file-info">
                      <h4>{item.file.originalName}</h4>
                      <p>{formatFileSize(item.file.size)} • {item.file.mimeType}</p>
                      {item.note && <p className="item-note">Note: {item.note}</p>}
                    </div>
                  </div>
                ) : item.folder ? (
                  <div className="folder-item-card">
                    <div className="folder-icon"></div>
                    <div className="folder-info">
                      <h4>{item.folder.name}</h4>
                      {item.note && <p className="item-note">Note: {item.note}</p>}
                    </div>
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="collections-container">
      <div className="collections-header">
        <h1> File Collections</h1>
        <p>Create curated collections of your files and folders</p>
        <button onClick={() => setShowCreateModal(true)} className="create-collection-btn">
          + Create Collection
        </button>
      </div>

      <div className="collections-grid">
        {collections.map((collection) => (
          <div
            key={collection._id}
            className="collection-card"
            onClick={() => setSelectedCollection(collection)}
          >
            <div className="collection-card-header">
              <h3>{collection.name}</h3>
              {collection.isPublic && <span className="public-badge">Public</span>}
            </div>
            {collection.description && (
              <p className="collection-description">{collection.description}</p>
            )}
            <div className="collection-meta">
              <span> {collection.files.length} items</span>
              <span> {collection.viewCount}</span>
              <span> {collection.likeCount}</span>
            </div>
            {collection.tags.length > 0 && (
              <div className="collection-tags">
                {collection.tags.map((tag, i) => (
                  <span key={i} className="tag">{tag}</span>
                ))}
              </div>
            )}
            <div className="collection-footer">
              <span>By {collection.owner.name}</span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleLike(collection._id);
                }}
                className="like-btn"
              >
                 Like
              </button>
            </div>
          </div>
        ))}
      </div>

      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Create Collection</h2>
            <div className="form-group">
              <label>Collection Name *</label>
              <input
                type="text"
                value={newCollection.name}
                onChange={(e) => setNewCollection({ ...newCollection, name: e.target.value })}
                placeholder="My Collection"
              />
            </div>
            <div className="form-group">
              <label>Description</label>
              <textarea
                value={newCollection.description}
                onChange={(e) => setNewCollection({ ...newCollection, description: e.target.value })}
                placeholder="Describe your collection..."
                rows={3}
              />
            </div>
            <div className="form-group">
              <label>Tags (comma-separated)</label>
              <input
                type="text"
                value={newCollection.tags}
                onChange={(e) => setNewCollection({ ...newCollection, tags: e.target.value })}
                placeholder="work, projects, important"
              />
            </div>
            <div className="form-group">
              <label>
                <input
                  type="checkbox"
                  checked={newCollection.isPublic}
                  onChange={(e) => setNewCollection({ ...newCollection, isPublic: e.target.checked })}
                />
                Make this collection public
              </label>
            </div>
            <div className="modal-actions">
              <button onClick={() => setShowCreateModal(false)}>Cancel</button>
              <button onClick={handleCreateCollection} className="primary">Create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FileCollections;








