import React, { useState, useEffect } from 'react';
import { webShortcutsAPI } from '../services/api';
import { ShortcutIcon, PlusIcon, LoadingIcon, StarredIcon, EditIcon, TrashIcon, EyeIcon, LinkIcon } from './Icons';
import './WebShortcuts.css';

interface WebShortcut {
  _id: string;
  title: string;
  url: string;
  description: string;
  tags: string[];
  favicon?: string;
  isStarred: boolean;
  clickCount: number;
  lastAccessedAt?: string;
  createdAt: string;
}

const WebShortcuts: React.FC = () => {
  const [shortcuts, setShortcuts] = useState<WebShortcut[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingShortcut, setEditingShortcut] = useState<WebShortcut | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showStarredOnly, setShowStarredOnly] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    title: '',
    url: '',
    description: '',
    tags: ''
  });

  useEffect(() => {
    loadShortcuts();
  }, [searchQuery, showStarredOnly]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadShortcuts = async () => {
    try {
      setLoading(true);
      const params: any = {};
      if (showStarredOnly) params.starred = true;
      if (searchQuery) params.search = searchQuery;
      
      const data = await webShortcutsAPI.getShortcuts(params);
      setShortcuts(data);
    } catch (error) {
      console.error('Error loading shortcuts:', error);
      alert('Failed to load shortcuts');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenModal = (shortcut?: WebShortcut) => {
    if (shortcut) {
      setEditingShortcut(shortcut);
      setFormData({
        title: shortcut.title,
        url: shortcut.url,
        description: shortcut.description || '',
        tags: shortcut.tags.join(', ')
      });
    } else {
      setEditingShortcut(null);
      setFormData({
        title: '',
        url: '',
        description: '',
        tags: ''
      });
    }
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const tagsArray = formData.tags.split(',').map(t => t.trim()).filter(t => t);
      
      if (editingShortcut) {
        await webShortcutsAPI.updateShortcut(editingShortcut._id, {
          title: formData.title,
          url: formData.url,
          description: formData.description,
          tags: tagsArray
        });
      } else {
        await webShortcutsAPI.createShortcut({
          title: formData.title || undefined,
          url: formData.url,
          description: formData.description || undefined,
          tags: tagsArray.length > 0 ? tagsArray : undefined
        });
      }
      
      setShowModal(false);
      loadShortcuts();
    } catch (error: any) {
      console.error('Error saving shortcut:', error);
      alert(error.response?.data?.message || 'Failed to save shortcut');
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this shortcut?')) return;
    
    try {
      await webShortcutsAPI.deleteShortcut(id);
      loadShortcuts();
    } catch (error) {
      console.error('Error deleting shortcut:', error);
      alert('Failed to delete shortcut');
    }
  };

  const handleAccess = async (shortcut: WebShortcut) => {
    try {
      await webShortcutsAPI.trackAccess(shortcut._id);
      window.open(shortcut.url, '_blank');
      loadShortcuts(); // Refresh to update access count
    } catch (error) {
      console.error('Error tracking access:', error);
      // Still open the link even if tracking fails
      window.open(shortcut.url, '_blank');
    }
  };

  const handleToggleStar = async (id: string) => {
    try {
      const shortcut = shortcuts.find(s => s._id === id);
      if (shortcut) {
        await webShortcutsAPI.updateShortcut(id, { isStarred: !shortcut.isStarred });
        loadShortcuts();
      }
    } catch (error) {
      console.error('Error toggling star:', error);
    }
  };

  const filteredShortcuts = shortcuts;

  return (
    <div className="web-shortcuts">
      <div className="shortcuts-header">
        <h2><ShortcutIcon size={24} color="currentColor" /> Web Shortcuts</h2>
        <button className="btn-primary" onClick={() => handleOpenModal()}>
          <PlusIcon size={14} color="currentColor" /> Add Shortcut
        </button>
      </div>

      <div className="shortcuts-filters">
        <div className="filter-group">
          <input
            type="text"
            placeholder="Search shortcuts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
        <div className="filter-group">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={showStarredOnly}
              onChange={(e) => setShowStarredOnly(e.target.checked)}
            />
            Starred only
          </label>
        </div>
      </div>

      {loading ? (
        <div className="loading-state">
          <LoadingIcon size={40} color="#3b82f6" />
          <p>Loading shortcuts...</p>
        </div>
      ) : filteredShortcuts.length === 0 ? (
        <div className="empty-state">
          <ShortcutIcon size={64} color="#ccc" />
          <h3>No shortcuts yet</h3>
          <p>Add your first web shortcut to get started</p>
        </div>
      ) : (
        <div className="shortcuts-grid">
          {filteredShortcuts.map(shortcut => (
            <div key={shortcut._id} className="shortcut-card">
              <div className="shortcut-card-header">
                <div className="shortcut-title-section">
                  {shortcut.favicon && (
                    <img src={shortcut.favicon} alt="" className="shortcut-favicon" onError={(e) => {
                      (e.target as HTMLImageElement).style.display = 'none';
                    }} />
                  )}
                  <h3>{shortcut.title}</h3>
                </div>
                <button
                  className={`star-button ${shortcut.isStarred ? 'starred' : ''}`}
                  onClick={() => handleToggleStar(shortcut._id)}
                  title={shortcut.isStarred ? 'Unstar' : 'Star'}
                >
                  <StarredIcon size={18} color="currentColor" />
                </button>
              </div>
              
              <div className="shortcut-url">
                <LinkIcon size={14} color="#9ca3af" />
                <span>{shortcut.url}</span>
              </div>
              
              {shortcut.description && (
                <p className="shortcut-description">{shortcut.description}</p>
              )}
              
              {shortcut.tags.length > 0 && (
                <div className="shortcut-tags">
                  {shortcut.tags.map(tag => (
                    <span key={tag} className="tag">{tag}</span>
                  ))}
                </div>
              )}

              <div className="shortcut-stats">
                <span>Accessed {shortcut.clickCount} time{shortcut.clickCount !== 1 ? 's' : ''}</span>
                {shortcut.lastAccessedAt && (
                  <span>Last: {new Date(shortcut.lastAccessedAt).toLocaleDateString()}</span>
                )}
              </div>

              <div className="shortcut-actions">
                <button
                  className="btn-access"
                  onClick={() => handleAccess(shortcut)}
                  title="Open link"
                >
                  <EyeIcon size={16} color="currentColor" /> Open
                </button>
                <button
                  className="btn-edit"
                  onClick={() => handleOpenModal(shortcut)}
                  title="Edit"
                >
                  <EditIcon size={16} color="currentColor" />
                </button>
                <button
                  className="btn-delete"
                  onClick={() => handleDelete(shortcut._id)}
                  title="Delete"
                >
                  <TrashIcon size={16} color="currentColor" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add/Edit Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>{editingShortcut ? 'Edit' : 'Add'} Web Shortcut</h3>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>URL *</label>
                <input
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  required
                  placeholder="https://example.com"
                />
              </div>

              <div className="form-group">
                <label>Title (optional - will be auto-generated if empty)</label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="Leave empty to auto-generate from URL"
                />
              </div>

              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  rows={3}
                  placeholder="Optional description"
                />
              </div>

              <div className="form-group">
                <label>Tags (comma-separated)</label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  placeholder="work, important, etc."
                />
              </div>

              <div className="modal-actions">
                <button type="button" onClick={() => setShowModal(false)} className="btn-cancel">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  {editingShortcut ? 'Update' : 'Create'} Shortcut
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default WebShortcuts;
