import React, { useState, useEffect } from 'react';
import { securedLinksAPI } from '../services/api';
import { SecurityIcon, PlusIcon, LoadingIcon, StarredIcon, LinkIcon, EditIcon, TrashIcon, EyeIcon } from './Icons';
import './SecuredLinks.css';

interface SecuredLink {
  _id: string;
  title: string;
  url?: string;
  description: string;
  category: string;
  tags: string[];
  isPasswordProtected: boolean;
  isEncrypted: boolean;
  passwordHint?: string;
  notes: string;
  isStarred: boolean;
  accessCount: number;
  lastAccessedAt?: string;
  expiresAt?: string;
  createdAt: string;
}

const SecuredLinks: React.FC = () => {
  const [links, setLinks] = useState<SecuredLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingLink, setEditingLink] = useState<SecuredLink | null>(null);
  const [showPasswordModal, setShowPasswordModal] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showStarredOnly, setShowStarredOnly] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    title: '',
    url: '',
    description: '',
    category: 'general',
    tags: '',
    password: '',
    passwordHint: '',
    isPasswordProtected: false,
    isEncrypted: false,
    notes: '',
    expiresAt: ''
  });

  useEffect(() => {
    loadLinks();
  }, [categoryFilter, showStarredOnly, searchQuery]);

  const loadLinks = async () => {
    try {
      setLoading(true);
      const params: any = {};
      if (categoryFilter !== 'all') params.category = categoryFilter;
      if (showStarredOnly) params.starred = true;
      if (searchQuery) params.search = searchQuery;
      
      const data = await securedLinksAPI.getSecuredLinks(params);
      setLinks(data);
    } catch (error) {
      console.error('Error loading secured links:', error);
      alert('Failed to load secured links');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenModal = (link?: SecuredLink) => {
    if (link) {
      setEditingLink(link);
      setFormData({
        title: link.title,
        url: link.url || '',
        description: link.description || '',
        category: link.category || 'general',
        tags: link.tags.join(', '),
        password: '',
        passwordHint: link.passwordHint || '',
        isPasswordProtected: link.isPasswordProtected,
        isEncrypted: link.isEncrypted,
        notes: link.notes || '',
        expiresAt: link.expiresAt ? new Date(link.expiresAt).toISOString().split('T')[0] : ''
      });
    } else {
      setEditingLink(null);
      setFormData({
        title: '',
        url: '',
        description: '',
        category: 'general',
        tags: '',
        password: '',
        passwordHint: '',
        isPasswordProtected: false,
        isEncrypted: false,
        notes: '',
        expiresAt: ''
      });
    }
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const tagsArray = formData.tags.split(',').map(t => t.trim()).filter(t => t);
      
      if (editingLink) {
        await securedLinksAPI.updateSecuredLink(editingLink._id, {
          title: formData.title,
          url: formData.url,
          description: formData.description,
          category: formData.category,
          tags: tagsArray,
          password: formData.password || undefined,
          passwordHint: formData.passwordHint,
          isPasswordProtected: formData.isPasswordProtected,
          isEncrypted: formData.isEncrypted,
          notes: formData.notes,
          expiresAt: formData.expiresAt || undefined
        });
      } else {
        await securedLinksAPI.createSecuredLink({
          title: formData.title,
          url: formData.url,
          description: formData.description,
          category: formData.category,
          tags: tagsArray,
          password: formData.password || undefined,
          passwordHint: formData.passwordHint,
          isPasswordProtected: formData.isPasswordProtected,
          isEncrypted: formData.isEncrypted,
          notes: formData.notes,
          expiresAt: formData.expiresAt || undefined
        });
      }
      
      setShowModal(false);
      loadLinks();
    } catch (error: any) {
      console.error('Error saving secured link:', error);
      alert(error.response?.data?.message || 'Failed to save secured link');
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this secured link?')) return;
    
    try {
      await securedLinksAPI.deleteSecuredLink(id);
      loadLinks();
    } catch (error) {
      console.error('Error deleting secured link:', error);
      alert('Failed to delete secured link');
    }
  };

  const handleAccess = async (link: SecuredLink) => {
    if (link.isPasswordProtected) {
      setShowPasswordModal(link._id);
      setPassword('');
      setPasswordError('');
    } else {
      await openLink(link._id);
    }
  };

  const openLink = async (linkId: string, providedPassword?: string) => {
    try {
      const result = await securedLinksAPI.accessSecuredLink(linkId, providedPassword);
      if (result.url) {
        window.open(result.url, '_blank');
        loadLinks(); // Refresh to update access count
        return true; // Success
      }
      return false;
    } catch (error: any) {
      if (error.response?.status === 401) {
        const errorMsg = error.response?.data?.passwordHint 
          ? `Invalid password. Hint: ${error.response.data.passwordHint}`
          : error.response?.data?.message || 'Invalid password';
        setPasswordError(errorMsg);
      } else {
        alert('Failed to access link');
      }
      return false; // Failed
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!showPasswordModal) return;
    
    setPasswordError('');
    const success = await openLink(showPasswordModal, password);
    if (success) {
      setShowPasswordModal(null);
      setPassword('');
      setPasswordError('');
    }
  };

  const handleToggleStar = async (id: string) => {
    try {
      await securedLinksAPI.toggleStar(id);
      loadLinks();
    } catch (error) {
      console.error('Error toggling star:', error);
    }
  };

  const categories = ['all', 'general', 'work', 'personal', 'finance', 'health', 'education', 'shopping', 'social', 'other'];
  // Links are already filtered by the API, so we just use them directly
  const filteredLinks = links;

  return (
    <div className="secured-links">
      <div className="secured-links-header">
        <h2>
          <SecurityIcon size={24} color="currentColor" /> Secured Links
        </h2>
        <button className="btn-primary" onClick={() => handleOpenModal()}>
          <PlusIcon size={16} color="currentColor" /> Add Secured Link
        </button>
      </div>

      <div className="secured-links-filters">
        <div className="filter-group">
          <input
            type="text"
            placeholder="Search links..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
        <div className="filter-group">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="category-select"
          >
            {categories.map(cat => (
              <option key={cat} value={cat}>{cat.charAt(0).toUpperCase() + cat.slice(1)}</option>
            ))}
          </select>
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
          <p>Loading secured links...</p>
        </div>
      ) : filteredLinks.length === 0 ? (
        <div className="empty-state">
          <SecurityIcon size={64} color="#ccc" />
          <h3>No secured links yet</h3>
          <p>Add your first secured link to get started</p>
        </div>
      ) : (
        <div className="secured-links-grid">
          {filteredLinks.map(link => (
            <div key={link._id} className="secured-link-card">
              <div className="link-card-header">
                <div className="link-title-section">
                  <h3>{link.title}</h3>
                  <div className="link-badges">
                    {link.isPasswordProtected && (
                      <span className="badge badge-lock"> Protected</span>
                    )}
                    {link.isEncrypted && (
                      <span className="badge badge-encrypted"> Encrypted</span>
                    )}
                    {link.expiresAt && new Date(link.expiresAt) < new Date() && (
                      <span className="badge badge-expired">Expired</span>
                    )}
                  </div>
                </div>
                <button
                  className={`star-button ${link.isStarred ? 'starred' : ''}`}
                  onClick={() => handleToggleStar(link._id)}
                  title={link.isStarred ? 'Unstar' : 'Star'}
                >
                  <StarredIcon size={18} color="currentColor" />
                </button>
              </div>
              
              {link.description && (
                <p className="link-description">{link.description}</p>
              )}
              
              <div className="link-meta">
                <span className="link-category">{link.category}</span>
                {link.tags.length > 0 && (
                  <div className="link-tags">
                    {link.tags.map(tag => (
                      <span key={tag} className="tag">{tag}</span>
                    ))}
                  </div>
                )}
              </div>

              {link.notes && (
                <div className="link-notes">
                  <strong>Notes:</strong> {link.notes}
                </div>
              )}

              <div className="link-stats">
                <span>Accessed {link.accessCount} time{link.accessCount !== 1 ? 's' : ''}</span>
                {link.lastAccessedAt && (
                  <span>Last: {new Date(link.lastAccessedAt).toLocaleDateString()}</span>
                )}
              </div>

              <div className="link-actions">
                <button
                  className="btn-access"
                  onClick={() => handleAccess(link)}
                  title="Open link"
                >
                  <EyeIcon size={16} color="currentColor" /> Open
                </button>
                <button
                  className="btn-edit"
                  onClick={() => handleOpenModal(link)}
                  title="Edit"
                >
                  <EditIcon size={16} color="currentColor" />
                </button>
                <button
                  className="btn-delete"
                  onClick={() => handleDelete(link._id)}
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
            <h3>{editingLink ? 'Edit' : 'Add'} Secured Link</h3>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Title *</label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label>URL *</label>
                <input
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  required={!formData.isEncrypted}
                  disabled={formData.isEncrypted}
                  placeholder={formData.isEncrypted ? 'URL will be encrypted' : 'https://example.com'}
                />
              </div>

              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  rows={3}
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Category</label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  >
                    {categories.filter(c => c !== 'all').map(cat => (
                      <option key={cat} value={cat}>{cat.charAt(0).toUpperCase() + cat.slice(1)}</option>
                    ))}
                  </select>
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
              </div>

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={formData.isPasswordProtected}
                    onChange={(e) => setFormData({ ...formData, isPasswordProtected: e.target.checked })}
                  />
                  Password Protected
                </label>
              </div>

              {formData.isPasswordProtected && (
                <div className="form-row">
                  <div className="form-group">
                    <label>Password {editingLink ? '(leave blank to keep current)' : '*'}</label>
                    <input
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      required={!editingLink}
                    />
                  </div>
                  <div className="form-group">
                    <label>Password Hint</label>
                    <input
                      type="text"
                      value={formData.passwordHint}
                      onChange={(e) => setFormData({ ...formData, passwordHint: e.target.value })}
                      placeholder="Optional hint"
                    />
                  </div>
                </div>
              )}

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={formData.isEncrypted}
                    onChange={(e) => setFormData({ ...formData, isEncrypted: e.target.checked })}
                  />
                  Encrypt URL (for sensitive links)
                </label>
              </div>

              <div className="form-group">
                <label>Notes</label>
                <textarea
                  value={formData.notes}
                  onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                  rows={2}
                  placeholder="Additional notes or reminders"
                />
              </div>

              <div className="form-group">
                <label>Expiration Date (optional)</label>
                <input
                  type="date"
                  value={formData.expiresAt}
                  onChange={(e) => setFormData({ ...formData, expiresAt: e.target.value })}
                />
              </div>

              <div className="modal-actions">
                <button type="button" onClick={() => setShowModal(false)} className="btn-cancel">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  {editingLink ? 'Update' : 'Create'} Link
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Password Modal */}
      {showPasswordModal && (
        <div className="modal-overlay" onClick={() => setShowPasswordModal(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Enter Password</h3>
            <form onSubmit={handlePasswordSubmit}>
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    setPasswordError('');
                  }}
                  autoFocus
                  required
                />
                {passwordError && (
                  <div className="error-message">{passwordError}</div>
                )}
                {links.find(l => l._id === showPasswordModal)?.passwordHint && (
                  <div className="password-hint">
                    Hint: {links.find(l => l._id === showPasswordModal)?.passwordHint}
                  </div>
                )}
              </div>
              <div className="modal-actions">
                <button type="button" onClick={() => setShowPasswordModal(null)} className="btn-cancel">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Open Link
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecuredLinks;
