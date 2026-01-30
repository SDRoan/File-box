import React, { useState, useEffect } from 'react';
import { TemplateIcon, PlusIcon, LoadingIcon, SearchIcon, FilterIcon, StarredIcon as StarIcon, EyeIcon, TrashIcon, EditIcon, DownloadIcon } from './Icons';
import { templatesAPI, filesAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './TemplatesLibrary.css';

interface Template {
  _id: string;
  name: string;
  description: string;
  category: string;
  tags: string[];
  isPublic: boolean;
  usageCount: number;
  rating: number;
  ratingCount: number;
  createdBy?: {
    _id: string;
    name: string;
    email: string;
  };
  createdAt: string;
}

const TemplatesLibrary: React.FC = () => {
  const { user } = useAuth();
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showUseModal, setShowUseModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<Template | null>(null);
  const [useFileName, setUseFileName] = useState('');

  const categories = [
    { value: 'all', label: 'All Categories' },
    { value: 'business', label: 'Business' },
    { value: 'academic', label: 'Academic' },
    { value: 'personal', label: 'Personal' },
    { value: 'legal', label: 'Legal' },
    { value: 'creative', label: 'Creative' },
    { value: 'other', label: 'Other' },
  ];

  useEffect(() => {
    loadTemplates();
  }, [searchQuery, selectedCategory]);

  const loadTemplates = async () => {
    try {
      setLoading(true);
      const params: any = {};
      if (searchQuery) params.search = searchQuery;
      if (selectedCategory !== 'all') params.category = selectedCategory;
      const data = await templatesAPI.getTemplates(params);
      setTemplates(data || []);
    } catch (error) {
      console.error('Error loading templates:', error);
      alert('Failed to load templates');
    } finally {
      setLoading(false);
    }
  };

  const handleUseTemplate = async () => {
    if (!selectedTemplate) return;
    try {
      await templatesAPI.useTemplate(selectedTemplate._id, {
        fileName: useFileName || `${selectedTemplate.name} - Copy`
      });
      alert('File created successfully from template!');
      setShowUseModal(false);
      setSelectedTemplate(null);
      setUseFileName('');
      // Refresh files list
      window.location.reload();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create file from template');
    }
  };

  const handleDeleteTemplate = async (templateId: string) => {
    if (!window.confirm('Are you sure you want to delete this template?')) return;
    try {
      await templatesAPI.deleteTemplate(templateId);
      loadTemplates();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to delete template');
    }
  };

  const filteredTemplates = templates.filter(template => {
    if (selectedCategory !== 'all' && template.category !== selectedCategory) return false;
    if (searchQuery && !template.name.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !template.description.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="templates-library">
      <div className="templates-header">
        <h2><TemplateIcon size={24} color="currentColor" /> Templates Library</h2>
        <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
          <PlusIcon size={16} color="currentColor" /> Create Template
        </button>
      </div>

      <div className="templates-filters">
        <div className="search-box">
          <SearchIcon size={18} color="#999" />
          <input
            type="text"
            placeholder="Search templates..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="category-filter">
          <FilterIcon size={18} color="#999" />
          <select value={selectedCategory} onChange={(e) => setSelectedCategory(e.target.value)}>
            {categories.map(cat => (
              <option key={cat.value} value={cat.value}>{cat.label}</option>
            ))}
          </select>
        </div>
      </div>

      {loading ? (
        <div className="loading-state">
          <LoadingIcon size={40} color="#6b7280" />
          <p>Loading templates...</p>
        </div>
      ) : filteredTemplates.length === 0 ? (
        <div className="empty-state">
          <TemplateIcon size={64} color="#ccc" />
          <h3>No templates found</h3>
          <p>{searchQuery || selectedCategory !== 'all' ? 'Try adjusting your filters' : 'Create your first template to get started'}</p>
        </div>
      ) : (
        <div className="templates-grid">
          {filteredTemplates.map(template => (
            <div key={template._id} className="template-card">
              <div className="template-header">
                <div className="template-icon">
                  <TemplateIcon size={32} color="#6b7280" />
                </div>
                <div className="template-meta">
                  <h3>{template.name}</h3>
                  <div className="template-stats">
                    <span><StarIcon size={14} color="#ffc107" /> {template.rating.toFixed(1)}</span>
                    <span><EyeIcon size={14} color="#999" /> {template.usageCount} uses</span>
                  </div>
                </div>
              </div>
              <p className="template-description">{template.description || 'No description'}</p>
              <div className="template-tags">
                {template.tags.slice(0, 3).map((tag, i) => (
                  <span key={i} className="tag">{tag}</span>
                ))}
                {template.tags.length > 3 && <span className="tag">+{template.tags.length - 3}</span>}
              </div>
              <div className="template-footer">
                <span className="template-category">{categories.find(c => c.value === template.category)?.label || template.category}</span>
                {template.createdBy && template.createdBy._id === user?.id && (
                  <div className="template-actions">
                    <button className="btn-icon-small" onClick={() => handleDeleteTemplate(template._id)} title="Delete">
                      <TrashIcon size={14} color="#ef4444" />
                    </button>
                  </div>
                )}
              </div>
              <button className="btn-use-template" onClick={() => {
                setSelectedTemplate(template);
                setUseFileName(`${template.name} - Copy`);
                setShowUseModal(true);
              }}>
                Use Template
              </button>
            </div>
          ))}
        </div>
      )}

      {showCreateModal && (
        <CreateTemplateModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            loadTemplates();
          }}
        />
      )}

      {showUseModal && selectedTemplate && (
        <div className="modal-overlay" onClick={() => setShowUseModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Use Template: {selectedTemplate.name}</h3>
            <div className="form-group">
              <label>File Name</label>
              <input
                type="text"
                value={useFileName}
                onChange={(e) => setUseFileName(e.target.value)}
                placeholder="Enter file name..."
              />
            </div>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setShowUseModal(false)}>Cancel</button>
              <button className="btn-primary" onClick={handleUseTemplate}>Create File</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const CreateTemplateModal: React.FC<{ onClose: () => void; onSuccess: () => void }> = ({ onClose, onSuccess }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('other');
  const [content, setContent] = useState('');
  const [tags, setTags] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createFromFile, setCreateFromFile] = useState(false);
  const [availableFiles, setAvailableFiles] = useState<any[]>([]);
  const [selectedFileId, setSelectedFileId] = useState('');

  useEffect(() => {
    if (createFromFile) {
      loadFiles();
    }
  }, [createFromFile]);

  const loadFiles = async () => {
    try {
      const data = await filesAPI.getFiles();
      setAvailableFiles(data.files || []);
    } catch (error) {
      console.error('Error loading files:', error);
    }
  };

  const handleCreate = async () => {
    if (!name.trim()) {
      alert('Template name is required');
      return;
    }

    try {
      setCreating(true);
      if (createFromFile && selectedFileId) {
        await templatesAPI.createTemplateFromFile(selectedFileId, {
          name,
          description,
          category,
          tags: tags.split(',').map(t => t.trim()).filter(t => t),
          isPublic
        });
      } else {
        await templatesAPI.createTemplate({
          name,
          description,
          category,
          content,
          tags: tags.split(',').map(t => t.trim()).filter(t => t),
          isPublic
        });
      }
      onSuccess();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create template');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content large" onClick={(e) => e.stopPropagation()}>
        <h3>Create New Template</h3>
        <div className="form-group">
          <label>Create from existing file?</label>
          <input
            type="checkbox"
            checked={createFromFile}
            onChange={(e) => setCreateFromFile(e.target.checked)}
          />
        </div>
        {createFromFile ? (
          <div className="form-group">
            <label>Select File</label>
            <select value={selectedFileId} onChange={(e) => setSelectedFileId(e.target.value)}>
              <option value="">Choose a file...</option>
              {availableFiles.map(file => (
                <option key={file._id} value={file._id}>{file.originalName}</option>
              ))}
            </select>
          </div>
        ) : (
          <div className="form-group">
            <label>Content</label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Enter template content..."
              rows={10}
            />
          </div>
        )}
        <div className="form-group">
          <label>Template Name *</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Meeting Notes Template"
          />
        </div>
        <div className="form-group">
          <label>Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe what this template is for..."
            rows={3}
          />
        </div>
        <div className="form-group">
          <label>Category</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="business">Business</option>
            <option value="academic">Academic</option>
            <option value="personal">Personal</option>
            <option value="legal">Legal</option>
            <option value="creative">Creative</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div className="form-group">
          <label>Tags (comma-separated)</label>
          <input
            type="text"
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="e.g., meeting, notes, agenda"
          />
        </div>
        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic(e.target.checked)}
            />
            Make this template public
          </label>
        </div>
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={creating}>Cancel</button>
          <button className="btn-primary" onClick={handleCreate} disabled={creating}>
            {creating ? 'Creating...' : 'Create Template'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default TemplatesLibrary;
