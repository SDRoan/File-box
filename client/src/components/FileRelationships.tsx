import React, { useState, useEffect } from 'react';
import { FileItemType } from '../types';
import { relationshipsAPI, filesAPI } from '../services/api';
import './FileRelationships.css';

interface FileRelationshipsProps {
  file: FileItemType;
  onClose: () => void;
  onFileClick?: (fileId: string) => void;
}

interface Relationship {
  _id: string;
  sourceFile: FileItemType;
  targetFile: FileItemType;
  relationshipType: string;
  customLabel?: string;
  description?: string;
  createdAt: string;
}

const FileRelationships: React.FC<FileRelationshipsProps> = ({ file, onClose, onFileClick }) => {
  const [relationships, setRelationships] = useState<{ outgoing: Relationship[]; incoming: Relationship[] }>({
    outgoing: [],
    incoming: []
  });
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [availableFiles, setAvailableFiles] = useState<FileItemType[]>([]);
  const [selectedFileId, setSelectedFileId] = useState('');
  const [relationshipType, setRelationshipType] = useState('related');
  const [customLabel, setCustomLabel] = useState('');
  const [description, setDescription] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadRelationships();
  }, [file._id]);

  const loadRelationships = async () => {
    try {
      setLoading(true);
      const data = await relationshipsAPI.getFileRelationships(file._id);
      setRelationships({
        outgoing: data.outgoing || [],
        incoming: data.incoming || []
      });
    } catch (error) {
      console.error('Error loading relationships:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAvailableFiles = async () => {
    try {
      const data = await filesAPI.getFiles();
      // Filter out current file and already related files
      const relatedFileIds = new Set([
        file._id,
        ...relationships.outgoing.map(r => r.targetFile._id),
        ...relationships.incoming.map(r => r.sourceFile._id)
      ]);
      
      const allFiles = [...(data.files || [])];
      const filtered = allFiles.filter(f => !relatedFileIds.has(f._id));
      setAvailableFiles(filtered);
    } catch (error) {
      console.error('Error loading files:', error);
    }
  };

  const handleAddRelationship = async () => {
    if (!selectedFileId) return;

    try {
      await relationshipsAPI.createRelationship(
        file._id,
        selectedFileId,
        relationshipType,
        customLabel || undefined,
        description || undefined
      );
      setShowAddModal(false);
      setSelectedFileId('');
      setCustomLabel('');
      setDescription('');
      setRelationshipType('related');
      loadRelationships();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create connection');
    }
  };

  const handleDeleteRelationship = async (relationshipId: string) => {
    if (!window.confirm('Delete this connection?')) return;

    try {
      await relationshipsAPI.deleteRelationship(relationshipId);
      loadRelationships();
    } catch (error) {
      console.error('Error deleting relationship:', error);
      alert('Failed to delete connection');
    }
  };

  const getRelationshipLabel = (rel: Relationship) => {
    if (rel.customLabel) return rel.customLabel;
    const typeLabels: { [key: string]: string } = {
      related: 'Related to',
      depends_on: 'Depends on',
      references: 'References',
      part_of: 'Part of',
      version_of: 'Version of',
      duplicate_of: 'Duplicate of',
      custom: 'Custom'
    };
    return typeLabels[rel.relationshipType] || 'Related to';
  };

  const getRelationshipIcon = (type: string) => {
    const icons: { [key: string]: string } = {
      related: '',
      depends_on: '',
      references: '',
      part_of: 'Package',
      version_of: '',
      duplicate_of: '',
      custom: 'Tag'
    };
    return icons[type] || '';
  };

  const filteredFiles = availableFiles.filter(f =>
    f.originalName.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="file-relationships-overlay" onClick={onClose}>
      <div className="file-relationships-container" onClick={(e) => e.stopPropagation()}>
        <div className="file-relationships-header">
          <h2>File Connections</h2>
          <div className="file-relationships-file-info">
            <span className="file-icon"></span>
            <span className="file-name">{file.originalName}</span>
          </div>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="file-relationships-content">
          {loading ? (
            <div className="loading">Loading connections...</div>
          ) : (
            <>
              <div className="relationships-actions">
                <button className="add-relationship-btn" onClick={() => {
                  setShowAddModal(true);
                  loadAvailableFiles();
                }}>
                  ➕ Add Connection
                </button>
              </div>

              {relationships.outgoing.length === 0 && relationships.incoming.length === 0 ? (
                <div className="no-relationships">
                  <div className="no-relationships-icon"></div>
                  <p>No connections yet</p>
                  <p className="hint">Link this file to related files to organize your work</p>
                </div>
              ) : (
                <>
                  {relationships.outgoing.length > 0 && (
                    <div className="relationships-section">
                      <h3>Outgoing Connections</h3>
                      <div className="relationships-list">
                        {relationships.outgoing.map(rel => (
                          <div key={rel._id} className="relationship-item">
                            <div className="relationship-info">
                              <span className="relationship-icon">{getRelationshipIcon(rel.relationshipType)}</span>
                              <span className="relationship-label">{getRelationshipLabel(rel)}</span>
                              <span className="relationship-arrow">→</span>
                              <span
                                className="related-file-name"
                                onClick={() => onFileClick?.(rel.targetFile._id)}
                              >
                                {rel.targetFile.originalName}
                              </span>
                            </div>
                            {rel.description && (
                              <div className="relationship-description">{rel.description}</div>
                            )}
                            <button
                              className="delete-relationship-btn"
                              onClick={() => handleDeleteRelationship(rel._id)}
                            >
                              Delete
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {relationships.incoming.length > 0 && (
                    <div className="relationships-section">
                      <h3>Incoming Connections</h3>
                      <div className="relationships-list">
                        {relationships.incoming.map(rel => (
                          <div key={rel._id} className="relationship-item">
                            <div className="relationship-info">
                              <span className="related-file-name" onClick={() => onFileClick?.(rel.sourceFile._id)}>
                                {rel.sourceFile.originalName}
                              </span>
                              <span className="relationship-arrow">→</span>
                              <span className="relationship-icon">{getRelationshipIcon(rel.relationshipType)}</span>
                              <span className="relationship-label">{getRelationshipLabel(rel)}</span>
                            </div>
                            {rel.description && (
                              <div className="relationship-description">{rel.description}</div>
                            )}
                            <button
                              className="delete-relationship-btn"
                              onClick={() => handleDeleteRelationship(rel._id)}
                            >
                              Delete
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>

        {showAddModal && (
          <div className="add-relationship-modal">
            <div className="modal-header">
              <h3>Add Connection</h3>
              <button className="close-btn" onClick={() => setShowAddModal(false)}>×</button>
            </div>
            <div className="modal-content">
              <div className="form-group">
                <label>Link to file:</label>
                <input
                  type="text"
                  placeholder="Search files..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="search-input"
                />
                <div className="files-list">
                  {filteredFiles.slice(0, 10).map(f => (
                    <div
                      key={f._id}
                      className={`file-option ${selectedFileId === f._id ? 'selected' : ''}`}
                      onClick={() => setSelectedFileId(f._id)}
                    >
                      <span className="file-icon"></span>
                      <span className="file-name">{f.originalName}</span>
                    </div>
                  ))}
                  {filteredFiles.length === 0 && searchQuery && (
                    <div className="no-results">No files found</div>
                  )}
                </div>
              </div>

              <div className="form-group">
                <label>Connection Type:</label>
                <select
                  value={relationshipType}
                  onChange={(e) => setRelationshipType(e.target.value)}
                  className="relationship-type-select"
                >
                  <option value="related">Related to</option>
                  <option value="depends_on">Depends on</option>
                  <option value="references">References</option>
                  <option value="part_of">Part of</option>
                  <option value="version_of">Version of</option>
                  <option value="duplicate_of">Duplicate of</option>
                  <option value="custom">Custom</option>
                </select>
              </div>

              {relationshipType === 'custom' && (
                <div className="form-group">
                  <label>Custom Label:</label>
                  <input
                    type="text"
                    value={customLabel}
                    onChange={(e) => setCustomLabel(e.target.value)}
                    placeholder="e.g., 'Implements', 'Uses', etc."
                    className="custom-label-input"
                  />
                </div>
              )}

              <div className="form-group">
                <label>Description (optional):</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Add a note about this connection..."
                  className="description-textarea"
                  rows={3}
                />
              </div>

              <div className="modal-actions">
                <button className="cancel-btn" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button
                  className="create-btn"
                  onClick={handleAddRelationship}
                  disabled={!selectedFileId}
                >
                  Create Connection
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default FileRelationships;


