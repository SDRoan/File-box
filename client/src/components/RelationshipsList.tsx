import React, { useState, useEffect } from 'react';
import { relationshipsAPI } from '../services/api';
import RelationshipGraph from './RelationshipGraph';
import { RelationshipsIcon, LinkIcon, ArrowRightIcon, PackageIcon, ScrollIcon, CopyIcon, TagIcon, DocumentIcon, ImageIcon, SummaryIcon, VideoIcon, AudioIcon, PaperclipIcon, TrashIcon } from './Icons';
import './RelationshipsList.css';

interface Relationship {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  description?: string;
}

interface FileNode {
  id: string;
  name: string;
  type: string;
  size: number;
}

interface GraphData {
  nodes: FileNode[];
  edges: Relationship[];
}

const RelationshipsList: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [showGraph, setShowGraph] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'date' | 'type' | 'source' | 'target'>('date');
  const [selectedRelationships, setSelectedRelationships] = useState<Set<string>>(new Set());
  const [showFileInfo, setShowFileInfo] = useState<string | null>(null);

  useEffect(() => {
    loadRelationships();
  }, []);

  const loadRelationships = async () => {
    try {
      setLoading(true);
      console.log('Loading relationships...');
      const data = await relationshipsAPI.getRelationshipGraph();
      console.log('Relationships loaded:', data);
      console.log('Nodes:', data.nodes);
      console.log('Edges:', data.edges);
      setGraphData(data);
    } catch (error) {
      console.error('Error loading relationships:', error);
      alert('Failed to load connections. Check console for details.');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteRelationship = async (relationshipId: string) => {
    if (!window.confirm('Are you sure you want to delete this connection?')) return;

    try {
      await relationshipsAPI.deleteRelationship(relationshipId);
      loadRelationships();
    } catch (error) {
      console.error('Error deleting relationship:', error);
      alert('Failed to delete relationship');
    }
  };

  const getRelationshipLabel = (type: string, customLabel?: string) => {
    if (customLabel) return customLabel;
    const labels: { [key: string]: string } = {
      related: 'Related to',
      depends_on: 'Depends on',
      references: 'References',
      part_of: 'Part of',
      version_of: 'Version of',
      duplicate_of: 'Duplicate of',
      custom: 'Custom'
    };
    return labels[type] || 'Related to';
  };

  const getRelationshipIcon = (type: string) => {
    const iconMap: { [key: string]: React.ReactNode } = {
      related: <LinkIcon size={16} color="currentColor" />,
      depends_on: <ArrowRightIcon size={16} color="currentColor" />,
      references: <PaperclipIcon size={16} color="currentColor" />,
      part_of: <PackageIcon size={16} color="currentColor" />,
      version_of: <LinkIcon size={16} color="currentColor" />,
      duplicate_of: <CopyIcon size={16} color="currentColor" />,
      custom: <TagIcon size={16} color="currentColor" />
    };
    return iconMap[type] || <LinkIcon size={16} color="currentColor" />;
  };

  const getFileName = (fileId: string) => {
    const node = graphData.nodes.find(n => n.id === fileId);
    return node?.name || 'Unknown File';
  };

  const getFileInfo = (fileId: string) => {
    return graphData.nodes.find(n => n.id === fileId);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getFileTypeIcon = (mimeType: string) => {
    if (mimeType.startsWith('image/')) return <ImageIcon size={16} color="currentColor" />;
    if (mimeType.includes('pdf')) return <DocumentIcon size={16} color="currentColor" />;
    if (mimeType.includes('word')) return <SummaryIcon size={16} color="currentColor" />;
    if (mimeType.includes('video')) return <VideoIcon size={16} color="currentColor" />;
    if (mimeType.includes('audio')) return <AudioIcon size={16} color="currentColor" />;
    return <PaperclipIcon size={16} color="currentColor" />;
  };

  // Filter and sort relationships
  const filteredAndSortedRelationships = graphData.edges
    .filter(rel => {
      // Type filter
      if (typeFilter !== 'all' && rel.type !== typeFilter) return false;
      
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const sourceName = getFileName(rel.source).toLowerCase();
        const targetName = getFileName(rel.target).toLowerCase();
        const label = getRelationshipLabel(rel.type, rel.label).toLowerCase();
        const desc = (rel.description || '').toLowerCase();
        
        return sourceName.includes(query) ||
          targetName.includes(query) ||
          label.includes(query) ||
          desc.includes(query);
      }
      
      return true;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'type':
          return a.type.localeCompare(b.type);
        case 'source':
          return getFileName(a.source).localeCompare(getFileName(b.source));
        case 'target':
          return getFileName(a.target).localeCompare(getFileName(b.target));
        case 'date':
        default:
          // Note: We don't have date in the edge data, so we'll sort by source name as fallback
          return getFileName(a.source).localeCompare(getFileName(b.source));
      }
    });

  const handleSelectRelationship = (relId: string) => {
    setSelectedRelationships(prev => {
      const newSet = new Set(prev);
      if (newSet.has(relId)) {
        newSet.delete(relId);
      } else {
        newSet.add(relId);
      }
      return newSet;
    });
  };

  const handleBulkDelete = async () => {
    if (selectedRelationships.size === 0) return;
    if (!window.confirm(`Delete ${selectedRelationships.size} connection(s)?`)) return;

    try {
      await Promise.all(
        Array.from(selectedRelationships).map(id => relationshipsAPI.deleteRelationship(id))
      );
      setSelectedRelationships(new Set());
      loadRelationships();
    } catch (error) {
      console.error('Error deleting relationships:', error);
      alert('Failed to delete some connections');
    }
  };

  const handleFileClick = (fileId: string) => {
    window.open(`http://localhost:5001/api/files/${fileId}/download`, '_blank');
  };

  const getRelationshipTypeColor = (type: string) => {
    const colors: { [key: string]: string } = {
      related: '#6b7280',
      depends_on: '#e74c3c',
      references: '#3498db',
      part_of: '#9b59b6',
      version_of: '#f39c12',
      duplicate_of: '#95a5a6',
      custom: '#1abc9c'
    };
    return colors[type] || '#6b7280';
  };

  if (loading) {
    return (
      <div className="relationships-list-container">
        <div className="relationships-header">
          <h2>File Connections</h2>
          <div className="header-actions">
            <button
              className="view-graph-btn"
              onClick={() => setShowGraph(true)}
            >
              <RelationshipsIcon size={16} color="currentColor" />
              <span>View Graph</span>
            </button>
          </div>
        </div>
        <div className="loading">Loading connections...</div>
      </div>
    );
  }

  if (graphData.edges.length === 0) {
    return (
      <div className="relationships-list-container">
        <div className="relationships-header">
          <h2>File Connections</h2>
          <div className="header-actions">
            <button
              className="view-graph-btn"
              onClick={() => setShowGraph(true)}
            >
              <RelationshipsIcon size={16} color="currentColor" />
              <span>View Graph</span>
            </button>
          </div>
        </div>
        <div className="no-relationships">
          <div className="empty-icon">
            <RelationshipsIcon size={48} color="#999" />
          </div>
          <p>No connections yet</p>
          <p className="hint">Create connections between files to see them here</p>
          <p className="hint" style={{ marginTop: '1rem', fontSize: '0.85rem', color: '#999' }}>
            Debug: Check browser console (F12) for API response details
          </p>
        </div>
        {showGraph && (
          <RelationshipGraph onClose={() => setShowGraph(false)} />
        )}
      </div>
    );
  }

  return (
    <div className="relationships-list-container">
      <div className="relationships-header">
        <div className="header-left">
          <h2>File Connections</h2>
          <span className="relationship-count">
            {filteredAndSortedRelationships.length} of {graphData.edges.length} connection{graphData.edges.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="header-actions">
          {selectedRelationships.size > 0 && (
            <button
              className="bulk-delete-btn"
              onClick={handleBulkDelete}
              title={`Delete ${selectedRelationships.size} selected`}
            >
              <TrashIcon size={16} color="currentColor" />
              <span>Delete ({selectedRelationships.size})</span>
            </button>
          )}
          <button
            className="view-graph-btn"
            onClick={() => setShowGraph(true)}
          >
            <RelationshipsIcon size={16} color="currentColor" />
            <span>View Graph</span>
          </button>
        </div>
      </div>

      <div className="relationships-controls">
        <div className="search-box-rel">
          <input
            type="text"
            placeholder="Search connections..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input-rel"
          />
          <span className="search-icon-rel"></span>
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="filter-select-rel"
        >
          <option value="all">All Types</option>
          <option value="related">Related</option>
          <option value="depends_on">Depends On</option>
          <option value="references">References</option>
          <option value="part_of">Part Of</option>
          <option value="version_of">Version Of</option>
          <option value="duplicate_of">Duplicate Of</option>
          <option value="custom">Custom</option>
        </select>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as any)}
          className="sort-select-rel"
        >
          <option value="date">Sort by Date</option>
          <option value="type">Sort by Type</option>
          <option value="source">Sort by Source</option>
          <option value="target">Sort by Target</option>
        </select>
      </div>

      <div className="relationships-list">
        {filteredAndSortedRelationships.length === 0 ? (
          <div className="no-results">
            <div className="empty-icon"></div>
            <p>No connections match your filters</p>
          </div>
        ) : (
          filteredAndSortedRelationships.map(relationship => {
            const sourceInfo = getFileInfo(relationship.source);
            const targetInfo = getFileInfo(relationship.target);
            const isSelected = selectedRelationships.has(relationship.id);
            
            return (
              <div 
                key={relationship.id} 
                className={`relationship-item ${isSelected ? 'selected' : ''}`}
                onClick={() => handleSelectRelationship(relationship.id)}
              >
                <div className="relationship-checkbox">
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => handleSelectRelationship(relationship.id)}
                    onClick={(e) => e.stopPropagation()}
                  />
                </div>
                <div className="relationship-content">
                  <span 
                    className="relationship-icon"
                    style={{ color: getRelationshipTypeColor(relationship.type) }}
                  >
                    {getRelationshipIcon(relationship.type)}
                  </span>
                  <div className="relationship-files">
                    <div 
                      className="file-name-section"
                      onMouseEnter={() => setShowFileInfo(relationship.source)}
                      onMouseLeave={() => setShowFileInfo(null)}
                    >
                      <span className="file-icon-small">
                        {sourceInfo ? getFileTypeIcon(sourceInfo.type) : ''}
                      </span>
                      <span 
                        className="file-name clickable"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleFileClick(relationship.source);
                        }}
                      >
                        {getFileName(relationship.source)}
                      </span>
                      {showFileInfo === relationship.source && sourceInfo && (
                        <div className="file-info-tooltip">
                          <div className="tooltip-name">{sourceInfo.name}</div>
                          <div className="tooltip-meta">
                            {formatFileSize(sourceInfo.size)} • {sourceInfo.type}
                          </div>
                        </div>
                      )}
                    </div>
                    <span className="relationship-arrow">→</span>
                    <div 
                      className="file-name-section"
                      onMouseEnter={() => setShowFileInfo(relationship.target)}
                      onMouseLeave={() => setShowFileInfo(null)}
                    >
                      <span className="file-icon-small">
                        {targetInfo ? getFileTypeIcon(targetInfo.type) : ''}
                      </span>
                      <span 
                        className="file-name clickable"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleFileClick(relationship.target);
                        }}
                      >
                        {getFileName(relationship.target)}
                      </span>
                      {showFileInfo === relationship.target && targetInfo && (
                        <div className="file-info-tooltip">
                          <div className="tooltip-name">{targetInfo.name}</div>
                          <div className="tooltip-meta">
                            {formatFileSize(targetInfo.size)} • {targetInfo.type}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                  <span 
                    className="relationship-type"
                    style={{ backgroundColor: getRelationshipTypeColor(relationship.type) + '20', color: getRelationshipTypeColor(relationship.type) }}
                  >
                    {getRelationshipLabel(relationship.type, relationship.label)}
                  </span>
                  {relationship.description && (
                    <span className="relationship-description" title={relationship.description}>
                      {relationship.description}
                    </span>
                  )}
                </div>
                <div className="relationship-actions">
                  <button
                    className="delete-relationship-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteRelationship(relationship.id);
                    }}
                    title="Delete connection"
                  >
                    <TrashIcon size={16} color="currentColor" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {showGraph && (
        <RelationshipGraph onClose={() => setShowGraph(false)} />
      )}
    </div>
  );
};

export default RelationshipsList;

