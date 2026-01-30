import React, { useState, useEffect, useRef } from 'react';
import { relationshipsAPI, filesAPI } from '../services/api';
import FilePreview from './FilePreview';
import { FileItemType } from '../types';
import './RelationshipGraph.css';

interface Node {
  id: string;
  name: string;
  type: string;
  size: number;
}

interface Edge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
}

interface GraphData {
  nodes: Node[];
  edges: Edge[];
}

const RelationshipGraph: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<Edge | null>(null);
  const [editingRelationshipType, setEditingRelationshipType] = useState<string>('');
  const [previewFile, setPreviewFile] = useState<FileItemType | null>(null);
  const [loadingFile, setLoadingFile] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useEffect(() => {
    loadGraphData();
  }, []);

  useEffect(() => {
    const updateDimensions = () => {
      if (svgRef.current && svgRef.current.parentElement) {
        const parent = svgRef.current.parentElement;
        const rect = parent.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          // Get the actual container to account for header and legend
          const container = parent.closest('.relationship-graph-container');
          if (container) {
            const containerRect = container.getBoundingClientRect();
            const header = container.querySelector('.graph-header');
            const legend = container.querySelector('.graph-legend');
            const headerHeight = header ? header.getBoundingClientRect().height : 0;
            const legendHeight = legend ? legend.getBoundingClientRect().height : 0;
            
            // Available height is container minus header and legend
            const availableHeight = containerRect.height - headerHeight - legendHeight;
            
            setDimensions({ 
              width: Math.max(rect.width, 400), 
              height: Math.max(availableHeight, 300) 
            });
          } else {
            // Fallback to parent dimensions
            setDimensions({ 
              width: Math.max(rect.width, 400), 
              height: Math.max(rect.height, 300) 
            });
          }
        }
      }
    };

    // Initial update
    updateDimensions();
    
    // Use ResizeObserver for better tracking
    let resizeObserver: ResizeObserver | null = null;
    if (svgRef.current?.parentElement && typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(() => {
        updateDimensions();
      });
      resizeObserver.observe(svgRef.current.parentElement);
    }
    
    // Also listen to window resize as fallback
    window.addEventListener('resize', updateDimensions);
    
    // Update after delays to ensure container is fully rendered
    const timeout = setTimeout(updateDimensions, 100);
    const timeout2 = setTimeout(updateDimensions, 500);
    const timeout3 = setTimeout(updateDimensions, 1000);
    
    return () => {
      window.removeEventListener('resize', updateDimensions);
      if (resizeObserver) {
        resizeObserver.disconnect();
      }
      clearTimeout(timeout);
      clearTimeout(timeout2);
      clearTimeout(timeout3);
    };
  }, [graphData.nodes.length]);

  const loadGraphData = async () => {
    try {
      setLoading(true);
      const data = await relationshipsAPI.getRelationshipGraph();
      setGraphData(data);
    } catch (error) {
      console.error('Error loading graph:', error);
    } finally {
      setLoading(false);
    }
  };

  // Simple force-directed layout (simplified)
  const calculateLayout = () => {
    if (graphData.nodes.length === 0) return [];

    // Use actual dimensions or fallback to reasonable defaults
    const width = dimensions.width > 0 ? dimensions.width : 800;
    const height = dimensions.height > 0 ? dimensions.height : 600;
    
    // Padding to ensure nodes and labels don't get cut off
    // Account for: node radius (25px max), label height (40px), and extra margin
    const nodeRadius = 25;
    const labelHeight = 45; // Space for label below node
    const padding = nodeRadius + labelHeight + 30; // Generous padding
    
    // Available space for node layout (centered)
    const availableWidth = width - padding * 2;
    const availableHeight = height - padding * 2;
    
    // Center coordinates - nodes will be centered in the viewBox
    const centerX = width / 2;
    const centerY = height / 2;
    
    // Calculate radius to fit all nodes within bounds
    // Use a conservative approach - ensure all nodes fit with labels
    const maxRadiusX = availableWidth / 2;
    const maxRadiusY = availableHeight / 2;
    const maxRadius = Math.min(maxRadiusX, maxRadiusY);
    
    // Use 18% of smallest dimension to ensure everything fits comfortably
    const radius = Math.min(maxRadius, Math.min(width, height) * 0.18);
    
    const angleStep = (2 * Math.PI) / graphData.nodes.length;

    return graphData.nodes.map((node, index) => {
      const angle = index * angleStep;
      return {
        ...node,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle)
      };
    });
  };

  const layoutNodes = calculateLayout();

  const getNodeColor = (type: string) => {
    if (type.includes('pdf')) return '#e74c3c';
    if (type.includes('image')) return '#3498db';
    if (type.includes('video')) return '#9b59b6';
    if (type.includes('text') || type.includes('javascript') || type.includes('json')) return '#2ecc71';
    return '#95a5a6';
  };

  const getRelationshipColor = (type: string) => {
    const colors: { [key: string]: string } = {
      related: '#6b7280',
      depends_on: '#e74c3c',
      references: '#3498db',
      part_of: '#9b59b6',
      version_of: '#f39c12',
      duplicate_of: '#e67e22',
      custom: '#1abc9c'
    };
    return colors[type] || '#6b7280';
  };

  const getRelationshipLabel = (type: string) => {
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

  const handleDeleteRelationship = async (edgeId: string) => {
    if (!window.confirm('Are you sure you want to delete this connection?')) return;

    try {
      await relationshipsAPI.deleteRelationship(edgeId);
      setSelectedEdge(null);
      loadGraphData();
    } catch (error) {
      console.error('Error deleting relationship:', error);
      alert('Failed to delete connection');
    }
  };

  const handleEdgeClick = (e: React.MouseEvent, edge: Edge) => {
    e.stopPropagation();
    setSelectedEdge(edge);
    setEditingRelationshipType(edge.type);
    setSelectedNode(null);
  };

  const handleUpdateRelationshipType = async () => {
    if (!selectedEdge || !editingRelationshipType) return;

    try {
      await relationshipsAPI.updateRelationship(selectedEdge.id, {
        relationshipType: editingRelationshipType
      });
      await loadGraphData();
      setSelectedEdge(null);
      setEditingRelationshipType('');
    } catch (error) {
      console.error('Error updating relationship:', error);
      alert('Failed to update relationship type');
    }
  };

  const handleOpenFile = async (nodeId: string) => {
    try {
      setLoadingFile(true);
      const fileData = await filesAPI.getFileById(nodeId);
      if (fileData && fileData.file) {
        setPreviewFile(fileData.file);
      } else {
        alert('File not found');
      }
    } catch (error: any) {
      console.error('Error loading file:', error);
      if (error.response?.status === 404) {
        alert('File not found or you do not have access to it');
      } else {
        alert('Failed to load file');
      }
    } finally {
      setLoadingFile(false);
    }
  };

  if (loading) {
    return (
      <div className="relationship-graph-overlay" onClick={onClose}>
        <div className="relationship-graph-container" onClick={(e) => e.stopPropagation()}>
          <div className="graph-loading">Loading relationship graph...</div>
        </div>
      </div>
    );
  }

  if (graphData.nodes.length === 0) {
    return (
      <div className="relationship-graph-overlay" onClick={onClose}>
        <div className="relationship-graph-container" onClick={(e) => e.stopPropagation()}>
          <div className="graph-header">
            <h2>Relationship Graph</h2>
            <button className="close-btn" onClick={onClose}>×</button>
          </div>
          <div className="graph-empty">
            <div className="empty-icon"></div>
            <p>No relationships yet</p>
            <p className="hint">Create relationships between files to see them here</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="relationship-graph-overlay" onClick={onClose}>
      <div className="relationship-graph-container" onClick={(e) => e.stopPropagation()}>
        <div className="graph-header">
          <h2>Relationship Graph</h2>
          <div className="graph-info">
            <span>{graphData.nodes.length} files</span>
            <span>{graphData.edges.length} relationships</span>
          </div>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="graph-content">
          <svg
            ref={svgRef}
            width="100%"
            height="100%"
            viewBox={`0 0 ${dimensions.width || 800} ${dimensions.height || 600}`}
            preserveAspectRatio="xMidYMid meet"
            className="graph-svg"
            onClick={() => {
              setSelectedNode(null);
              setSelectedEdge(null);
            }}
          >
            {/* Arrow markers for different relationship types */}
            <defs>
              {['related', 'depends_on', 'references', 'part_of', 'version_of', 'duplicate_of', 'custom'].map(type => (
                <marker
                  key={`arrowhead-${type}`}
                  id={`arrowhead-${type}`}
                  markerWidth="12"
                  markerHeight="12"
                  refX="10"
                  refY="4"
                  orient="auto"
                  markerUnits="strokeWidth"
                >
                  <polygon 
                    points="0 0, 12 4, 0 8" 
                    fill={getRelationshipColor(type)}
                    stroke={getRelationshipColor(type)}
                    strokeWidth="0.5"
                  />
                </marker>
              ))}
              {/* Default arrow */}
              <marker
                id="arrowhead-default"
                markerWidth="12"
                markerHeight="12"
                refX="10"
                refY="4"
                orient="auto"
                markerUnits="strokeWidth"
              >
                <polygon 
                  points="0 0, 12 4, 0 8" 
                  fill="#6b7280"
                  stroke="#6b7280"
                  strokeWidth="0.5"
                />
              </marker>
            </defs>

            {/* Render edges */}
            {graphData.edges.map(edge => {
              const sourceNode = layoutNodes.find(n => n.id === edge.source);
              const targetNode = layoutNodes.find(n => n.id === edge.target);
              if (!sourceNode || !targetNode) return null;

              const isSelected = selectedEdge?.id === edge.id;
              const edgeColor = getRelationshipColor(edge.type);
              const midX = (sourceNode.x + targetNode.x) / 2;
              const midY = (sourceNode.y + targetNode.y) / 2;
              
              // Calculate arrow position (slightly before the target node)
              const dx = targetNode.x - sourceNode.x;
              const dy = targetNode.y - sourceNode.y;
              const length = Math.sqrt(dx * dx + dy * dy);
              const nodeRadius = 20; // Match the node radius
              const arrowOffset = nodeRadius + 5; // Distance from node center
              const arrowX = targetNode.x - (dx / length) * arrowOffset;
              const arrowY = targetNode.y - (dy / length) * arrowOffset;

              return (
                <g key={edge.id}>
                  {/* Invisible thicker line for easier clicking */}
                  <line
                    x1={sourceNode.x}
                    y1={sourceNode.y}
                    x2={targetNode.x}
                    y2={targetNode.y}
                    stroke="transparent"
                    strokeWidth="12"
                    style={{ cursor: 'pointer' }}
                    onClick={(e) => handleEdgeClick(e, edge)}
                  />
                  {/* Visible edge line with arrow */}
                  <line
                    x1={sourceNode.x}
                    y1={sourceNode.y}
                    x2={arrowX}
                    y2={arrowY}
                    stroke={edgeColor}
                    strokeWidth={isSelected ? "4" : "3"}
                    opacity={isSelected ? "1" : "0.8"}
                    markerEnd={`url(#arrowhead-${edge.type})`}
                    style={{ cursor: 'pointer' }}
                    onClick={(e) => handleEdgeClick(e, edge)}
                  />
                  {/* Edge label with background for visibility */}
                  <rect
                    x={midX - 40}
                    y={midY - 12}
                    width="80"
                    height="16"
                    fill="#0d1117"
                    opacity="0.9"
                    rx="4"
                    stroke={edgeColor}
                    strokeWidth="1"
                    style={{ pointerEvents: 'none' }}
                  />
                  <text
                    x={midX}
                    y={midY - 1}
                    textAnchor="middle"
                    fill="#fff"
                    fontSize="11"
                    fontWeight="600"
                    style={{ cursor: 'pointer', pointerEvents: 'none' }}
                  >
                    {edge.label || getRelationshipLabel(edge.type)}
                  </text>
                </g>
              );
            })}

            {/* Render nodes */}
            {layoutNodes.map(node => (
              <g key={node.id}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={selectedNode?.id === node.id ? 25 : 20}
                  fill={getNodeColor(node.type)}
                  stroke={selectedNode?.id === node.id ? '#6b7280' : '#fff'}
                  strokeWidth={selectedNode?.id === node.id ? 3 : 2}
                  className="node-circle"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(node);
                    setSelectedEdge(null);
                  }}
                  style={{ cursor: 'pointer' }}
                />
                <text
                  x={node.x}
                  y={node.y + 35}
                  textAnchor="middle"
                  fill="#fff"
                  fontSize="12"
                  className="node-label"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(node);
                    setSelectedEdge(null);
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  {node.name.length > 20 ? node.name.substring(0, 17) + '...' : node.name}
                </text>
              </g>
            ))}
          </svg>
        </div>

        {selectedNode && (
          <div className="node-details">
            <h3>{selectedNode.name}</h3>
            <p>Type: {selectedNode.type}</p>
            <p>Size: {(selectedNode.size / 1024).toFixed(1)} KB</p>
            <div className="node-actions">
              <button 
                className="open-file-btn"
                onClick={() => handleOpenFile(selectedNode.id)}
                disabled={loadingFile}
              >
                {loadingFile ? 'Loading...' : ' Open File'}
              </button>
              <button onClick={() => setSelectedNode(null)}>Close</button>
            </div>
          </div>
        )}

        {selectedEdge && (
          <div className="edge-details">
            <h3>Relationship Details</h3>
            <div className="edge-info">
              <div className="edge-files">
                <span className="edge-file">
                  {layoutNodes.find(n => n.id === selectedEdge.source)?.name || 'Unknown'}
                </span>
                <span className="edge-arrow">→</span>
                <span className="edge-file">
                  {layoutNodes.find(n => n.id === selectedEdge.target)?.name || 'Unknown'}
                </span>
              </div>
              <div className="edge-type-selector">
                <label>
                  <strong>Relationship Type:</strong>
                  <select
                    value={editingRelationshipType}
                    onChange={(e) => setEditingRelationshipType(e.target.value)}
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
                </label>
                {editingRelationshipType !== selectedEdge.type && (
                  <button
                    className="update-btn"
                    onClick={handleUpdateRelationshipType}
                  >
                     Update Type
                  </button>
                )}
              </div>
              {selectedEdge.label && selectedEdge.label !== selectedEdge.type && (
                <p className="edge-label">
                  <strong>Label:</strong> {selectedEdge.label}
                </p>
              )}
            </div>
            <div className="edge-actions">
              <button 
                className="delete-btn" 
                onClick={() => handleDeleteRelationship(selectedEdge.id)}
              >
                Delete Delete Relationship
              </button>
              <button onClick={() => {
                setSelectedEdge(null);
                setEditingRelationshipType('');
              }}>Close</button>
            </div>
          </div>
        )}

        <div className="graph-legend">
          <div className="legend-section">
            <h4>File Types</h4>
            <div className="legend-items">
              <div className="legend-item">
                <span className="legend-color" style={{ background: '#e74c3c' }}></span>
                <span>PDF</span>
              </div>
              <div className="legend-item">
                <span className="legend-color" style={{ background: '#3498db' }}></span>
                <span>Image</span>
              </div>
              <div className="legend-item">
                <span className="legend-color" style={{ background: '#2ecc71' }}></span>
                <span>Code/Text</span>
              </div>
            </div>
          </div>
          <div className="legend-section">
            <h4>Relationship Types</h4>
            <div className="legend-items">
              {['related', 'depends_on', 'references', 'part_of'].map(type => (
                <div key={type} className="legend-item">
                  <span className="legend-line" style={{ borderColor: getRelationshipColor(type) }}></span>
                  <span>{type.replace('_', ' ')}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {previewFile && (
        <FilePreview
          file={previewFile}
          onClose={() => setPreviewFile(null)}
        />
      )}
    </div>
  );
};

export default RelationshipGraph;


