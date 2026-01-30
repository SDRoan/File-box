import React, { useState, useEffect } from 'react';
import { smartOrgAPI } from '../services/api';
import { filesAPI } from '../services/api';
import './SmartOrganization.css';

interface SmartOrganizationProps {
  folderId?: string;
  onClose: () => void;
  onOrganized?: () => void;
}

interface FileSuggestion {
  fileId: string;
  fileName: string;
  suggestedFolder: string;
  category: string;
  tags: string[];
  confidence: number;
  reasoning: string;
}

interface FolderGroup {
  [folderName: string]: FileSuggestion[];
}

interface SuggestionsResult {
  suggestions: FileSuggestion[];
  folderGroups: FolderGroup;
  totalFiles: number;
}

const SmartOrganization: React.FC<SmartOrganizationProps> = ({
  folderId,
  onClose,
  onOrganized
}) => {
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [suggestions, setSuggestions] = useState<SuggestionsResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [organizing, setOrganizing] = useState<string | null>(null);

  useEffect(() => {
    loadSuggestions();
  }, [folderId]);

  const loadSuggestions = async () => {
    setAnalyzing(true);
    setError(null);
    try {
      const result = await smartOrgAPI.getSuggestions(folderId);
      setSuggestions(result);
    } catch (err: any) {
      console.error('Error loading suggestions:', err);
      setError(err.response?.data?.message || 'Failed to load suggestions');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleOrganize = async (folderName: string, fileIds: string[]) => {
    setOrganizing(folderName);
    try {
      await smartOrgAPI.organizeFiles(folderName, fileIds, folderId);
      if (onOrganized) {
        onOrganized();
      }
      // Reload suggestions
      await loadSuggestions();
      alert(` Organized ${fileIds.length} files into "${folderName}"`);
    } catch (err: any) {
      console.error('Error organizing files:', err);
      alert(err.response?.data?.message || 'Failed to organize files');
    } finally {
      setOrganizing(null);
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.7) return '#2ecc71'; // Green
    if (confidence >= 0.5) return '#f39c12'; // Orange
    return '#e74c3c'; // Red
  };

  if (analyzing) {
    return (
      <div className="smart-org-overlay" onClick={onClose}>
        <div className="smart-org-container" onClick={(e) => e.stopPropagation()}>
          <div className="smart-org-header">
            <h2>֎ Smart Organization</h2>
            <button onClick={onClose} className="close-btn">×</button>
          </div>
          <div className="smart-org-content">
            <div className="analyzing-state">
              <div className="spinner"></div>
              <p>Analyzing your files...</p>
              <p className="hint">This may take a few moments</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="smart-org-overlay" onClick={onClose}>
      <div className="smart-org-container" onClick={(e) => e.stopPropagation()}>
        <div className="smart-org-header">
          <h2>֎ Smart Organization</h2>
          <button onClick={onClose} className="close-btn">×</button>
        </div>
        <div className="smart-org-content">
          {error ? (
            <div className="error-message">
              <p>{error}</p>
              <button onClick={loadSuggestions} className="retry-btn">
                Try Again
              </button>
            </div>
          ) : suggestions && suggestions.totalFiles > 0 ? (
            <>
              <div className="suggestions-summary">
                <p>
                  Found <strong>{suggestions.totalFiles}</strong> files to organize into{' '}
                  <strong>{Object.keys(suggestions.folderGroups).length}</strong> folders
                </p>
                <button onClick={loadSuggestions} className="refresh-btn" disabled={analyzing}>
                   Refresh
                </button>
              </div>

              <div className="folder-groups">
                {Object.entries(suggestions.folderGroups).map(([folderName, files]) => (
                  <div key={folderName} className="folder-group">
                    <div className="folder-group-header">
                      <h3> {folderName}</h3>
                      <span className="file-count">{files.length} file{files.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div className="files-list">
                      {files.map((file) => (
                        <div key={file.fileId} className="file-suggestion">
                          <span className="file-name">{file.fileName}</span>
                          <div className="file-meta">
                            {file.tags.length > 0 && (
                              <span className="tags">
                                {file.tags.map(tag => (
                                  <span key={tag} className="tag">{tag}</span>
                                ))}
                              </span>
                            )}
                            <span
                              className="confidence"
                              style={{ color: getConfidenceColor(file.confidence) }}
                            >
                              {Math.round(file.confidence * 100)}% match
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                    <button
                      onClick={() => handleOrganize(folderName, files.map(f => f.fileId))}
                      className="organize-btn"
                      disabled={organizing === folderName}
                    >
                      {organizing === folderName ? (
                        <>
                          <div className="spinner-small"></div>
                          Organizing...
                        </>
                      ) : (
                        ` Organize ${files.length} file${files.length !== 1 ? 's' : ''}`
                      )}
                    </button>
                  </div>
                ))}
              </div>

              <div className="bulk-actions">
                <button
                  onClick={async () => {
                    const allFileIds = suggestions.suggestions.map(s => s.fileId);
                    const folderNames = Object.keys(suggestions.folderGroups);
                    for (const folderName of folderNames) {
                      const fileIds = suggestions.folderGroups[folderName].map(f => f.fileId);
                      await handleOrganize(folderName, fileIds);
                    }
                  }}
                  className="organize-all-btn"
                  disabled={organizing !== null}
                >
                  {organizing ? 'Organizing...' : ' Organize All'}
                </button>
              </div>
            </>
          ) : (
            <div className="no-suggestions">
              <div className="no-suggestions-icon"></div>
              <p>All files are already organized!</p>
              <p className="hint">Upload more files to get organization suggestions</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SmartOrganization;


