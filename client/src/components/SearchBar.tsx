import React, { useState, useEffect, useRef } from 'react';
import { FileItemType, Folder } from '../types';
import { searchAPI } from '../services/api';
import './SearchBar.css';

interface SearchBarProps {
  onFileClick: (file: FileItemType) => void;
  onFolderClick: (folderId: string) => void;
}

const SearchBar: React.FC<SearchBarProps> = ({ onFileClick, onFolderClick }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<{ files: FileItemType[]; folders: Folder[] }>({ files: [], folders: [] });
  const [loading, setLoading] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Keyboard shortcut: Ctrl+K or Cmd+K to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
      if (e.key === 'Escape' && showResults) {
        setShowResults(false);
        setQuery('');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showResults]);

  useEffect(() => {
    if (query.trim().length === 0) {
      setResults({ files: [], folders: [] });
      setShowResults(false);
      return;
    }

    const searchFiles = async () => {
      setLoading(true);
      try {
        // Use AI-powered semantic search
        const searchData = await searchAPI.aiSearch(query);
        
        setResults({
          files: searchData.files || [],
          folders: searchData.folders || [],
        });
        setShowResults(true);
      } catch (error) {
        console.error('Search error:', error);
        // Fallback to empty results on error
        setResults({ files: [], folders: [] });
        setShowResults(true);
      } finally {
        setLoading(false);
      }
    };

    const debounceTimer = setTimeout(searchFiles, 300);
    return () => clearTimeout(debounceTimer);
  }, [query]);

  const handleFileClick = (file: FileItemType) => {
    onFileClick(file);
    setQuery('');
    setShowResults(false);
  };

  const handleFolderClick = (folder: Folder) => {
    onFolderClick(folder._id);
    setQuery('');
    setShowResults(false);
  };

  return (
    <div className="search-bar-container">
      <div className="search-input-wrapper">
        <input
          ref={inputRef}
          type="text"
          placeholder="Search files and folders..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => query.trim().length > 0 && setShowResults(true)}
          className="search-input"
        />
        <span className="search-icon"></span>
        <div className="search-shortcut-hint">
          <kbd>⌘</kbd><kbd>K</kbd>
        </div>
      </div>

      {showResults && (results.files.length > 0 || results.folders.length > 0 || loading) && (
        <div className="search-results">
          {loading && (
            <div className="search-loading">Searching...</div>
          )}

          {!loading && results.folders.length > 0 && (
            <div className="search-section">
              <div className="search-section-title">Folders</div>
              {results.folders.map((folder) => (
                <div
                  key={folder._id}
                  className="search-result-item"
                  onClick={() => handleFolderClick(folder)}
                >
                  <span className="result-icon"></span>
                  <span className="result-name">{folder.name}</span>
                </div>
              ))}
            </div>
          )}

          {!loading && results.files.length > 0 && (
            <div className="search-section">
              <div className="search-section-title">
                Files
              </div>
              {results.files.map((file) => (
                <div
                  key={file._id}
                  className="search-result-item"
                  onClick={() => handleFileClick(file)}
                >
                  <span className="result-icon">
                    {file.mimeType.startsWith('image/') ? '' :
                     file.mimeType.startsWith('video/') ? 'Video' :
                     file.mimeType.includes('pdf') ? '' : ''}
                  </span>
                  <span className="result-name">{file.originalName}</span>
                  <span className="result-meta">
                    {(file.size / 1024).toFixed(1)} KB
                  </span>
                </div>
              ))}
            </div>
          )}

          {!loading && results.files.length === 0 && results.folders.length === 0 && query.trim().length > 0 && (
            <div className="search-no-results">No results found</div>
          )}
        </div>
      )}
    </div>
  );
};

export default SearchBar;

