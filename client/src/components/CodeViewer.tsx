import React, { useState, useRef, useEffect } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import './CodeViewer.css';

interface CodeViewerProps {
  code: string;
  language?: string;
  filename: string;
}

const CodeViewer: React.FC<CodeViewerProps> = ({ code, language, filename }) => {
  const [detectedLanguage, setDetectedLanguage] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<number[]>([]);
  const [currentResultIndex, setCurrentResultIndex] = useState(-1);
  const [showSearch, setShowSearch] = useState(false);
  const [copied, setCopied] = useState(false);
  const codeRef = useRef<HTMLDivElement>(null);

  // Detect language from filename if not provided
  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl+F or Cmd+F to open search
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        setShowSearch(true);
      }
      // Escape to close search
      if (e.key === 'Escape' && showSearch) {
        setShowSearch(false);
        setSearchQuery('');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showSearch]);

  useEffect(() => {
    if (language) {
      setDetectedLanguage(language);
      return;
    }

    const extension = filename.split('.').pop()?.toLowerCase() || '';
    const langMap: { [key: string]: string } = {
      'js': 'javascript',
      'jsx': 'jsx',
      'ts': 'typescript',
      'tsx': 'tsx',
      'py': 'python',
      'java': 'java',
      'cpp': 'cpp',
      'c': 'c',
      'cs': 'csharp',
      'php': 'php',
      'rb': 'ruby',
      'go': 'go',
      'rs': 'rust',
      'swift': 'swift',
      'kt': 'kotlin',
      'scala': 'scala',
      'sh': 'bash',
      'bash': 'bash',
      'zsh': 'bash',
      'fish': 'bash',
      'ps1': 'powershell',
      'sql': 'sql',
      'html': 'html',
      'css': 'css',
      'scss': 'scss',
      'sass': 'sass',
      'less': 'less',
      'json': 'json',
      'xml': 'xml',
      'yaml': 'yaml',
      'yml': 'yaml',
      'toml': 'toml',
      'ini': 'ini',
      'md': 'markdown',
      'markdown': 'markdown',
      'vue': 'vue',
      'svelte': 'svelte',
      'r': 'r',
      'R': 'r',
      'm': 'objectivec',
      'mm': 'objectivec',
      'dart': 'dart',
      'lua': 'lua',
      'pl': 'perl',
      'pm': 'perl',
      'vim': 'vim',
      'dockerfile': 'dockerfile',
      'makefile': 'makefile',
      'cmake': 'cmake',
    };

    setDetectedLanguage(langMap[extension] || 'text');
  }, [filename, language]);

  // Search functionality
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      setCurrentResultIndex(-1);
      return;
    }

    const lines = code.split('\n');
    const results: number[] = [];
    const query = searchQuery.toLowerCase();

    lines.forEach((line, index) => {
      if (line.toLowerCase().includes(query)) {
        results.push(index);
      }
    });

    setSearchResults(results);
    setCurrentResultIndex(results.length > 0 ? 0 : -1);
  }, [searchQuery, code]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const scrollToLine = (lineNumber: number) => {
    const lineElement = document.querySelector(`[data-line-number="${lineNumber + 1}"]`);
    if (lineElement) {
      lineElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      // Highlight the line temporarily
      lineElement.classList.add('highlight-line');
      setTimeout(() => {
        lineElement.classList.remove('highlight-line');
      }, 2000);
    }
  };

  const handleNextResult = () => {
    if (searchResults.length === 0) return;
    const nextIndex = (currentResultIndex + 1) % searchResults.length;
    setCurrentResultIndex(nextIndex);
    scrollToLine(searchResults[nextIndex]);
  };

  const handlePrevResult = () => {
    if (searchResults.length === 0) return;
    const prevIndex = (currentResultIndex - 1 + searchResults.length) % searchResults.length;
    setCurrentResultIndex(prevIndex);
    scrollToLine(searchResults[prevIndex]);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && e.shiftKey) {
      e.preventDefault();
      handlePrevResult();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      handleNextResult();
    } else if (e.key === 'Escape') {
      setShowSearch(false);
      setSearchQuery('');
    }
  };

  // Copy single line
  const copyLine = (lineNumber: number) => {
    const lines = code.split('\n');
    const lineText = lines[lineNumber - 1] || '';
    navigator.clipboard.writeText(lineText).catch(console.error);
  };

  return (
    <div className="code-viewer">
      <div className="code-viewer-toolbar">
        <div className="code-viewer-info">
          <span className="code-language-badge">{detectedLanguage || 'text'}</span>
          <span className="code-lines-count">{code.split('\n').length} lines</span>
        </div>
        <div className="code-viewer-actions">
          <button
            className="code-action-btn"
            onClick={() => setShowSearch(!showSearch)}
            title="Search (Ctrl+F)"
          >
             Search
          </button>
          <button
            className="code-action-btn"
            onClick={handleCopy}
            title="Copy code"
          >
            {copied ? ' Copied!' : ' Copy'}
          </button>
        </div>
      </div>

      {showSearch && (
        <div className="code-search-bar">
          <input
            type="text"
            placeholder="Search in file..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="code-search-input"
            autoFocus
          />
          {searchResults.length > 0 && (
            <div className="code-search-results">
              <span>
                {currentResultIndex + 1} / {searchResults.length}
              </span>
              <button onClick={handlePrevResult} className="code-search-nav">↑</button>
              <button onClick={handleNextResult} className="code-search-nav">↓</button>
            </div>
          )}
          {searchQuery && searchResults.length === 0 && (
            <span className="code-search-no-results">No results</span>
          )}
        </div>
      )}

      <div className="code-viewer-content" ref={codeRef}>
        <SyntaxHighlighter
          language={detectedLanguage}
          style={vscDarkPlus}
          showLineNumbers
          customStyle={{
            margin: 0,
            padding: '1rem',
            borderRadius: '0',
            fontSize: '14px',
            lineHeight: '1.6',
            height: '100%',
          }}
          lineNumberStyle={{
            minWidth: '3em',
            paddingRight: '1em',
            color: '#858585',
            userSelect: 'none',
            cursor: 'pointer',
          }}
          lineProps={(lineNumber) => {
            const isMatch = searchResults.includes(lineNumber - 1);
            const isCurrent = currentResultIndex >= 0 && searchResults[currentResultIndex] === lineNumber - 1;
            return {
              'data-line-number': lineNumber,
              className: isCurrent ? 'current-match-line' : (isMatch ? 'search-match-line' : ''),
              onClick: () => copyLine(lineNumber),
            };
          }}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    </div>
  );
};

export default CodeViewer;

