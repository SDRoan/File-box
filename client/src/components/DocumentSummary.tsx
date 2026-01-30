import React, { useState, useEffect } from 'react';
import { FileItemType } from '../types';
import { summarizationAPI, searchAPI } from '../services/api';
import './DocumentSummary.css';

interface DocumentSummaryProps {
  file: FileItemType;
  onClose?: () => void;
  compact?: boolean;
}

const DocumentSummary: React.FC<DocumentSummaryProps> = ({ file, onClose, compact = false }) => {
  const [summary, setSummary] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [cached, setCached] = useState(false);
  const [model, setModel] = useState<string>('');
  const [extracting, setExtracting] = useState(false);

  useEffect(() => {
    loadSummary();
  }, [file._id]);

  const loadSummary = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await summarizationAPI.getSummary(file._id);
      
      if (data.hasSummary && data.summary) {
        setSummary(data.summary);
        setCached(true);
        setModel(data.model || '');
      } else {
        setSummary(null);
      }
    } catch (err: any) {
      console.error('Error loading summary:', err);
      setError(err.response?.data?.message || 'Failed to load summary');
    } finally {
      setLoading(false);
    }
  };

  const handleExtractText = async () => {
    try {
      setExtracting(true);
      setError(null);
      setLoading(true);
      
      console.log(`[DocumentSummary] Extracting text for file: ${file._id}`);
      const result = await searchAPI.extractText(file._id);
      console.log(`[DocumentSummary] Extraction result:`, result);
      
      if (result.textLength === 0) {
        setError(result.message || 'No text could be extracted from this file. The file may be image-based or corrupted.');
        setLoading(false);
        setExtracting(false);
        return;
      }
      
      // Wait a moment for the database to update
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Reload the summary data to get the extracted text
      await loadSummary();
      
      // Try generating summary again
      await handleGenerateSummary();
    } catch (err: any) {
      console.error('Error extracting text:', err);
      const errorMsg = err.response?.data?.message || 'Failed to extract text';
      const suggestion = err.response?.data?.suggestion;
      setError(suggestion ? `${errorMsg}\n\n ${suggestion}` : errorMsg);
      setLoading(false);
    } finally {
      setExtracting(false);
    }
  };

  const handleGenerateSummary = async () => {
    try {
      setGenerating(true);
      setError(null);
      const data = await summarizationAPI.generateSummary(file._id);
      
      if (data.summary) {
        setSummary(data.summary);
        setCached(data.cached || false);
        setModel(data.model || '');
      } else {
        setError('No summary generated');
      }
    } catch (err: any) {
      console.error('Error generating summary:', err);
      const errorMessage = err.response?.data?.message || 'Failed to generate summary';
      const suggestion = err.response?.data?.suggestion;
      const needsExtraction = errorMessage.includes('No text could be extracted') || 
                              errorMessage.includes('extracted: false');
      
      if (needsExtraction) {
        setError(`${errorMessage}\n\n ${suggestion || 'Try extracting text first.'}`);
      } else {
        setError(suggestion ? `${errorMessage}\n\n ${suggestion}` : errorMessage);
      }
    } finally {
      setGenerating(false);
    }
  };

  const handleRegenerate = async () => {
    try {
      setGenerating(true);
      setError(null);
      const data = await summarizationAPI.generateSummary(file._id, true); // Force regenerate
      
      if (data.summary) {
        setSummary(data.summary);
        setCached(false);
        setModel(data.model || '');
      }
    } catch (err: any) {
      console.error('Error regenerating summary:', err);
      setError(err.response?.data?.message || 'Failed to regenerate summary');
    } finally {
      setGenerating(false);
    }
  };

  if (compact) {
    return (
      <div className="document-summary-compact">
        {loading ? (
          <div className="summary-loading">Loading summary...</div>
        ) : summary ? (
          <div className="summary-content-compact">
            <div className="summary-header-compact">
              <span className="summary-icon"></span>
              <span className="summary-label">Summary</span>
            </div>
            <p className="summary-text-compact">{summary}</p>
            {model && (
              <div className="summary-meta-compact">
                <span className="summary-model">AI: {model}</span>
              </div>
            )}
          </div>
        ) : (
          <button 
            className="generate-summary-btn-compact"
            onClick={handleGenerateSummary}
            disabled={generating}
          >
            {generating ? ' Generating...' : ' Generate Summary'}
          </button>
        )}
        {error && (
          <div className="summary-error-compact">{error}</div>
        )}
      </div>
    );
  }

  return (
    <div className="document-summary-overlay" onClick={onClose}>
      <div className="document-summary-container" onClick={(e) => e.stopPropagation()}>
        <div className="document-summary-header">
          <h2>Document Summary</h2>
          <div className="file-info">
            <span className="file-icon"></span>
            <span className="file-name">{file.originalName}</span>
          </div>
          {onClose && (
            <button className="close-btn" onClick={onClose}>×</button>
          )}
        </div>

        <div className="document-summary-content">
          {loading && !summary && (
            <div className="summary-loading">
              <div className="spinner"></div>
              <p>Loading summary...</p>
            </div>
          )}

          {error && (
            <div className="summary-error">
              <p style={{ whiteSpace: 'pre-line' }}>{error}</p>
              <div className="error-actions">
                {(error.includes('No text could be extracted') || error.includes('extracted: false')) && (
                  <button 
                    onClick={handleExtractText} 
                    className="extract-text-btn"
                    disabled={extracting || loading}
                  >
                    {extracting ? (
                      <>
                        <div className="spinner-small"></div>
                        <span>Extracting...</span>
                      </>
                    ) : (
                      <>
                        <span></span>
                        <span>Extract Text First</span>
                      </>
                    )}
                  </button>
                )}
                <button 
                  onClick={handleGenerateSummary} 
                  className="retry-btn" 
                  disabled={extracting || loading || generating}
                >
                  {generating ? 'Generating...' : 'Try Again'}
                </button>
              </div>
            </div>
          )}

          {!loading && !error && summary && (
            <div className="summary-content">
              <div className="summary-text">{summary}</div>
              {model && (
                <div className="summary-footer">
                  <span className="summary-model">Generated by: {model}</span>
                  {cached && <span className="summary-cached">(Cached)</span>}
                </div>
              )}
              <div className="summary-actions">
                <button onClick={handleRegenerate} className="regenerate-btn" disabled={generating}>
                  {generating ? ' Regenerating...' : ' Regenerate'}
                </button>
                <button 
                  onClick={() => {
                    navigator.clipboard.writeText(summary);
                    alert('Summary copied to clipboard!');
                  }}
                  className="copy-btn"
                >
                   Copy
                </button>
              </div>
            </div>
          )}

          {!loading && !error && !summary && (
            <div className="no-summary">
              <div className="no-summary-icon"></div>
              <p>No summary available</p>
              <p className="hint">Generate an AI-powered summary of this document</p>
              <button 
                className="generate-summary-btn"
                onClick={handleGenerateSummary}
                disabled={generating}
              >
                {generating ? (
                  <>
                    <div className="spinner-small"></div>
                    <span>Generating summary...</span>
                  </>
                ) : (
                  <>
                    <span></span>
                    <span>Generate Summary</span>
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DocumentSummary;

