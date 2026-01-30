import React, { useState, useEffect, useRef } from 'react';
import { FileItemType } from '../types';
import { filesAPI } from '../services/api';
import { EditIcon, SaveIcon, CloseIcon, LoadingIcon, DownloadIcon } from './Icons';
import './FileEditor.css';

interface FileEditorProps {
  file: FileItemType;
  onClose: () => void;
  onSave?: () => void;
}

const getFileType = (file: FileItemType): 'pdf' | 'docx' | 'txt' => {
    const mimeType = file.mimeType.toLowerCase();
    const extension = file.originalName.split('.').pop()?.toLowerCase() || '';
    
    if (mimeType.includes('pdf') || extension === 'pdf') return 'pdf';
    if (
      mimeType.includes('word') ||
      mimeType.includes('document') ||
      mimeType.includes('msword') ||
      mimeType.includes('vnd.openxmlformats-officedocument.wordprocessingml') ||
      extension === 'docx' ||
      extension === 'doc'
    ) return 'docx';
    return 'txt';
  };

const FileEditor: React.FC<FileEditorProps> = ({ file, onClose, onSave }) => {
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);
  const [originalContent, setOriginalContent] = useState<string>('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileType = getFileType(file);

  useEffect(() => {
    loadFileContent();
  }, [file._id]);

  const loadFileContent = async () => {
    try {
      setLoading(true);
      setError(null);

      if (fileType === 'txt') {
        // For TXT files, get the text content directly
        const blob = await filesAPI.downloadFile(file._id);
        const text = await blob.text();
        setContent(text);
        setOriginalContent(text);
      } else if (fileType === 'docx') {
        // For DOCX files, get extracted text
        const result = await filesAPI.getPreviewText(file._id);
        setContent(result.text || '');
        setOriginalContent(result.text || '');
      } else if (fileType === 'pdf') {
        // For PDFs, we'll extract text for editing
        // Note: PDF editing is complex, so we'll provide text extraction and re-creation
        const result = await filesAPI.getPreviewText(file._id);
        setContent(result.text || '');
        setOriginalContent(result.text || '');
      }
    } catch (err: any) {
      console.error('Error loading file content:', err);
      setError(err.response?.data?.message || 'Failed to load file content');
    } finally {
      setLoading(false);
    }
  };

  const handleContentChange = (newContent: string) => {
    setContent(newContent);
    setHasChanges(newContent !== originalContent);
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);

      if (fileType === 'txt') {
        // Save TXT file
        const blob = new Blob([content], { type: 'text/plain' });
        await filesAPI.updateFile(file._id, blob, file.originalName);
      } else if (fileType === 'docx') {
        // Save DOCX file - convert text to DOCX format
        await filesAPI.updateFileAsDocx(file._id, content, file.originalName);
      } else if (fileType === 'pdf') {
        // Save PDF file - convert text to PDF format
        await filesAPI.updateFileAsPdf(file._id, content, file.originalName);
      }

      setHasChanges(false);
      setOriginalContent(content);
      alert('File saved successfully!');
      onSave?.();
    } catch (err: any) {
      console.error('Error saving file:', err);
      setError(err.response?.data?.message || 'Failed to save file');
      alert('Failed to save file: ' + (err.response?.data?.message || err.message));
    } finally {
      setSaving(false);
    }
  };

  const handleDownload = async () => {
    try {
      const blob = await filesAPI.downloadFile(file._id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.originalName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      alert('Failed to download file');
    }
  };

  if (loading) {
    return (
      <div className="file-editor-overlay">
        <div className="file-editor-container">
          <div className="editor-loading">
            <LoadingIcon size={32} color="#6b7280" />
            <p>Loading file...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error && !content) {
    return (
      <div className="file-editor-overlay">
        <div className="file-editor-container">
          <div className="editor-error">
            <p>Error: {error}</p>
            <button onClick={onClose} className="editor-btn secondary">
              <CloseIcon size={16} color="currentColor" /> Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="file-editor-overlay" onClick={onClose}>
      <div className="file-editor-container" onClick={(e) => e.stopPropagation()}>
        <div className="file-editor-header">
          <div className="editor-title">
            <EditIcon size={20} color="currentColor" />
            <h3>Editing: {file.originalName}</h3>
            {hasChanges && <span className="unsaved-indicator">• Unsaved changes</span>}
          </div>
          <div className="editor-actions">
            <button
              onClick={handleDownload}
              className="editor-btn secondary"
              title="Download original"
            >
              <DownloadIcon size={16} color="currentColor" /> Download
            </button>
            <button
              onClick={handleSave}
              disabled={!hasChanges || saving}
              className="editor-btn primary"
              title="Save changes"
            >
              {saving ? (
                <>
                  <LoadingIcon size={16} color="currentColor" /> Saving...
                </>
              ) : (
                <>
                  <SaveIcon size={16} color="currentColor" /> Save
                </>
              )}
            </button>
            <button
              onClick={onClose}
              className="editor-btn close-btn"
              title="Close editor"
              disabled={saving}
            >
              <CloseIcon size={16} color="currentColor" />
            </button>
          </div>
        </div>

        {error && (
          <div className="editor-error-banner">
            <p>{error}</p>
          </div>
        )}

        <div className="file-editor-content">
          {fileType === 'pdf' && (
            <div className="pdf-editor-info">
              <p>
                <strong>PDF Editing Mode:</strong> You can edit the extracted text below. 
                When you save, a new PDF will be created with your changes.
              </p>
            </div>
          )}
          {fileType === 'docx' && (
            <div className="docx-editor-info">
              <p>
                <strong>DOCX Editing Mode:</strong> You can edit the document text below. 
                When you save, the document will be updated with your changes.
              </p>
            </div>
          )}
          <textarea
            ref={textareaRef}
            value={content}
            onChange={(e) => handleContentChange(e.target.value)}
            className="editor-textarea"
            placeholder="Start editing..."
            spellCheck={true}
          />
        </div>

        <div className="file-editor-footer">
          <div className="editor-stats">
            <span>Characters: {content.length}</span>
            <span>Words: {content.split(/\s+/).filter(w => w.length > 0).length}</span>
            <span>Lines: {content.split('\n').length}</span>
          </div>
          {hasChanges && (
            <div className="editor-warning">
              You have unsaved changes. Don't forget to save!
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default FileEditor;

