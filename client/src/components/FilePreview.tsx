import React, { useState, useEffect } from 'react';
import { FileItemType } from '../types';
import { filesAPI, summariesAPI, searchAPI } from '../services/api';
import CodeViewer from './CodeViewer';
import FileMemory from './FileMemory';
import PredictiveOrganization from './PredictiveOrganization';
import FileEditor from './FileEditor';
import { MemoryIcon, DownloadIcon, CloseIcon, EditIcon } from './Icons';
import './FilePreview.css';

interface FilePreviewProps {
  file: FileItemType;
  onClose: () => void;
}

const FilePreview: React.FC<FilePreviewProps> = ({ file, onClose }) => {
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [textContent, setTextContent] = useState<string | null>(null);
  const [showMemory, setShowMemory] = useState(false);
  const [showOrgSuggestions, setShowOrgSuggestions] = useState(true);
  const [showEditor, setShowEditor] = useState(false);

  useEffect(() => {
    loadPreview();
    return () => {
      if (previewUrl && previewUrl.startsWith('blob:')) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [file._id]);


  const loadPreview = async () => {
    try {
      setLoading(true);
      setError(null);

      const mimeType = file.mimeType.toLowerCase();

      // Handle images
      if (mimeType.startsWith('image/')) {
        const blob = await filesAPI.downloadFile(file._id);
        const url = URL.createObjectURL(blob);
        setPreviewUrl(url);
        setLoading(false);
        return;
      }

      // Handle videos
      if (mimeType.startsWith('video/')) {
        const blob = await filesAPI.downloadFile(file._id);
        const url = URL.createObjectURL(blob);
        setPreviewUrl(url);
        setLoading(false);
        return;
      }

      // Handle PDFs
      if (mimeType.includes('pdf')) {
        const blob = await filesAPI.downloadFile(file._id);
        const url = URL.createObjectURL(blob);
        setPreviewUrl(url);
        setLoading(false);
        return;
      }

      // Handle Word documents (DOCX, DOC)
      if (
        mimeType.includes('word') ||
        mimeType.includes('document') ||
        mimeType.includes('msword') ||
        mimeType.includes('vnd.openxmlformats-officedocument.wordprocessingml') ||
        file.originalName.toLowerCase().endsWith('.docx') ||
        file.originalName.toLowerCase().endsWith('.doc')
      ) {
        try {
          // Get extracted text from backend for preview
          const result = await filesAPI.getPreviewText(file._id);
          if (result && result.text && result.text.trim().length > 0) {
            const text = result.text.trim();
            
            // STRICT validation: Check if the text looks like binary/XML data
            // DOCX files are ZIP archives, so they start with "PK" (ZIP signature)
            const firstChars = text.substring(0, 10);
            const hasPK = text.includes('PK') && (text.includes('word/') || text.includes('word\\'));
            const hasXMLTags = (text.match(/<[^>]+>/g)?.length || 0) > 5;
            const hasControlChars = /[\x00-\x08\x0E-\x1F]/.test(text);
            const isMostlyBinary = text.length > 100 && (text.match(/[^\x20-\x7E\n\r\t]/g)?.length || 0) > text.length * 0.3;
            
            // Check for DOCX/ZIP signatures
            if (text.startsWith('PK') || hasPK || (hasXMLTags && text.includes('word/'))) {
              console.warn('[FilePreview] Received binary/XML data instead of extracted text');
              setError('This Word document cannot be previewed as text. Please download the file to view it in Microsoft Word or another compatible application.');
              setLoading(false);
              return;
            }
            
            // Check for control characters or mostly binary content
            if (hasControlChars || isMostlyBinary) {
              console.warn('[FilePreview] Text contains binary or control characters');
              setError('This document contains binary data that cannot be displayed. Please download the file to view it.');
              setLoading(false);
              return;
            }
            
            // Check if text is actually readable (not just XML tags)
            const readableText = text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
            if (readableText.length < text.length * 0.2 && text.length > 50) {
              // Less than 20% readable text means mostly XML tags or binary
              setError('This Word document contains mostly formatting or binary data. Please download the file to view it properly.');
              setLoading(false);
              return;
            }
            
            // Final check: ensure we have actual readable content
            if (readableText.length === 0) {
              setError('No readable text could be extracted from this document. Please download the file to view it.');
              setLoading(false);
              return;
            }
            
            // Use the cleaned readable text instead of raw text
            setTextContent(readableText);
            setLoading(false);
            return;
          } else {
            // No text extracted - show download option
            setError('Text extraction is not available for this document. Please download the file to view it.');
            setLoading(false);
            return;
          }
        } catch (extractError: any) {
          console.error('Error extracting DOCX text:', extractError);
          setError('Preview not available for this file type. Please download the file to view it.');
          setLoading(false);
          return;
        }
      }

      // Handle text files
      if (
        mimeType.startsWith('text/') ||
        mimeType.includes('json') ||
        mimeType.includes('xml') ||
        mimeType.includes('javascript') ||
        mimeType.includes('css') ||
        mimeType.includes('html')
      ) {
        const blob = await filesAPI.downloadFile(file._id);
        const text = await blob.text();
        setTextContent(text);
        setLoading(false);
        return;
      }

      // Unsupported file type
      setError('Preview not available for this file type');
      setLoading(false);
    } catch (err) {
      setError('Failed to load preview');
      setLoading(false);
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
    } catch (error) {
      console.error('Error downloading file:', error);
      alert('Failed to download file');
    }
  };

  const handleMove = async (fileId: string, destinationFolderId: string) => {
    try {
      await filesAPI.moveFile(fileId, destinationFolderId === 'root' ? undefined : destinationFolderId);
      setShowOrgSuggestions(false);
      alert('File moved successfully!');
      // Optionally reload or close preview
    } catch (error) {
      console.error('Error moving file:', error);
      alert('Failed to move file');
    }
  };


  const isCodeFile = (): boolean => {
    const mimeType = file.mimeType.toLowerCase();
    const extension = file.originalName.split('.').pop()?.toLowerCase() || '';
    
    // Code file extensions
    const codeExtensions = [
      'js', 'jsx', 'ts', 'tsx', 'py', 'java', 'cpp', 'c', 'cs', 'php', 'rb', 'go',
      'rs', 'swift', 'kt', 'scala', 'sh', 'bash', 'zsh', 'fish', 'ps1', 'sql',
      'html', 'css', 'scss', 'sass', 'less', 'json', 'xml', 'yaml', 'yml', 'toml',
      'ini', 'md', 'markdown', 'vue', 'svelte', 'r', 'm', 'mm', 'dart', 'lua',
      'pl', 'pm', 'vim', 'dockerfile', 'makefile', 'cmake', 'h', 'hpp', 'cc',
      'cxx', 'mjs', 'jsx', 'tsx', 'coffee', 'litcoffee', 'coffee.md'
    ];
    
    // Code MIME types
    const codeMimeTypes = [
      'text/javascript', 'application/javascript', 'text/x-javascript',
      'application/x-javascript', 'text/typescript', 'application/typescript',
      'text/x-python', 'application/x-python', 'text/x-java', 'text/x-c++',
      'text/x-c', 'text/x-csharp', 'application/x-php', 'text/x-ruby',
      'text/x-go', 'text/x-rust', 'text/x-swift', 'text/x-kotlin',
      'text/x-scala', 'application/x-sh', 'text/x-shellscript', 'text/x-sql',
      'text/css', 'text/x-scss', 'text/x-sass', 'text/x-less',
      'application/json', 'text/xml', 'application/xml', 'text/yaml',
      'application/x-yaml', 'text/x-toml', 'text/x-ini', 'text/markdown',
      'text/x-markdown', 'text/x-vue', 'text/x-svelte', 'text/x-r',
      'text/x-objective-c', 'text/x-dart', 'text/x-lua', 'text/x-perl',
      'text/x-vim', 'text/x-dockerfile', 'text/x-makefile', 'text/x-cmake'
    ];
    
    return codeExtensions.includes(extension) || codeMimeTypes.some(mt => mimeType.includes(mt));
  };

  const isEditableFile = (): boolean => {
    const mimeType = file.mimeType.toLowerCase();
    const extension = file.originalName.split('.').pop()?.toLowerCase() || '';
    
    // PDF files
    if (mimeType.includes('pdf') || extension === 'pdf') {
      return true;
    }
    
    // Word documents (DOCX, DOC)
    if (mimeType.includes('word') || 
        mimeType.includes('document') || 
        mimeType.includes('msword') ||
        mimeType.includes('vnd.openxmlformats-officedocument.wordprocessingml') ||
        extension === 'docx' || extension === 'doc') {
      return true;
    }
    
    // Text files
    if (mimeType.startsWith('text/') || 
        extension === 'txt' || 
        extension === 'md' || 
        extension === 'markdown') {
      return true;
    }
    
    return false;
  };


  const getFileType = () => {
    const mimeType = file.mimeType.toLowerCase();
    const extension = file.originalName.split('.').pop()?.toLowerCase() || '';
    if (mimeType.startsWith('image/')) return 'image';
    if (mimeType.startsWith('video/')) return 'video';
    if (mimeType.includes('pdf')) return 'pdf';
    if (isCodeFile()) return 'code';
    // Word documents
    if (
      mimeType.includes('word') ||
      mimeType.includes('document') ||
      mimeType.includes('msword') ||
      mimeType.includes('vnd.openxmlformats-officedocument.wordprocessingml') ||
      extension === 'docx' ||
      extension === 'doc'
    ) {
      return 'docx';
    }
    if (mimeType.startsWith('text/') || mimeType.includes('json') || mimeType.includes('xml')) return 'text';
    return 'unsupported';
  };

  const fileType = getFileType();

  return (
    <div className="file-preview-overlay" onClick={onClose}>
      <div className="file-preview-container" onClick={(e) => e.stopPropagation()}>
        <div className="file-preview-header">
          <div className="file-preview-title">
            <h3>{file.originalName}</h3>
            <span className="file-preview-size">
              {(file.size / 1024 / 1024).toFixed(2)} MB
            </span>
          </div>
          <div className="file-preview-actions">
            <button 
              onClick={() => setShowMemory(true)} 
              className="preview-action-btn memory-btn"
              title="View File Memory"
            >
              <MemoryIcon size={16} color="#ffffff" />
              <span>Memory</span>
            </button>
            {isEditableFile() && (
              <button 
                onClick={() => setShowEditor(true)} 
                className="preview-action-btn edit-btn"
                title="Edit File"
              >
                <EditIcon size={16} color="#ffffff" />
                <span>Edit</span>
              </button>
            )}
            <button onClick={handleDownload} className="preview-action-btn" title="Download File">
              <DownloadIcon size={16} color="#ffffff" />
              <span>Download</span>
            </button>
            <button onClick={onClose} className="preview-close-btn" title="Close Preview">
              <CloseIcon size={18} color="#ffffff" />
            </button>
          </div>
        </div>

        <div className="file-preview-content">
          {showOrgSuggestions && !loading && (
            <PredictiveOrganization
              fileId={file._id}
              fileName={file.originalName}
              fileType={file.mimeType}
              onMove={handleMove}
              onDismiss={() => setShowOrgSuggestions(false)}
            />
          )}
          {loading && (
            <div className="preview-loading">
              <div className="spinner"></div>
              <p>Loading preview...</p>
            </div>
          )}

          {error && (
            <div className="preview-error">
              <p>{error}</p>
              <button onClick={handleDownload} className="preview-download-btn">
                Download File Instead
              </button>
            </div>
          )}

          {!loading && !error && fileType === 'image' && previewUrl && (
            <img src={previewUrl} alt={file.originalName} className="preview-image" />
          )}

          {!loading && !error && fileType === 'video' && previewUrl && (
            <video src={previewUrl} controls className="preview-video">
              Your browser does not support the video tag.
            </video>
          )}

          {!loading && !error && fileType === 'pdf' && previewUrl && (
            <iframe
              src={previewUrl}
              className="preview-pdf"
              title={file.originalName}
              style={{
                width: '100%',
                height: '100%',
                border: 'none'
              }}
            />
          )}

          {!loading && !error && fileType === 'code' && textContent && (
            <CodeViewer
              code={textContent}
              filename={file.originalName}
            />
          )}

          {!loading && !error && fileType === 'text' && textContent && (
            <pre className="preview-text">
              <code>{textContent}</code>
            </pre>
          )}
          
          {!loading && !error && fileType === 'docx' && textContent && (
            <div className="preview-text-container">
              <div className="preview-docx-header">
                <h4>Document Preview</h4>
                <p className="preview-note">This is a text-only preview. Download the file to see formatting, images, and other elements.</p>
              </div>
              <pre className="preview-text preview-docx">
                <code>{textContent}</code>
              </pre>
            </div>
          )}

          {!loading && !error && fileType === 'unsupported' && (
            <div className="preview-unsupported">
              <div className="unsupported-icon"></div>
              <p>Preview not available for this file type</p>
              <button onClick={handleDownload} className="preview-download-btn">
                Download File
              </button>
            </div>
          )}
        </div>
      </div>
      {showEditor && (
        <FileEditor 
          file={file} 
          onClose={() => setShowEditor(false)} 
          onSave={() => {
            setShowEditor(false);
            loadPreview(); // Reload preview after save
          }}
        />
      )}
      {showMemory && (
        <FileMemory fileId={file._id} onClose={() => setShowMemory(false)} />
      )}
    </div>
  );
};

export default FilePreview;

