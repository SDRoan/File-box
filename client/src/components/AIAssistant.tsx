import React, { useState, useRef, useEffect } from 'react';
import { aiAssistantAPI, filesAPI } from '../services/api';
import { FileItemType } from '../types';
import { AIAssistantIcon, UploadIcon, DocumentIcon, LoadingIcon, CheckIcon, CloseIcon, ArrowRightIcon } from './Icons';
import './AIAssistant.css';

interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  fileId?: string;
  uploadedFiles?: FileItemType[];
  action?: {
    type: string;
    success: boolean;
    data?: any;
    error?: string;
  };
}

interface UploadedFile {
  id: string;
  file: File;
  uploading: boolean;
  uploaded?: FileItemType;
  error?: string;
}

const AIAssistant: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      type: 'assistant',
      content: "Hi! I'm your AI assistant for File Box - think of me as ChatGPT for your File Box platform!\n\nI can answer **ANY question** about how to use File Box, including:\n- How to create relationships between files\n- How to share files with other users\n- How to use study groups and all their features\n- How to navigate and use any feature\n- How to organize your files\n- And much more!\n\nI can also **read and summarize your files** - just ask me to summarize any file, or select a file below.\n\n**What would you like to know?**",
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [availableFiles, setAvailableFiles] = useState<FileItemType[]>([]);
  const [fileSearchQuery, setFileSearchQuery] = useState('');
  const [showFileSelector, setShowFileSelector] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  const MAX_UPLOAD_FILES = 10;

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    loadAvailableFiles();
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadAvailableFiles = async () => {
    try {
      const data = await filesAPI.getFiles();
      // Filter to only show files (not folders) and supported file types
      const supportedTypes = ['pdf', 'doc', 'docx', 'txt', 'md', 'rtf', 'odt'];
      const files = (data.files || []).filter((file: FileItemType) => 
        !file.isFolder && 
        supportedTypes.some(type => file.originalName.toLowerCase().endsWith(`.${type}`))
      );
      setAvailableFiles(files);
    } catch (error) {
      console.error('Error loading files:', error);
    }
  };

  const handleFileUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    const filesArray = Array.from(files);
    
    // Check if adding these files would exceed the limit
    if (uploadedFiles.length + filesArray.length > MAX_UPLOAD_FILES) {
      alert(`You can upload a maximum of ${MAX_UPLOAD_FILES} files. You currently have ${uploadedFiles.length} file(s) uploaded.`);
      return;
    }

    // Create upload file objects
    const newUploads: UploadedFile[] = filesArray.map(file => ({
      id: Date.now().toString() + Math.random().toString(),
      file,
      uploading: true
    }));

    setUploadedFiles(prev => [...prev, ...newUploads]);

    // Upload files
    for (let i = 0; i < newUploads.length; i++) {
      const upload = newUploads[i];
      try {
        const uploadedFile = await filesAPI.uploadFile(upload.file);
        
        setUploadedFiles(prev => prev.map(u => 
          u.id === upload.id 
            ? { ...u, uploading: false, uploaded: uploadedFile }
            : u
        ));

        // Reload available files first
        await loadAvailableFiles();

        // Add message showing file was uploaded
        const uploadMessage: Message = {
          id: `upload-${upload.id}`,
          type: 'user',
          content: `Uploaded: ${upload.file.name}`,
          timestamp: new Date(),
          uploadedFiles: [uploadedFile]
        };
        setMessages(prev => [...prev, uploadMessage]);
        
        // Add assistant confirmation message
        const confirmMessage: Message = {
          id: `confirm-${upload.id}`,
          type: 'assistant',
          content: `File "${upload.file.name}" has been uploaded successfully! You can now ask me to create relationships with it, summarize it, or perform other actions.`,
          timestamp: new Date()
        };
        setTimeout(() => {
          setMessages(prev => [...prev, confirmMessage]);
        }, 500);
      } catch (error: any) {
        console.error('Error uploading file:', error);
        setUploadedFiles(prev => prev.map(u => 
          u.id === upload.id 
            ? { ...u, uploading: false, error: error.message || 'Upload failed' }
            : u
        ));
      }
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files) {
      handleFileUpload(files);
    }
    // Reset input so same file can be selected again
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removeUploadedFile = (id: string) => {
    setUploadedFiles(prev => prev.filter(u => u.id !== id));
  };

  const handleSend = async () => {
    if (!input.trim() || loading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      type: 'user',
      content: input,
      timestamp: new Date(),
      fileId: selectedFileId || undefined
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      const response = await aiAssistantAPI.chat(
        input,
        selectedFileId || undefined,
        `User is asking about files. Previous context: ${messages.slice(-3).map(m => m.content).join(' ')}`
      );

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: response.answer,
        timestamp: new Date(response.timestamp),
        fileId: response.fileId || undefined,
        action: response.action || undefined
      };

      setMessages(prev => [...prev, assistantMessage]);
      
      // If an action was performed successfully, refresh file list
      if (response.action && response.action.success) {
        // Reload available files to reflect changes
        setTimeout(() => {
          loadAvailableFiles();
        }, 500);
      }
    } catch (error: any) {
      console.error('AI Assistant error:', error);
      
      // Handle different error formats - backend returns errors in 'answer' field
      let errorContent = 'Sorry, I encountered an error. ';
      
      if (error.response?.data?.answer) {
        // Backend returned formatted error message in answer field
        errorContent = error.response.data.answer;
      } else if (error.response?.data?.message) {
        // Backend returned error message
        errorContent = error.response.data.message;
      } else if (error.message) {
        // Network or other error
        errorContent += error.message;
      } else {
        errorContent += 'Please try again or check your connection.';
      }
      
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: errorContent,
        timestamp: new Date(),
        action: undefined
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const suggestedQuestions = [
    "How do I create a relationship between two files?",
    "How do I share a file with another user?",
    "How do I create a study group?",
    "How do I upload files?",
    "What features does File Box have?",
    "How do I use the relationship graph?"
  ];

  const filteredFiles = availableFiles.filter(file =>
    file.originalName.toLowerCase().includes(fileSearchQuery.toLowerCase())
  ).slice(0, 10);

  return (
    <div className="ai-assistant-container">
      <div className="ai-assistant-header">
        <h2>AI Assistant</h2>
        <p>Ask me anything or upload files to get started</p>
        
        {/* Simplified File Actions */}
        <div className="file-actions">
          <button 
            className="action-btn upload-btn"
            onClick={() => fileInputRef.current?.click()}
            disabled={uploadedFiles.length >= MAX_UPLOAD_FILES}
          >
            <UploadIcon size={16} color="#ffffff" />
            <span>Upload ({uploadedFiles.length}/{MAX_UPLOAD_FILES})</span>
          </button>
          <button 
            className="action-btn select-btn"
            onClick={() => setShowFileSelector(!showFileSelector)}
          >
            <DocumentIcon size={16} color="#ffffff" />
            <span>Select File</span>
          </button>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            style={{ display: 'none' }}
            onChange={handleFileInputChange}
          />
        </div>

        {/* Uploaded Files - Simplified */}
        {uploadedFiles.length > 0 && (
          <div className="uploaded-files-mini">
            {uploadedFiles.map(upload => (
              <div key={upload.id} className="upload-mini-item">
                {upload.uploading ? (
                  <LoadingIcon size={16} color="currentColor" />
                ) : upload.error ? (
                  <CloseIcon size={16} color="#ef4444" />
                ) : (
                  <CheckIcon size={16} color="#10b981" />
                )}
                <span>{upload.file.name}</span>
                {!upload.uploading && (
                  <button onClick={() => removeUploadedFile(upload.id)}>
                    <CloseIcon size={14} color="currentColor" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        {/* File Selector Dropdown */}
        {showFileSelector && (
          <div className="file-selector-dropdown">
            <input
              type="text"
              placeholder="Search files..."
              value={fileSearchQuery}
              onChange={(e) => setFileSearchQuery(e.target.value)}
              className="file-search-input"
            />
            <div className="file-list">
              {filteredFiles.length > 0 ? (
                filteredFiles.map(file => (
                  <div
                    key={file._id}
                    className={`file-item ${selectedFileId === file._id ? 'selected' : ''}`}
                    onClick={() => {
                      setSelectedFileId(file._id);
                      setShowFileSelector(false);
                      setFileSearchQuery('');
                    }}
                  >
                    <span className="file-name">{file.originalName}</span>
                  </div>
                ))
              ) : (
                <div className="no-files">No files found</div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="ai-assistant-messages">
        {messages.map((message) => (
          <div key={message.id} className={`message message-${message.type}`}>
            <div className="message-content">
              {message.type === 'assistant' && (
                <span className="message-avatar">
                  <AIAssistantIcon size={24} color="#6b7280" />
                </span>
              )}
              <div className="message-text">
                <div 
                  dangerouslySetInnerHTML={{ 
                    __html: message.content.replace(/\n/g, '<br />').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                  }} 
                />
                {message.uploadedFiles && message.uploadedFiles.length > 0 && (
                  <div className="uploaded-files-in-message">
                    {message.uploadedFiles.map(file => (
                      <div key={file._id} className="file-chip">
                        <DocumentIcon size={16} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
                        {file.originalName}
                      </div>
                    ))}
                  </div>
                )}
                {message.action && message.action.success && (
                  <div className="action-success-badge">
                    <CheckIcon size={14} color="#10b981" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
                    Action completed
                  </div>
                )}
                <span className="message-time">
                  {message.timestamp.toLocaleTimeString()}
                </span>
              </div>
            </div>
          </div>
        ))}
        {loading && (
          <div className="message message-assistant">
            <div className="message-content">
              <span className="message-avatar">
                <AIAssistantIcon size={24} color="#6b7280" />
              </span>
              <div className="message-text">
                <div className="typing-indicator">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {messages.length === 1 && (
        <div className="suggested-questions">
          <div className="suggestions-grid">
            {suggestedQuestions.slice(0, 4).map((q, i) => (
              <button
                key={i}
                className="suggestion-btn"
                onClick={() => {
                  setInput(q);
                  setTimeout(() => handleSend(), 100);
                }}
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="ai-assistant-input">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Ask me anything about your files..."
          disabled={loading}
        />
        <button onClick={handleSend} disabled={loading || !input.trim()}>
          {loading ? (
            <LoadingIcon size={16} color="currentColor" />
          ) : (
            <ArrowRightIcon size={16} color="currentColor" />
          )}
        </button>
      </div>
    </div>
  );
};

export default AIAssistant;

