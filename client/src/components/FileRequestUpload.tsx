import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { fileRequestsAPI } from '../services/api';
import './FileRequestUpload.css';

const FileRequestUpload: React.FC = () => {
  const { requestId } = useParams<{ requestId: string }>();
  const [request, setRequest] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(false);

  useEffect(() => {
    if (requestId) {
      loadRequest();
    }
  }, [requestId]);

  const loadRequest = async () => {
    try {
      setLoading(true);
      const data = await fileRequestsAPI.getFileRequest(requestId!);
      setRequest(data);
    } catch (error: any) {
      console.error('Error loading request:', error);
      alert(error.response?.data?.message || 'File request not found');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !requestId) return;

    setUploading(true);
    try {
      await fileRequestsAPI.uploadToRequest(requestId, file);
      setUploadSuccess(true);
      setTimeout(() => {
        loadRequest();
        setUploadSuccess(false);
      }, 2000);
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to upload file');
    } finally {
      setUploading(false);
      if (e.target) {
        e.target.value = '';
      }
    }
  };

  if (loading) {
    return (
      <div className="file-request-upload-page">
        <div className="loading">Loading file request...</div>
      </div>
    );
  }

  if (!request) {
    return (
      <div className="file-request-upload-page">
        <div className="error-message">File request not found</div>
      </div>
    );
  }

  const isExpired = request.expiresAt && new Date() > new Date(request.expiresAt);
  const isClosed = request.status === 'closed';

  return (
    <div className="file-request-upload-page">
      <div className="upload-container">
        <h1>File Request</h1>
        <h2>{request.title}</h2>
        {request.description && <p className="request-description">{request.description}</p>}

        {(isExpired || isClosed) && (
          <div className="status-message error">
            {isExpired ? 'This file request has expired' : 'This file request is closed'}
          </div>
        )}

        {!isExpired && !isClosed && (
          <>
            <div className="upload-area">
              <input
                type="file"
                id="file-upload"
                onChange={handleFileUpload}
                disabled={uploading}
                style={{ display: 'none' }}
              />
              <label htmlFor="file-upload" className="upload-label">
                {uploading ? (
                  <>
                    <div className="spinner-small"></div>
                    <span>Uploading...</span>
                  </>
                ) : uploadSuccess ? (
                  <>
                    <span className="success-icon"></span>
                    <span>File uploaded successfully!</span>
                  </>
                ) : (
                  <>
                    <span className="upload-icon">➜</span>
                    <span>Click to upload or drag and drop</span>
                  </>
                )}
              </label>
            </div>

            {request.uploadedFiles && request.uploadedFiles.length > 0 && (
              <div className="uploaded-files-section">
                <h3>Uploaded Files ({request.uploadedFiles.length})</h3>
                <div className="uploaded-files-list">
                  {request.uploadedFiles.map((upload: any, idx: number) => (
                    <div key={idx} className="uploaded-file-item">
                      <span className="file-icon"></span>
                      <span className="file-name">{upload.file.originalName}</span>
                      {upload.uploadedBy && (
                        <span className="uploader">by {upload.uploadedBy.name}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default FileRequestUpload;


