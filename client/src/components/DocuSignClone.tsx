import React, { useState, useRef, useEffect } from 'react';
import './DocuSignClone.css';

interface DocuSignCloneProps {
  fileId?: string;
  pdfUrl?: string;
  fileName?: string;
}

interface Document {
  id: string;
  name: string;
  type: string;
  dataUrl: string;
  uploadDate: Date;
  status: 'draft' | 'sent' | 'completed';
  fields: Field[];
  signers: Signer[];
}

interface Signer {
  id: string;
  name: string;
  email: string;
  color: string;
}

interface Field {
  id: string;
  type: 'signature' | 'initial' | 'date' | 'text';
  x: number; // percentage
  y: number; // percentage
  width: number; // percentage
  height: number; // percentage
  signerId: string;
  value?: string;
  pageNumber: number;
}

type View = 'dashboard' | 'prepare' | 'sign';

const DocuSignClone: React.FC<DocuSignCloneProps> = ({ fileId, pdfUrl, fileName }) => {
  const [view, setView] = useState<View>(pdfUrl ? 'prepare' : 'dashboard');
  const [documents, setDocuments] = useState<Document[]>([]);
  const [selectedDoc, setSelectedDoc] = useState<Document | null>(null);
  const [draggedFieldType, setDraggedFieldType] = useState<Field['type'] | null>(null);
  const [showSignatureModal, setShowSignatureModal] = useState(false);
  const [activeFieldId, setActiveFieldId] = useState<string | null>(null);
  const [signatureInput, setSignatureInput] = useState('');
  const documentRef = useRef<HTMLDivElement>(null);
  const fieldIdCounter = useRef(0);

  const signerColors = ['#3B82F6', '#8B5CF6', '#10B981', '#F59E0B', '#EF4444'];

  const stats = {
    draft: documents.filter(d => d.status === 'draft').length,
    sent: documents.filter(d => d.status === 'sent').length,
    completed: documents.filter(d => d.status === 'completed').length,
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target?.result as string;
      const newDoc: Document = {
        id: `doc-${Date.now()}`,
        name: file.name,
        type: file.type,
        dataUrl,
        uploadDate: new Date(),
        status: 'draft',
        fields: [],
        signers: [],
      };
      setDocuments([...documents, newDoc]);
    };
    reader.readAsDataURL(file);
  };

  const handlePrepareDocument = (doc: Document) => {
    setSelectedDoc(doc);
    setView('prepare');
  };

  const handleSignDocument = (doc: Document) => {
    setSelectedDoc(doc);
    setView('sign');
  };

  const addSigner = () => {
    if (!selectedDoc) return;
    const signer: Signer = {
      id: `signer-${Date.now()}`,
      name: `Signer ${selectedDoc.signers.length + 1}`,
      email: `signer${selectedDoc.signers.length + 1}@example.com`,
      color: signerColors[selectedDoc.signers.length % signerColors.length],
    };
    setSelectedDoc({
      ...selectedDoc,
      signers: [...selectedDoc.signers, signer],
    });
  };

  const removeSigner = (signerId: string) => {
    if (!selectedDoc) return;
    setSelectedDoc({
      ...selectedDoc,
      signers: selectedDoc.signers.filter(s => s.id !== signerId),
      fields: selectedDoc.fields.filter(f => f.signerId !== signerId),
    });
  };

  const handleDragStart = (e: React.DragEvent, fieldType: Field['type']) => {
    e.dataTransfer.effectAllowed = 'copy';
    setDraggedFieldType(fieldType);
    if (documentRef.current) {
      documentRef.current.classList.add('dragging');
    }
  };

  const handleDragEnd = () => {
    setDraggedFieldType(null);
    if (documentRef.current) {
      documentRef.current.classList.remove('dragging');
    }
  };

  const handleDocumentDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (!draggedFieldType || !selectedDoc) {
      alert('Please add at least one signer first');
      return;
    }
    
    if (selectedDoc.signers.length === 0) {
      alert('Please add at least one signer before adding fields');
      return;
    }

    const container = documentRef.current;
    if (!container) return;

    const rect = container.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;

    const fieldWidth = draggedFieldType === 'text' ? 20 : draggedFieldType === 'date' ? 12 : 15;
    const fieldHeight = draggedFieldType === 'text' ? 3 : draggedFieldType === 'date' ? 3 : 5;

    const clampedX = Math.max(0, Math.min(100 - fieldWidth, x));
    const clampedY = Math.max(0, Math.min(100 - fieldHeight, y));

    const newField: Field = {
      id: `field-${fieldIdCounter.current++}`,
      type: draggedFieldType,
      x: clampedX,
      y: clampedY,
      width: fieldWidth,
      height: fieldHeight,
      signerId: selectedDoc.signers[0].id,
      pageNumber: 1,
    };

    setSelectedDoc({
      ...selectedDoc,
      fields: [...selectedDoc.fields, newField],
    });
    setDraggedFieldType(null);
  };

  const handleFieldClick = (fieldId: string, fieldType: Field['type']) => {
    if (view === 'sign') {
      setActiveFieldId(fieldId);
      if (fieldType === 'signature') {
        setShowSignatureModal(true);
      }
    }
  };

  const handleFieldValueChange = (fieldId: string, value: string) => {
    if (!selectedDoc) return;
    setSelectedDoc({
      ...selectedDoc,
      fields: selectedDoc.fields.map(f =>
        f.id === fieldId ? { ...f, value } : f
      ),
    });
  };

  const handleAddSignature = () => {
    if (!activeFieldId || !selectedDoc) return;
    handleFieldValueChange(activeFieldId, signatureInput);
    setShowSignatureModal(false);
    setSignatureInput('');
    setActiveFieldId(null);
  };

  const handleSendDocument = () => {
    if (!selectedDoc) return;
    setDocuments(documents.map(d =>
      d.id === selectedDoc.id ? { ...selectedDoc, status: 'sent' } : d
    ));
    setView('dashboard');
    setSelectedDoc(null);
  };

  const handleCompleteSignature = () => {
    if (!selectedDoc) return;
    const allFieldsFilled = selectedDoc.fields.every(f => f.value);
    if (!allFieldsFilled) {
      alert('Please fill all fields before completing');
      return;
    }
    setDocuments(documents.map(d =>
      d.id === selectedDoc.id ? { ...selectedDoc, status: 'completed' } : d
    ));
    setView('dashboard');
    setSelectedDoc(null);
  };

  const removeField = (fieldId: string) => {
    if (!selectedDoc) return;
    setSelectedDoc({
      ...selectedDoc,
      fields: selectedDoc.fields.filter(f => f.id !== fieldId),
    });
  };

  const getFieldIcon = (type: Field['type']) => {
    switch (type) {
      case 'signature': return '';
      case 'initial': return '';
      case 'date': return 'Date';
      case 'text': return '';
    }
  };

  const getSignerColor = (signerId: string) => {
    if (!selectedDoc) return '#3B82F6';
    const signer = selectedDoc.signers.find(s => s.id === signerId);
    return signer?.color || '#3B82F6';
  };

  useEffect(() => {
    if (selectedDoc) {
      setDocuments(documents.map(d =>
        d.id === selectedDoc.id ? selectedDoc : d
      ));
    }
  }, [selectedDoc]);

  useEffect(() => {
    if (pdfUrl && fileName && !selectedDoc) {
      const initialDoc: Document = {
        id: fileId || `doc-${Date.now()}`,
        name: fileName,
        type: 'application/pdf',
        dataUrl: pdfUrl,
        uploadDate: new Date(),
        status: 'draft',
        fields: [],
        signers: [],
      };
      setSelectedDoc(initialDoc);
      setDocuments([initialDoc]);
    }
  }, [pdfUrl, fileName, fileId]);



  return (
    <div className="docusign-clone">
      <header className="docusign-header">
        <h1 className="docusign-logo">DocuSign Clone</h1>
        <nav className="docusign-nav">
          <button
            className={`nav-btn ${view === 'dashboard' ? 'active' : ''}`}
            onClick={() => setView('dashboard')}
          >
            Dashboard
          </button>
        </nav>
      </header>

      {view === 'dashboard' && (
        <div className="docusign-dashboard">
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{stats.draft}</div>
              <div className="stat-label">Draft</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.sent}</div>
              <div className="stat-label">Sent</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.completed}</div>
              <div className="stat-label">Completed</div>
            </div>
          </div>

          <div className="upload-section">
            <label className="upload-btn">
               Upload Document
              <input
                type="file"
                accept=".pdf,.png,.jpg,.jpeg"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
            </label>
          </div>

          <div className="documents-list">
            <h2 className="section-title">Documents</h2>
            {documents.length === 0 ? (
              <div className="empty-state">
                <p>No documents yet. Upload your first document!</p>
              </div>
            ) : (
              <div className="documents-grid">
                {documents.map(doc => (
                  <div key={doc.id} className="document-card">
                    <div className="document-preview">
                      <img src={doc.dataUrl} alt={doc.name} />
                    </div>
                    <div className="document-info">
                      <h3>{doc.name}</h3>
                      <div className="document-meta">
                        <span className={`status-badge ${doc.status}`}>
                          {doc.status}
                        </span>
                        <span className="document-date">
                          {doc.uploadDate.toLocaleDateString()}
                        </span>
                      </div>
                      <div className="document-actions">
                        {doc.status === 'draft' && (
                          <button
                            className="action-btn prepare"
                            onClick={() => handlePrepareDocument(doc)}
                          >
                            Prepare
                          </button>
                        )}
                        {doc.status === 'sent' && (
                          <button
                            className="action-btn sign"
                            onClick={() => handleSignDocument(doc)}
                          >
                            Sign
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {view === 'prepare' && selectedDoc && (
        <div className="docusign-prepare">
          <div className="prepare-sidebar">
            <div className="sidebar-section">
              <h3>Signers</h3>
              {selectedDoc.signers.map(signer => (
                <div key={signer.id} className="signer-item">
                  <div
                    className="signer-color"
                    style={{ backgroundColor: signer.color }}
                  />
                  <div className="signer-info">
                    <div className="signer-name">{signer.name}</div>
                    <div className="signer-email">{signer.email}</div>
                  </div>
                  <button
                    className="remove-btn"
                    onClick={() => removeSigner(signer.id)}
                  >
                    ×
                  </button>
                </div>
              ))}
              <button className="add-signer-btn" onClick={addSigner}>
                + Add Signer
              </button>
            </div>

            <div className="sidebar-section">
              <h3>Fields</h3>
              <div className="field-types">
                {(['signature', 'initial', 'date', 'text'] as Field['type'][]).map(type => (
                  <div
                    key={type}
                    className="field-type-item"
                    draggable
                    onDragStart={(e) => handleDragStart(e, type)}
                    onDragEnd={handleDragEnd}
                  >
                    <span className="field-icon">{getFieldIcon(type)}</span>
                    <span className="field-label">{type.charAt(0).toUpperCase() + type.slice(1)}</span>
                  </div>
                ))}
              </div>
            </div>

            <button
              className="send-btn"
              onClick={handleSendDocument}
              disabled={selectedDoc.fields.length === 0 || selectedDoc.signers.length === 0}
            >
              Send Document
            </button>
          </div>

          <div className="prepare-main">
            <div
              ref={documentRef}
              className="document-canvas"
              onDrop={handleDocumentDrop}
              onDragOver={(e) => {
                e.preventDefault();
                e.stopPropagation();
              }}
              onDragEnter={(e) => {
                e.preventDefault();
                e.stopPropagation();
              }}
            >
              <div className="document-wrapper">
                {selectedDoc.type === 'application/pdf' ? (
                  <iframe 
                    src={selectedDoc.dataUrl} 
                    className="pdf-iframe"
                    style={{ pointerEvents: 'none' }}
                  />
                ) : (
                  <img src={selectedDoc.dataUrl} alt={selectedDoc.name} />
                )}
                {selectedDoc.fields.map(field => {
                  const signer = selectedDoc.signers.find(s => s.id === field.signerId);
                  return (
                    <div
                      key={field.id}
                      className="field-overlay"
                      style={{
                        left: `${field.x}%`,
                        top: `${field.y}%`,
                        width: `${field.width}%`,
                        height: `${field.height}%`,
                        borderColor: signer?.color || '#3B82F6',
                      }}
                      onMouseEnter={(e) => {
                        const deleteBtn = e.currentTarget.querySelector('.field-delete-btn');
                        if (deleteBtn) deleteBtn.classList.add('visible');
                      }}
                      onMouseLeave={(e) => {
                        const deleteBtn = e.currentTarget.querySelector('.field-delete-btn');
                        if (deleteBtn) deleteBtn.classList.remove('visible');
                      }}
                    >
                      <div className="field-label">
                        {getFieldIcon(field.type)} {field.type}
                      </div>
                      <button
                        className="field-delete-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          removeField(field.id);
                        }}
                      >
                        ×
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {view === 'sign' && selectedDoc && (
        <div className="docusign-sign">
          <div className="sign-main">
            <div className="document-canvas">
              {selectedDoc.type === 'application/pdf' ? (
                <iframe src={selectedDoc.dataUrl} className="pdf-iframe" />
              ) : (
                <img src={selectedDoc.dataUrl} alt={selectedDoc.name} />
              )}
              {selectedDoc.fields.map(field => {
                const signer = selectedDoc.signers.find(s => s.id === field.signerId);
                const signerColor = signer?.color || '#3B82F6';
                return (
                  <div
                    key={field.id}
                    className={`field-overlay sign-field ${field.value ? 'filled' : ''}`}
                    style={{
                      left: `${field.x}%`,
                      top: `${field.y}%`,
                      width: `${field.width}%`,
                      height: `${field.height}%`,
                      borderColor: signerColor,
                      backgroundColor: field.value ? `${signerColor}20` : 'transparent',
                    }}
                    onClick={() => handleFieldClick(field.id, field.type)}
                  >
                    {field.value ? (
                      <div className="field-value">
                        {field.type === 'signature' ? (
                          <span className="signature-text" style={{ fontFamily: "'Brush Script MT', cursive" }}>
                            {field.value}
                          </span>
                        ) : field.type === 'initial' ? (
                          <span className="initial-text">{field.value.toUpperCase()}</span>
                        ) : (
                          <span>{field.value}</span>
                        )}
                      </div>
                    ) : (
                      <div className="field-placeholder">
                        {getFieldIcon(field.type)} Click to {field.type}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          <div className="sign-footer">
            <button className="complete-btn" onClick={handleCompleteSignature}>
              Complete Signature
            </button>
          </div>
        </div>
      )}

      {showSignatureModal && (
        <div className="modal-overlay" onClick={() => setShowSignatureModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Add Signature</h3>
            <div className="signature-input-section">
              <input
                type="text"
                className="signature-input"
                value={signatureInput}
                onChange={(e) => setSignatureInput(e.target.value)}
                placeholder="Type your name"
                autoFocus
              />
              <div className="signature-preview">
                <span className="signature-text" style={{ fontFamily: "'Brush Script MT', cursive" }}>
                  {signatureInput || 'Your signature'}
                </span>
              </div>
            </div>
            <div className="modal-actions">
              <button className="cancel-btn" onClick={() => setShowSignatureModal(false)}>
                Cancel
              </button>
              <button className="add-btn" onClick={handleAddSignature}>
                Add Signature
              </button>
            </div>
          </div>
        </div>
      )}

      {view === 'sign' && selectedDoc && activeFieldId && !showSignatureModal && (() => {
        const field = selectedDoc.fields.find(f => f.id === activeFieldId);
        if (!field || field.type === 'signature') return null;
        
        return (
          <div className="field-input-overlay">
            {field.type === 'initial' && (
              <input
                type="text"
                maxLength={3}
                className="field-input"
                value={field.value || ''}
                onChange={(e) => handleFieldValueChange(field.id, e.target.value.toUpperCase())}
                onBlur={() => setActiveFieldId(null)}
                autoFocus
                style={{ textTransform: 'uppercase' }}
              />
            )}
            {field.type === 'date' && (
              <input
                type="date"
                className="field-input"
                value={field.value || ''}
                onChange={(e) => handleFieldValueChange(field.id, e.target.value)}
                onBlur={() => setActiveFieldId(null)}
                autoFocus
              />
            )}
            {field.type === 'text' && (
              <input
                type="text"
                className="field-input"
                value={field.value || ''}
                onChange={(e) => handleFieldValueChange(field.id, e.target.value)}
                onBlur={() => setActiveFieldId(null)}
                autoFocus
              />
            )}
          </div>
        );
      })()}

    </div>
  );
};

export default DocuSignClone;

