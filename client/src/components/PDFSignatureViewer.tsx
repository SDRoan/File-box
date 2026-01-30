import React, { useState, useEffect, useRef } from 'react';
import { signaturesAPI } from '../services/api';
import SignaturePad from './SignaturePad';
import './PDFSignatureViewer.css';

interface PDFSignatureViewerProps {
  fileId: string;
  pdfUrl: string;
  fileName: string;
}

interface Signature {
  _id: string;
  name: string;
  signatureData: string;
  isDefault: boolean;
}

interface DocumentSignature {
  _id: string;
  pageNumber: number;
  position: { x: number; y: number; width: number; height: number };
  signature: Signature;
  user: { name: string; email: string };
  signedAt: string;
}

interface SignatureField {
  id: string;
  pageNumber: number;
  x: number;
  y: number;
  width: number;
  height: number;
  signatureId?: string;
  signatureData?: string;
}

const PDFSignatureViewer: React.FC<PDFSignatureViewerProps> = ({ fileId, pdfUrl, fileName }) => {
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [documentSignatures, setDocumentSignatures] = useState<DocumentSignature[]>([]);
  const [isPlacingField, setIsPlacingField] = useState(false);
  const [signatureFields, setSignatureFields] = useState<SignatureField[]>([]);
  const [showSignFieldsModal, setShowSignFieldsModal] = useState(false);
  const [showCreatePad, setShowCreatePad] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const containerRef = useRef<HTMLDivElement>(null);
  const fieldIdCounter = useRef(0);

  useEffect(() => {
    loadSignatures();
    loadDocumentSignatures();
  }, [fileId]);

  useEffect(() => {
    const savedFields: SignatureField[] = documentSignatures.map(docSig => ({
      id: docSig._id,
      pageNumber: docSig.pageNumber,
      x: docSig.position.x,
      y: docSig.position.y,
      width: docSig.position.width,
      height: docSig.position.height,
      signatureId: docSig.signature._id,
      signatureData: docSig.signature.signatureData
    }));
    
    setSignatureFields(prevFields => {
      const unsavedFields = prevFields.filter(field => !field.signatureId);
      const allFields = [...savedFields, ...unsavedFields];
      
      const uniqueFields = allFields.reduce((acc, field) => {
        const existing = acc.find(f => 
          f.pageNumber === field.pageNumber &&
          Math.abs(f.x - field.x) < 0.01 &&
          Math.abs(f.y - field.y) < 0.01
        );
        if (!existing) {
          acc.push(field);
        } else if (field.signatureId && !existing.signatureId) {
          const index = acc.indexOf(existing);
          acc[index] = field;
        }
        return acc;
      }, [] as SignatureField[]);
      
      return uniqueFields;
    });
  }, [documentSignatures]);

  const loadSignatures = async () => {
    try {
      const data = await signaturesAPI.getSignatures();
      setSignatures(data);
    } catch (error) {
      console.error('Error loading signatures:', error);
    }
  };

  const loadDocumentSignatures = async () => {
    try {
      const data = await signaturesAPI.getDocumentSignatures(fileId);
      setDocumentSignatures(data);
    } catch (error) {
      console.error('Error loading document signatures:', error);
    }
  };

  const handleAddSignatureField = () => {
    setIsPlacingField(true);
  };

  const handlePDFClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!isPlacingField) return;

    const target = e.target as HTMLElement;
    if (target.closest('.signature-field-box')) {
      return;
    }

    e.preventDefault();
    e.stopPropagation();

    const container = containerRef.current;
    if (!container) return;

    const rect = container.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;

    const newField: SignatureField = {
      id: `field-${Date.now()}-${fieldIdCounter.current++}`,
      pageNumber: currentPage,
      x: Math.max(0, Math.min(0.85, x - 0.075)),
      y: Math.max(0, Math.min(0.85, y - 0.025)),
      width: 0.15,
      height: 0.05
    };

    setSignatureFields(prev => [...prev, newField]);
    setIsPlacingField(false);
  };

  const handleSignField = async (fieldId: string, signature: Signature) => {
    const field = signatureFields.find(f => f.id === fieldId);
    if (!field) return;

    try {
      setSignatureFields(prevFields => 
        prevFields.map(f => 
          f.id === fieldId 
            ? { ...f, signatureId: signature._id, signatureData: signature.signatureData }
            : f
        )
      );

      await signaturesAPI.applySignature(fileId, {
        signatureId: signature._id,
        pageNumber: field.pageNumber,
        position: {
          x: field.x,
          y: field.y,
          width: field.width,
          height: field.height
        }
      });

      await loadDocumentSignatures();
      setShowSignFieldsModal(false);
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to apply signature');
      await loadDocumentSignatures();
    }
  };

  const handleCreateSignature = async (signatureData: string, name: string, isDefault: boolean) => {
    try {
      await signaturesAPI.createSignature({
        name,
        signatureData,
        isDefault: isDefault || signatures.length === 0
      });
      await loadSignatures();
      setShowCreatePad(false);
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to save signature');
    }
  };

  const handleDeleteField = (fieldId: string) => {
    setSignatureFields(prev => prev.filter(f => f.id !== fieldId));
  };

  const emptyFields = signatureFields.filter(f => !f.signatureData && f.pageNumber === currentPage);

  return (
    <div className="pdf-signature-viewer">
      <div className="pdf-signature-toolbar">
        <div className="pdf-page-info">
          Page {currentPage} of {totalPages}
        </div>
        <div className="pdf-signature-actions">
          <button
            onClick={handleAddSignatureField}
            className={`sign-place-btn ${isPlacingField ? 'active' : ''}`}
          >
             {isPlacingField ? 'Click to Create Signature Field' : 'Add Signature Field'}
          </button>
          {isPlacingField && (
            <button onClick={() => setIsPlacingField(false)} className="cancel-btn">
              Cancel
            </button>
          )}
          {emptyFields.length > 0 && (
            <button
              onClick={() => setShowSignFieldsModal(true)}
              className="sign-fields-btn"
            >
               Sign Fields ({emptyFields.length})
            </button>
          )}
        </div>
      </div>

      <div
        ref={containerRef}
        className={`pdf-signature-container ${isPlacingField ? 'placing-field' : ''}`}
      >
        {isPlacingField && (
          <div 
            className="pdf-click-overlay"
            onClick={handlePDFClick}
            style={{ 
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              zIndex: 100,
              cursor: 'crosshair'
            }}
          />
        )}
        
        <iframe
          ref={useRef<HTMLIFrameElement>(null)}
          src={pdfUrl}
          className="pdf-signature-iframe"
          title={fileName}
        />
        
        <div className="signature-fields-container">
          {signatureFields
            .filter(field => field.pageNumber === currentPage)
            .map((field) => (
              <div
                key={field.id}
                className={`signature-field-box ${field.signatureData ? 'filled' : 'empty'}`}
                style={{
                  left: `${field.x * 100}%`,
                  top: `${field.y * 100}%`,
                  width: `${field.width * 100}%`,
                  height: `${field.height * 100}%`,
                }}
              >
                {field.signatureData ? (
                  <div className="signature-field-content">
                    <img src={field.signatureData} alt="Signature" />
                    <button
                      className="field-delete-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteField(field.id);
                      }}
                      title="Delete"
                    >
                      ×
                    </button>
                  </div>
                ) : (
                  <div className="signature-field-placeholder">
                    <span>Signature Field {signatureFields.indexOf(field) + 1}</span>
                    <button
                      className="field-delete-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteField(field.id);
                      }}
                      title="Delete"
                    >
                      ×
                    </button>
                  </div>
                )}
              </div>
            ))}
        </div>
      </div>

      {showSignFieldsModal && (
        <div 
          className="signature-modal-overlay" 
          onClick={() => setShowSignFieldsModal(false)}
        >
          <div 
            className="signature-modal-content" 
            onClick={(e) => e.stopPropagation()}
          >
            <div className="signature-modal-header">
              <h3>Sign Fields - Page {currentPage}</h3>
              <button 
                className="close-btn" 
                onClick={() => setShowSignFieldsModal(false)}
              >
                ×
              </button>
            </div>
            
            <div className="signature-modal-body">
              <button
                className="create-signature-btn"
                onClick={() => {
                  setShowCreatePad(true);
                }}
              >
                + Create New Signature
              </button>

              {emptyFields.length === 0 ? (
                <div className="no-signatures">All fields on this page are signed!</div>
              ) : signatures.length === 0 ? (
                <div className="no-signatures">No signatures available. Create one first!</div>
              ) : (
                <div className="fields-to-sign-list">
                  {emptyFields.map((field, index) => (
                    <div key={field.id} className="field-to-sign-item">
                      <div className="field-info">
                        <strong>Field {index + 1}</strong>
                        <span className="field-position">Position: {Math.round(field.x * 100)}%, {Math.round(field.y * 100)}%</span>
                      </div>
                      <div className="signatures-grid-small">
                        {signatures.map((signature) => (
                          <div
                            key={signature._id}
                            className="signature-option-small"
                            onClick={() => handleSignField(field.id, signature)}
                          >
                            <img src={signature.signatureData} alt={signature.name} />
                            <span>{signature.name}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showCreatePad && (
        <SignaturePad
          onSave={handleCreateSignature}
          onClose={() => setShowCreatePad(false)}
        />
      )}
    </div>
  );
};

export default PDFSignatureViewer;
