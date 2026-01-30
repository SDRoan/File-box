import React, { useState, useEffect } from 'react';
import { signaturesAPI } from '../services/api';
import SignaturePad from './SignaturePad';
import './SignatureManager.css';

interface Signature {
  _id: string;
  name: string;
  signatureData: string;
  isDefault: boolean;
  createdAt: string;
}

interface SignatureManagerProps {
  onSelectSignature?: (signature: Signature) => void;
  onClose?: () => void;
  selectedFieldId?: string | null;
}

const SignatureManager: React.FC<SignatureManagerProps> = ({ onSelectSignature, onClose, selectedFieldId }) => {
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [loading, setLoading] = useState(true);
  const [showSignaturePad, setShowSignaturePad] = useState(false);
  const [editingSignature, setEditingSignature] = useState<Signature | null>(null);

  useEffect(() => {
    loadSignatures();
  }, []);

  const loadSignatures = async () => {
    try {
      setLoading(true);
      const data = await signaturesAPI.getSignatures();
      setSignatures(data);
    } catch (error) {
      console.error('Error loading signatures:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSignature = async (signatureData: string, name: string, isDefault: boolean) => {
    try {
      const defaultValue = isDefault || signatures.length === 0; // First signature is default
      await signaturesAPI.createSignature({
        name,
        signatureData,
        isDefault: defaultValue
      });

      await loadSignatures();
      setShowSignaturePad(false);
      setEditingSignature(null);
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to save signature');
    }
  };

  const handleDeleteSignature = async (signatureId: string) => {
    if (!window.confirm('Delete this signature?')) return;

    try {
      await signaturesAPI.deleteSignature(signatureId);
      await loadSignatures();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to delete signature');
    }
  };

  const handleSetDefault = async (signatureId: string) => {
    try {
      await signaturesAPI.updateSignature(signatureId, { isDefault: true });
      await loadSignatures();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to set default signature');
    }
  };

  const handleSelectSignature = (signature: Signature, e?: React.MouseEvent) => {
    e?.stopPropagation();
    console.log('SignatureManager: handleSelectSignature called with:', signature);
    console.log('SignatureManager: onSelectSignature callback exists?', !!onSelectSignature);
    
    if (onSelectSignature) {
      console.log('SignatureManager: Calling onSelectSignature callback');
      onSelectSignature(signature);
    } else {
      console.warn('SignatureManager: No onSelectSignature callback provided');
    }
    
    // Don't close immediately - let the parent handle closing after signature is applied
    // The parent component will close the modal after successfully applying the signature
  };

  if (showSignaturePad) {
    return (
      <SignaturePad
        onSave={handleCreateSignature}
        onClose={() => setShowSignaturePad(false)}
        existingSignature={editingSignature?.signatureData}
      />
    );
  }

  return (
    <div className="signature-manager-overlay" onClick={(e) => {
      // Only close if clicking directly on the overlay, not on child elements
      if (e.target === e.currentTarget && onClose) {
        onClose();
      }
    }}>
      <div className="signature-manager-container" onClick={(e) => e.stopPropagation()}>
        <div className="signature-manager-header">
          <h2>My Signatures</h2>
          {selectedFieldId && (
            <div style={{ fontSize: '0.875rem', color: '#666', marginRight: '1rem' }}>
              Select a signature to apply
            </div>
          )}
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="signature-manager-content">
          <button
            className="create-signature-btn"
            onClick={() => setShowSignaturePad(true)}
          >
            + Create New Signature
          </button>

          {loading ? (
            <div className="loading">Loading signatures...</div>
          ) : signatures.length === 0 ? (
            <div className="no-signatures">
              <p>No signatures yet. Create your first signature!</p>
            </div>
          ) : (
            <div className="signatures-list">
              {signatures.map((signature) => (
                <div
                  key={signature._id}
                  className={`signature-item ${signature.isDefault ? 'default' : ''}`}
                >
                  <div 
                    className="signature-preview" 
                    onClick={(e) => handleSelectSignature(signature, e)}
                    style={{ cursor: 'pointer' }}
                  >
                    <img src={signature.signatureData} alt={signature.name} />
                    <div className="signature-info">
                      <div className="signature-name">{signature.name}</div>
                      {signature.isDefault && (
                        <span className="default-badge">Default</span>
                      )}
                    </div>
                  </div>
                  <div className="signature-actions">
                    {!signature.isDefault && (
                      <button
                        onClick={() => handleSetDefault(signature._id)}
                        className="set-default-btn"
                      >
                        Set Default
                      </button>
                    )}
                    <button
                      onClick={() => handleDeleteSignature(signature._id)}
                      className="delete-btn"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SignatureManager;

