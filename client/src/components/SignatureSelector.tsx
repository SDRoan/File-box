import React, { useState, useEffect } from 'react';
import { signaturesAPI } from '../services/api';
import SignaturePad from './SignaturePad';
import './SignatureSelector.css';

interface Signature {
  _id: string;
  name: string;
  signatureData: string;
  isDefault: boolean;
}

interface SignatureSelectorProps {
  onSelect: (signature: Signature) => void;
  onClose: () => void;
  onCreateNew?: () => void;
}

const SignatureSelector: React.FC<SignatureSelectorProps> = ({ onSelect, onClose, onCreateNew }) => {
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [loading, setLoading] = useState(true);
  const [showPad, setShowPad] = useState(false);

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

  const handleSelectSignature = (signature: Signature, e: React.MouseEvent) => {
    e.stopPropagation();
    console.log('SignatureSelector: Selecting signature:', signature);
    onSelect(signature);
  };

  const handleCreateSignature = async (signatureData: string, name: string, isDefault: boolean) => {
    try {
      await signaturesAPI.createSignature({
        name,
        signatureData,
        isDefault: isDefault || signatures.length === 0
      });
      await loadSignatures();
      setShowPad(false);
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to save signature');
    }
  };

  if (showPad) {
    return (
      <SignaturePad
        onSave={handleCreateSignature}
        onClose={() => setShowPad(false)}
      />
    );
  }

  return (
    <div className="signature-selector-overlay" onClick={(e) => {
      if (e.target === e.currentTarget) {
        onClose();
      }
    }}>
      <div className="signature-selector-container" onClick={(e) => e.stopPropagation()}>
        <div className="signature-selector-header">
          <h3>Select Signature</h3>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="signature-selector-content">
          <button
            className="create-new-signature-btn"
            onClick={() => setShowPad(true)}
          >
            + Create New Signature
          </button>

          {loading ? (
            <div className="loading">Loading signatures...</div>
          ) : signatures.length === 0 ? (
            <div className="no-signatures">
              <p>No signatures available. Create your first signature!</p>
            </div>
          ) : (
            <div className="signatures-grid">
              {signatures.map((signature) => (
                <div
                  key={signature._id}
                  className={`signature-option ${signature.isDefault ? 'default' : ''}`}
                  onClick={(e) => handleSelectSignature(signature, e)}
                >
                  <div className="signature-option-preview">
                    <img src={signature.signatureData} alt={signature.name} />
                  </div>
                  <div className="signature-option-name">{signature.name}</div>
                  {signature.isDefault && (
                    <span className="default-badge">Default</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SignatureSelector;





