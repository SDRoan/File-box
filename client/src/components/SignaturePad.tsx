import React, { useRef, useState, useEffect } from 'react';
import { signaturesAPI } from '../services/api';
import './SignaturePad.css';

interface SignaturePadProps {
  onSave: (signatureData: string, name: string, isDefault: boolean) => void;
  onClose: () => void;
  existingSignature?: string;
}

const SignaturePad: React.FC<SignaturePadProps> = ({ onSave, onClose, existingSignature }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isDrawing, setIsDrawing] = useState(false);
  const [signatureName, setSignatureName] = useState('');
  const [isDefault, setIsDefault] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    canvas.width = 800;
    canvas.height = 300;

    // Set drawing styles
    ctx.strokeStyle = '#000000';
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';

    // If existing signature, draw it
    if (existingSignature) {
      const img = new Image();
      img.onload = () => {
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      };
      img.src = existingSignature;
    }
  }, [existingSignature]);

  const startDrawing = (e: React.MouseEvent<HTMLCanvasElement> | React.TouchEvent<HTMLCanvasElement>) => {
    setIsDrawing(true);
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    const x = 'touches' in e ? e.touches[0].clientX - rect.left : e.clientX - rect.left;
    const y = 'touches' in e ? e.touches[0].clientY - rect.top : e.clientY - rect.top;

    ctx.beginPath();
    ctx.moveTo(x, y);
  };

  const draw = (e: React.MouseEvent<HTMLCanvasElement> | React.TouchEvent<HTMLCanvasElement>) => {
    if (!isDrawing) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    const x = 'touches' in e ? e.touches[0].clientX - rect.left : e.clientX - rect.left;
    const y = 'touches' in e ? e.touches[0].clientY - rect.top : e.clientY - rect.top;

    ctx.lineTo(x, y);
    ctx.stroke();
  };

  const stopDrawing = () => {
    setIsDrawing(false);
  };

  const clearCanvas = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);
  };

  const handleSave = () => {
    if (!signatureName.trim()) {
      alert('Please enter a name for your signature');
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Check if canvas has any drawing (more reliable check)
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    let hasContent = false;
    
    // Check for non-white pixels (more accurate than just alpha)
    for (let i = 0; i < imageData.data.length; i += 4) {
      const r = imageData.data[i];
      const g = imageData.data[i + 1];
      const b = imageData.data[i + 2];
      const a = imageData.data[i + 3];
      
      // If pixel is not white/transparent, we have content
      if (a > 0 && (r < 250 || g < 250 || b < 250)) {
        hasContent = true;
        break;
      }
    }

    if (!hasContent && !existingSignature) {
      alert('Please draw your signature first');
      return;
    }

    // Always save, even if it's just white space (user might want to save an empty signature)
    const signatureData = canvas.toDataURL('image/png');
    
    // Call onSave callback
    try {
      onSave(signatureData, signatureName.trim(), isDefault);
    } catch (error) {
      console.error('Error saving signature:', error);
      alert('Failed to save signature. Please try again.');
    }
  };

  return (
    <div className="signature-pad-overlay" onClick={onClose}>
      <div className="signature-pad-container" onClick={(e) => e.stopPropagation()}>
        <div className="signature-pad-header">
          <h2>Create Signature</h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="signature-pad-content">
          <div className="signature-pad-inputs">
            <input
              type="text"
              placeholder="Signature name (e.g., 'My Signature')"
              value={signatureName}
              onChange={(e) => setSignatureName(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter' && signatureName.trim()) {
                  handleSave();
                }
              }}
              className="signature-name-input"
              autoFocus
            />
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={isDefault}
                onChange={(e) => setIsDefault(e.target.checked)}
              />
              Set as default signature
            </label>
          </div>

          <div className="signature-pad-canvas-container">
            <canvas
              ref={canvasRef}
              className="signature-canvas"
              onMouseDown={startDrawing}
              onMouseMove={draw}
              onMouseUp={stopDrawing}
              onMouseLeave={stopDrawing}
              onTouchStart={startDrawing}
              onTouchMove={draw}
              onTouchEnd={stopDrawing}
            />
            <div className="signature-pad-hint">
              Sign above using your mouse or touch screen
            </div>
          </div>

          <div className="signature-pad-actions">
            <button onClick={clearCanvas} className="clear-btn">
              Clear
            </button>
            <button 
              onClick={handleSave} 
              className="save-btn"
              disabled={!signatureName.trim()}
              type="button"
            >
              Save Signature
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SignaturePad;

