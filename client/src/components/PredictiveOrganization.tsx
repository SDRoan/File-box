import React, { useState, useEffect } from 'react';
import { predictiveOrgAPI, filesAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { CheckIcon, CloseIcon, AIAssistantIcon } from './Icons';
import './PredictiveOrganization.css';

interface OrganizationSuggestion {
  patternId: string;
  destinationFolder: string;
  destinationFolderName: string;
  confidence: number;
  explanation: string;
  reason: string;
  occurrences: number;
}

interface PredictiveOrganizationProps {
  fileId: string;
  fileName: string;
  fileType: string;
  onMove: (fileId: string, destinationFolderId: string) => void;
  onDismiss?: () => void;
}

const PredictiveOrganization: React.FC<PredictiveOrganizationProps> = ({
  fileId,
  fileName,
  fileType,
  onMove,
  onDismiss
}) => {
  const { user } = useAuth();
  const [suggestions, setSuggestions] = useState<OrganizationSuggestion[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(true);

  useEffect(() => {
    loadSuggestions();
  }, [fileId]);

  const loadSuggestions = async () => {
    try {
      setLoading(true);
      const data = await predictiveOrgAPI.getSuggestions(fileId, 'viewed');
      setSuggestions(data.suggestions || []);
    } catch (error) {
      console.error('Error loading suggestions:', error);
      setSuggestions([]);
    } finally {
      setLoading(false);
    }
  };

  const handleAccept = async (suggestion: OrganizationSuggestion) => {
    try {
      // Record positive feedback
      await predictiveOrgAPI.recordFeedback(suggestion.patternId, 'accepted');
      
      // Move the file
      await onMove(fileId, suggestion.destinationFolder);
      
      // Remove this suggestion
      setSuggestions(suggestions.filter(s => s.patternId !== suggestion.patternId));
      
      if (onDismiss) {
        onDismiss();
      }
    } catch (error) {
      console.error('Error accepting suggestion:', error);
      alert('Failed to move file');
    }
  };

  const handleReject = async (suggestion: OrganizationSuggestion) => {
    try {
      await predictiveOrgAPI.recordFeedback(suggestion.patternId, 'rejected');
      setSuggestions(suggestions.filter(s => s.patternId !== suggestion.patternId));
    } catch (error) {
      console.error('Error rejecting suggestion:', error);
    }
  };

  const handleIgnore = async (suggestion: OrganizationSuggestion) => {
    try {
      await predictiveOrgAPI.recordFeedback(suggestion.patternId, 'ignored');
      setSuggestions(suggestions.filter(s => s.patternId !== suggestion.patternId));
    } catch (error) {
      console.error('Error ignoring suggestion:', error);
    }
  };

  if (loading) {
    return (
      <div className="predictive-org-container">
        <div className="predictive-org-loading">
          <div className="spinner"></div>
          <span>Analyzing organization patterns...</span>
        </div>
      </div>
    );
  }

  if (suggestions.length === 0) {
    return null; // Don't show anything if no suggestions
  }

  return (
    <div className="predictive-org-container">
      <div className="predictive-org-header" onClick={() => setExpanded(!expanded)}>
        <div className="predictive-org-title">
          <AIAssistantIcon size={20} color="currentColor" />
          <span>AI Organization Suggestions</span>
          {suggestions.length > 0 && (
            <span className="suggestion-count">{suggestions.length}</span>
          )}
        </div>
        <button className="toggle-btn">
          {expanded ? '▼' : '▶'}
        </button>
      </div>

      {expanded && (
        <div className="predictive-org-content">
          {suggestions.map((suggestion, index) => (
            <div key={suggestion.patternId} className="suggestion-card">
              <div className="suggestion-header">
                <div className="suggestion-info">
                  <div className="suggestion-explanation">
                    {suggestion.explanation || `Move to ${suggestion.destinationFolderName}`}
                  </div>
                  <div className="suggestion-meta">
                    <span className="confidence-badge" style={{
                      backgroundColor: suggestion.confidence > 0.7 ? '#1e40af' : 
                                       suggestion.confidence > 0.5 ? '#3b82f6' : '#60a5fa'
                    }}>
                      {(suggestion.confidence * 100).toFixed(0)}% confidence
                    </span>
                    <span className="occurrences-badge">
                      {suggestion.occurrences} {suggestion.occurrences === 1 ? 'time' : 'times'}
                    </span>
                  </div>
                </div>
              </div>
              
              <div className="suggestion-actions">
                <button
                  className="accept-btn"
                  onClick={() => handleAccept(suggestion)}
                  title="Accept and move file"
                >
                  <CheckIcon size={16} color="currentColor" /> Accept & Move
                </button>
                <button
                  className="reject-btn"
                  onClick={() => handleReject(suggestion)}
                  title="Reject this suggestion"
                >
                  <CloseIcon size={16} color="currentColor" /> Reject
                </button>
                <button
                  className="ignore-btn"
                  onClick={() => handleIgnore(suggestion)}
                  title="Ignore for now"
                >
                  Ignore
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default PredictiveOrganization;

