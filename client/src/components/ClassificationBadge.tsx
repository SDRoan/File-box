import React from 'react';
import './ClassificationBadge.css';

interface ClassificationBadgeProps {
  classification: 'Public' | 'Internal' | 'Confidential' | 'Top Secret';
  size?: 'small' | 'medium' | 'large';
}

const ClassificationBadge: React.FC<ClassificationBadgeProps> = ({ 
  classification, 
  size = 'medium' 
}) => {
  const getClassificationColor = () => {
    switch (classification) {
      case 'Public':
        return { bg: '#60a5fa', text: '#ffffff' };
      case 'Internal':
        return { bg: '#3b82f6', text: '#ffffff' };
      case 'Confidential':
        return { bg: '#2563eb', text: '#ffffff' };
      case 'Top Secret':
        return { bg: '#1e40af', text: '#ffffff' };
      default:
        return { bg: '#3b82f6', text: '#ffffff' };
    }
  };

  const getIcon = () => {
    return '';
  };

  const colors = getClassificationColor();
  const sizeClass = `classification-badge-${size}`;

  return (
    <span
      className={`classification-badge ${sizeClass}`}
      style={{
        backgroundColor: colors.bg,
        color: colors.text,
      }}
      title={`Classification: ${classification}`}
    >
      <span className="classification-icon">{getIcon()}</span>
      <span className="classification-text">{classification}</span>
    </span>
  );
};

export default ClassificationBadge;








