import React from 'react';
import './Logo.css';

interface LogoProps {
  size?: 'small' | 'medium' | 'large';
  showText?: boolean;
  text?: string;
}

const Logo: React.FC<LogoProps> = ({ size = 'medium', showText = true, text = 'File Box' }) => {
  const sizeClasses = {
    small: 'logo-small',
    medium: 'logo-medium',
    large: 'logo-large'
  };

  return (
    <div className={`logo-container ${sizeClasses[size]}`}>
      <img 
        src="/file-box-logo.png" 
        alt="File Box Logo" 
        className="logo-img"
      />
      {showText && (
        <span className="logo-text">{text}</span>
      )}
    </div>
  );
};

export default Logo;

