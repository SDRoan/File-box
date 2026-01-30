import React from 'react';
import { Folder } from '../types';
import { FolderIcon } from './Icons';
import './Breadcrumb.css';

interface BreadcrumbProps {
  folders: Folder[];
  onFolderClick: (folderId: string) => void;
  onRootClick: () => void;
}

const Breadcrumb: React.FC<BreadcrumbProps> = ({ folders, onFolderClick, onRootClick }) => {
  return (
    <nav className="breadcrumb" aria-label="Breadcrumb">
      <button className="breadcrumb-item root" onClick={onRootClick}>
        <FolderIcon size={16} color="currentColor" />
        <span>Home</span>
      </button>
      {folders.map((folder, index) => (
        <React.Fragment key={folder._id}>
          <span className="breadcrumb-separator">/</span>
          <button
            className={`breadcrumb-item ${index === folders.length - 1 ? 'current' : ''}`}
            onClick={() => onFolderClick(folder._id)}
          >
            {folder.name}
          </button>
        </React.Fragment>
      ))}
    </nav>
  );
};

export default Breadcrumb;
