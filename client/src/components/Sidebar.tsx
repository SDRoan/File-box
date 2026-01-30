import React from 'react';
import { useAuth } from '../context/AuthContext';
import Logo from './Logo';
import {
  FilesIcon,
  SharedIcon,
  StarredIcon,
  TrashIcon,
  TeamFoldersIcon,
  FileRequestsIcon,
  RelationshipsIcon,
  SocialFeedIcon,
  AnalyticsIcon,
  SecurityIcon,
  AIAssistantIcon,
  StudentIcon,
  BackIcon,
  TemplateIcon,
  ShortcutIcon,
  IntegrationIcon,
  ForumIcon,
  LearningIcon,
  CloudBackupIcon,
} from './Icons';
import './Sidebar.css';

interface SidebarProps {
  currentView: string;
  onViewChange: (view: string) => void;
  onNavigateUp: () => void;
  currentFolderId?: string;
}

const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onViewChange,
  onNavigateUp,
  currentFolderId,
}) => {
  const { user, logout } = useAuth();

  const formatStorage = (bytes: number) => {
    const gb = bytes / (1024 * 1024 * 1024);
    return `${gb.toFixed(2)} GB`;
  };

  const storagePercent = user
    ? (user.storageUsed / user.storageLimit) * 100
    : 0;

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <Logo size="small" showText={true} text="File Box" />
      </div>
      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-title">Main</div>
          <button
            className={`nav-item ${currentView === 'files' ? 'active' : ''}`}
            onClick={() => onViewChange('files')}
          >
            <FilesIcon size={18} color="currentColor" />
            <span>Files</span>
          </button>
          <button
            className={`nav-item ${currentView === 'shared' ? 'active' : ''}`}
            onClick={() => onViewChange('shared')}
          >
            <SharedIcon size={18} color="currentColor" />
            <span>Shared</span>
          </button>
          <button
            className={`nav-item ${currentView === 'starred' ? 'active' : ''}`}
            onClick={() => onViewChange('starred')}
          >
            <StarredIcon size={18} color="currentColor" />
            <span>Starred</span>
          </button>
          <button
            className={`nav-item ${currentView === 'trash' ? 'active' : ''}`}
            onClick={() => onViewChange('trash')}
          >
            <TrashIcon size={18} color="currentColor" />
            <span>Trash</span>
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Collaboration</div>
          <button
            className={`nav-item ${currentView === 'teams' ? 'active' : ''}`}
            onClick={() => onViewChange('teams')}
          >
            <TeamFoldersIcon size={18} color="currentColor" />
            <span>Team Folders</span>
          </button>
          <button
            className={`nav-item ${currentView === 'requests' ? 'active' : ''}`}
            onClick={() => onViewChange('requests')}
          >
            <FileRequestsIcon size={18} color="currentColor" />
            <span>File Requests</span>
          </button>
          <button
            className={`nav-item ${currentView === 'relationships' ? 'active' : ''}`}
            onClick={() => onViewChange('relationships')}
          >
            <RelationshipsIcon size={18} color="currentColor" />
            <span>Connections</span>
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Tools</div>
          <button
            className={`nav-item ${currentView === 'templates' ? 'active' : ''}`}
            onClick={() => onViewChange('templates')}
          >
            <TemplateIcon size={18} color="currentColor" />
            <span>Templates</span>
          </button>
          <button
            className={`nav-item ${currentView === 'shortcuts' ? 'active' : ''}`}
            onClick={() => onViewChange('shortcuts')}
          >
            <ShortcutIcon size={18} color="currentColor" />
            <span>Shortcuts</span>
          </button>
          <button
            className={`nav-item ${currentView === 'secured-links' ? 'active' : ''}`}
            onClick={() => onViewChange('secured-links')}
          >
            <SecurityIcon size={18} color="currentColor" />
            <span>Secured Links</span>
          </button>
          <button
            className={`nav-item ${currentView === 'cloud-backup' ? 'active' : ''}`}
            onClick={() => onViewChange('cloud-backup')}
          >
            <CloudBackupIcon size={18} color="currentColor" />
            <span>Cloud Backup</span>
          </button>
          <button
            className={`nav-item ${currentView === 'analytics' ? 'active' : ''}`}
            onClick={() => onViewChange('analytics')}
          >
            <AnalyticsIcon size={18} color="currentColor" />
            <span>Analytics</span>
          </button>
          <button
            className={`nav-item ${currentView === 'security' ? 'active' : ''}`}
            onClick={() => onViewChange('security')}
          >
            <SecurityIcon size={18} color="currentColor" />
            <span>Security</span>
          </button>
          <button
            className={`nav-item ${currentView === 'integrations' ? 'active' : ''}`}
            onClick={() => onViewChange('integrations')}
          >
            <IntegrationIcon size={18} color="currentColor" />
            <span>Integrations</span>
          </button>
          <button
            className={`nav-item ${currentView === 'ai-assistant' ? 'active' : ''}`}
            onClick={() => onViewChange('ai-assistant')}
          >
            <AIAssistantIcon size={18} color="currentColor" />
            <span>AI Assistant</span>
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Community</div>
          <button
            className={`nav-item ${currentView === 'social' ? 'active' : ''}`}
            onClick={() => onViewChange('social')}
          >
            <SocialFeedIcon size={18} color="currentColor" />
            <span>Community Feed</span>
          </button>
          <button
            className={`nav-item ${currentView === 'learning' ? 'active' : ''}`}
            onClick={() => onViewChange('learning')}
          >
            <LearningIcon size={18} color="currentColor" />
            <span>Learning</span>
          </button>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Student</div>
          <button
            className={`nav-item ${currentView === 'student' ? 'active' : ''}`}
            onClick={() => onViewChange('student')}
          >
            <StudentIcon size={18} color="currentColor" />
            <span>Student</span>
          </button>
        </div>
      </nav>
      {currentFolderId && currentFolderId !== 'root' && (
        <button className="nav-item" onClick={onNavigateUp}>
          <BackIcon size={18} color="currentColor" />
          <span>Back</span>
        </button>
      )}
      <div className="sidebar-footer">
        <div className="storage-info">
          <div className="storage-label">
            Storage: {formatStorage(user?.storageUsed || 0)} /{' '}
            {formatStorage(user?.storageLimit || 0)}
          </div>
          <div className="storage-bar">
            <div
              className="storage-bar-fill"
              style={{ width: `${storagePercent}%` }}
            />
          </div>
        </div>
        <div className="user-info">
          <div className="user-name" style={{ color: '#ffffff' }}>{user?.name}</div>
          <button onClick={logout} className="logout-button">
            Logout
          </button>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;

