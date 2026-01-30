import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from './Sidebar';
import FileBrowser from './FileBrowser';
import SearchBar from './SearchBar';
import TeamFolders from './TeamFolders';
import FileRequests from './FileRequests';
import RelationshipGraph from './RelationshipGraph';
import AnalyticsDashboard from './AnalyticsDashboard';
import RelationshipsList from './RelationshipsList';
import SocialFeed from './SocialFeed';
import GroupsList from './GroupsList';
import SecurityDashboard from './SecurityDashboard';
import StudentDashboard from './StudentDashboard';
import AIAssistant from './AIAssistant';
import SharedFiles from './SharedFiles';
import TemplatesLibrary from './TemplatesLibrary';
import WebShortcuts from './WebShortcuts';
import SecuredLinks from './SecuredLinks';
import CloudBackup from './CloudBackup';
import Integrations from './Integrations';
import Forums from './Forums';
import Learning from './Learning';
import { FileItemType } from '../types';
import './Dashboard.css';

const Dashboard: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [currentView, setCurrentView] = useState('files');

  // Sync currentView with URL pathname
  useEffect(() => {
    const path = location.pathname;
    if (path === '/integrations' || path.startsWith('/integrations')) {
      setCurrentView('integrations');
    } else if (path === '/cloud-backup' || path.startsWith('/cloud-backup')) {
      setCurrentView('cloud-backup');
    } else if (path === '/social' || path.startsWith('/social')) {
      setCurrentView('social');
    } else if (path === '/learning' || path.startsWith('/learning')) {
      setCurrentView('learning');
    } else if (path === '/secured-links' || path.startsWith('/secured-links')) {
      setCurrentView('secured-links');
    } else if (path === '/web-shortcuts' || path.startsWith('/web-shortcuts')) {
      setCurrentView('web-shortcuts');
    } else if (path === '/templates' || path.startsWith('/templates')) {
      setCurrentView('templates');
    } else if (path === '/shared-files' || path.startsWith('/shared-files')) {
      setCurrentView('shared-files');
    } else if (path === '/ai-assistant' || path.startsWith('/ai-assistant')) {
      setCurrentView('ai-assistant');
    } else if (path === '/security' || path.startsWith('/security')) {
      setCurrentView('security');
    } else if (path === '/student' || path.startsWith('/student')) {
      setCurrentView('student');
    } else if (path === '/groups' || path.startsWith('/groups')) {
      setCurrentView('groups');
    } else if (path === '/social' || path.startsWith('/social')) {
      setCurrentView('social');
    } else if (path === '/relationships' || path.startsWith('/relationships')) {
      setCurrentView('relationships');
    } else if (path === '/analytics' || path.startsWith('/analytics')) {
      setCurrentView('analytics');
    } else if (path === '/file-requests' || path.startsWith('/file-requests')) {
      setCurrentView('file-requests');
    } else if (path === '/team-folders' || path.startsWith('/team-folders')) {
      setCurrentView('team-folders');
    } else if (path === '/' || path === '') {
      setCurrentView('files');
    }
  }, [location.pathname]);
  const [folderStack, setFolderStack] = useState<string[]>(['root']);
  const [showGraph, setShowGraph] = useState(false);
  const [showAnalytics, setShowAnalytics] = useState(false);
  const [selectedTeamFolder, setSelectedTeamFolder] = useState<string | null>(null);
  const [relationshipsRefreshKey, setRelationshipsRefreshKey] = useState(0);

  const currentFolderId = folderStack[folderStack.length - 1];

  const handleFolderClick = (folderId: string) => {
    setFolderStack([...folderStack, folderId]);
    setCurrentView('files');
  };

  const handleSearchFileClick = (file: FileItemType) => {
    // Navigate to the file's folder if it's in a folder
    if (file.parentFolder) {
      // We'd need to build the path, but for now just show the file
      setCurrentView('files');
    } else {
      setFolderStack(['root']);
      setCurrentView('files');
    }
  };

  const handleNavigateUp = () => {
    if (folderStack.length > 1) {
      setFolderStack(folderStack.slice(0, -1));
    }
  };

  const handleViewChange = (view: string) => {
    setCurrentView(view);
    if (view === 'files') {
      setFolderStack(['root']);
      setSelectedTeamFolder(null);
    }
    if (view === 'teams') {
      setSelectedTeamFolder(null);
      setFolderStack(['root']);
    }
    if (view === 'analytics') {
      setShowAnalytics(true);
    }
    if (view === 'relationships') {
      // Force refresh of relationships when navigating to this view
      setRelationshipsRefreshKey(prev => prev + 1);
    }
  };

  return (
    <div className="dashboard">
      <Sidebar
        currentView={currentView}
        onViewChange={handleViewChange}
        onNavigateUp={handleNavigateUp}
        currentFolderId={currentFolderId}
      />
      <div className="dashboard-content">
        <div className="dashboard-header">
          <div className="dashboard-header-content">
            <div className="dashboard-header-left">
              <SearchBar
                onFileClick={handleSearchFileClick}
                onFolderClick={handleFolderClick}
              />
            </div>
            <div className="dashboard-header-right">
              {/* Quick actions can be added here */}
            </div>
          </div>
        </div>
        {currentView === 'files' && (
          <FileBrowser
            currentFolderId={currentFolderId}
            onFolderClick={handleFolderClick}
            onNavigateUp={handleNavigateUp}
            showTrash={false}
            folderStack={folderStack}
          />
        )}
        {currentView === 'trash' && (
          <FileBrowser
            currentFolderId={undefined}
            onFolderClick={handleFolderClick}
            onNavigateUp={handleNavigateUp}
            showTrash={true}
            folderStack={['root']}
          />
        )}
        {currentView === 'shared' && (
          <SharedFiles />
        )}
        {currentView === 'starred' && (
          <FileBrowser
            currentFolderId={undefined}
            onFolderClick={handleFolderClick}
            onNavigateUp={handleNavigateUp}
            showTrash={false}
            showStarred={true}
            folderStack={['root']}
          />
        )}
        {currentView === 'teams' && !selectedTeamFolder && (
          <TeamFolders
            onClose={() => setCurrentView('files')}
            onFolderSelect={(folderId) => {
              setSelectedTeamFolder(folderId);
              setFolderStack([folderId]);
            }}
          />
        )}
        {currentView === 'teams' && selectedTeamFolder && (
          <>
            <div style={{ padding: '1rem', borderBottom: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <button
                onClick={() => {
                  setSelectedTeamFolder(null);
                  setFolderStack(['root']);
                }}
                style={{ padding: '0.5rem 1rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-md)', cursor: 'pointer' }}
              >
                ← Back to Team Folders
              </button>
            </div>
            <FileBrowser
              currentFolderId={selectedTeamFolder}
              onFolderClick={handleFolderClick}
              onNavigateUp={() => {
                if (folderStack.length > 1) {
                  setFolderStack(folderStack.slice(0, -1));
                } else {
                  setSelectedTeamFolder(null);
                  setFolderStack(['root']);
                }
              }}
              showTrash={false}
              isTeamFolder={true}
              teamFolderId={selectedTeamFolder}
            />
          </>
        )}
        {currentView === 'requests' && (
          <FileRequests
            onClose={() => setCurrentView('files')}
          />
        )}
        {currentView === 'relationships' && (
          <RelationshipsList key={relationshipsRefreshKey} />
        )}
        {currentView === 'social' && (
          <SocialFeed />
        )}
        {currentView === 'security' && (
          <SecurityDashboard />
        )}
        {currentView === 'student' && (
          <StudentDashboard />
        )}
        {currentView === 'ai-assistant' && (
          <AIAssistant />
        )}
        {currentView === 'templates' && (
          <TemplatesLibrary />
        )}
        {currentView === 'shortcuts' && (
          <WebShortcuts />
        )}
        {currentView === 'secured-links' && (
          <SecuredLinks />
        )}
        {currentView === 'cloud-backup' && (
          <CloudBackup />
        )}
        {currentView === 'integrations' && (
          <Integrations />
        )}
        {currentView === 'learning' && (
          <Learning />
        )}
      </div>
      {showGraph && (
        <RelationshipGraph onClose={() => setShowGraph(false)} />
      )}
      {showAnalytics && (
        <AnalyticsDashboard onClose={() => {
          setShowAnalytics(false);
          setCurrentView('files');
        }} />
      )}
    </div>
  );
};

export default Dashboard;

