import React, { useState, useEffect } from 'react';
import { teamFoldersAPI, usersAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import TeamFolderChat from './TeamFolderChat';
import './TeamFolders.css';

interface TeamMember {
  user: {
    _id: string;
    name: string;
    email: string;
  };
  role: 'admin' | 'editor' | 'viewer';
  joinedAt: string;
}

interface TeamFolder {
  _id: string;
  name: string;
  owner: {
    name: string;
    email: string;
  };
  members: TeamMember[];
  createdAt: string;
}

interface TeamFoldersProps {
  onClose: () => void;
  onFolderSelect: (folderId: string) => void;
}

const TeamFolders: React.FC<TeamFoldersProps> = ({ onClose, onFolderSelect }) => {
  const { user } = useAuth();
  const [teamFolders, setTeamFolders] = useState<TeamFolder[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [selectedFolder, setSelectedFolder] = useState<TeamFolder | null>(null);
  const [showAddMember, setShowAddMember] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [folderSearchQuery, setFolderSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'name' | 'date' | 'members'>('date');
  const [showFolderMenu, setShowFolderMenu] = useState<string | null>(null);
  const [showRenameModal, setShowRenameModal] = useState(false);
  const [renameValue, setRenameValue] = useState('');
  const [folderStats, setFolderStats] = useState<{ [key: string]: { fileCount: number; totalSize: number } }>({});
  const [showChat, setShowChat] = useState(false);
  const [chatFolderId, setChatFolderId] = useState<string | null>(null);
  const [chatFolderName, setChatFolderName] = useState<string>('');

  useEffect(() => {
    loadTeamFolders();
  }, []);

  useEffect(() => {
    // Load stats for each folder
    teamFolders.forEach(folder => {
      loadFolderStats(folder._id);
    });
  }, [teamFolders]);

  const loadFolderStats = async (folderId: string) => {
    try {
      const data = await teamFoldersAPI.getTeamFolderFiles(folderId);
      const fileCount = (data.files?.length || 0) + (data.folders?.length || 0);
      const totalSize = data.files?.reduce((sum: number, f: any) => sum + (f.size || 0), 0) || 0;
      setFolderStats(prev => ({ ...prev, [folderId]: { fileCount, totalSize } }));
    } catch (error) {
      console.error('Error loading folder stats:', error);
    }
  };

  const loadTeamFolders = async () => {
    try {
      setLoading(true);
      const data = await teamFoldersAPI.getTeamFolders();
      setTeamFolders(data);
    } catch (error) {
      console.error('Error loading team folders:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFolderName.trim()) return;

    try {
      await teamFoldersAPI.createTeamFolder(newFolderName.trim());
      setNewFolderName('');
      setShowCreateModal(false);
      loadTeamFolders();
    } catch (error) {
      alert('Failed to create team folder');
    }
  };

  const handleSearchUsers = async (query: string) => {
    if (query.length < 2) {
      setSearchResults([]);
      return;
    }

    try {
      const results = await usersAPI.searchUsers(query);
      setSearchResults(results);
    } catch (error) {
      console.error('Error searching users:', error);
    }
  };

  const handleAddMember = async (userId: string, role: 'admin' | 'editor' | 'viewer') => {
    if (!selectedFolder) return;

    try {
      await teamFoldersAPI.addMember(selectedFolder._id, userId, role);
      setShowAddMember(false);
      setSearchQuery('');
      setSearchResults([]);
      loadTeamFolders();
    } catch (error) {
      alert('Failed to add member');
    }
  };

  const handleRemoveMember = async (userId: string) => {
    if (!selectedFolder) return;
    if (!window.confirm('Remove this member?')) return;

    try {
      await teamFoldersAPI.removeMember(selectedFolder._id, userId);
      loadTeamFolders();
    } catch (error) {
      alert('Failed to remove member');
    }
  };

  const handleChangeRole = async (userId: string, newRole: 'admin' | 'editor' | 'viewer') => {
    if (!selectedFolder) return;
    try {
      await teamFoldersAPI.addMember(selectedFolder._id, userId, newRole);
      loadTeamFolders();
    } catch (error) {
      alert('Failed to change role');
    }
  };

  const handleRenameFolder = async () => {
    if (!selectedFolder || !renameValue.trim()) return;
    try {
      // Add rename API call when backend supports it
      alert('Rename functionality - backend endpoint needed');
      setShowRenameModal(false);
      setRenameValue('');
    } catch (error) {
      alert('Failed to rename folder');
    }
  };

  const handleDeleteFolder = async (folderId: string) => {
    if (!window.confirm('Are you sure you want to delete this team folder? This will delete all files and folders inside. This action cannot be undone.')) {
      return;
    }
    try {
      await teamFoldersAPI.deleteTeamFolder(folderId);
      setShowFolderMenu(null);
      loadTeamFolders();
    } catch (error: any) {
      console.error('Error deleting team folder:', error);
      alert(error.response?.data?.message || 'Failed to delete team folder');
    }
  };

  const handleLeaveFolder = async (folderId: string) => {
    if (!window.confirm('Leave this team folder?')) return;
    try {
      // Add leave API call when backend supports it
      alert('Leave functionality - backend endpoint needed');
      loadTeamFolders();
    } catch (error) {
      alert('Failed to leave folder');
    }
  };

  // Filter and sort folders
  const filteredAndSortedFolders = teamFolders
    .filter(folder => {
      if (!folderSearchQuery) return true;
      const query = folderSearchQuery.toLowerCase();
      return folder.name.toLowerCase().includes(query) ||
        folder.owner.name.toLowerCase().includes(query) ||
        folder.owner.email.toLowerCase().includes(query);
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'name':
          return a.name.localeCompare(b.name);
        case 'members':
          return b.members.length - a.members.length;
        case 'date':
        default:
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      }
    });

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getUserInitials = (name: string) => {
    return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'admin': return '#e74c3c';
      case 'editor': return '#3498db';
      case 'viewer': return '#95a5a6';
      default: return '#95a5a6';
    }
  };

  const isOwner = (folder: TeamFolder) => {
    return folder.owner.email === user?.email;
  };

  const getUserRole = (folder: TeamFolder) => {
    if (isOwner(folder)) return 'owner';
    const member = folder.members.find(m => m.user.email === user?.email);
    return member?.role || null;
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content team-folders-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Team Folders</h2>
          <button onClick={onClose} className="close-btn">×</button>
        </div>

        <div className="team-folders-actions">
          <div className="team-folders-header-controls">
            <div className="search-box-team">
              <input
                type="text"
                placeholder="Search team folders..."
                value={folderSearchQuery}
                onChange={(e) => setFolderSearchQuery(e.target.value)}
                className="search-input-team"
              />
              <span className="search-icon-team"></span>
            </div>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="sort-select-team"
            >
              <option value="date">Sort by Date</option>
              <option value="name">Sort by Name</option>
              <option value="members">Sort by Members</option>
            </select>
            <button onClick={() => setShowCreateModal(true)} className="action-button">
              + Create Team Folder
            </button>
          </div>
        </div>

        {loading ? (
          <div className="loading">Loading...</div>
        ) : (
          <div className="team-folders-list">
            {filteredAndSortedFolders.length === 0 ? (
              <div className="empty-state">
                {folderSearchQuery ? 'No folders match your search' : 'No team folders yet'}
              </div>
            ) : (
              filteredAndSortedFolders.map((folder) => {
                const stats = folderStats[folder._id];
                const userRole = getUserRole(folder);
                const isFolderOwner = isOwner(folder);
                
                return (
                  <div
                    key={folder._id}
                    className="team-folder-item"
                    onClick={() => {
                      setSelectedFolder(folder);
                      onFolderSelect(folder._id);
                    }}
                  >
                    <div className="team-folder-icon"></div>
                    <div className="team-folder-info">
                      <div className="team-folder-header">
                        <div className="team-folder-name">{folder.name}</div>
                        {userRole && (
                          <span 
                            className="role-badge"
                            style={{ backgroundColor: getRoleBadgeColor(userRole) }}
                          >
                            {userRole === 'owner' ? ' Owner' : userRole.charAt(0).toUpperCase() + userRole.slice(1)}
                          </span>
                        )}
                      </div>
                      <div className="team-folder-meta">
                        <span className="meta-item">
                           {folder.members.length} member{folder.members.length !== 1 ? 's' : ''}
                        </span>
                        {stats && (
                          <>
                            <span className="meta-item">
                               {stats.fileCount} item{stats.fileCount !== 1 ? 's' : ''}
                            </span>
                            <span className="meta-item">
                               {formatFileSize(stats.totalSize)}
                            </span>
                          </>
                        )}
                        <span className="meta-item">
                           {new Date(folder.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="team-folder-members-preview">
                        {folder.members.slice(0, 5).map((member, idx) => (
                          <div
                            key={member.user._id}
                            className="member-avatar"
                            title={`${member.user.name} (${member.role})`}
                            style={{ backgroundColor: getRoleBadgeColor(member.role) }}
                          >
                            {getUserInitials(member.user.name)}
                          </div>
                        ))}
                        {folder.members.length > 5 && (
                          <div className="member-avatar more-members">
                            +{folder.members.length - 5}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="team-folder-actions">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setChatFolderId(folder._id);
                          setChatFolderName(folder.name);
                          setShowChat(true);
                        }}
                        className="chat-btn"
                        title="Open chat"
                      >
                         Chat
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFolder(folder);
                          setShowAddMember(true);
                        }}
                        className="add-member-btn"
                      >
                        + Add Member
                      </button>
                      <div className="folder-menu-wrapper">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setShowFolderMenu(showFolderMenu === folder._id ? null : folder._id);
                          }}
                          className="folder-menu-btn"
                        >
                          ⋮
                        </button>
                        {showFolderMenu === folder._id && (
                          <div className="folder-menu" onClick={(e) => e.stopPropagation()}>
                            {isFolderOwner && (
                              <>
                                <button
                                  onClick={() => {
                                    setRenameValue(folder.name);
                                    setShowRenameModal(true);
                                    setShowFolderMenu(null);
                                  }}
                                  className="menu-item"
                                >
                                  Edit Rename
                                </button>
                                <button
                                  onClick={() => {
                                    handleDeleteFolder(folder._id);
                                    setShowFolderMenu(null);
                                  }}
                                  className="menu-item delete"
                                >
                                  Delete Delete
                                </button>
                              </>
                            )}
                            {!isFolderOwner && (
                              <button
                                onClick={() => {
                                  handleLeaveFolder(folder._id);
                                  setShowFolderMenu(null);
                                }}
                                className="menu-item delete"
                              >
                                🚪 Leave Folder
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}

        {showCreateModal && (
          <div className="modal-overlay-inner" onClick={() => setShowCreateModal(false)}>
            <div className="modal-content-small" onClick={(e) => e.stopPropagation()}>
              <h3>Create Team Folder</h3>
              <form onSubmit={handleCreateFolder}>
                <input
                  type="text"
                  value={newFolderName}
                  onChange={(e) => setNewFolderName(e.target.value)}
                  placeholder="Folder Name"
                  className="form-input"
                  autoFocus
                />
                <div className="modal-actions">
                  <button type="button" onClick={() => setShowCreateModal(false)} className="cancel-button">
                    Cancel
                  </button>
                  <button type="submit" className="action-button">Create</button>
                </div>
              </form>
            </div>
          </div>
        )}

        {showAddMember && selectedFolder && (
          <div className="modal-overlay-inner" onClick={() => setShowAddMember(false)}>
            <div className="modal-content-small" onClick={(e) => e.stopPropagation()}>
              <h3>Add Member to {selectedFolder.name}</h3>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  handleSearchUsers(e.target.value);
                }}
                placeholder="Search users by name or email..."
                className="form-input"
              />
              {searchResults.length > 0 && (
                <div className="search-results">
                  {searchResults.map((result) => (
                    <div key={result._id} className="search-result-item">
                      <div>
                        <div className="result-name">{result.name}</div>
                        <div className="result-email">{result.email}</div>
                      </div>
                      <select
                        onChange={(e) => handleAddMember(result._id, e.target.value as any)}
                        className="role-select"
                      >
                        <option value="viewer">Viewer</option>
                        <option value="editor">Editor</option>
                        <option value="admin">Admin</option>
                      </select>
                    </div>
                  ))}
                </div>
              )}
              <div className="current-members">
                <h4>Current Members ({selectedFolder.members.length})</h4>
                {selectedFolder.members.map((member) => {
                  const isMemberOwner = selectedFolder.owner.email === member.user.email;
                  const canManage = selectedFolder.owner.email === user?.email;
                  
                  return (
                    <div key={member.user._id} className="member-item">
                      <div className="member-info">
                        <div 
                          className="member-avatar-large"
                          style={{ backgroundColor: getRoleBadgeColor(member.role) }}
                        >
                          {getUserInitials(member.user.name)}
                        </div>
                        <div className="member-details">
                          <div className="member-name">
                            {member.user.name}
                            {isMemberOwner && <span className="owner-badge"> Owner</span>}
                          </div>
                          <div className="member-email">{member.user.email}</div>
                          {canManage && !isMemberOwner && (
                            <select
                              value={member.role}
                              onChange={(e) => handleChangeRole(member.user._id, e.target.value as any)}
                              className="role-select-inline"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <option value="viewer">Viewer</option>
                              <option value="editor">Editor</option>
                              <option value="admin">Admin</option>
                            </select>
                          )}
                          {!canManage && (
                            <span 
                              className="role-badge-inline"
                              style={{ backgroundColor: getRoleBadgeColor(member.role) }}
                            >
                              {member.role.charAt(0).toUpperCase() + member.role.slice(1)}
                            </span>
                          )}
                        </div>
                      </div>
                      {canManage && !isMemberOwner && (
                        <button
                          onClick={() => handleRemoveMember(member.user._id)}
                          className="remove-member-btn"
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
              <button onClick={() => setShowAddMember(false)} className="action-button">
                Done
              </button>
            </div>
          </div>
        )}

        {showRenameModal && selectedFolder && (
          <div className="modal-overlay-inner" onClick={() => setShowRenameModal(false)}>
            <div className="modal-content-small" onClick={(e) => e.stopPropagation()}>
              <h3>Rename Team Folder</h3>
              <form onSubmit={(e) => { e.preventDefault(); handleRenameFolder(); }}>
                <input
                  type="text"
                  value={renameValue}
                  onChange={(e) => setRenameValue(e.target.value)}
                  placeholder="New folder name"
                  className="form-input"
                  autoFocus
                />
                <div className="modal-actions">
                  <button type="button" onClick={() => setShowRenameModal(false)} className="cancel-button">
                    Cancel
                  </button>
                  <button type="submit" className="action-button">Rename</button>
                </div>
              </form>
            </div>
          </div>
        )}

        {showChat && chatFolderId && (
          <div className="chat-modal-overlay" onClick={() => setShowChat(false)}>
            <div className="chat-modal-content" onClick={(e) => e.stopPropagation()}>
              <TeamFolderChat
                teamFolderId={chatFolderId}
                teamFolderName={chatFolderName}
                onClose={() => setShowChat(false)}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TeamFolders;










