import React, { useState, useEffect } from 'react';
import { shareAPI, usersAPI, integrationsAPI } from '../services/api';
import { IntegrationIcon } from './Icons';
import './ShareModal.css';

interface ShareModalProps {
  fileId: string;
  fileName: string;
  onClose: () => void;
  onShareCreated: (shareLink: string) => void;
}

const ShareModal: React.FC<ShareModalProps> = ({
  fileId,
  fileName,
  onClose,
  onShareCreated,
}) => {
  const [accessType, setAccessType] = useState<'view' | 'edit'>('view');
  const [password, setPassword] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [loading, setLoading] = useState(false);
  
  // User sharing
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [allUsers, setAllUsers] = useState<any[]>([]);
  const [selectedUsers, setSelectedUsers] = useState<Set<string>>(new Set());
  const [sharedUsers, setSharedUsers] = useState<any[]>([]);
  const [showAllUsers, setShowAllUsers] = useState(false);
  const [loadingUsers, setLoadingUsers] = useState(false);
  
  // Integration sharing
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [loadingIntegrations, setLoadingIntegrations] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState<string | null>(null);
  const [integrationChannel, setIntegrationChannel] = useState('');
  const [integrationMessage, setIntegrationMessage] = useState('');
  const [sharingViaIntegration, setSharingViaIntegration] = useState(false);
  const [activeTab, setActiveTab] = useState<'users' | 'integrations'>('users');

  useEffect(() => {
    if (userSearchQuery.length >= 2) {
      handleSearchUsers(userSearchQuery);
    } else {
      setSearchResults([]);
    }
  }, [userSearchQuery]);

  useEffect(() => {
    if (showAllUsers && allUsers.length === 0) {
      loadAllUsers();
    }
  }, [showAllUsers]);

  useEffect(() => {
    if (activeTab === 'integrations') {
      loadIntegrations();
    }
  }, [activeTab]);

  const loadIntegrations = async () => {
    try {
      setLoadingIntegrations(true);
      const data = await integrationsAPI.getIntegrations();
      setIntegrations(data.filter((int: any) => int.enabled));
    } catch (error) {
      console.error('Error loading integrations:', error);
    } finally {
      setLoadingIntegrations(false);
    }
  };

  const handleShareViaIntegration = async () => {
    if (!selectedIntegration) return;

    try {
      setSharingViaIntegration(true);
      const result = await integrationsAPI.shareFile(selectedIntegration, {
        fileId,
        channel: integrationChannel || undefined,
        message: integrationMessage || undefined,
      });
      
      const integration = integrations.find((int: any) => int._id === selectedIntegration);
      const integrationName = integration ? getIntegrationName(integration.provider) : 'integration';
      
      let successMessage = `File shared successfully via ${integrationName}!`;
      if (result?.result?.shareLink) {
        successMessage += `\n\nShare link: ${result.result.shareLink}`;
      }
      if (result?.result?.channel) {
        successMessage += `\n\nLocation: ${result.result.channel}`;
      }
      
      alert(successMessage);
      setSelectedIntegration(null);
      setIntegrationChannel('');
      setIntegrationMessage('');
      onShareCreated('');
      onClose();
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Failed to share via integration';
      console.error('Share error:', error);
      alert(`Error: ${errorMessage}`);
    } finally {
      setSharingViaIntegration(false);
    }
  };

  const getIntegrationName = (provider: string) => {
    switch (provider) {
      case 'microsoft_teams':
        return 'Microsoft Teams';
      case 'zoom':
        return 'Zoom';
      case 'slack':
        return 'Slack';
      default:
        return provider;
    }
  };

  const loadAllUsers = async () => {
    try {
      setLoadingUsers(true);
      const users = await usersAPI.getAllUsers();
      setAllUsers(users);
    } catch (error) {
      console.error('Error loading users:', error);
    } finally {
      setLoadingUsers(false);
    }
  };

  const handleSearchUsers = async (query: string) => {
    if (query.length < 2) {
      setSearchResults([]);
      return;
    }

    try {
      const results = await usersAPI.searchUsers(query);
      setSearchResults(results.filter((u: any) => !selectedUsers.has(u._id)));
    } catch (error) {
      console.error('Error searching users:', error);
    }
  };

  const handleSelectUser = (userId: string) => {
    setSelectedUsers(prev => {
      const newSet = new Set(prev);
      if (newSet.has(userId)) {
        newSet.delete(userId);
      } else {
        newSet.add(userId);
      }
      return newSet;
    });
    setUserSearchQuery('');
    setSearchResults([]);
  };

  const handleShareWithUsers = async () => {
    if (selectedUsers.size === 0) return;

    try {
      setLoading(true);
      const expiresDate = expiresAt ? new Date(expiresAt).toISOString() : undefined;
      
      await Promise.all(
        Array.from(selectedUsers).map(userId =>
          shareAPI.shareWithUser(fileId, userId, accessType, password || undefined, expiresDate)
        )
      );
      alert(`Successfully shared with ${selectedUsers.size} user(s)!`);
      setSelectedUsers(new Set());
      setPassword('');
      setExpiresAt('');
      onShareCreated('');
      onClose();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to share with users');
    } finally {
      setLoading(false);
    }
  };

  const getMinDate = () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    return tomorrow.toISOString().split('T')[0];
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content share-modal" onClick={(e) => e.stopPropagation()}>
        <h2>Share "{fileName}"</h2>

        <div className="share-tabs">
          <button
            className={`share-tab ${activeTab === 'users' ? 'active' : ''}`}
            onClick={() => setActiveTab('users')}
          >
            Share with Users
          </button>
          <button
            className={`share-tab ${activeTab === 'integrations' ? 'active' : ''}`}
            onClick={() => setActiveTab('integrations')}
          >
            <IntegrationIcon size={16} color="currentColor" />
            Share via Integrations
          </button>
        </div>

        {activeTab === 'users' && (
        <div className="share-with-user-section">
            <div className="share-info-banner">
              <span className="info-icon"></span>
              <span>Only users with accounts on this platform can be shared with</span>
            </div>
            
            <div className="form-group">
              <div className="search-header">
                <label>Search Registered Users</label>
                <button
                  type="button"
                  onClick={() => {
                    setShowAllUsers(!showAllUsers);
                    if (!showAllUsers && allUsers.length === 0) {
                      loadAllUsers();
                    }
                  }}
                  className="browse-users-btn"
                >
                  {showAllUsers ? ' Search Mode' : ' Browse All Users'}
                </button>
              </div>
              
              {!showAllUsers && (
                <input
                  type="text"
                  placeholder="Search by name or email..."
                  value={userSearchQuery}
                  onChange={(e) => setUserSearchQuery(e.target.value)}
                  className="form-input"
                />
              )}
              
              {showAllUsers && (
                <div className="all-users-info">
                  <span className="users-count">Showing {allUsers.length} registered users</span>
                </div>
              )}
              
              {loadingUsers && (
                <div className="loading-users">Loading users...</div>
              )}
              
              {!showAllUsers && searchResults.length > 0 && (
                <div className="user-search-results">
                  <div className="results-header">
                    Found {searchResults.length} user{searchResults.length !== 1 ? 's' : ''}
                  </div>
                  {searchResults.map(user => (
                    <div
                      key={user._id}
                      className="user-result-item"
                      onClick={() => handleSelectUser(user._id)}
                    >
                      <div className="user-avatar-share">
                        {(user.name || user.email)[0].toUpperCase()}
                      </div>
                      <div className="user-info-share">
                        <div className="user-name-share">{user.name}</div>
                        <div className="user-email-share">{user.email}</div>
                      </div>
                      <span className="add-user-icon">+</span>
                    </div>
                  ))}
                </div>
              )}
              
              {showAllUsers && allUsers.length > 0 && (
                <div className="user-search-results all-users-list">
                  <div className="results-header">
                    All Registered Users ({allUsers.length})
                  </div>
                  {allUsers
                    .filter((u: any) => !selectedUsers.has(u._id))
                    .map(user => (
                      <div
                        key={user._id}
                        className="user-result-item"
                        onClick={() => handleSelectUser(user._id)}
                      >
                        <div className="user-avatar-share">
                          {(user.name || user.email)[0].toUpperCase()}
                        </div>
                        <div className="user-info-share">
                          <div className="user-name-share">{user.name}</div>
                          <div className="user-email-share">{user.email}</div>
                        </div>
                        <span className="add-user-icon">+</span>
                      </div>
                    ))}
                </div>
              )}
              
              {!showAllUsers && userSearchQuery.length >= 2 && searchResults.length === 0 && (
                <div className="no-users-found">
                  <span className="no-users-icon"></span>
                  <span>No registered users found matching "{userSearchQuery}"</span>
                </div>
              )}
            </div>

            {selectedUsers.size > 0 && (
              <div className="selected-users-section">
                <label>Selected Registered Users ({selectedUsers.size})</label>
                <div className="selected-users-list">
                  {Array.from(selectedUsers).map(userId => {
                    const user = searchResults.find((u: any) => u._id === userId) || 
                                 allUsers.find((u: any) => u._id === userId) ||
                                 sharedUsers.find((u: any) => u._id === userId);
                    if (!user) return null;
                    return (
                      <div key={userId} className="selected-user-tag">
                        <span className="user-avatar-small">
                          {(user.name || user.email)[0].toUpperCase()}
                        </span>
                        <span>{user.name || user.email}</span>
                        <button
                          type="button"
                          onClick={() => handleSelectUser(userId)}
                          className="remove-user-btn"
                        >
                          ×
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="form-group">
              <label>Permission</label>
              <select
                value={accessType}
                onChange={(e) => setAccessType(e.target.value as 'view' | 'edit')}
                className="form-input"
              >
                <option value="view">View Only</option>
                <option value="edit">Can Edit</option>
              </select>
            </div>

            <div className="form-group">
              <label>
                Password Protection (Optional)
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Leave empty for no password"
                  className="form-input"
                />
              </label>
            </div>

            <div className="form-group">
              <label>
                Expiration Date (Optional)
                <input
                  type="date"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                  min={getMinDate()}
                  className="form-input"
                />
              </label>
            </div>

            <div className="modal-actions">
              <button type="button" onClick={onClose} className="cancel-button" disabled={loading}>
                Cancel
              </button>
              <button
                type="button"
                onClick={handleShareWithUsers}
                className="action-button"
                disabled={loading || selectedUsers.size === 0}
              >
                {loading ? 'Sharing...' : `Share with ${selectedUsers.size} User(s)`}
              </button>
            </div>
          </div>
        )}

        {activeTab === 'integrations' && (
          <div className="share-with-integrations-section">
            {loadingIntegrations ? (
              <div className="loading-integrations">Loading integrations...</div>
            ) : integrations.length === 0 ? (
              <div className="no-integrations">
                <IntegrationIcon size={48} color="#ccc" />
                <p>No integrations connected</p>
                <p className="no-integrations-hint">Go to Integrations page to connect Microsoft Teams, Zoom, or Slack</p>
              </div>
            ) : (
              <>
                <div className="form-group">
                  <label>Select Integration</label>
                  <div className="integrations-list">
                    {integrations.map((integration) => (
                      <div
                        key={integration._id}
                        className={`integration-option ${selectedIntegration === integration._id ? 'selected' : ''}`}
                        onClick={() => setSelectedIntegration(integration._id)}
                      >
                        <div className="integration-option-icon">
                          {integration.provider === 'microsoft_teams' && 'Teams'}
                          {integration.provider === 'zoom' && 'Zoom'}
                          {integration.provider === 'slack' && ''}
                        </div>
                        <div className="integration-option-info">
                          <div className="integration-option-name">
                            {getIntegrationName(integration.provider)}
                          </div>
                          {integration.providerEmail && (
                            <div className="integration-option-email">
                              {integration.providerEmail}
                            </div>
                          )}
                        </div>
                        {selectedIntegration === integration._id && (
                          <span className="integration-selected-check"></span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {selectedIntegration && (
                  <>
                    {(integrations.find((int: any) => int._id === selectedIntegration)?.provider === 'slack' ||
                      integrations.find((int: any) => int._id === selectedIntegration)?.provider === 'microsoft_teams') && (
                      <div className="form-group">
                        <label>Channel (Optional)</label>
                        <input
                          type="text"
                          value={integrationChannel}
                          onChange={(e) => setIntegrationChannel(e.target.value)}
                          placeholder="e.g., #general or channel-name"
                          className="form-input"
                        />
                      </div>
                    )}

                    <div className="form-group">
                      <label>Message (Optional)</label>
                      <textarea
                        value={integrationMessage}
                        onChange={(e) => setIntegrationMessage(e.target.value)}
                        placeholder="Add a message to accompany the file..."
                        className="form-input form-textarea"
                        rows={3}
                      />
                    </div>

                    <div className="modal-actions">
                      <button type="button" onClick={onClose} className="cancel-button" disabled={sharingViaIntegration}>
                        Cancel
                      </button>
                      <button
                        type="button"
                        onClick={handleShareViaIntegration}
                        className="action-button"
                        disabled={sharingViaIntegration}
                      >
                        {sharingViaIntegration ? 'Sharing...' : 'Share via Integration'}
                      </button>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ShareModal;










