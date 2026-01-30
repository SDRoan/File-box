import React, { useState, useEffect } from 'react';
import { IntegrationIcon, LoadingIcon, CheckIcon, TrashIcon } from './Icons';
import { integrationsAPI } from '../services/api';
import './Integrations.css';

interface Integration {
  _id: string;
  provider: 'microsoft_teams' | 'zoom' | 'slack';
  providerEmail?: string;
  enabled: boolean;
  settings?: any;
  createdAt: string;
  updatedAt: string;
}

const Integrations: React.FC = () => {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState<string | null>(null);

  useEffect(() => {
    loadIntegrations();
  }, []);

  const loadIntegrations = async () => {
    try {
      setLoading(true);
      const data = await integrationsAPI.getIntegrations();
      setIntegrations(data);
    } catch (error: any) {
      console.error('Error loading integrations:', error);
      alert(error.response?.data?.message || 'Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const getIntegrationStatus = (provider: string) => {
    return integrations.find(int => int.provider === provider);
  };

  const handleConnect = async (provider: 'microsoft_teams' | 'zoom' | 'slack') => {
    try {
      setConnecting(provider);
      
      // Get OAuth URL from backend
      const response = await integrationsAPI.getAuthUrl(provider);
      
      if (response.authUrl) {
        // Redirect to OAuth provider
        window.location.href = response.authUrl;
      } else {
        throw new Error('Failed to get OAuth URL');
      }
    } catch (error: any) {
      setConnecting(null);
      alert(error.response?.data?.message || `Failed to initiate ${provider} connection`);
    }
  };

  useEffect(() => {
    // Check for OAuth callback success/error
    const urlParams = new URLSearchParams(window.location.search);
    const success = urlParams.get('success');
    const error = urlParams.get('error');
    
    if (success) {
      const providerName = success === 'microsoft_teams' ? 'Microsoft Teams' : 
                          success === 'zoom' ? 'Zoom' : 'Slack';
      alert(`${providerName} connected successfully!`);
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
      loadIntegrations();
    } else if (error) {
      alert(`Connection failed: ${error}`);
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []);

  const handleDisconnect = async (integrationId: string, providerName: string) => {
    if (!window.confirm(`Are you sure you want to disconnect ${providerName}?`)) {
      return;
    }

    try {
      await integrationsAPI.disconnectIntegration(integrationId);
      await loadIntegrations();
      alert(`${providerName} disconnected successfully`);
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to disconnect integration');
    }
  };

  const integrationConfigs = [
    {
      id: 'microsoft_teams',
      name: 'Microsoft Teams',
      description: 'Share files directly to Teams channels',
      icon: 'Teams',
      color: '#6264A7'
    },
    {
      id: 'zoom',
      name: 'Zoom',
      description: 'Share files in Zoom meetings',
      icon: 'Zoom',
      color: '#2D8CFF'
    },
    {
      id: 'slack',
      name: 'Slack',
      description: 'Share files to Slack channels',
      icon: '',
      color: '#4A154B'
    }
  ];

  return (
    <div className="integrations">
      <div className="integrations-header">
        <h2><IntegrationIcon size={24} color="currentColor" /> Integrations</h2>
        <p className="integrations-subtitle">Connect your favorite apps to share files seamlessly</p>
      </div>

      {loading ? (
        <div className="loading-state">
          <LoadingIcon size={40} color="#3b82f6" />
          <p>Loading integrations...</p>
        </div>
      ) : (
        <div className="integrations-grid">
          {integrationConfigs.map((config) => {
            const integration = getIntegrationStatus(config.id as any);
            const isConnected = !!integration;
            const isConnecting = connecting === config.id;

            return (
              <div key={config.id} className="integration-card">
                <div className="integration-card-header">
                  <div className="integration-icon" style={{ backgroundColor: `${config.color}20`, color: config.color }}>
                    <span className="integration-emoji">{config.icon}</span>
                  </div>
                  {isConnected && (
                    <span className="connected-badge">
                      <CheckIcon size={14} color="currentColor" />
                      Connected
                    </span>
                  )}
                </div>
                
                <h3>{config.name}</h3>
                <p>{config.description}</p>

                {isConnected && integration.providerEmail && (
                  <div className="integration-info">
                    <span className="integration-email">{integration.providerEmail}</span>
                  </div>
                )}

                <div className="integration-actions">
                  {isConnected ? (
                    <>
                      <button
                        className="btn-secondary"
                        onClick={() => {
                          // In production, this would open a share dialog
                          alert(`Share functionality will be available when you share files from the file browser.`);
                        }}
                      >
                        Share File
                      </button>
                      <button
                        className="btn-secondary"
                        onClick={() => {
                          if (window.confirm(`Do you want to reconnect ${config.name} with a different account?`)) {
                            handleConnect(config.id as any);
                          }
                        }}
                        title="Reconnect with a different account"
                      >
                        Change Account
                      </button>
                      <button
                        className="btn-danger"
                        onClick={() => handleDisconnect(integration._id, config.name)}
                      >
                        <TrashIcon size={16} color="currentColor" />
                        Disconnect
                      </button>
                    </>
                  ) : (
                    <button
                      className="btn-primary"
                      onClick={() => handleConnect(config.id as any)}
                      disabled={isConnecting}
                    >
                      {isConnecting ? 'Connecting...' : 'Connect'}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {integrations.length > 0 && (
        <div className="integrations-info">
          <h3>How to use integrations</h3>
          <ul>
            <li>Connect your accounts using the Connect button above</li>
            <li>When sharing files, you'll see options to share via connected integrations</li>
            <li>Files will be shared directly to your Teams channels, Slack channels, or Zoom meetings</li>
            <li>You can disconnect integrations at any time</li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default Integrations;
