import React, { useState, useEffect } from 'react';
import { securityAPI } from '../services/api';
import { LockIcon, DocumentIcon, FolderIcon, SecurityIcon, AnalyticsIcon, KeyIcon, ShieldIcon, CheckIcon } from './Icons';
import './SecurityDashboard.css';

interface AuditLog {
  _id: string;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  details: any;
  ipAddress: string | null;
  userAgent: string | null;
  status: 'success' | 'failure' | 'denied';
  timestamp: string;
  userId?: {
    name: string;
    email: string;
  };
}

interface SecurityDashboardData {
  recentLogs: AuditLog[];
  securitySettings: {
    mfaEnabled: boolean;
    sessionTimeout: number;
    encryptionEnabled: boolean;
    requireIpWhitelist: boolean;
  };
  stats: {
    totalFiles: number;
    confidentialFiles: number;
    recentAccessCount: number;
  };
  recentAccess: any[];
  failedLogins: AuditLog[];
}

const SecurityDashboard: React.FC = () => {
  const [data, setData] = useState<SecurityDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState<'overview' | 'logs' | 'settings'>('overview');
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [logsPage, setLogsPage] = useState(1);
  const [logsTotal, setLogsTotal] = useState(0);

  useEffect(() => {
    loadDashboard();
  }, []);

  useEffect(() => {
    if (selectedTab === 'logs') {
      loadAuditLogs();
    }
  }, [selectedTab, logsPage]);

  const loadDashboard = async () => {
    try {
      const response = await securityAPI.getDashboard();
      setData(response);
      setLoading(false);
    } catch (error) {
      console.error('Error loading security dashboard:', error);
      setLoading(false);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const response = await securityAPI.getAuditLogs({ page: logsPage, limit: 50 });
      setAuditLogs(response.logs);
      setLogsTotal(response.total);
    } catch (error) {
      console.error('Error loading audit logs:', error);
    }
  };

  const getActionIcon = (action: string) => {
    if (action.includes('login')) return <LockIcon size={18} color="currentColor" />;
    if (action.includes('file')) return <DocumentIcon size={18} color="currentColor" />;
    if (action.includes('folder')) return <FolderIcon size={18} color="currentColor" />;
    if (action.includes('security')) return <SecurityIcon size={18} color="currentColor" />;
    return <DocumentIcon size={18} color="currentColor" />;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return '#10b981';
      case 'failure': return '#ef4444';
      case 'denied': return '#f59e0b';
      default: return '#6b7280';
    }
  };

  const getClassificationColor = (classification: string) => {
    switch (classification) {
      case 'Public': return '#10b981';
      case 'Internal': return '#3b82f6';
      case 'Confidential': return '#f59e0b';
      case 'Top Secret': return '#ef4444';
      default: return '#6b7280';
    }
  };

  if (loading) {
    return <div className="security-dashboard-loading">Loading security dashboard...</div>;
  }

  if (!data) {
    return <div className="security-dashboard-error">Failed to load security data</div>;
  }

  return (
    <div className="security-dashboard">
      <div className="security-header">
        <h1>
          <SecurityIcon size={32} color="currentColor" style={{ display: 'inline-block', marginRight: '0.5rem', verticalAlign: 'middle' }} />
          Security Dashboard
        </h1>
        <p>Monitor and manage your security settings and activity</p>
      </div>

      <div className="security-tabs">
        <button
          className={selectedTab === 'overview' ? 'active' : ''}
          onClick={() => setSelectedTab('overview')}
        >
          Overview
        </button>
        <button
          className={selectedTab === 'logs' ? 'active' : ''}
          onClick={() => setSelectedTab('logs')}
        >
          Audit Logs
        </button>
        <button
          className={selectedTab === 'settings' ? 'active' : ''}
          onClick={() => setSelectedTab('settings')}
        >
          Security Settings
        </button>
      </div>

      {selectedTab === 'overview' && (
        <div className="security-overview">
          <div className="security-stats-grid">
            <div className="stat-card">
              <div className="stat-icon">
                <AnalyticsIcon size={32} color="currentColor" />
              </div>
              <div className="stat-content">
                <h3>{data.stats.totalFiles}</h3>
                <p>Total Files</p>
              </div>
            </div>
            <div className="stat-card confidential">
              <div className="stat-icon">
                <LockIcon size={32} color="currentColor" />
              </div>
              <div className="stat-content">
                <h3>{data.stats.confidentialFiles}</h3>
                <p>Confidential Files</p>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">
                <LockIcon size={32} color="currentColor" />
              </div>
              <div className="stat-content">
                <h3>{data.securitySettings.mfaEnabled ? 'Enabled' : 'Disabled'}</h3>
                <p>Multi-Factor Auth</p>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">
                <KeyIcon size={32} color="currentColor" />
              </div>
              <div className="stat-content">
                <h3>{data.securitySettings.encryptionEnabled ? 'Enabled' : 'Disabled'}</h3>
                <p>Encryption</p>
              </div>
            </div>
          </div>

          <div className="security-sections">
            <div className="security-section">
              <h2>Recent Activity</h2>
              <div className="activity-list">
                {data.recentLogs.slice(0, 10).map((log) => (
                  <div key={log._id} className="activity-item">
                    <div className="activity-icon">{getActionIcon(log.action)}</div>
                    <div className="activity-content">
                      <div className="activity-action">{log.action.replace(/_/g, ' ')}</div>
                      <div className="activity-meta">
                        {new Date(log.timestamp).toLocaleString()} • {log.ipAddress || 'Unknown IP'}
                      </div>
                    </div>
                    <div
                      className="activity-status"
                      style={{ color: getStatusColor(log.status) }}
                    >
                      {log.status}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="security-section">
              <h2>Failed Login Attempts</h2>
              {data.failedLogins.length > 0 ? (
                <div className="failed-logins-list">
                  {data.failedLogins.map((log) => (
                    <div key={log._id} className="failed-login-item">
                      <div className="failed-login-time">
                        {new Date(log.timestamp).toLocaleString()}
                      </div>
                      <div className="failed-login-ip">{log.ipAddress || 'Unknown IP'}</div>
                      <div className="failed-login-reason">
                        {log.details?.reason || 'Unknown reason'}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="no-data">No failed login attempts</p>
              )}
            </div>
          </div>
        </div>
      )}

      {selectedTab === 'logs' && (
        <div className="audit-logs-view">
          <div className="audit-logs-header">
            <h2>Audit Logs</h2>
            <p>Complete activity history for compliance and security monitoring</p>
          </div>
          <div className="audit-logs-list">
            {auditLogs.map((log) => (
              <div key={log._id} className="audit-log-item">
                <div className="audit-log-icon">{getActionIcon(log.action)}</div>
                <div className="audit-log-content">
                  <div className="audit-log-header">
                    <span className="audit-log-action">{log.action.replace(/_/g, ' ')}</span>
                    <span
                      className="audit-log-status"
                      style={{ color: getStatusColor(log.status) }}
                    >
                      {log.status}
                    </span>
                  </div>
                  <div className="audit-log-details">
                    <span>{new Date(log.timestamp).toLocaleString()}</span>
                    {log.ipAddress && <span>• IP: {log.ipAddress}</span>}
                    {log.resourceType && <span>• {log.resourceType}</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
          {logsTotal > 50 && (
            <div className="audit-logs-pagination">
              <button
                disabled={logsPage === 1}
                onClick={() => setLogsPage(logsPage - 1)}
              >
                Previous
              </button>
              <span>Page {logsPage} of {Math.ceil(logsTotal / 50)}</span>
              <button
                disabled={logsPage >= Math.ceil(logsTotal / 50)}
                onClick={() => setLogsPage(logsPage + 1)}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {selectedTab === 'settings' && (
        <div className="security-settings-view">
          <h2>Security Settings</h2>
          <div className="settings-section">
            <h3>Session Management</h3>
            <div className="setting-item">
              <label>Session Timeout (minutes)</label>
              <input
                type="number"
                defaultValue={data.securitySettings.sessionTimeout}
                min="5"
                max="480"
              />
            </div>
          </div>
          <div className="settings-section">
            <h3>Access Control</h3>
            <div className="setting-item">
              <label>
                <input
                  type="checkbox"
                  defaultChecked={data.securitySettings.requireIpWhitelist}
                />
                Require IP Whitelist
              </label>
            </div>
          </div>
          <div className="settings-section">
            <h3>Encryption</h3>
            <div className="setting-item">
              <label>
                <input
                  type="checkbox"
                  defaultChecked={data.securitySettings.encryptionEnabled}
                  disabled
                />
                End-to-End Encryption (Always Enabled)
              </label>
            </div>
          </div>
        </div>
      )}

      <div className="compliance-badges">
        <div className="badge">
          <LockIcon size={16} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
          SOC 2 Compliant
        </div>
        <div className="badge">
          <ShieldIcon size={16} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
          ISO 27001
        </div>
        <div className="badge">
          <CheckIcon size={16} color="#10b981" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
          GDPR Ready
        </div>
        <div className="badge">
          <LockIcon size={16} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
          AES-256 Encryption
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;

