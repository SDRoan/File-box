import React, { useState, useEffect } from 'react';
import { filesAPI } from '../services/api';
import { UploadIcon, DownloadIcon, TrashIcon, RestoreIcon, EditIcon, PackageIcon, CopyIcon, ShareIcon, StarredIcon, ScrollIcon, RefreshIcon, CommentIcon, DocumentIcon } from './Icons';
import './FileActivity.css';

interface Activity {
  _id: string;
  user: {
    name: string;
    email: string;
  };
  action: string;
  details: string;
  createdAt: string;
  file?: {
    originalName: string;
  };
  folder?: {
    name: string;
  };
}

interface FileActivityProps {
  fileId?: string;
  folderId?: string;
  onClose: () => void;
}

const FileActivity: React.FC<FileActivityProps> = ({ fileId, folderId, onClose }) => {
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadActivity();
  }, [fileId, folderId]);

  const loadActivity = async () => {
    try {
      setLoading(true);
      let data;
      if (fileId) {
        data = await filesAPI.getFileActivity(fileId);
      } else if (folderId) {
        data = await filesAPI.getFolderActivity(folderId);
      } else {
        data = await filesAPI.getUserActivity();
      }
      setActivities(data);
    } catch (error) {
      console.error('Error loading activity:', error);
    } finally {
      setLoading(false);
    }
  };

  const getActionIcon = (action: string) => {
    const iconMap: { [key: string]: React.ReactNode } = {
      uploaded: <UploadIcon size={18} color="currentColor" />,
      downloaded: <DownloadIcon size={18} color="currentColor" />,
      deleted: <TrashIcon size={18} color="currentColor" />,
      restored: <RestoreIcon size={18} color="currentColor" />,
      renamed: <EditIcon size={18} color="currentColor" />,
      moved: <PackageIcon size={18} color="currentColor" />,
      copied: <CopyIcon size={18} color="currentColor" />,
      shared: <ShareIcon size={18} color="currentColor" />,
      starred: <StarredIcon size={18} color="currentColor" />,
      unstarred: <StarredIcon size={18} color="currentColor" />,
      version_created: <ScrollIcon size={18} color="currentColor" />,
      version_restored: <RefreshIcon size={18} color="currentColor" />,
      commented: <CommentIcon size={18} color="currentColor" />
    };
    return iconMap[action] || <DocumentIcon size={18} color="currentColor" />;
  };

  const getActionText = (action: string) => {
    const texts: { [key: string]: string } = {
      uploaded: 'uploaded',
      downloaded: 'downloaded',
      deleted: 'deleted',
      restored: 'restored',
      renamed: 'renamed',
      moved: 'moved',
      copied: 'copied',
      shared: 'shared',
      starred: 'starred',
      unstarred: 'unstarred',
      version_created: 'created version',
      version_restored: 'restored version',
      commented: 'commented on'
    };
    return texts[action] || action;
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content file-activity-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Activity History</h2>
          <button onClick={onClose} className="close-btn">×</button>
        </div>

        <div className="activity-section">
          {loading ? (
            <div className="loading">Loading activity...</div>
          ) : activities.length === 0 ? (
            <div className="empty-state">No activity recorded</div>
          ) : (
            <div className="activity-list">
              {activities.map((activity) => (
                <div key={activity._id} className="activity-item">
                  <div className="activity-icon">{getActionIcon(activity.action)}</div>
                  <div className="activity-content">
                    <div className="activity-text">
                      <span className="activity-user">{activity.user.name}</span>
                      {' '}
                      <span className="activity-action">{getActionText(activity.action)}</span>
                      {' '}
                      {activity.file && (
                        <span className="activity-target">{activity.file.originalName}</span>
                      )}
                      {activity.folder && (
                        <span className="activity-target">{activity.folder.name}</span>
                      )}
                      {activity.details && (
                        <span className="activity-details"> - {activity.details}</span>
                      )}
                    </div>
                    <div className="activity-time">
                      {new Date(activity.createdAt).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default FileActivity;


