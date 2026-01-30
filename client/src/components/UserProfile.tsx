import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { socialAPI } from '../services/api';
import './UserProfile.css';

interface User {
  _id: string;
  name: string;
  email: string;
  bio?: string;
}

interface FileItem {
  _id: string;
  originalName: string;
  mimeType: string;
  size: number;
}

interface Folder {
  _id: string;
  name: string;
}

interface SocialPost {
  _id: string;
  owner: User;
  file: FileItem | null;
  folder: Folder | null;
  description: string;
  likes: any[];
  comments: any[];
  downloadCount: number;
  viewCount: number;
  repostCount: number;
  originalPost: SocialPost | null;
  repostedBy: User | null;
  createdAt: string;
}

interface UserProfileProps {
  userId: string;
  onClose: () => void;
}

const UserProfile: React.FC<UserProfileProps> = ({ userId, onClose }) => {
  const [profile, setProfile] = useState<any>(null);
  const [posts, setPosts] = useState<SocialPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [isFollowing, setIsFollowing] = useState(false);
  const [followLoading, setFollowLoading] = useState(false);

  useEffect(() => {
    loadProfile();
  }, [userId]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadProfile = async () => {
    try {
      setLoading(true);
      const [profileData, postsData] = await Promise.all([
        socialAPI.getUserProfile(userId),
        socialAPI.getUserPosts(userId, 1, 50) // Get more posts to separate
      ]);
      setProfile(profileData);
      setPosts(postsData.posts || []);
      setIsFollowing(profileData.isFollowing || false);
    } catch (error) {
      console.error('Error loading profile:', error);
    } finally {
      setLoading(false);
    }
  };

  // Separate posts and reposts
  const originalPosts = posts.filter(post => !post.originalPost);
  const reposts = posts.filter(post => post.originalPost);

  const handleFollow = async () => {
    try {
      setFollowLoading(true);
      const result = await socialAPI.followUser(userId);
      setIsFollowing(result.following);
      if (profile) {
        setProfile({
          ...profile,
          stats: {
            ...profile.stats,
            followers: result.following 
              ? profile.stats.followers + 1 
              : Math.max(0, profile.stats.followers - 1)
          }
        });
      }
    } catch (error: any) {
      console.error('Error following user:', error);
      alert(error.response?.data?.message || error.message || 'Failed to follow/unfollow user');
    } finally {
      setFollowLoading(false);
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getFileIcon = (mimeType: string) => {
    if (mimeType.includes('pdf')) return '';
    if (mimeType.includes('image')) return '';
    if (mimeType.includes('video')) return 'Video';
    if (mimeType.includes('audio')) return 'Audio';
    return '';
  };

  if (loading) {
    return (
      <div className="user-profile-overlay" onClick={onClose}>
        <div className="user-profile-container" onClick={(e) => e.stopPropagation()}>
          <div className="loading">Loading profile...</div>
        </div>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="user-profile-overlay" onClick={onClose}>
        <div className="user-profile-container" onClick={(e) => e.stopPropagation()}>
          <div className="error">User not found</div>
        </div>
      </div>
    );
  }

  return (
    <div className="user-profile-overlay" onClick={onClose}>
      <div className="user-profile-container" onClick={(e) => e.stopPropagation()}>
        <div className="profile-header">
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="profile-content">
          <div className="profile-info">
            <div className="profile-avatar-large">
              {profile.user.name.charAt(0).toUpperCase()}
            </div>
            <h2>{profile.user.name}</h2>
            {profile.user.bio && <p className="profile-bio">{profile.user.bio}</p>}
            
            <div className="profile-stats">
              <div className="stat-item">
                <div className="stat-value">{profile.stats.posts}</div>
                <div className="stat-label">Posts</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{profile.stats.followers}</div>
                <div className="stat-label">Followers</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{profile.stats.following}</div>
                <div className="stat-label">Following</div>
              </div>
            </div>

            {!profile.isOwnProfile && (
              <button
                className={`follow-profile-btn ${isFollowing ? 'following' : ''}`}
                onClick={handleFollow}
                disabled={followLoading}
              >
                {followLoading ? '...' : isFollowing ? 'Unfollow' : '+ Follow'}
              </button>
            )}
          </div>

          <div className="profile-posts-container">
            <div className="profile-posts-section">
              <h3>Posts</h3>
              {originalPosts.length === 0 ? (
                <div className="no-posts">
                  <p>No posts yet</p>
                </div>
              ) : (
                <div className="posts-grid">
                  {originalPosts.map(post => (
                    <div key={post._id} className="profile-post-card">
                      {post.file && (
                        <div className="post-preview">
                          <span className="preview-icon">{getFileIcon(post.file.mimeType)}</span>
                          <div className="preview-info">
                            <div className="preview-name">{post.file.originalName}</div>
                            <div className="preview-size">{formatSize(post.file.size)}</div>
                          </div>
                        </div>
                      )}
                      {post.folder && (
                        <div className="post-preview">
                          <span className="preview-icon"></span>
                          <div className="preview-info">
                            <div className="preview-name">{post.folder.name}</div>
                            <div className="preview-size">Folder</div>
                          </div>
                        </div>
                      )}
                      {post.description && (
                        <div className="post-preview-description">{post.description}</div>
                      )}
                      <div className="post-preview-stats">
                        <span> {post.likes.length}</span>
                        <span> {post.comments.length}</span>
                        <span> {post.repostCount || 0}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="profile-reposts-section">
              <h3>Reposts</h3>
              {reposts.length === 0 ? (
                <div className="no-posts">
                  <p>No reposts yet</p>
                </div>
              ) : (
                <div className="posts-grid">
                  {reposts.map(post => (
                    <div key={post._id} className="profile-post-card repost-card">
                      {post.originalPost && (
                        <div className="repost-indicator">Reposted</div>
                      )}
                      {post.file && (
                        <div className="post-preview">
                          <span className="preview-icon">{getFileIcon(post.file.mimeType)}</span>
                          <div className="preview-info">
                            <div className="preview-name">{post.file.originalName}</div>
                            <div className="preview-size">{formatSize(post.file.size)}</div>
                          </div>
                        </div>
                      )}
                      {post.folder && (
                        <div className="post-preview">
                          <span className="preview-icon"></span>
                          <div className="preview-info">
                            <div className="preview-name">{post.folder.name}</div>
                            <div className="preview-size">Folder</div>
                          </div>
                        </div>
                      )}
                      {post.description && (
                        <div className="post-preview-description">{post.description}</div>
                      )}
                      <div className="post-preview-stats">
                        <span> {post.likes.length}</span>
                        <span> {post.comments.length}</span>
                        <span> {post.repostCount || 0}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProfile;









