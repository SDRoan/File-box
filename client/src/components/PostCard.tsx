import React, { useState } from 'react';
import { filesAPI } from '../services/api';
import { TrashIcon, RefreshIcon, BookmarkIcon, DownloadIcon, FolderIcon, EyeIcon, HeartIcon, CommentIcon } from './Icons';
import './PostCard.css';

interface User {
  _id: string;
  name: string;
  email: string;
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

interface PostCardProps {
  post: SocialPost;
  currentUserId?: string;
  onLike: () => void;
  onComment: (text: string) => void;
  onDelete: () => void;
  onRepost: () => void;
  onSave: () => void;
  onUserClick: (userId: string) => void;
  isLiked: boolean;
  isSaved: boolean;
  formatSize: (bytes: number) => string;
  getFileIcon: (mimeType: string | undefined | null) => React.ReactNode;
}

const PostCard: React.FC<PostCardProps> = ({
  post,
  currentUserId,
  onLike,
  onComment,
  onDelete,
  onRepost,
  onSave,
  onUserClick,
  isLiked,
  isSaved,
  formatSize,
  getFileIcon
}) => {
  const [commentText, setCommentText] = useState('');
  const [showComments, setShowComments] = useState(false);

  return (
    <div className="post-card">
      {post.originalPost && (
        <div className="repost-header">
          <span><RefreshIcon size={14} color="currentColor" style={{ display: 'inline-block', verticalAlign: 'middle', marginRight: '0.25rem' }} /> Reposted by {post.repostedBy?.name || post.owner?.name || 'Unknown User'}</span>
        </div>
      )}
      <div className="post-header">
        <div className="post-author">
          <div className="author-avatar">
            {(() => {
              const owner = post.originalPost?.owner || post.owner;
              return owner?.name ? owner.name.charAt(0).toUpperCase() : '?';
            })()}
          </div>
          <div className="author-info">
            <div 
              className="author-name clickable"
              onClick={() => {
                const owner = post.originalPost?.owner || post.owner;
                if (owner?._id) {
                  onUserClick(owner._id);
                }
              }}
              style={{ cursor: 'pointer' }}
            >
              {(post.originalPost?.owner || post.owner)?.name || 'Unknown User'}
              {post.originalPost && (
                <span className="repost-indicator"> (Original)</span>
              )}
            </div>
            <div className="post-date">
              {new Date((post.originalPost?.createdAt || post.createdAt)).toLocaleDateString()}
            </div>
          </div>
        </div>
        <div className="post-header-actions">
          <button 
            className={`save-btn ${isSaved ? 'saved' : ''}`}
            onClick={onSave}
            title={isSaved ? 'Unsave post' : 'Save post'}
          >
            <BookmarkIcon size={18} color={isSaved ? "#f59e0b" : "currentColor"} />
          </button>
          {post.owner._id === currentUserId && (
            <button className="delete-post-btn" onClick={onDelete} title="Delete post">
              <TrashIcon size={16} color="currentColor" />
            </button>
          )}
        </div>
      </div>

      {(post.originalPost?.description || post.description) && (
        <div className="post-description">
          {post.originalPost?.description || post.description}
        </div>
      )}

      <div className="post-content">
        {(() => {
          const displayFile = post.file || post.originalPost?.file;
          const displayFolder = post.folder || post.originalPost?.folder;
          
          if (!displayFile && !displayFolder) {
            return null;
          }
          
          return (
            <>
              {displayFile && (displayFile._id || typeof displayFile === 'object') && (
                <div className="shared-item">
                  <span className="item-icon">{getFileIcon(displayFile?.mimeType)}</span>
                  <div className="item-info">
                    <div className="item-name">{displayFile?.originalName || 'Unknown File'}</div>
                    <div className="item-meta">
                      {displayFile?.size ? formatSize(displayFile.size) : 'Unknown size'} • {displayFile?.mimeType || 'Unknown type'}
                    </div>
                  </div>
                  <button 
                    className="download-btn" 
                    title="Download"
                    onClick={async () => {
                      const fileId = typeof displayFile === 'object' && displayFile._id 
                        ? displayFile._id 
                        : typeof displayFile === 'string' 
                        ? displayFile 
                        : null;
                      if (!fileId) return;
                      try {
                        const blob = await filesAPI.downloadFile(fileId);
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = displayFile?.originalName || 'download';
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                      } catch (error) {
                        alert('Failed to download file');
                      }
                    }}
                  >
                    <DownloadIcon size={18} color="currentColor" />
                  </button>
                </div>
              )}

              {displayFolder && (displayFolder._id || typeof displayFolder === 'object') && (
                <div className="shared-item">
                  <span className="item-icon"><FolderIcon size={20} color="currentColor" /></span>
                  <div className="item-info">
                    <div className="item-name">{displayFolder?.name || 'Unknown Folder'}</div>
                    <div className="item-meta">Folder</div>
                  </div>
                  <button className="download-btn" title="Open folder">
                    <EyeIcon size={18} color="currentColor" />
                  </button>
                </div>
              )}
            </>
          );
        })()}
      </div>

      <div className="post-stats">
        <span>{post.likes.length} likes</span>
        <span>{post.comments.length} comments</span>
        <span>{post.repostCount || 0} reposts</span>
        <span>{post.downloadCount} downloads</span>
        <span>{post.viewCount} views</span>
      </div>

      <div className="post-actions">
        <button 
          className={`action-btn ${isLiked ? 'liked' : ''}`}
          onClick={onLike}
        >
          <HeartIcon size={18} color={isLiked ? "#ef4444" : "currentColor"} /> Like
        </button>
        <button 
          className="action-btn"
          onClick={() => setShowComments(!showComments)}
        >
          <CommentIcon size={18} color="currentColor" /> Comment
        </button>
        {onRepost && (
          <button 
            className="action-btn"
            onClick={onRepost}
          >
            <RefreshIcon size={18} color="currentColor" /> Repost
          </button>
        )}
      </div>

      {showComments && (
        <div className="comments-section">
          <div className="comments-list">
            {post.comments.map((comment: any, index: number) => (
              <div key={index} className="comment-item">
                <div className="comment-author">{comment.user?.name || 'Unknown'}</div>
                <div className="comment-text">{comment.text}</div>
              </div>
            ))}
          </div>
          <div className="comment-input">
            <input
              type="text"
              placeholder="Write a comment..."
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter' && commentText.trim()) {
                  onComment(commentText);
                  setCommentText('');
                }
              }}
            />
            <button
              onClick={() => {
                if (commentText.trim()) {
                  onComment(commentText);
                  setCommentText('');
                }
              }}
            >
              Post
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default PostCard;


