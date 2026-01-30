import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { socialAPI } from '../services/api';
import { filesAPI } from '../services/api';
import UserProfile from './UserProfile';
import CreatePostModal from './CreatePostModal';
import { SocialFeedIcon, PlusIcon, EyeIcon, LoadingIcon, DocumentIcon, ImageIcon, VideoIcon, AudioIcon, HeartIcon, CommentIcon, TrashIcon, DownloadIcon, FolderIcon, ShareIcon } from './Icons';
import './SocialFeed.css';

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

interface Comment {
  _id: string;
  user: User;
  text: string;
  createdAt: string;
}

interface Like {
  _id: string;
  user: User;
  createdAt: string;
}

interface SocialPost {
  _id: string;
  owner: User;
  file: FileItem | null;
  folder: Folder | null;
  description: string;
  likes: Like[];
  comments: Comment[];
  downloadCount: number;
  viewCount: number;
  repostCount: number;
  originalPost: SocialPost | null;
  repostedBy: User | null;
  createdAt: string;
}

interface DiscoveredUser extends User {
  followers: number;
  posts: number;
  isFollowing?: boolean;
}

const SocialFeed: React.FC = () => {
  const { user } = useAuth();
  const [posts, setPosts] = useState<SocialPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [availableFiles, setAvailableFiles] = useState<FileItem[]>([]);
  const [availableFolders, setAvailableFolders] = useState<Folder[]>([]);
  const [selectedFileId, setSelectedFileId] = useState<string>('');
  const [selectedFolderId, setSelectedFolderId] = useState<string>('');
  const [postDescription, setPostDescription] = useState('');
  const [isPublic, setIsPublic] = useState(true);
  const [discoveredUsers, setDiscoveredUsers] = useState<DiscoveredUser[]>([]);
  const [followingStatus, setFollowingStatus] = useState<{ [userId: string]: boolean }>({});
  const [showDiscover, setShowDiscover] = useState(false);
  const [savedPosts, setSavedPosts] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<DiscoveredUser[]>([]);
  const [showSearch, setShowSearch] = useState(false);
  const [viewMode, setViewMode] = useState<'feed' | 'saved'>('feed');
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<string>('createdAt');
  const [expandedComments, setExpandedComments] = useState<Set<string>>(new Set());
  const [commentTexts, setCommentTexts] = useState<{ [postId: string]: string }>({});
  const [imagePreviews, setImagePreviews] = useState<{ [fileId: string]: string }>({});
  const [loadingPreviews, setLoadingPreviews] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (viewMode === 'feed') {
      loadFeed();
    } else {
      loadSavedPosts();
    }
    loadDiscoveredUsers();
  }, [viewMode, sortBy, searchQuery]);

  const loadSavedPosts = async () => {
    try {
      const data = await socialAPI.getSavedPosts();
      const savedPostsList = data.posts || [];
      const savedIds = new Set<string>(savedPostsList.map((p: SocialPost) => p._id as string));
      setSavedPosts(savedIds);
      
      if (viewMode === 'saved') {
        setPosts(savedPostsList);
        setLoading(false);
      }
    } catch (error) {
      console.error('Error loading saved posts:', error);
    }
  };

  const loadFeed = async () => {
    try {
      setLoading(true);
      const data = await socialAPI.getFeed(page, 20);
      let postsList = data.posts || [];
      
      // Apply search filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        postsList = postsList.filter((post: SocialPost) => 
          post.description?.toLowerCase().includes(query) ||
          post.owner?.name?.toLowerCase().includes(query) ||
          post.file?.originalName?.toLowerCase().includes(query) ||
          post.folder?.name?.toLowerCase().includes(query)
        );
      }
      
      // Apply sorting
      if (sortBy === 'popular') {
        postsList.sort((a: SocialPost, b: SocialPost) => (b.likes?.length || 0) - (a.likes?.length || 0));
      } else if (sortBy === 'comments') {
        postsList.sort((a: SocialPost, b: SocialPost) => (b.comments?.length || 0) - (a.comments?.length || 0));
      } else {
        postsList.sort((a: SocialPost, b: SocialPost) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      }
      
      if (page === 1) {
        setPosts(postsList);
      } else {
        setPosts(prev => [...prev, ...postsList]);
      }
      setHasMore(data.hasMore || false);
    } catch (error) {
      console.error('Error loading feed:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAvailableItems = async () => {
    try {
      console.log('Loading available files and folders...');
      const data = await filesAPI.getFiles();
      console.log('Loaded files:', data.files?.length || 0, 'folders:', data.folders?.length || 0);
      setAvailableFiles(data.files || []);
      setAvailableFolders(data.folders || []);
      
      if (!data.files || data.files.length === 0) {
        console.warn('No files available to share');
      }
    } catch (error) {
      console.error('Error loading files:', error);
      alert('Failed to load files. Please try again.');
    }
  };

  const loadDiscoveredUsers = async () => {
    try {
      const users = await socialAPI.discoverUsers(10);
      setDiscoveredUsers(users || []);
      
      // Load follow status for each user
      const statuses: { [userId: string]: boolean } = {};
      await Promise.all(
        (users || []).map(async (u: DiscoveredUser) => {
          const status = await socialAPI.getFollowStatus(u._id);
          statuses[u._id] = status.following;
        })
      );
      setFollowingStatus(statuses);
    } catch (error) {
      console.error('Error loading discovered users:', error);
    }
  };

  const handleFollow = async (userId: string) => {
    try {
      const result = await socialAPI.followUser(userId);
      setFollowingStatus(prev => ({
        ...prev,
        [userId]: result.following
      }));
      // Reload feed to see their posts
      if (result.following) {
        loadFeed();
      }
    } catch (error) {
      console.error('Error following user:', error);
      alert('Failed to follow/unfollow user');
    }
  };

  const handleRepost = async (postId: string) => {
    try {
      const result = await socialAPI.repostPost(postId);
      // Reload feed to show updated repost count and new/removed repost
      await loadFeed();
    } catch (error: any) {
      console.error('Error reposting:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to repost';
      alert(errorMessage);
    }
  };

  const handleSave = async (postId: string) => {
    try {
      const result = await socialAPI.savePost(postId);
      if (result.saved) {
        setSavedPosts(prev => new Set([...Array.from(prev), postId]));
      } else {
        setSavedPosts(prev => {
          const newSet = new Set(prev);
          newSet.delete(postId);
          return newSet;
        });
      }
    } catch (error) {
      console.error('Error saving post:', error);
    }
  };

  const handleSearchUsers = async (query: string) => {
    setSearchQuery(query);
    if (query.trim().length === 0) {
      setSearchResults([]);
      setShowSearch(false);
      return;
    }

    try {
      const data = await socialAPI.searchUsers(query);
      setSearchResults(data.users || []);
      setShowSearch(true);
    } catch (error) {
      console.error('Error searching users:', error);
    }
  };

  const handleCreatePost = async () => {
    if (!selectedFileId && !selectedFolderId) {
      alert('Please select a file or folder to share');
      return;
    }

    try {
      console.log('Creating post with:', { selectedFileId, selectedFolderId, postDescription, isPublic });
      const result = await socialAPI.createPost(
        selectedFileId || undefined,
        selectedFolderId || undefined,
        postDescription,
        isPublic
      );
      console.log('Post created successfully:', result);
      setShowCreateModal(false);
      setSelectedFileId('');
      setSelectedFolderId('');
      setPostDescription('');
      setIsPublic(true);
      setPage(1);
      await loadFeed();
    } catch (error: any) {
      console.error('Error creating post:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to create post';
      alert(`Error: ${errorMessage}`);
    }
  };

  const handleLike = async (postId: string) => {
    try {
      await socialAPI.likePost(postId);
      // Reload feed to get updated likes
      await loadFeed();
    } catch (error) {
      console.error('Error liking post:', error);
      alert('Failed to upvote post');
    }
  };

  const handleAddComment = async (postId: string, text: string) => {
    if (!text.trim()) return;

    try {
      await socialAPI.addComment(postId, text);
      // Reload feed to get updated comments
      await loadFeed();
    } catch (error) {
      console.error('Error adding comment:', error);
      alert('Failed to add comment');
    }
  };

  const handleDeletePost = async (postId: string) => {
    if (!window.confirm('Are you sure you want to delete this post?')) return;

    try {
      await socialAPI.deletePost(postId);
      // Remove from local state immediately for better UX
      setPosts(posts.filter(post => post._id !== postId));
      // Also reload feed to ensure consistency
      await loadFeed();
    } catch (error) {
      console.error('Error deleting post:', error);
      alert('Failed to delete post');
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getFileIcon = (mimeType: string | undefined | null) => {
    if (!mimeType) return <DocumentIcon size={20} color="currentColor" />;
    if (mimeType.includes('pdf')) return <DocumentIcon size={20} color="currentColor" />;
    if (mimeType.includes('image')) return <ImageIcon size={20} color="currentColor" />;
    if (mimeType.includes('video')) return <VideoIcon size={20} color="currentColor" />;
    if (mimeType.includes('audio')) return <AudioIcon size={20} color="currentColor" />;
    return <DocumentIcon size={20} color="currentColor" />;
  };

  const isLiked = (post: SocialPost) => {
    return post.likes?.some(like => like.user._id === user?.id) || false;
  };

  const isReposted = (post: SocialPost) => {
    if (!user) return false;
    // Get the original post (if this is a repost, get the original)
    const originalPostId = post.originalPost?._id || post._id;
    // Check if there's a repost in the feed where:
    // - The repost references the original post
    // - The repost was made by the current user
    return posts.some(p => 
      p.originalPost?._id === originalPostId && 
      p.repostedBy?._id === user.id
    );
  };

  const toggleComments = (postId: string) => {
    setExpandedComments(prev => {
      const newSet = new Set(prev);
      if (newSet.has(postId)) {
        newSet.delete(postId);
      } else {
        newSet.add(postId);
      }
      return newSet;
    });
  };

  const handleCommentChange = (postId: string, text: string) => {
    setCommentTexts(prev => ({
      ...prev,
      [postId]: text
    }));
  };

  const handleSubmitComment = async (postId: string) => {
    const text = commentTexts[postId] || '';
    if (!text.trim()) return;

    try {
      await handleAddComment(postId, text);
      setCommentTexts(prev => {
        const newObj = { ...prev };
        delete newObj[postId];
        return newObj;
      });
    } catch (error) {
      console.error('Error submitting comment:', error);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const loadImagePreview = async (fileId: string, mimeType: string) => {
    if (!mimeType.startsWith('image/')) return;
    if (imagePreviews[fileId] || loadingPreviews.has(fileId)) return;

    try {
      setLoadingPreviews(prev => new Set(prev).add(fileId));
      const blob = await filesAPI.downloadFile(fileId);
      const url = URL.createObjectURL(blob);
      setImagePreviews(prev => ({ ...prev, [fileId]: url }));
    } catch (error) {
      console.error('Error loading image preview:', error);
    } finally {
      setLoadingPreviews(prev => {
        const newSet = new Set(prev);
        newSet.delete(fileId);
        return newSet;
      });
    }
  };

  const handleDownloadFile = async (fileId: string, fileName: string) => {
    try {
      const blob = await filesAPI.downloadFile(fileId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error downloading file:', error);
      alert('Failed to download file');
    }
  };

  // Load image previews for posts with image files
  useEffect(() => {
    posts.forEach(post => {
      if (post.file && post.file.mimeType?.startsWith('image/') && !imagePreviews[post.file._id] && !loadingPreviews.has(post.file._id)) {
        loadImagePreview(post.file._id, post.file.mimeType);
      }
    });
  }, [posts]);

  // Cleanup image URLs on unmount
  useEffect(() => {
    return () => {
      Object.values(imagePreviews).forEach(url => {
        if (url.startsWith('blob:')) {
          URL.revokeObjectURL(url);
        }
      });
    };
  }, []);

  if (loading && posts.length === 0) {
    return (
      <div className="social-feed-container">
        <div className="loading">Loading feed...</div>
      </div>
    );
  }

  return (
    <div className="social-feed-container forums">
      <div className="forums-header">
        <h2>
          <SocialFeedIcon size={24} color="currentColor" />
          Community Feed
        </h2>
        <div className="forums-header-actions">
          <button className="btn-primary" onClick={() => {
            setShowCreateModal(true);
            loadAvailableItems();
          }}>
            <PlusIcon size={16} color="currentColor" /> New Post
          </button>
        </div>
      </div>

      <div className="forums-filters">
        <div className="filter-group">
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="filter-select"
          >
            <option value="createdAt">Newest</option>
            <option value="popular">Most Popular</option>
            <option value="comments">Most Comments</option>
          </select>
        </div>
        <div className="search-group">
          <input
            type="text"
            placeholder="Search posts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
      </div>

      {loading ? (
        <div className="loading-state">
          <LoadingIcon size={40} color="#1e40af" />
          <p>Loading posts...</p>
        </div>
      ) : posts.length === 0 ? (
        <div className="empty-state">
          <SocialFeedIcon size={64} color="#ccc" />
          <h3>No posts yet</h3>
          <p>Be the first to share something!</p>
        </div>
      ) : (
        <div className="posts-list">
          {posts.map(post => (
            <div
              key={post._id}
              className="post-card"
            >
              <div className="post-card-header">
                <div className="post-card-title-section">
                  <h3>
                    {post.description || post.file?.originalName || post.folder?.name || 'Shared Item'}
                  </h3>
                </div>
                {user && post.owner?._id === user.id && (
                  <button
                    className="delete-post-btn"
                    onClick={() => handleDeletePost(post._id)}
                    title="Delete post"
                  >
                    <TrashIcon size={18} color="#ef4444" />
                  </button>
                )}
              </div>
              
              {/* File/Folder Preview */}
              {post.file && (
                <div className="shared-file-preview">
                  {post.file.mimeType?.startsWith('image/') && imagePreviews[post.file._id] ? (
                    <div className="file-image-preview">
                      <img 
                        src={imagePreviews[post.file._id]} 
                        alt={post.file.originalName}
                        className="preview-image"
                      />
                    </div>
                  ) : (
                    <div className="file-info-card">
                      <div className="file-info-icon">
                        {getFileIcon(post.file.mimeType)}
                      </div>
                      <div className="file-info-details">
                        <div className="file-info-name">{post.file.originalName}</div>
                        <div className="file-info-meta">
                          {formatSize(post.file.size || 0)} • {post.file.mimeType || 'Unknown type'}
                        </div>
                      </div>
                      <button
                        className="file-download-btn"
                        onClick={() => handleDownloadFile(post.file!._id, post.file!.originalName)}
                        title="Download file"
                      >
                        <DownloadIcon size={18} color="currentColor" />
                      </button>
                    </div>
                  )}
                </div>
              )}

              {post.folder && (
                <div className="shared-folder-preview">
                  <div className="file-info-card">
                    <div className="file-info-icon">
                      <FolderIcon size={24} color="currentColor" />
                    </div>
                    <div className="file-info-details">
                      <div className="file-info-name">{post.folder.name}</div>
                      <div className="file-info-meta">Folder</div>
                    </div>
                  </div>
                </div>
              )}

              <div className="post-card-footer">
                <span 
                  className="post-card-author clickable-author"
                  onClick={() => post.owner?._id && setSelectedUserId(post.owner._id)}
                  title="View profile"
                >
                  {post.owner?.name || 'Unknown'}
                </span>
                <span>•</span>
                <span>{formatDate(post.createdAt)}</span>
                <span>•</span>
                <span><EyeIcon size={14} color="#666" /> {post.viewCount || 0}</span>
              </div>
              <div className="post-card-actions">
                <button
                  className={`action-btn upvote-btn ${isLiked(post) ? 'liked' : ''}`}
                  onClick={() => handleLike(post._id)}
                  title="Upvote"
                >
                  <span>⬆</span>
                  <span>{post.likes?.length || 0}</span>
                </button>
                <button
                  className="action-btn comment-btn"
                  onClick={() => toggleComments(post._id)}
                  title="Comments"
                >
                  <CommentIcon size={16} color="currentColor" />
                  <span>{post.comments?.length || 0}</span>
                </button>
                {user && (() => {
                  // Get the original post to check ownership and repost count
                  const originalPost = post.originalPost || post;
                  const originalOwner = originalPost.owner;
                  // Don't show repost button for user's own posts
                  if (originalOwner?._id === user.id) return null;
                  // Get the post ID to repost (original post if this is a repost)
                  const postToRepost = post.originalPost?._id || post._id;
                  // Show repost count of the original post
                  const repostCount = originalPost.repostCount || 0;
                  return (
                    <button
                      className={`action-btn repost-btn ${isReposted(post) ? 'reposted' : ''}`}
                      onClick={() => handleRepost(postToRepost)}
                      title={isReposted(post) ? 'Remove repost' : 'Repost'}
                    >
                      <ShareIcon size={16} color="currentColor" />
                      <span>{repostCount}</span>
                    </button>
                  );
                })()}
              </div>
              {expandedComments.has(post._id) && (
                <div className="comments-section">
                  {post.comments && post.comments.length > 0 && (
                    <div className="comments-list">
                      {post.comments.map((comment: Comment) => (
                        <div key={comment._id} className="comment-item">
                          <div 
                            className="comment-author clickable-author"
                            onClick={() => comment.user?._id && setSelectedUserId(comment.user._id)}
                            title="View profile"
                          >
                            {comment.user?.name || 'Unknown'}
                          </div>
                          <div className="comment-text">{comment.text}</div>
                          <div className="comment-date">{formatDate(comment.createdAt)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                  {user && (
                    <div className="comment-input-section">
                      <textarea
                        placeholder="Write a comment..."
                        value={commentTexts[post._id] || ''}
                        onChange={(e) => handleCommentChange(post._id, e.target.value)}
                        className="comment-input"
                        rows={2}
                      />
                      <button
                        className="submit-comment-btn"
                        onClick={() => handleSubmitComment(post._id)}
                        disabled={!commentTexts[post._id]?.trim()}
                      >
                        Post
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {showCreateModal && (
        <CreatePostModal
          files={availableFiles}
          folders={availableFolders}
          selectedFileId={selectedFileId}
          selectedFolderId={selectedFolderId}
          description={postDescription}
          isPublic={isPublic}
          onFileSelect={setSelectedFileId}
          onFolderSelect={setSelectedFolderId}
          onDescriptionChange={setPostDescription}
          onPublicChange={setIsPublic}
          onSubmit={handleCreatePost}
          onClose={() => setShowCreateModal(false)}
          formatSize={formatSize}
          getFileIcon={getFileIcon}
        />
      )}

      {selectedUserId && (
        <UserProfile
          userId={selectedUserId}
          onClose={() => setSelectedUserId(null)}
        />
      )}
    </div>
  );
};

export default SocialFeed;

