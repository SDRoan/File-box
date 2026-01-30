import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { forumsAPI } from '../services/api';
import { ForumIcon, PlusIcon, LoadingIcon, EditIcon, DeleteIcon, CloseIcon, EyeIcon } from './Icons';
import './Forums.css';

interface ForumPost {
  _id: string;
  title: string;
  content: string;
  author: {
    _id: string;
    name: string;
    email: string;
  };
  category: string;
  tags: string[];
  views: number;
  upvotes: number;
  downvotes: number;
  replyCount: number;
  isPinned: boolean;
  isLocked: boolean;
  createdAt: string;
  lastActivityAt: string;
  replies?: Array<{
    _id: string;
    author: {
      _id: string;
      name: string;
      email: string;
    };
    content: string;
    upvotes: number;
    downvotes: number;
    createdAt: string;
  }>;
}

const Forums: React.FC = () => {
  const { user } = useAuth();
  const [posts, setPosts] = useState<ForumPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedPost, setSelectedPost] = useState<ForumPost | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<string>('createdAt');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Form state
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    category: 'general',
    tags: '',
  });
  const [replyContent, setReplyContent] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadPosts();
  }, [categoryFilter, sortBy, searchQuery]);

  const loadPosts = async () => {
    try {
      setLoading(true);
      const data = await forumsAPI.getPosts({
        category: categoryFilter !== 'all' ? categoryFilter : undefined,
        search: searchQuery || undefined,
        sortBy,
        order: 'desc',
      });
      setPosts(data);
    } catch (error) {
      console.error('Error loading posts:', error);
      alert('Failed to load posts');
    } finally {
      setLoading(false);
    }
  };

  const handleCreatePost = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.title.trim() || !formData.content.trim()) {
      alert('Please fill in all required fields');
      return;
    }

    try {
      setSubmitting(true);
      const tags = formData.tags
        .split(',')
        .map(tag => tag.trim())
        .filter(tag => tag.length > 0);
      
      await forumsAPI.createPost({
        title: formData.title.trim(),
        content: formData.content.trim(),
        category: formData.category,
        tags,
      });
      
      setShowCreateModal(false);
      setFormData({ title: '', content: '', category: 'general', tags: '' });
      loadPosts();
    } catch (error: any) {
      console.error('Error creating post:', error);
      alert(error.response?.data?.message || 'Failed to create post');
    } finally {
      setSubmitting(false);
    }
  };

  const handleViewPost = async (postId: string) => {
    try {
      const post = await forumsAPI.getPost(postId);
      setSelectedPost(post);
    } catch (error) {
      console.error('Error loading post:', error);
      alert('Failed to load post');
    }
  };

  const handleReply = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedPost || !replyContent.trim()) return;

    try {
      setSubmitting(true);
      await forumsAPI.replyToPost(selectedPost._id, replyContent.trim());
      const updatedPost = await forumsAPI.getPost(selectedPost._id);
      setSelectedPost(updatedPost);
      setReplyContent('');
      loadPosts(); // Refresh list to update reply count
    } catch (error: any) {
      console.error('Error replying:', error);
      alert(error.response?.data?.message || 'Failed to post reply');
    } finally {
      setSubmitting(false);
    }
  };

  const handleVote = async (postId: string, vote: 'up' | 'down') => {
    try {
      await forumsAPI.voteOnPost(postId, vote);
      if (selectedPost && selectedPost._id === postId) {
        const updatedPost = await forumsAPI.getPost(postId);
        setSelectedPost(updatedPost);
      }
      loadPosts();
    } catch (error) {
      console.error('Error voting:', error);
    }
  };

  const handleDeletePost = async (postId: string) => {
    if (!window.confirm('Are you sure you want to delete this post?')) return;

    try {
      await forumsAPI.deletePost(postId);
      if (selectedPost && selectedPost._id === postId) {
        setSelectedPost(null);
      }
      loadPosts();
    } catch (error: any) {
      console.error('Error deleting post:', error);
      alert(error.response?.data?.message || 'Failed to delete post');
    }
  };

  const categories = [
    { value: 'all', label: 'All Categories' },
    { value: 'general', label: 'General' },
    { value: 'help', label: 'Help' },
    { value: 'feature-request', label: 'Feature Request' },
    { value: 'bug-report', label: 'Bug Report' },
    { value: 'showcase', label: 'Showcase' },
    { value: 'off-topic', label: 'Off Topic' },
  ];

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

  if (selectedPost) {
    return (
      <div className="forums">
        <div className="post-detail-header">
          <button className="back-button" onClick={() => setSelectedPost(null)}>
            ← Back to Forums
          </button>
        </div>

        <div className="post-detail">
          <div className="post-detail-content">
            <div className="post-detail-header-info">
              <h2>{selectedPost.title}</h2>
              {selectedPost.isPinned && <span className="badge pinned">Pinned</span>}
              {selectedPost.isLocked && <span className="badge locked">Locked</span>}
              <span className={`badge category category-${selectedPost.category}`}>
                {categories.find(c => c.value === selectedPost.category)?.label || selectedPost.category}
              </span>
            </div>

            <div className="post-meta">
              <span className="author">By {selectedPost.author.name}</span>
              <span>•</span>
              <span>{formatDate(selectedPost.createdAt)}</span>
              <span>•</span>
              <span><EyeIcon size={14} color="#666" /> {selectedPost.views} views</span>
            </div>

            {selectedPost.tags.length > 0 && (
              <div className="post-tags">
                {selectedPost.tags.map((tag, idx) => (
                  <span key={idx} className="tag">#{tag}</span>
                ))}
              </div>
            )}

            <div className="post-content">{selectedPost.content}</div>

            <div className="post-actions">
              <button
                className="vote-button upvote"
                onClick={() => handleVote(selectedPost._id, 'up')}
              >
                ▲ {selectedPost.upvotes}
              </button>
              <button
                className="vote-button downvote"
                onClick={() => handleVote(selectedPost._id, 'down')}
              >
                ▼ {selectedPost.downvotes}
              </button>
              {user && user.id === selectedPost.author._id && (
                <button
                  className="action-button delete"
                  onClick={() => handleDeletePost(selectedPost._id)}
                >
                  <DeleteIcon size={16} color="currentColor" /> Delete
                </button>
              )}
            </div>
          </div>

          <div className="replies-section">
            <h3>{selectedPost.replyCount || 0} {selectedPost.replyCount === 1 ? 'Reply' : 'Replies'}</h3>

            {selectedPost.replies && selectedPost.replies.length > 0 ? (
              <div className="replies-list">
                {selectedPost.replies.map((reply) => (
                  <div key={reply._id} className="reply-item">
                    <div className="reply-header">
                      <span className="reply-author">{reply.author.name}</span>
                      <span className="reply-date">{formatDate(reply.createdAt)}</span>
                    </div>
                    <div className="reply-content">{reply.content}</div>
                    <div className="reply-actions">
                      <button
                        className="vote-button small upvote"
                        onClick={() => {}}
                      >
                        ▲ {reply.upvotes}
                      </button>
                      <button
                        className="vote-button small downvote"
                        onClick={() => {}}
                      >
                        ▼ {reply.downvotes}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-replies">No replies yet. Be the first to reply!</div>
            )}

            {!selectedPost.isLocked && user && (
              <form onSubmit={handleReply} className="reply-form">
                <textarea
                  value={replyContent}
                  onChange={(e) => setReplyContent(e.target.value)}
                  placeholder="Write a reply..."
                  rows={4}
                  className="reply-input"
                  required
                />
                <div className="reply-form-actions">
                  <button type="button" onClick={() => setReplyContent('')} className="cancel-button">
                    Cancel
                  </button>
                  <button type="submit" disabled={submitting || !replyContent.trim()} className="submit-button">
                    {submitting ? 'Posting...' : 'Post Reply'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="forums">
      <div className="forums-header">
        <h2><ForumIcon size={24} color="currentColor" /> Community Forums</h2>
        <div className="forums-header-actions">
          <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
            <PlusIcon size={16} color="currentColor" /> New Post
          </button>
        </div>
      </div>

      <div className="forums-filters">
        <div className="filter-group">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="filter-select"
          >
            {categories.map(cat => (
              <option key={cat.value} value={cat.value}>{cat.label}</option>
            ))}
          </select>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="filter-select"
          >
            <option value="createdAt">Newest</option>
            <option value="popular">Most Popular</option>
            <option value="replies">Most Replies</option>
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
          <ForumIcon size={64} color="#ccc" />
          <h3>No posts yet</h3>
          <p>Be the first to start a discussion!</p>
        </div>
      ) : (
        <div className="posts-list">
          {posts.map((post) => (
            <div
              key={post._id}
              className={`post-card ${post.isPinned ? 'pinned' : ''}`}
              onClick={() => handleViewPost(post._id)}
            >
              <div className="post-card-header">
                <div className="post-card-title-section">
                  <h3>{post.title}</h3>
                  {post.isPinned && <span className="badge pinned">Pinned</span>}
                  <span className={`badge category category-${post.category}`}>
                    {categories.find(c => c.value === post.category)?.label || post.category}
                  </span>
                </div>
              </div>
              <p className="post-card-content">{post.content.substring(0, 150)}...</p>
              {post.tags.length > 0 && (
                <div className="post-card-tags">
                  {post.tags.slice(0, 3).map((tag, idx) => (
                    <span key={idx} className="tag">#{tag}</span>
                  ))}
                </div>
              )}
              <div className="post-card-footer">
                <span className="post-card-author">{post.author.name}</span>
                <span>•</span>
                <span>{formatDate(post.createdAt)}</span>
                <span>•</span>
                <span><EyeIcon size={14} color="#666" /> {post.views}</span>
                <span>•</span>
                <span> {post.replyCount || 0}</span>
                <span>•</span>
                <span>▲ {post.upvotes}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content forum-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Create New Post</h2>
              <button className="close-button" onClick={() => setShowCreateModal(false)}>
                <CloseIcon size={20} color="currentColor" />
              </button>
            </div>
            <form onSubmit={handleCreatePost}>
              <div className="form-group">
                <label>Title *</label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="Enter post title"
                  required
                  className="form-input"
                />
              </div>
              <div className="form-group">
                <label>Category</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  className="form-select"
                >
                  {categories.filter(c => c.value !== 'all').map(cat => (
                    <option key={cat.value} value={cat.value}>{cat.label}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Content *</label>
                <textarea
                  value={formData.content}
                  onChange={(e) => setFormData({ ...formData, content: e.target.value })}
                  placeholder="Write your post content..."
                  rows={8}
                  required
                  className="form-textarea"
                />
              </div>
              <div className="form-group">
                <label>Tags (comma-separated)</label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  placeholder="e.g., question, help, feature"
                  className="form-input"
                />
              </div>
              <div className="modal-actions">
                <button type="button" onClick={() => setShowCreateModal(false)} className="cancel-button">
                  Cancel
                </button>
                <button type="submit" disabled={submitting} className="submit-button">
                  {submitting ? 'Creating...' : 'Create Post'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Forums;
