import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { commentsAPI } from '../services/api';
import './FileComments.css';

interface Reply {
  _id: string;
  user: {
    name: string;
    email: string;
  };
  text: string;
  createdAt: string;
}

interface Comment {
  _id: string;
  user: {
    name: string;
    email: string;
  };
  text: string;
  replies: Reply[];
  createdAt: string;
  updatedAt: string;
}

interface FileCommentsProps {
  fileId: string;
  onClose: () => void;
}

const FileComments: React.FC<FileCommentsProps> = ({ fileId, onClose }) => {
  const { user } = useAuth();
  const [comments, setComments] = useState<Comment[]>([]);
  const [newComment, setNewComment] = useState('');
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  const [replyText, setReplyText] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadComments();
  }, [fileId]);

  const loadComments = async () => {
    try {
      setLoading(true);
      const data = await commentsAPI.getFileComments(fileId);
      setComments(data);
    } catch (error) {
      console.error('Error loading comments:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newComment.trim()) return;

    try {
      await commentsAPI.addComment(fileId, newComment.trim());
      setNewComment('');
      loadComments();
    } catch (error) {
      console.error('Error adding comment:', error);
      alert('Failed to add comment');
    }
  };

  const handleAddReply = async (commentId: string) => {
    if (!replyText.trim()) return;

    try {
      await commentsAPI.addReply(commentId, replyText.trim());
      setReplyText('');
      setReplyingTo(null);
      loadComments();
    } catch (error) {
      console.error('Error adding reply:', error);
      alert('Failed to add reply');
    }
  };

  const handleDeleteComment = async (commentId: string) => {
    if (!window.confirm('Delete this comment?')) return;

    try {
      await commentsAPI.deleteComment(commentId);
      loadComments();
    } catch (error) {
      console.error('Error deleting comment:', error);
      alert('Failed to delete comment');
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content file-comments-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Comments</h2>
          <button onClick={onClose} className="close-btn">×</button>
        </div>

        <div className="comments-section">
          {loading ? (
            <div className="loading">Loading comments...</div>
          ) : (
            <>
              <div className="comments-list">
                {comments.length === 0 ? (
                  <div className="empty-state">No comments yet</div>
                ) : (
                  comments.map((comment) => (
                    <div key={comment._id} className="comment-item">
                      <div className="comment-header">
                        <div className="comment-author">
                          <span className="author-name">{comment.user.name}</span>
                          <span className="comment-date">
                            {new Date(comment.createdAt).toLocaleString()}
                          </span>
                        </div>
                        {comment.user.email === user?.email && (
                          <button
                            onClick={() => handleDeleteComment(comment._id)}
                            className="delete-comment-btn"
                            title="Delete"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                      <div className="comment-text">{comment.text}</div>
                      
                      {comment.replies && comment.replies.length > 0 && (
                        <div className="replies-section">
                          {comment.replies.map((reply, idx) => (
                            <div key={idx} className="reply-item">
                              <span className="reply-author">{reply.user.name}:</span>
                              <span className="reply-text">{reply.text}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {replyingTo === comment._id ? (
                        <div className="reply-form">
                          <input
                            type="text"
                            value={replyText}
                            onChange={(e) => setReplyText(e.target.value)}
                            placeholder="Write a reply..."
                            className="reply-input"
                            autoFocus
                          />
                          <div className="reply-actions">
                            <button
                              onClick={() => handleAddReply(comment._id)}
                              className="reply-btn"
                            >
                              Reply
                            </button>
                            <button
                              onClick={() => {
                                setReplyingTo(null);
                                setReplyText('');
                              }}
                              className="cancel-reply-btn"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      ) : (
                        <button
                          onClick={() => setReplyingTo(comment._id)}
                          className="reply-toggle-btn"
                        >
                          Reply
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>

              <form onSubmit={handleAddComment} className="new-comment-form">
                <input
                  type="text"
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  placeholder="Add a comment..."
                  className="comment-input"
                />
                <button type="submit" className="add-comment-btn" disabled={!newComment.trim()}>
                  Post
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default FileComments;


