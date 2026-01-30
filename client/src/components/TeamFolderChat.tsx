import React, { useState, useEffect, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { teamFoldersAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './TeamFolderChat.css';

interface Message {
  _id: string;
  sender: {
    _id: string;
    name: string;
    email: string;
  };
  message: string;
  type: 'text' | 'file' | 'system' | 'thread';
  file?: {
    _id: string;
    originalName: string;
    size: number;
    mimeType: string;
  };
  threadParent?: string;
  mentions?: Array<{ _id: string; name: string; email: string }>;
  reactions?: Array<{
    emoji: string;
    users: string[];
    count: number;
  }>;
  isEdited?: boolean;
  editedAt?: string;
  isPinned?: boolean;
  createdAt: string;
  threadCount?: number;
}

interface TeamFolderChatProps {
  teamFolderId: string;
  teamFolderName: string;
  onClose: () => void;
}

const TeamFolderChat: React.FC<TeamFolderChatProps> = ({
  teamFolderId,
  teamFolderName,
  onClose,
}) => {
  const { user } = useAuth();
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [threadReplies, setThreadReplies] = useState<{ [key: string]: Message[] }>({});
  const [showThread, setShowThread] = useState<string | null>(null);
  const [editingMessage, setEditingMessage] = useState<string | null>(null);
  const [editText, setEditText] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    loadMessages();
    setupSocket();

    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, [teamFolderId]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const setupSocket = () => {
    const socket = io(process.env.REACT_APP_API_URL?.replace('/api', '') || 'http://localhost:5001');
    socketRef.current = socket;

    socket.emit('join-team-folder', teamFolderId);

    socket.on('new-message', (message: Message) => {
      setMessages(prev => [...prev, message]);
      scrollToBottom();
    });

    socket.on('message-updated', (message: Message) => {
      setMessages(prev =>
        prev.map(m => m._id === message._id ? message : m)
      );
    });

    socket.on('message-deleted', ({ messageId }: { messageId: string }) => {
      setMessages(prev => prev.filter(m => m._id !== messageId));
      setThreadReplies(prev => {
        const updated = { ...prev };
        delete updated[messageId];
        return updated;
      });
    });

    socket.on('reaction-added', ({ messageId, reactions }: { messageId: string; reactions: any[] }) => {
      setMessages(prev =>
        prev.map(m => m._id === messageId ? { ...m, reactions } : m)
      );
    });

    socket.on('reaction-removed', ({ messageId, reactions }: { messageId: string; reactions: any[] }) => {
      setMessages(prev =>
        prev.map(m => m._id === messageId ? { ...m, reactions } : m)
      );
    });

    socket.on('message-pinned', ({ messageId, isPinned }: { messageId: string; isPinned: boolean }) => {
      setMessages(prev =>
        prev.map(m => m._id === messageId ? { ...m, isPinned } : m)
      );
    });
  };

  const loadMessages = async () => {
    try {
      setLoading(true);
      const data = await teamFoldersAPI.getMessages(teamFolderId, { limit: 50 });
      setMessages(data);
    } catch (error) {
      console.error('Error loading messages:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadThreadReplies = async (messageId: string) => {
    try {
      const replies = await teamFoldersAPI.getThreadReplies(teamFolderId, messageId);
      setThreadReplies(prev => ({ ...prev, [messageId]: replies }));
    } catch (error) {
      console.error('Error loading thread replies:', error);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMessage.trim()) return;

    try {
      await teamFoldersAPI.sendMessage(teamFolderId, newMessage.trim());
      setNewMessage('');
      loadMessages();
    } catch (error: any) {
      console.error('Error sending message:', error);
      const errorMessage = error?.response?.data?.message || error?.message || 'Failed to send message';
      alert(errorMessage);
    }
  };

  const handleEditMessage = async (messageId: string) => {
    try {
      await teamFoldersAPI.editMessage(teamFolderId, messageId, editText);
      setEditingMessage(null);
      setEditText('');
    } catch (error) {
      console.error('Error editing message:', error);
      alert('Failed to edit message');
    }
  };

  const handleDeleteMessage = async (messageId: string) => {
    if (!window.confirm('Delete this message?')) return;
    try {
      await teamFoldersAPI.deleteMessage(teamFolderId, messageId);
    } catch (error) {
      console.error('Error deleting message:', error);
      alert('Failed to delete message');
    }
  };

  const handleAddReaction = async (messageId: string, emoji: string) => {
    try {
      await teamFoldersAPI.addReaction(teamFolderId, messageId, emoji);
    } catch (error) {
      console.error('Error adding reaction:', error);
    }
  };

  const handleRemoveReaction = async (messageId: string, emoji: string) => {
    try {
      await teamFoldersAPI.removeReaction(teamFolderId, messageId, emoji);
    } catch (error) {
      console.error('Error removing reaction:', error);
    }
  };

  const handlePinMessage = async (messageId: string) => {
    try {
      await teamFoldersAPI.pinMessage(teamFolderId, messageId);
    } catch (error) {
      console.error('Error pinning message:', error);
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const formatTime = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);

    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
    return date.toLocaleDateString();
  };

  const getUserInitials = (name: string) => {
    return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
  };

  const commonEmojis: string[] = [];

  return (
    <div className="team-folder-chat">
      <div className="chat-header">
        <div className="chat-header-info">
          <h3>{teamFolderName}</h3>
          <span className="chat-subtitle">Team collaboration</span>
        </div>
        <button onClick={onClose} className="close-chat-btn">×</button>
      </div>

      <div className="comments-section">
        {loading ? (
          <div className="chat-loading">Loading messages...</div>
        ) : (
          <>
            <div className="comments-list">
              {messages.length === 0 ? (
                <div className="chat-empty">
                  <div className="empty-icon"></div>
                  <p>No messages yet. Start the conversation!</p>
                </div>
              ) : (
                messages.map((message) => (
                  <div key={message._id} className={`comment-item ${message.isPinned ? 'pinned' : ''}`}>
                    {message.isPinned && <div className="pin-indicator">Pinned</div>}
                    
                    <div className="comment-content-wrapper">
                      <div className="comment-avatar">
                        {getUserInitials(message.sender.name)}
                      </div>
                      
                      <div className="comment-main">
                        <div className="comment-header">
                          <div className="comment-author">
                            <span className="author-name">{message.sender.name}</span>
                            <span className="comment-date">{formatTime(message.createdAt)}</span>
                          </div>
                          {message.sender._id === user?.id && (
                            <div className="comment-actions">
                              <button
                                onClick={() => {
                                  setEditingMessage(message._id);
                                  setEditText(message.message);
                                }}
                                className="action-btn"
                                title="Edit"
                              >
                                Edit
                              </button>
                              <button
                                onClick={() => handleDeleteMessage(message._id)}
                                className="action-btn"
                                title="Delete"
                              >
                                Delete
                              </button>
                            </div>
                          )}
                        </div>

                    {editingMessage === message._id ? (
                      <div className="message-edit">
                        <input
                          type="text"
                          value={editText}
                          onChange={(e) => setEditText(e.target.value)}
                          className="edit-input"
                          autoFocus
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              handleEditMessage(message._id);
                            } else if (e.key === 'Escape') {
                              setEditingMessage(null);
                              setEditText('');
                            }
                          }}
                        />
                        <div className="edit-actions">
                          <button onClick={() => handleEditMessage(message._id)}>Save</button>
                          <button onClick={() => { setEditingMessage(null); setEditText(''); }}>Cancel</button>
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="comment-text">
                          {message.message}
                          {message.isEdited && <span className="edited-badge"> (edited)</span>}
                        </div>
                        
                        {message.file && (
                          <div className="message-file">
                            {message.file.originalName} ({Math.round(message.file.size / 1024)} KB)
                          </div>
                        )}
                        
                        {message.mentions && message.mentions.length > 0 && (
                          <div className="message-mentions">
                            Mentioned: {message.mentions.map(m => m.name).join(', ')}
                          </div>
                        )}

                        <div className="message-reactions">
                          {message.reactions?.map((reaction, idx) => {
                            const hasReacted = reaction.users.includes(user?.id || '');
                            return (
                              <button
                                key={idx}
                                className={`reaction ${hasReacted ? 'active' : ''}`}
                                onClick={() => {
                                  if (hasReacted) {
                                    handleRemoveReaction(message._id, reaction.emoji);
                                  } else {
                                    handleAddReaction(message._id, reaction.emoji);
                                  }
                                }}
                              >
                                {reaction.emoji} {reaction.count}
                              </button>
                            );
                          })}
                          <div className="reaction-picker">
                            {commonEmojis.map(emoji => (
                              <button
                                key={emoji}
                                className="emoji-btn"
                                onClick={() => handleAddReaction(message._id, emoji)}
                                title={emoji}
                              >
                                {emoji}
                              </button>
                            ))}
                          </div>
                        </div>

                        {message.threadCount && message.threadCount > 0 && (
                          <button
                            className="thread-toggle"
                            onClick={() => {
                              if (showThread === message._id) {
                                setShowThread(null);
                              } else {
                                setShowThread(message._id);
                                if (!threadReplies[message._id]) {
                                  loadThreadReplies(message._id);
                                }
                              }
                            }}
                          >
                            {message.threadCount} {message.threadCount === 1 ? 'reply' : 'replies'}
                          </button>
                        )}

                        {showThread === message._id && threadReplies[message._id] && (
                          <div className="replies-section">
                            {threadReplies[message._id].map(reply => (
                              <div key={reply._id} className="reply-item">
                                <span className="reply-author">{reply.sender.name}:</span>
                                <span className="reply-text">{reply.message}</span>
                              </div>
                            ))}
                            <form
                              onSubmit={async (e) => {
                                e.preventDefault();
                                const input = e.currentTarget.querySelector('input') as HTMLInputElement;
                                if (input.value.trim()) {
                                  await teamFoldersAPI.sendMessage(teamFolderId, input.value, message._id);
                                  input.value = '';
                                  loadThreadReplies(message._id);
                                  loadMessages();
                                }
                              }}
                              className="reply-form"
                            >
                              <input type="text" placeholder="Write a reply..." className="reply-input" />
                              <div className="reply-actions">
                                <button type="submit" className="reply-btn">Reply</button>
                                <button
                                  type="button"
                                  onClick={() => setShowThread(null)}
                                  className="cancel-reply-btn"
                                >
                                  Cancel
                                </button>
                              </div>
                            </form>
                          </div>
                        )}

                        {showThread !== message._id && (
                          <button
                            onClick={() => {
                              setShowThread(message._id);
                              if (!threadReplies[message._id]) {
                                loadThreadReplies(message._id);
                              }
                            }}
                            className="reply-toggle-btn"
                          >
                            Reply
                          </button>
                        )}
                      </>
                    )}
                      </div>
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            <form onSubmit={handleSendMessage} className="new-comment-form">
              <input
                type="text"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                placeholder="Add a comment..."
                className="comment-input"
              />
              <button type="submit" className="add-comment-btn" disabled={!newMessage.trim()}>
                Post
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
};

export default TeamFolderChat;
