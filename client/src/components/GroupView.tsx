import React, { useState, useEffect } from 'react';
import { groupsAPI, socialAPI, filesAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import PostCard from './PostCard';
import CreatePostModal from './CreatePostModal';
import InviteUsersModal from './InviteUsersModal';
import { BackIcon, LockIcon, ScrollIcon, PlusIcon, MailIcon, SummaryIcon, DocumentIcon, ImageIcon, VideoIcon, AudioIcon, CloseIcon, CheckIcon, UsersIcon } from './Icons';
import './GroupView.css';
import './JoinRequestsModal.css';

interface Group {
  _id: string;
  name: string;
  description: string;
  creator: {
    _id: string;
    name: string;
    email: string;
  };
  memberCount: number;
  postCount: number;
  privacy: 'public' | 'private';
  isMember: boolean;
  isAdmin: boolean;
  isCreator: boolean;
  members: Array<{
    user: {
      _id: string;
      name: string;
      email: string;
    };
    role: string;
  }>;
}

interface SocialPost {
  _id: string;
  owner: any;
  file: any;
  folder: any;
  description: string;
  likes: any[];
  comments: any[];
  downloadCount: number;
  viewCount: number;
  repostCount: number;
  originalPost: SocialPost | null;
  repostedBy: any | null;
  createdAt: string;
}

interface GroupViewProps {
  groupId: string;
  onBack: () => void;
  onUpdate: () => void;
}

const GroupView: React.FC<GroupViewProps> = ({ groupId, onBack, onUpdate }) => {
  const { user } = useAuth();
  const [group, setGroup] = useState<Group | null>(null);
  const [posts, setPosts] = useState<SocialPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [availableFiles, setAvailableFiles] = useState<any[]>([]);
  const [availableFolders, setAvailableFolders] = useState<any[]>([]);
  const [selectedFileId, setSelectedFileId] = useState<string>('');
  const [selectedFolderId, setSelectedFolderId] = useState<string>('');
  const [postDescription, setPostDescription] = useState('');
  const [showJoinRequests, setShowJoinRequests] = useState(false);
  const [joinRequests, setJoinRequests] = useState<any[]>([]);
  const [showInviteModal, setShowInviteModal] = useState(false);

  useEffect(() => {
    loadGroup();
    loadPosts();
  }, [groupId]);

  useEffect(() => {
    if ((group?.isAdmin || group?.isCreator) && group.privacy === 'private') {
      loadJoinRequests();
    }
  }, [group?.isAdmin, group?.isCreator, group?.privacy, groupId]);

  // Reload requests when modal opens
  useEffect(() => {
    if (showJoinRequests && group?.isAdmin) {
      loadJoinRequests();
    }
  }, [showJoinRequests]);

  const loadGroup = async () => {
    try {
      const data = await groupsAPI.getGroup(groupId);
      setGroup(data);
      // If admin, load join requests
      if (data.isAdmin && data.privacy === 'private') {
        loadJoinRequests();
      }
    } catch (error) {
      console.error('Error loading group:', error);
    }
  };

  const loadPosts = async () => {
    try {
      setLoading(true);
      const data = await groupsAPI.getGroupPosts(groupId, 1, 50);
      setPosts(data.posts || []);
    } catch (error) {
      console.error('Error loading posts:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAvailableItems = async () => {
    try {
      const data = await filesAPI.getFiles();
      setAvailableFiles(data.files || []);
      setAvailableFolders(data.folders || []);
    } catch (error) {
      console.error('Error loading files:', error);
    }
  };

  const handleCreatePost = async () => {
    if (!selectedFileId && !selectedFolderId) {
      alert('Please select a file or folder to share');
      return;
    }

    try {
      await socialAPI.createPost(
        selectedFileId || undefined,
        selectedFolderId || undefined,
        postDescription,
        true,
        groupId
      );
      setShowCreateModal(false);
      setSelectedFileId('');
      setSelectedFolderId('');
      setPostDescription('');
      loadPosts();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create post');
    }
  };

  const handleJoinGroup = async () => {
    try {
      if (group?.privacy === 'private') {
        // For private groups, request to join
        const message = prompt('Optional message to group admin:') || '';
        const result = await groupsAPI.requestToJoin(groupId, message);
        if (result.joined) {
          alert('Joined group successfully!');
        } else {
          alert('Join request sent! The admin will review your request.');
        }
      } else {
        // For public groups, join directly
        await groupsAPI.joinGroup(groupId);
        alert('Joined group successfully!');
      }
      await loadGroup();
      onUpdate();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to join/request to join group');
    }
  };

  const handleLeaveGroup = async () => {
    if (!window.confirm('Are you sure you want to leave this group?')) return;
    try {
      await groupsAPI.leaveGroup(groupId);
      onBack();
      onUpdate();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to leave group');
    }
  };

  const loadJoinRequests = async () => {
    try {
      console.log('Loading join requests for group:', groupId);
      const data = await groupsAPI.getJoinRequests(groupId);
      console.log('Join requests data:', data);
      setJoinRequests(data.requests || []);
    } catch (error: any) {
      console.error('Error loading join requests:', error);
      console.error('Error response:', error.response?.data);
      alert('Failed to load join requests: ' + (error.response?.data?.message || error.message));
    }
  };

  const handleAcceptRequest = async (requestId: string) => {
    try {
      await groupsAPI.acceptJoinRequest(groupId, requestId);
      await loadJoinRequests();
      await loadGroup();
      await loadPosts();
      alert('Join request accepted!');
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to accept request');
    }
  };

  const handleRejectRequest = async (requestId: string) => {
    if (!window.confirm('Are you sure you want to reject this join request?')) return;
    try {
      await groupsAPI.rejectJoinRequest(groupId, requestId);
      await loadJoinRequests();
      alert('Join request rejected');
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to reject request');
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
    return post.likes.some(like => like.user._id === user?.id);
  };

  const handleLike = async (postId: string) => {
    try {
      await socialAPI.likePost(postId);
      loadPosts();
    } catch (error) {
      console.error('Error liking post:', error);
    }
  };

  const handleAddComment = async (postId: string, text: string) => {
    try {
      await socialAPI.addComment(postId, text);
      loadPosts();
    } catch (error) {
      console.error('Error adding comment:', error);
    }
  };

  const handleDeletePost = async (postId: string) => {
    if (!window.confirm('Are you sure you want to delete this post?')) return;
    try {
      await socialAPI.deletePost(postId);
      setPosts(posts.filter(post => post._id !== postId));
    } catch (error) {
      console.error('Error deleting post:', error);
      alert('Failed to delete post');
    }
  };

  if (loading && !group) {
    return (
      <div className="group-view-container">
        <div className="loading">Loading group...</div>
      </div>
    );
  }

  if (!group) {
    return (
      <div className="group-view-container">
        <div className="error">Group not found</div>
        <button onClick={onBack}>Go Back</button>
      </div>
    );
  }

  return (
    <div className="group-view-container">
      <div className="group-header-section">
        <button className="back-btn" onClick={onBack}><BackIcon size={18} color="currentColor" /> Back</button>
        <div className="group-header-info">
          <div className="group-avatar-large">
            {group.name.charAt(0).toUpperCase()}
          </div>
          <div className="group-header-details">
            <h1>{group.name}</h1>
            {group.description && <p className="group-description">{group.description}</p>}
            <div className="group-stats">
              <span>{group.memberCount} members</span>
              <span>•</span>
              <span>{group.postCount} posts</span>
              {group.privacy === 'private' && (
                <span>• <LockIcon size={14} color="currentColor" style={{ display: 'inline-block', verticalAlign: 'middle', marginRight: '0.25rem' }} /> Private</span>
              )}
            </div>
          </div>
        </div>
        <div className="group-header-actions">
          {group.isMember ? (
            <>
              {group.isAdmin || group.isCreator ? (
                <>
                  <button
                    className="action-btn invite"
                    onClick={() => setShowInviteModal(true)}
                  >
                    <UsersIcon size={18} color="currentColor" /> Invite Users
                  </button>
                  {group.privacy === 'private' && (
                    <button
                      className="action-btn admin"
                      onClick={async () => {
                        await loadJoinRequests();
                        setShowJoinRequests(true);
                      }}
                    >
                      <ScrollIcon size={18} color="currentColor" /> Join Requests {joinRequests.length > 0 && `(${joinRequests.length})`}
                    </button>
                  )}
                </>
              ) : null}
              <button
                className="action-btn primary"
                onClick={() => {
                  setShowCreateModal(true);
                  loadAvailableItems();
                }}
              >
                <PlusIcon size={18} color="currentColor" /> Post to Group
              </button>
              {!group.isCreator && (
                <button
                  className="action-btn secondary"
                  onClick={handleLeaveGroup}
                >
                  Leave Group
                </button>
              )}
            </>
          ) : (
            <button
              className="action-btn primary"
              onClick={handleJoinGroup}
            >
              {group.privacy === 'private' ? (
                <>
                  <MailIcon size={18} color="currentColor" /> Request to Join
                </>
              ) : (
                <>
                  <PlusIcon size={18} color="currentColor" /> Join Group
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {group.isMember ? (
        <>
          {posts.length === 0 ? (
            <div className="empty-posts">
              <div className="empty-icon"><SummaryIcon size={48} color="#999" /></div>
              <p>No posts yet</p>
              <p className="hint">Be the first to share a file or folder!</p>
            </div>
          ) : (
            <div className="group-posts">
              {posts.map(post => (
                <PostCard
                  key={post._id}
                  post={post}
                  currentUserId={user?.id}
                  onLike={() => handleLike(post._id)}
                  onComment={(text) => handleAddComment(post._id, text)}
                  onDelete={() => handleDeletePost(post._id)}
                  onRepost={() => {}}
                  onSave={() => {}}
                  onUserClick={() => {}}
                  isLiked={isLiked(post)}
                  isSaved={false}
                  formatSize={formatSize}
                  getFileIcon={getFileIcon}
                />
              ))}
            </div>
          )}
        </>
      ) : (
        <div className="private-group-message">
          <p>This is a private group. Join to see posts and share files.</p>
        </div>
      )}

      {showCreateModal && (
        <CreatePostModal
          files={availableFiles}
          folders={availableFolders}
          selectedFileId={selectedFileId}
          selectedFolderId={selectedFolderId}
          description={postDescription}
          isPublic={true}
          onFileSelect={setSelectedFileId}
          onFolderSelect={setSelectedFolderId}
          onDescriptionChange={setPostDescription}
          onPublicChange={() => {}}
          onSubmit={handleCreatePost}
          onClose={() => setShowCreateModal(false)}
          formatSize={formatSize}
          getFileIcon={getFileIcon}
        />
      )}

      {showJoinRequests && (
        <JoinRequestsModal
          requests={joinRequests}
          onAccept={handleAcceptRequest}
          onReject={handleRejectRequest}
          onClose={() => setShowJoinRequests(false)}
        />
      )}

      {showInviteModal && group && (
        <InviteUsersModal
          groupId={groupId}
          groupName={group.name}
          existingMemberIds={group.members.map((m: any) => m.user._id || m.user)}
          onClose={() => setShowInviteModal(false)}
          onInviteSuccess={() => {
            loadGroup();
            onUpdate();
          }}
        />
      )}
    </div>
  );
};

interface JoinRequestsModalProps {
  requests: any[];
  onAccept: (requestId: string) => void;
  onReject: (requestId: string) => void;
  onClose: () => void;
}

const JoinRequestsModal: React.FC<JoinRequestsModalProps> = ({ requests, onAccept, onReject, onClose }) => {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content join-requests-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Join Requests ({requests.length})</h3>
          <button className="close-btn" onClick={onClose}><CloseIcon size={18} color="currentColor" /></button>
        </div>
        <div className="modal-body">
          {requests.length === 0 ? (
            <div className="no-requests">
              <p>No pending join requests</p>
            </div>
          ) : (
            <div className="requests-list">
              {requests.map(request => (
                <div key={request._id} className="request-item">
                  <div className="request-user-info">
                    <div className="user-avatar-small">
                      {request.user?.name?.charAt(0).toUpperCase() || '?'}
                    </div>
                    <div className="request-details">
                      <div className="request-user-name">{request.user?.name || 'Unknown User'}</div>
                      <div className="request-user-email">{request.user?.email || ''}</div>
                      {request.message && (
                        <div className="request-message">"{request.message}"</div>
                      )}
                      <div className="request-date">
                        Requested {new Date(request.createdAt).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                  <div className="request-actions">
                    <button
                      className="accept-btn"
                      onClick={() => onAccept(request._id)}
                    >
                      <CheckIcon size={16} color="currentColor" /> Accept
                    </button>
                    <button
                      className="reject-btn"
                      onClick={() => onReject(request._id)}
                    >
                      <CloseIcon size={16} color="currentColor" /> Reject
                    </button>
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

export default GroupView;

