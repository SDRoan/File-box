import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  // Don't override Content-Type for FormData (file uploads) - let browser set it with boundary
  if (config.data instanceof FormData) {
    delete config.headers['Content-Type'];
  }
  return config;
});

// Auth API
export const authAPI = {
  register: async (email: string, password: string, name: string) => {
    const response = await api.post('/auth/register', { email, password, name });
    return response.data;
  },
  verifyCode: async (email: string, code: string) => {
    const response = await api.post('/auth/verify-code', { email, code });
    return response.data;
  },
  resendCode: async (email: string) => {
    const response = await api.post('/auth/resend-code', { email });
    return response.data;
  },
  login: async (email: string, password: string) => {
    const response = await api.post('/auth/login', { email, password });
    return response.data;
  },
  getCurrentUser: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  },
};

// Security API
export const securityAPI = {
  getDashboard: async () => {
    const response = await api.get('/security/dashboard');
    return response.data;
  },
  getAuditLogs: async (params?: { page?: number; limit?: number; action?: string; startDate?: string; endDate?: string }) => {
    const response = await api.get('/security/audit-logs', { params });
    return response.data;
  },
  updateSettings: async (settings: { sessionTimeout?: number; requireIpWhitelist?: boolean; ipWhitelist?: string[] }) => {
    const response = await api.put('/security/settings', settings);
    return response.data;
  },
  updateClassification: async (type: 'file' | 'folder', id: string, dataClassification: string) => {
    const response = await api.put(`/security/classification/${type}/${id}`, { dataClassification });
    return response.data;
  },
  toggleWatermark: async (fileId: string, enabled: boolean) => {
    const response = await api.put(`/security/watermark/${fileId}`, { enabled });
    return response.data;
  },
};

// Files API
export const filesAPI = {
  getFiles: async (folderId?: string, trashed?: boolean, starred?: boolean) => {
    const params: any = {};
    if (folderId) params.folderId = folderId;
    if (trashed) params.trashed = 'true';
    if (starred) params.starred = 'true';
    const response = await api.get('/files', { params });
    return response.data;
  },
  getFileById: async (fileId: string) => {
    const response = await api.get(`/files/file/${fileId}`);
    return response.data;
  },
  getFolder: async (folderId: string) => {
    const response = await api.get(`/files/folder/${folderId}`);
    return response.data.folder;
  },
  uploadFile: async (file: File, parentFolder?: string) => {
    const formData = new FormData();
    formData.append('file', file);
    if (parentFolder) formData.append('parentFolder', parentFolder);
    const response = await api.post('/files/upload', formData, {
      timeout: 60000, // 60 second timeout for large files
    });
    return response.data;
  },
  createFolder: async (name: string, parentFolder?: string) => {
    const response = await api.post('/files/folder', { name, parentFolder });
    return response.data;
  },
  downloadFile: async (fileId: string) => {
    const response = await api.get(`/files/download/${fileId}`, {
      responseType: 'blob',
    });
    return response.data;
  },
  deleteFile: async (fileId: string) => {
    const response = await api.delete(`/files/${fileId}?type=file`);
    return response.data;
  },
  deleteFolder: async (folderId: string) => {
    const response = await api.delete(`/files/${folderId}?type=folder`);
    return response.data;
  },
  permanentDeleteFile: async (fileId: string) => {
    const response = await api.delete(`/files/permanent/${fileId}?type=file`);
    return response.data;
  },
  permanentDeleteFolder: async (folderId: string) => {
    const response = await api.delete(`/files/permanent/${folderId}?type=folder`);
    return response.data;
  },
  restoreFile: async (fileId: string) => {
    const response = await api.post(`/files/restore/${fileId}?type=file`);
    return response.data;
  },
  restoreFolder: async (folderId: string) => {
    const response = await api.post(`/files/restore/${folderId}?type=folder`);
    return response.data;
  },
  starFile: async (fileId: string) => {
    const response = await api.post(`/files/star/${fileId}?type=file`);
    return response.data;
  },
  starFolder: async (folderId: string) => {
    const response = await api.post(`/files/star/${folderId}?type=folder`);
    return response.data;
  },
  renameFile: async (fileId: string, name: string) => {
    const response = await api.patch(`/files/rename/${fileId}`, { name, type: 'file' });
    return response.data;
  },
  renameFolder: async (folderId: string, name: string) => {
    const response = await api.patch(`/files/rename/${folderId}`, { name, type: 'folder' });
    return response.data;
  },
  moveFile: async (fileId: string, targetFolderId?: string) => {
    const response = await api.patch(`/files/move/${fileId}`, { type: 'file', targetFolderId: targetFolderId || 'root' });
    return response.data;
  },
  moveFolder: async (folderId: string, targetFolderId?: string) => {
    const response = await api.patch(`/files/move/${folderId}`, { type: 'folder', targetFolderId: targetFolderId || 'root' });
    return response.data;
  },
  copyFile: async (fileId: string, targetFolderId?: string) => {
    const response = await api.post(`/files/copy/${fileId}`, { targetFolderId: targetFolderId || 'root' });
    return response.data;
  },
  downloadFolderAsZip: async (folderId: string) => {
    const response = await api.get(`/files/download-folder/${folderId}`, {
      responseType: 'blob',
    });
    return response.data;
  },
  getFileVersions: async (fileId: string) => {
    const response = await api.get(`/files/versions/${fileId}`);
    return response.data;
  },
  downloadFileVersion: async (versionId: string) => {
    const response = await api.get(`/files/version/${versionId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  },
  restoreFileVersion: async (versionId: string) => {
    const response = await api.post(`/files/version/${versionId}/restore`);
    return response.data;
  },
  uploadFileVersion: async (fileId: string, file: File, changeDescription?: string) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('isNewVersion', 'true');
    formData.append('fileId', fileId);
    if (changeDescription) formData.append('changeDescription', changeDescription);
    const response = await api.post('/files/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },
  getFileActivity: async (fileId: string) => {
    const response = await api.get(`/files/activity/${fileId}`);
    return response.data;
  },
  getFolderActivity: async (folderId: string) => {
    const response = await api.get(`/files/folder-activity/${folderId}`);
    return response.data;
  },
  getUserActivity: async () => {
    const response = await api.get('/files/activity');
    return response.data;
  },
  getPreviewText: async (fileId: string) => {
    const response = await api.get(`/files/preview-text/${fileId}`);
    return response.data;
  },
  updateFile: async (fileId: string, blob: Blob, fileName: string) => {
    const formData = new FormData();
    formData.append('file', blob, fileName);
    const response = await api.put(`/files/update/${fileId}`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  updateFileAsDocx: async (fileId: string, text: string, fileName: string) => {
    const response = await api.put(`/files/update-docx/${fileId}`, { text, fileName });
    return response.data;
  },
  updateFileAsPdf: async (fileId: string, text: string, fileName: string) => {
    const response = await api.put(`/files/update-pdf/${fileId}`, { text, fileName });
    return response.data;
  },
};

// Team Folders API
export const teamFoldersAPI = {
  getTeamFolders: async () => {
    const response = await api.get('/team-folders');
    return response.data;
  },
  createTeamFolder: async (name: string, parentFolder?: string) => {
    const response = await api.post('/team-folders', { name, parentFolder });
    return response.data;
  },
  getTeamFolder: async (folderId: string) => {
    const response = await api.get(`/team-folders/${folderId}`);
    return response.data;
  },
  addMember: async (folderId: string, userId: string, role: 'admin' | 'editor' | 'viewer') => {
    const response = await api.post(`/team-folders/${folderId}/members`, { userId, role });
    return response.data;
  },
  removeMember: async (folderId: string, userId: string) => {
    const response = await api.delete(`/team-folders/${folderId}/members/${userId}`);
    return response.data;
  },
  getTeamFolderFiles: async (folderId: string) => {
    const response = await api.get(`/team-folders/${folderId}/files`);
    return response.data;
  },
  uploadFile: async (folderId: string, file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post(`/team-folders/${folderId}/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },
  createFolder: async (folderId: string, folderName: string) => {
    const response = await api.post(`/team-folders/${folderId}/folders`, { name: folderName });
    return response.data;
  },
  deleteTeamFolder: async (folderId: string) => {
    const response = await api.delete(`/team-folders/${folderId}`);
    return response.data;
  },
  // Messaging (Slack-like features)
  getMessages: async (folderId: string, params?: { limit?: number; before?: string }) => {
    const response = await api.get(`/team-folders/${folderId}/messages`, { params });
    return response.data;
  },
  sendMessage: async (folderId: string, message: string, threadParent?: string, fileId?: string) => {
    const response = await api.post(`/team-folders/${folderId}/messages`, {
      message,
      threadParent,
      fileId
    });
    return response.data;
  },
  getThreadReplies: async (folderId: string, messageId: string) => {
    const response = await api.get(`/team-folders/${folderId}/messages/${messageId}/thread`);
    return response.data;
  },
  editMessage: async (folderId: string, messageId: string, message: string) => {
    const response = await api.patch(`/team-folders/${folderId}/messages/${messageId}`, { message });
    return response.data;
  },
  deleteMessage: async (folderId: string, messageId: string) => {
    const response = await api.delete(`/team-folders/${folderId}/messages/${messageId}`);
    return response.data;
  },
  addReaction: async (folderId: string, messageId: string, emoji: string) => {
    const response = await api.post(`/team-folders/${folderId}/messages/${messageId}/reactions`, { emoji });
    return response.data;
  },
  removeReaction: async (folderId: string, messageId: string, emoji: string) => {
    const response = await api.delete(`/team-folders/${folderId}/messages/${messageId}/reactions/${emoji}`);
    return response.data;
  },
  pinMessage: async (folderId: string, messageId: string) => {
    const response = await api.post(`/team-folders/${folderId}/messages/${messageId}/pin`);
    return response.data;
  },
};

// File Requests API
export const fileRequestsAPI = {
  getFileRequests: async () => {
    const response = await api.get('/file-requests');
    return response.data;
  },
  createFileRequest: async (title: string, description?: string, folderId?: string, expiresAt?: string) => {
    const response = await api.post('/file-requests', { title, description, folderId, expiresAt });
    return response.data;
  },
  getFileRequest: async (requestId: string) => {
    const response = await api.get(`/file-requests/${requestId}`);
    return response.data;
  },
  uploadToRequest: async (requestId: string, file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post(`/file-requests/${requestId}/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },
  closeFileRequest: async (requestId: string) => {
    const response = await api.patch(`/file-requests/${requestId}/close`);
    return response.data;
  },
  deleteFileRequest: async (requestId: string) => {
    const response = await api.delete(`/file-requests/${requestId}`);
    return response.data;
  },
};

// Comments API
export const commentsAPI = {
  getFileComments: async (fileId: string) => {
    const response = await api.get(`/comments/file/${fileId}`);
    return response.data;
  },
  addComment: async (fileId: string, text: string) => {
    const response = await api.post(`/comments/file/${fileId}`, { text });
    return response.data;
  },
  updateComment: async (commentId: string, text: string) => {
    const response = await api.patch(`/comments/${commentId}`, { text });
    return response.data;
  },
  deleteComment: async (commentId: string) => {
    const response = await api.delete(`/comments/${commentId}`);
    return response.data;
  },
  addReply: async (commentId: string, text: string) => {
    const response = await api.post(`/comments/${commentId}/reply`, { text });
    return response.data;
  },
};

// Share API
export const shareAPI = {
  createShare: async (fileId: string, accessType?: string, password?: string, expiresAt?: string) => {
    const response = await api.post('/share/create', { fileId, accessType, password, expiresAt });
    return response.data;
  },
  getShare: async (shareId: string) => {
    const response = await api.get(`/share/${shareId}`);
    return response.data;
  },
  shareWithUser: async (fileId: string, userId: string, permission?: string, password?: string, expiresAt?: string) => {
    const response = await api.post('/share/user', { fileId, userId, permission, password, expiresAt });
    return response.data;
  },
  getSharedWithMe: async () => {
    const response = await api.get('/share/shared/with-me');
    return response.data;
  },
  getSharedByMe: async () => {
    const response = await api.get('/share/shared/by-me');
    return response.data;
  },
  getSharedFileActivity: async (fileId: string) => {
    const response = await api.get(`/share/activity/${fileId}`);
    return response.data;
  },
  getSharedFilesStats: async () => {
    const response = await api.get('/share/shared/by-me/stats');
    return response.data;
  },
  removeShare: async (shareId: string) => {
    const response = await api.delete(`/share/${shareId}`);
    return response.data;
  },
};

// Users API
export const usersAPI = {
  getProfile: async () => {
    const response = await api.get('/users/profile');
    return response.data;
  },
  updateProfile: async (name?: string, email?: string) => {
    const response = await api.patch('/users/profile', { name, email });
    return response.data;
  },
  searchUsers: async (query: string) => {
    const response = await api.get('/users/search', { params: { q: query } });
    return response.data;
  },
  getAllUsers: async () => {
    const response = await api.get('/users/all');
    return response.data;
  },
};

// Search API
export const searchAPI = {
  aiSearch: async (query: string) => {
    const response = await api.get('/search/ai', { params: { q: query } });
    return response.data;
  },
  extractText: async (fileId: string) => {
    const response = await api.post(`/search/extract/${fileId}`);
    return response.data;
  },
  extractAll: async (force: boolean = true) => {
    const response = await api.post('/search/extract-all', { force });
    return response.data;
  },
};

// Summarization API
export const summarizationAPI = {
  generateSummary: async (fileId: string, force: boolean = false) => {
    const response = await api.post(`/summarization/${fileId}`, { force });
    return response.data;
  },
  getSummary: async (fileId: string) => {
    const response = await api.get(`/summarization/${fileId}`);
    return response.data;
  },
  getConfig: async () => {
    const response = await api.get('/summarization/config');
    return response.data;
  },
};

// Relationships API
export const relationshipsAPI = {
  createRelationship: async (
    sourceFileId: string,
    targetFileId: string,
    relationshipType?: string,
    customLabel?: string,
    description?: string
  ) => {
    const response = await api.post('/relationships', {
      sourceFileId,
      targetFileId,
      relationshipType,
      customLabel,
      description,
    });
    return response.data;
  },
  getFileRelationships: async (fileId: string) => {
    const response = await api.get(`/relationships/file/${fileId}`);
    return response.data;
  },
  getRelationshipGraph: async () => {
    const response = await api.get('/relationships/graph');
    return response.data;
  },
  updateRelationship: async (relationshipId: string, data: { relationshipType?: string; customLabel?: string; description?: string }) => {
    const response = await api.put(`/relationships/${relationshipId}`, data);
    return response.data;
  },
  deleteRelationship: async (relationshipId: string) => {
    const response = await api.delete(`/relationships/${relationshipId}`);
    return response.data;
  },
  getSuggestions: async (fileId: string) => {
    const response = await api.get(`/relationships/suggestions/${fileId}`);
    return response.data;
  },
};

// Smart Organization API
export const smartOrgAPI = {
  analyzeFile: async (fileId: string) => {
    const response = await api.post(`/smart-org/analyze/${fileId}`);
    return response.data;
  },
  analyzeBulk: async (fileIds: string[]) => {
    const response = await api.post('/smart-org/analyze-bulk', { fileIds });
    return response.data;
  },
  getSuggestions: async (folderId?: string) => {
    const url = folderId ? `/smart-org/suggest/${folderId}` : '/smart-org/suggest';
    const response = await api.get(url);
    return response.data;
  },
  organizeFiles: async (folderName: string, fileIds: string[], parentFolderId?: string) => {
    const response = await api.post('/smart-org/organize', {
      folderName,
      fileIds,
      parentFolderId
    });
    return response.data;
  },
};

// Social API
export const socialAPI = {
  createPost: async (fileId?: string, folderId?: string, description?: string, isPublic?: boolean, groupId?: string) => {
    const response = await api.post('/social/post', { fileId, folderId, description, isPublic, groupId });
    return response.data;
  },
  getFeed: async (page: number = 1, limit: number = 20) => {
    const response = await api.get('/social/feed', { params: { page, limit } });
    return response.data;
  },
  getUserPosts: async (userId: string, page: number = 1, limit: number = 20) => {
    const response = await api.get(`/social/user/${userId}/posts`, { params: { page, limit } });
    return response.data;
  },
  likePost: async (postId: string) => {
    const response = await api.post(`/social/post/${postId}/like`);
    return response.data;
  },
  addComment: async (postId: string, text: string) => {
    const response = await api.post(`/social/post/${postId}/comment`, { text });
    return response.data;
  },
  deletePost: async (postId: string) => {
    const response = await api.delete(`/social/post/${postId}`);
    return response.data;
  },
  followUser: async (userId: string) => {
    const response = await api.post(`/social/follow/${userId}`);
    return response.data;
  },
  getFollowStatus: async (userId: string) => {
    const response = await api.get(`/social/follow/${userId}`);
    return response.data;
  },
  getUserStats: async (userId: string) => {
    const response = await api.get(`/social/user/${userId}/stats`);
    return response.data;
  },
  discoverUsers: async (limit: number = 10) => {
    const response = await api.get('/social/discover', { params: { limit } });
    return response.data;
  },
  repostPost: async (postId: string) => {
    const response = await api.post(`/social/post/${postId}/repost`);
    return response.data;
  },
  savePost: async (postId: string) => {
    const response = await api.post(`/social/post/${postId}/save`);
    return response.data;
  },
  getSavedPosts: async () => {
    const response = await api.get('/social/saved');
    return response.data;
  },
  searchUsers: async (query: string) => {
    const response = await api.get('/social/search/users', { params: { q: query } });
    return response.data;
  },
  getUserProfile: async (userId: string) => {
    const response = await api.get(`/social/user/${userId}/profile`);
    return response.data;
  },
  updateProfile: async (bio: string) => {
    const response = await api.patch('/social/profile', { bio });
    return response.data;
  },
  getNotifications: async (limit: number = 50) => {
    const response = await api.get('/social/notifications', { params: { limit } });
    return response.data;
  },
  markNotificationRead: async (notificationId: string) => {
    const response = await api.patch(`/social/notifications/${notificationId}/read`);
    return response.data;
  },
  markAllNotificationsRead: async () => {
    const response = await api.patch('/social/notifications/read-all');
    return response.data;
  },
};

export const groupsAPI = {
  createGroup: async (name: string, description: string, privacy: string = 'public') => {
    const response = await api.post('/groups', { name, description, privacy });
    return response.data;
  },
  getGroups: async (page: number = 1, limit: number = 20, search?: string) => {
    const response = await api.get('/groups', { params: { page, limit, search } });
    return response.data;
  },
  getGroup: async (groupId: string) => {
    const response = await api.get(`/groups/${groupId}`);
    return response.data;
  },
  joinGroup: async (groupId: string) => {
    const response = await api.post(`/groups/${groupId}/join`);
    return response.data;
  },
  leaveGroup: async (groupId: string) => {
    const response = await api.post(`/groups/${groupId}/leave`);
    return response.data;
  },
  getGroupPosts: async (groupId: string, page: number = 1, limit: number = 20) => {
    const response = await api.get(`/groups/${groupId}/posts`, { params: { page, limit } });
    return response.data;
  },
  addAdmin: async (groupId: string, userId: string) => {
    const response = await api.post(`/groups/${groupId}/admin/${userId}`, { action: 'add' });
    return response.data;
  },
  removeAdmin: async (groupId: string, userId: string) => {
    const response = await api.post(`/groups/${groupId}/admin/${userId}`, { action: 'remove' });
    return response.data;
  },
  requestToJoin: async (groupId: string, message?: string) => {
    const response = await api.post(`/groups/${groupId}/join`, { message });
    return response.data;
  },
  getJoinRequests: async (groupId: string) => {
    const response = await api.get(`/groups/${groupId}/requests`);
    return response.data;
  },
  acceptJoinRequest: async (groupId: string, requestId: string) => {
    const response = await api.post(`/groups/${groupId}/requests/${requestId}/accept`);
    return response.data;
  },
  rejectJoinRequest: async (groupId: string, requestId: string) => {
    const response = await api.post(`/groups/${groupId}/requests/${requestId}/reject`);
    return response.data;
  },
  inviteUsers: async (groupId: string, userIds: string[]) => {
    const response = await api.post(`/groups/${groupId}/invite`, { userIds });
    return response.data;
  },
  getMyJoinRequests: async () => {
    const response = await api.get('/groups/requests/my');
    return response.data;
  },
};

// Analytics API
export const analyticsAPI = {
  getAccessStats: async (timeRange: string = '30d') => {
    const response = await api.get('/analytics/access-stats', { params: { timeRange } });
    return response.data;
  },
  getHeatmap: async (timeRange: string = '30d') => {
    const response = await api.get('/analytics/heatmap', { params: { timeRange } });
    return response.data;
  },
  getUnusedFiles: async (daysUnused: number = 90) => {
    const response = await api.get('/analytics/unused-files', { params: { daysUnused } });
    return response.data;
  },
  getStorageBreakdown: async () => {
    const response = await api.get('/analytics/storage-breakdown');
    return response.data;
  },
  getActivityTimeline: async (timeRange: string = '7d') => {
    const response = await api.get('/analytics/timeline', { params: { timeRange } });
    return response.data;
  },
  getTopFileTypes: async (timeRange: string = '30d') => {
    const response = await api.get('/analytics/top-types', { params: { timeRange } });
    return response.data;
  },
  getSuggestions: async () => {
    const response = await api.get('/analytics/suggestions');
    return response.data;
  },
};

// Assignments API
export const assignmentsAPI = {
  getAssignments: async (params?: { status?: string; course?: string; upcoming?: boolean }) => {
    const response = await api.get('/assignments', { params });
    return response.data;
  },
  getAssignment: async (id: string) => {
    const response = await api.get(`/assignments/${id}`);
    return response.data;
  },
  createAssignment: async (data: any) => {
    const response = await api.post('/assignments', data);
    return response.data;
  },
  updateAssignment: async (id: string, data: any) => {
    const response = await api.put(`/assignments/${id}`, data);
    return response.data;
  },
  deleteAssignment: async (id: string) => {
    const response = await api.delete(`/assignments/${id}`);
    return response.data;
  },
  attachFile: async (assignmentId: string, fileId: string) => {
    const response = await api.post(`/assignments/${assignmentId}/attach-file`, { fileId });
    return response.data;
  },
  removeFile: async (assignmentId: string, fileId: string) => {
    const response = await api.delete(`/assignments/${assignmentId}/attach-file/${fileId}`);
    return response.data;
  },
};

// Courses API
export const coursesAPI = {
  getCourses: async (params?: { semester?: string; year?: number }) => {
    const response = await api.get('/courses', { params });
    return response.data;
  },
  getCourse: async (id: string) => {
    const response = await api.get(`/courses/${id}`);
    return response.data;
  },
  createCourse: async (data: any) => {
    const response = await api.post('/courses', data);
    return response.data;
  },
  updateCourse: async (id: string, data: any) => {
    const response = await api.put(`/courses/${id}`, data);
    return response.data;
  },
  deleteCourse: async (id: string) => {
    const response = await api.delete(`/courses/${id}`);
    return response.data;
  },
};

// Study Groups API
// File Memory API
// Predictive Organization API
export const predictiveOrgAPI = {
  getSuggestions: async (fileId: string, actionBefore?: string) => {
    const response = await api.get(`/predictive-org/suggestions/${fileId}`, {
      params: { actionBefore }
    });
    return response.data;
  },
  getPatterns: async () => {
    const response = await api.get('/predictive-org/patterns');
    return response.data;
  },
  recordFeedback: async (patternId: string, action: 'accepted' | 'rejected' | 'ignored') => {
    const response = await api.post(`/predictive-org/feedback/${patternId}`, { action });
    return response.data;
  },
};

export const fileMemoryAPI = {
  getFileMemory: async (fileId: string) => {
    const response = await api.get(`/file-memory/file/${fileId}`);
    return response.data;
  },
  updateFileMemory: async (fileId: string, data: {
    userAction?: string;
    projectContext?: string;
    meetingContext?: string;
    deadlineContext?: string;
    notes?: string;
  }) => {
    const response = await api.put(`/file-memory/file/${fileId}`, data);
    return response.data;
  },
  getAllMemories: async (params?: { project?: string; search?: string; sortBy?: string }) => {
    const response = await api.get('/file-memory', { params });
    return response.data;
  },
  askAboutFile: async (fileId: string, question: string) => {
    const response = await api.post(`/file-memory/file/${fileId}/ask`, { question });
    return response.data;
  },
  linkFile: async (fileId: string, data: {
    project?: string;
    courseId?: string;
    studyGroupId?: string;
    assignmentId?: string;
  }) => {
    const response = await api.post(`/file-memory/file/${fileId}/link`, data);
    return response.data;
  },
};

export const studyGroupsAPI = {
  getStudyGroups: async (params?: { courseCode?: string }) => {
    const response = await api.get('/study-groups', { params });
    return response.data;
  },
  getStudyGroup: async (id: string) => {
    const response = await api.get(`/study-groups/${id}`);
    return response.data;
  },
  createStudyGroup: async (data: any) => {
    const response = await api.post('/study-groups', data);
    return response.data;
  },
  joinStudyGroup: async (id: string) => {
    const response = await api.post(`/study-groups/${id}/join`);
    return response.data;
  },
  leaveStudyGroup: async (id: string) => {
    const response = await api.post(`/study-groups/${id}/leave`);
    return response.data;
  },
  updateStudyGroup: async (id: string, data: any) => {
    const response = await api.put(`/study-groups/${id}`, data);
    return response.data;
  },
  deleteStudyGroup: async (id: string) => {
    const response = await api.delete(`/study-groups/${id}`);
    return response.data;
  },
  inviteUser: async (groupId: string, userId: string, message?: string) => {
    const response = await api.post(`/study-groups/${groupId}/invite`, { userId, message });
    return response.data;
  },
  respondToInvitation: async (invitationId: string, action: 'accept' | 'reject') => {
    const response = await api.post(`/study-groups/invitations/${invitationId}/respond`, { action });
    return response.data;
  },
  getMyInvitations: async () => {
    const response = await api.get('/study-groups/invitations/my');
    return response.data;
  },
  getNotes: async (groupId: string) => {
    const response = await api.get(`/study-groups/${groupId}/notes`);
    return response.data;
  },
  createNote: async (groupId: string, data: any) => {
    const response = await api.post(`/study-groups/${groupId}/notes`, data);
    return response.data;
  },
  updateNote: async (noteId: string, data: any) => {
    const response = await api.put(`/study-groups/notes/${noteId}`, data);
    return response.data;
  },
  deleteNote: async (noteId: string) => {
    const response = await api.delete(`/study-groups/notes/${noteId}`);
    return response.data;
  },
  getFlashcards: async (groupId: string, deck?: string) => {
    const response = await api.get(`/study-groups/${groupId}/flashcards`, { params: { deck } });
    return response.data;
  },
  createFlashcard: async (groupId: string, data: any) => {
    const response = await api.post(`/study-groups/${groupId}/flashcards`, data);
    return response.data;
  },
  getWhiteboards: async (groupId: string) => {
    const response = await api.get(`/study-groups/${groupId}/whiteboards`);
    return response.data;
  },
  createWhiteboard: async (groupId: string, name?: string) => {
    const response = await api.post(`/study-groups/${groupId}/whiteboards`, { name });
    return response.data;
  },
  updateWhiteboard: async (whiteboardId: string, data: any) => {
    const response = await api.put(`/study-groups/whiteboards/${whiteboardId}`, data);
    return response.data;
  },
  getChatMessages: async (groupId: string, limit?: number) => {
    const response = await api.get(`/study-groups/${groupId}/chat`, { params: { limit } });
    return response.data;
  },
  sendChatMessage: async (groupId: string, message: string, type?: string, fileUrl?: string) => {
    const response = await api.post(`/study-groups/${groupId}/chat`, { message, type, fileUrl });
    return response.data;
  },
};

// Annotations API
export const annotationsAPI = {
  getAnnotations: async (fileId: string) => {
    const response = await api.get(`/annotations/file/${fileId}`);
    return response.data;
  },
  createAnnotation: async (data: any) => {
    const response = await api.post('/annotations', data);
    return response.data;
  },
  updateAnnotation: async (id: string, data: any) => {
    const response = await api.put(`/annotations/${id}`, data);
    return response.data;
  },
  deleteAnnotation: async (id: string) => {
    const response = await api.delete(`/annotations/${id}`);
    return response.data;
  },
};

// Calendar API
export const calendarAPI = {
  getEvents: async (params?: { startDate?: string; endDate?: string; type?: string; courseCode?: string }) => {
    const response = await api.get('/calendar', { params });
    return response.data;
  },
  getUpcomingEvents: async (limit?: number) => {
    const response = await api.get('/calendar/upcoming', { params: { limit } });
    return response.data;
  },
  getEvent: async (id: string) => {
    const response = await api.get(`/calendar/${id}`);
    return response.data;
  },
  createEvent: async (data: any) => {
    const response = await api.post('/calendar', data);
    return response.data;
  },
  updateEvent: async (id: string, data: any) => {
    const response = await api.put(`/calendar/${id}`, data);
    return response.data;
  },
  deleteEvent: async (id: string) => {
    const response = await api.delete(`/calendar/${id}`);
    return response.data;
  },
  syncAssignments: async () => {
    const response = await api.post('/calendar/sync-assignments');
    return response.data;
  },
};

// File Collections API
export const collectionsAPI = {
  getCollections: async (isPublic?: boolean) => {
    const response = await api.get('/collections', {
      params: isPublic ? { public: true } : {}
    });
    return response.data;
  },
  getCollection: async (id: string) => {
    const response = await api.get(`/collections/${id}`);
    return response.data;
  },
  createCollection: async (data: { name: string; description?: string; files?: any[]; isPublic?: boolean; tags?: string[] }) => {
    const response = await api.post('/collections', data);
    return response.data;
  },
  updateCollection: async (id: string, data: { name?: string; description?: string; files?: any[]; isPublic?: boolean; tags?: string[] }) => {
    const response = await api.put(`/collections/${id}`, data);
    return response.data;
  },
  addFileToCollection: async (collectionId: string, data: { fileId?: string; folderId?: string; note?: string }) => {
    const response = await api.post(`/collections/${collectionId}/files`, data);
    return response.data;
  },
  removeFileFromCollection: async (collectionId: string, fileIndex: number) => {
    const response = await api.delete(`/collections/${collectionId}/files/${fileIndex}`);
    return response.data;
  },
  deleteCollection: async (id: string) => {
    const response = await api.delete(`/collections/${id}`);
    return response.data;
  },
  likeCollection: async (id: string) => {
    const response = await api.post(`/collections/${id}/like`);
    return response.data;
  },
};

// File Summaries API
export const summariesAPI = {
  getSummary: async (fileId: string) => {
    const response = await api.get(`/summaries/file/${fileId}`);
    return response.data;
  },
  generateSummary: async (fileId: string) => {
    const response = await api.post(`/summaries/file/${fileId}`);
    return response.data;
  },
};

// Signatures API
export const signaturesAPI = {
  getSignatures: async () => {
    const response = await api.get('/signatures');
    return response.data;
  },
  getSignature: async (signatureId: string) => {
    const response = await api.get(`/signatures/${signatureId}`);
    return response.data;
  },
  createSignature: async (data: { name: string; signatureData: string; isDefault?: boolean }) => {
    const response = await api.post('/signatures', data);
    return response.data;
  },
  updateSignature: async (signatureId: string, data: { name?: string; isDefault?: boolean }) => {
    const response = await api.put(`/signatures/${signatureId}`, data);
    return response.data;
  },
  deleteSignature: async (signatureId: string) => {
    const response = await api.delete(`/signatures/${signatureId}`);
    return response.data;
  },
  applySignature: async (fileId: string, data: { signatureId: string; pageNumber: number; position: { x: number; y: number; width: number; height: number } }) => {
    const response = await api.post(`/signatures/apply/${fileId}`, data);
    return response.data;
  },
  getDocumentSignatures: async (fileId: string) => {
    const response = await api.get(`/signatures/document/${fileId}`);
    return response.data;
  },
};

// AI Assistant API
export const aiAssistantAPI = {
  chat: async (question: string, fileId?: string, context?: string) => {
    const response = await api.post('/ai-assistant/chat', {
      question,
      fileId,
      context
    });
    return response.data;
  },
  getFileInsights: async (fileId: string) => {
    const response = await api.get(`/ai-assistant/insights/${fileId}`);
    return response.data;
  },
};

// Templates API
export const templatesAPI = {
  getTemplates: async (params?: { category?: string; search?: string; tags?: string[] }) => {
    const response = await api.get('/templates', { params });
    return response.data;
  },
  getTemplate: async (id: string) => {
    const response = await api.get(`/templates/${id}`);
    return response.data;
  },
  createTemplate: async (data: { name: string; description?: string; category?: string; content?: string; tags?: string[]; isPublic?: boolean; mimeType?: string }) => {
    const response = await api.post('/templates', data);
    return response.data;
  },
  createTemplateFromFile: async (fileId: string, data: { name?: string; description?: string; category?: string; tags?: string[]; isPublic?: boolean }) => {
    const response = await api.post(`/templates/create-from-file/${fileId}`, data);
    return response.data;
  },
  useTemplate: async (templateId: string, data: { fileName?: string; parentFolder?: string }) => {
    const response = await api.post(`/templates/${templateId}/use`, data);
    return response.data;
  },
  updateTemplate: async (id: string, data: { name?: string; description?: string; category?: string; content?: string; tags?: string[]; isPublic?: boolean }) => {
    const response = await api.put(`/templates/${id}`, data);
    return response.data;
  },
  rateTemplate: async (id: string, rating: number) => {
    const response = await api.post(`/templates/${id}/rate`, { rating });
    return response.data;
  },
  deleteTemplate: async (id: string) => {
    const response = await api.delete(`/templates/${id}`);
    return response.data;
  },
};

// Secured Links API
export const securedLinksAPI = {
  getSecuredLinks: async (params?: { category?: string; starred?: boolean; tags?: string[]; search?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.category) queryParams.append('category', params.category);
    if (params?.starred) queryParams.append('starred', 'true');
    if (params?.tags) params.tags.forEach(tag => queryParams.append('tags', tag));
    if (params?.search) queryParams.append('search', params.search);
    
    const queryString = queryParams.toString();
    const url = queryString ? `/secured-links?${queryString}` : '/secured-links';
    const response = await api.get(url);
    return response.data;
  },
  getSecuredLink: async (id: string) => {
    const response = await api.get(`/secured-links/${id}`);
    return response.data;
  },
  createSecuredLink: async (data: {
    title: string;
    url: string;
    description?: string;
    category?: string;
    tags?: string[];
    password?: string;
    passwordHint?: string;
    isPasswordProtected?: boolean;
    isEncrypted?: boolean;
    notes?: string;
    expiresAt?: string;
  }) => {
    const response = await api.post('/secured-links', data);
    return response.data;
  },
  updateSecuredLink: async (id: string, data: {
    title?: string;
    url?: string;
    description?: string;
    category?: string;
    tags?: string[];
    password?: string;
    passwordHint?: string;
    isPasswordProtected?: boolean;
    isEncrypted?: boolean;
    notes?: string;
    isStarred?: boolean;
    expiresAt?: string;
  }) => {
    const response = await api.put(`/secured-links/${id}`, data);
    return response.data;
  },
  deleteSecuredLink: async (id: string) => {
    const response = await api.delete(`/secured-links/${id}`);
    return response.data;
  },
  accessSecuredLink: async (id: string, password?: string) => {
    const response = await api.post(`/secured-links/${id}/access`, { password });
    return response.data;
  },
  toggleStar: async (id: string) => {
    const response = await api.patch(`/secured-links/${id}/star`);
    return response.data;
  },
};

// Web Shortcuts API
export const webShortcutsAPI = {
  getShortcuts: async (params?: { folder?: string; starred?: boolean; tags?: string[]; search?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.folder !== undefined) queryParams.append('folder', params.folder || 'null');
    if (params?.starred) queryParams.append('starred', 'true');
    if (params?.tags) params.tags.forEach(tag => queryParams.append('tags', tag));
    if (params?.search) queryParams.append('search', params.search);
    
    const queryString = queryParams.toString();
    const url = queryString ? `/web-shortcuts?${queryString}` : '/web-shortcuts';
    const response = await api.get(url);
    return response.data;
  },
  getShortcut: async (id: string) => {
    const response = await api.get(`/web-shortcuts/${id}`);
    return response.data;
  },
  createShortcut: async (data: {
    title?: string;
    url: string;
    description?: string;
    tags?: string[];
    folder?: string;
    favicon?: string;
  }) => {
    const response = await api.post('/web-shortcuts', data);
    return response.data;
  },
  updateShortcut: async (id: string, data: {
    title?: string;
    url?: string;
    description?: string;
    tags?: string[];
    folder?: string;
    isStarred?: boolean;
    favicon?: string;
  }) => {
    const response = await api.put(`/web-shortcuts/${id}`, data);
    return response.data;
  },
  deleteShortcut: async (id: string) => {
    const response = await api.delete(`/web-shortcuts/${id}`);
    return response.data;
  },
  trackAccess: async (id: string) => {
    const response = await api.post(`/web-shortcuts/${id}/access`);
    return response.data;
  },
};

// Cloud Backup API
export const cloudBackupAPI = {
  getBackups: async () => {
    const response = await api.get('/cloud-backup');
    return response.data;
  },
  getDefaultPaths: async () => {
    const response = await api.get('/cloud-backup/default-paths');
    return response.data;
  },
  createBackup: async (data: {
    sourceType: 'desktop' | 'documents' | 'custom';
    sourcePath: string;
    enabled?: boolean;
    backupFrequency?: 'hourly' | 'daily' | 'weekly';
  }) => {
    const response = await api.post('/cloud-backup', data);
    return response.data;
  },
  updateBackup: async (backupId: string, data: {
    enabled?: boolean;
    backupFrequency?: 'hourly' | 'daily' | 'weekly';
  }) => {
    const response = await api.put(`/cloud-backup/${backupId}`, data);
    return response.data;
  },
  deleteBackup: async (backupId: string) => {
    const response = await api.delete(`/cloud-backup/${backupId}`);
    return response.data;
  },
  performBackup: async (backupId: string) => {
    const response = await api.post(`/cloud-backup/${backupId}/backup`);
    return response.data;
  },
};

// Integrations API
export const integrationsAPI = {
  getIntegrations: async () => {
    const response = await api.get('/integrations');
    return response.data;
  },
  getAuthUrl: async (provider: 'microsoft_teams' | 'zoom' | 'slack') => {
    // Convert provider name to match backend route format
    const routeProvider = provider === 'microsoft_teams' ? 'microsoft-teams' : provider;
    const response = await api.get(`/integrations/${routeProvider}/auth`);
    return response.data;
  },
  connectMicrosoftTeams: async (data: {
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
    userId?: string;
    email?: string;
  }) => {
    const response = await api.post('/integrations/microsoft-teams/connect', data);
    return response.data;
  },
  connectZoom: async (data: {
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
    userId?: string;
    email?: string;
  }) => {
    const response = await api.post('/integrations/zoom/connect', data);
    return response.data;
  },
  connectSlack: async (data: {
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
    userId?: string;
    email?: string;
    teamId?: string;
  }) => {
    const response = await api.post('/integrations/slack/connect', data);
    return response.data;
  },
  disconnectIntegration: async (integrationId: string) => {
    const response = await api.delete(`/integrations/${integrationId}`);
    return response.data;
  },
  shareFile: async (integrationId: string, data: {
    fileId: string;
    channel?: string;
    message?: string;
  }) => {
    const response = await api.post(`/integrations/${integrationId}/share`, data);
    return response.data;
  },
};

// Forums API
export const forumsAPI = {
  getPosts: async (params?: {
    category?: string;
    search?: string;
    sortBy?: string;
    order?: string;
  }) => {
    const queryParams = new URLSearchParams();
    if (params?.category) queryParams.append('category', params.category);
    if (params?.search) queryParams.append('search', params.search);
    if (params?.sortBy) queryParams.append('sortBy', params.sortBy);
    if (params?.order) queryParams.append('order', params.order);
    
    const queryString = queryParams.toString();
    const response = await api.get(`/forums${queryString ? `?${queryString}` : ''}`);
    return response.data;
  },
  getPost: async (postId: string) => {
    const response = await api.get(`/forums/${postId}`);
    return response.data;
  },
  createPost: async (data: {
    title: string;
    content: string;
    category?: string;
    tags?: string[];
  }) => {
    const response = await api.post('/forums', data);
    return response.data;
  },
  updatePost: async (postId: string, data: {
    title?: string;
    content?: string;
    tags?: string[];
  }) => {
    const response = await api.put(`/forums/${postId}`, data);
    return response.data;
  },
  deletePost: async (postId: string) => {
    const response = await api.delete(`/forums/${postId}`);
    return response.data;
  },
  replyToPost: async (postId: string, content: string) => {
    const response = await api.post(`/forums/${postId}/reply`, { content });
    return response.data;
  },
  voteOnPost: async (postId: string, vote: 'up' | 'down') => {
    const response = await api.post(`/forums/${postId}/vote`, { vote });
    return response.data;
  },
};

// Learning API
export const learningAPI = {
  getResources: async (params?: {
    category?: string;
    type?: string;
    difficulty?: string;
    search?: string;
    tags?: string[];
  }) => {
    const queryParams = new URLSearchParams();
    if (params?.category) queryParams.append('category', params.category);
    if (params?.type) queryParams.append('type', params.type);
    if (params?.difficulty) queryParams.append('difficulty', params.difficulty);
    if (params?.search) queryParams.append('search', params.search);
    if (params?.tags) {
      params.tags.forEach(tag => queryParams.append('tags', tag));
    }
    
    const queryString = queryParams.toString();
    const response = await api.get(`/learning${queryString ? `?${queryString}` : ''}`);
    return response.data;
  },
  getResource: async (resourceId: string) => {
    const response = await api.get(`/learning/${resourceId}`);
    return response.data;
  },
  rateResource: async (resourceId: string, rating: number) => {
    const response = await api.post(`/learning/${resourceId}/rate`, { rating });
    return response.data;
  },
};

// Course Notes API
export const courseNotesAPI = {
  getNotes: async (courseId: string) => {
    const response = await api.get(`/course-notes/course/${courseId}`);
    return response.data;
  },
  getNote: async (noteId: string) => {
    const response = await api.get(`/course-notes/${noteId}`);
    return response.data;
  },
  createNote: async (data: {
    course: string;
    title: string;
    content?: string;
    tags?: string[];
    topic?: string;
    relatedFiles?: string[];
    isPinned?: boolean;
  }) => {
    const response = await api.post('/course-notes', data);
    return response.data;
  },
  updateNote: async (noteId: string, data: {
    title?: string;
    content?: string;
    tags?: string[];
    topic?: string;
    relatedFiles?: string[];
    isPinned?: boolean;
  }) => {
    const response = await api.put(`/course-notes/${noteId}`, data);
    return response.data;
  },
  deleteNote: async (noteId: string) => {
    const response = await api.delete(`/course-notes/${noteId}`);
    return response.data;
  },
  searchNotes: async (courseId: string, params?: { q?: string; tag?: string; topic?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.q) queryParams.append('q', params.q);
    if (params?.tag) queryParams.append('tag', params.tag);
    if (params?.topic) queryParams.append('topic', params.topic);
    const queryString = queryParams.toString();
    const response = await api.get(`/course-notes/search/${courseId}${queryString ? `?${queryString}` : ''}`);
    return response.data;
  },
};

// Study Schedule API
export const studyScheduleAPI = {
  getSchedules: async (courseId: string, params?: { startDate?: string; endDate?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.startDate) queryParams.append('startDate', params.startDate);
    if (params?.endDate) queryParams.append('endDate', params.endDate);
    const queryString = queryParams.toString();
    const response = await api.get(`/study-schedule/course/${courseId}${queryString ? `?${queryString}` : ''}`);
    return response.data;
  },
  getSchedule: async (scheduleId: string) => {
    const response = await api.get(`/study-schedule/${scheduleId}`);
    return response.data;
  },
  createSchedule: async (data: {
    course: string;
    title: string;
    description?: string;
    startTime: string;
    endTime: string;
    type?: string;
    location?: string;
    isRecurring?: boolean;
    recurringPattern?: any;
    reminderMinutes?: number;
  }) => {
    const response = await api.post('/study-schedule', data);
    return response.data;
  },
  updateSchedule: async (scheduleId: string, data: {
    title?: string;
    description?: string;
    startTime?: string;
    endTime?: string;
    type?: string;
    location?: string;
    isRecurring?: boolean;
    recurringPattern?: any;
    completed?: boolean;
    reminderMinutes?: number;
  }) => {
    const response = await api.put(`/study-schedule/${scheduleId}`, data);
    return response.data;
  },
  deleteSchedule: async (scheduleId: string) => {
    const response = await api.delete(`/study-schedule/${scheduleId}`);
    return response.data;
  },
};

// Progress Tracking API
export const progressTrackingAPI = {
  getProgress: async (courseId: string) => {
    const response = await api.get(`/progress-tracking/course/${courseId}`);
    return response.data;
  },
  getEntry: async (entryId: string) => {
    const response = await api.get(`/progress-tracking/${entryId}`);
    return response.data;
  },
  createEntry: async (data: {
    course: string;
    assignmentName: string;
    pointsEarned?: number;
    pointsPossible: number;
    category?: string;
    weight?: number;
    dateCompleted?: string;
    notes?: string;
  }) => {
    const response = await api.post('/progress-tracking', data);
    return response.data;
  },
  updateEntry: async (entryId: string, data: {
    assignmentName?: string;
    pointsEarned?: number;
    pointsPossible?: number;
    category?: string;
    weight?: number;
    dateCompleted?: string;
    notes?: string;
  }) => {
    const response = await api.put(`/progress-tracking/${entryId}`, data);
    return response.data;
  },
  deleteEntry: async (entryId: string) => {
    const response = await api.delete(`/progress-tracking/${entryId}`);
    return response.data;
  },
};

// Study Sessions API
export const studySessionsAPI = {
  getSessions: async (courseId: string, params?: { startDate?: string; endDate?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.startDate) queryParams.append('startDate', params.startDate);
    if (params?.endDate) queryParams.append('endDate', params.endDate);
    const queryString = queryParams.toString();
    const response = await api.get(`/study-sessions/course/${courseId}${queryString ? `?${queryString}` : ''}`);
    return response.data;
  },
  startSession: async (data: {
    course: string;
    topic?: string;
    filesAccessed?: string[];
  }) => {
    const response = await api.post('/study-sessions/start', data);
    return response.data;
  },
  endSession: async (sessionId: string, data?: {
    notes?: string;
    productivity?: string;
    notesCreated?: number;
  }) => {
    const response = await api.put(`/study-sessions/${sessionId}/end`, data || {});
    return response.data;
  },
  updateSession: async (sessionId: string, data: {
    topic?: string;
    filesAccessed?: string[];
    notes?: string;
    productivity?: string;
    notesCreated?: number;
  }) => {
    const response = await api.put(`/study-sessions/${sessionId}`, data);
    return response.data;
  },
  deleteSession: async (sessionId: string) => {
    const response = await api.delete(`/study-sessions/${sessionId}`);
    return response.data;
  },
};

export default api;

