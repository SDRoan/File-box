import React, { useState, useEffect, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { studyGroupsAPI, usersAPI } from '../services/api';
import FileBrowser from './FileBrowser';
import { useAuth } from '../context/AuthContext';
import { FolderIcon, SummaryIcon, BookIcon, CommentIcon, UsersIcon, EditIcon, TrashIcon, PlusIcon, BookIcon as StudyBookIcon, TagIcon } from './Icons';
import './StudyGroups.css';

interface StudyGroup {
  _id: string;
  name: string;
  description: string;
  course?: string;
  courseCode?: string;
  creator: {
    _id: string;
    name: string;
    email: string;
  };
  members: Array<{
    user: {
      _id: string;
      name: string;
      email: string;
    };
    role: 'member' | 'admin';
    joinedAt: string;
  }>;
  folder?: {
    _id: string;
    name: string;
  };
  isPublic: boolean;
  maxMembers: number;
  createdAt: string;
}

interface StudyNote {
  _id: string;
  title: string;
  content: string;
  author: {
    _id: string;
    name: string;
    email: string;
  };
  tags: string[];
  isPublic: boolean;
  createdAt: string;
  updatedAt: string;
}

interface Flashcard {
  _id: string;
  front: string;
  back: string;
  author: {
    _id: string;
    name: string;
    email: string;
  };
  deck: string;
  difficulty: 'easy' | 'medium' | 'hard';
  createdAt: string;
}

interface Whiteboard {
  _id: string;
  name: string;
  content: string;
  author: {
    _id: string;
    name: string;
    email: string;
  };
  createdAt: string;
  updatedAt: string;
}

interface ChatMessage {
  _id: string;
  sender: {
    _id: string;
    name: string;
    email: string;
  };
  message: string;
  type: 'text' | 'file' | 'system';
  fileUrl?: string;
  createdAt: string;
}

interface Invitation {
  _id: string;
  group: {
    _id: string;
    name: string;
    description: string;
    course?: string;
    courseCode?: string;
  };
  inviter: {
    _id: string;
    name: string;
    email: string;
  };
  message: string;
  status: 'pending' | 'accepted' | 'rejected';
  createdAt: string;
}

const StudyGroups: React.FC = () => {
  const [groups, setGroups] = useState<StudyGroup[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<StudyGroup | null>(null);
  const [activeTab, setActiveTab] = useState<'groups' | 'files' | 'notes' | 'flashcards' | 'whiteboard' | 'chat' | 'members'>('groups');
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  
  // Study tools state
  const [notes, setNotes] = useState<StudyNote[]>([]);
  const [flashcards, setFlashcards] = useState<Flashcard[]>([]);
  const [whiteboards, setWhiteboards] = useState<Whiteboard[]>([]);
  const [selectedWhiteboard, setSelectedWhiteboard] = useState<Whiteboard | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [newChatMessage, setNewChatMessage] = useState('');
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [allUsers, setAllUsers] = useState<any[]>([]);
  const [selectedUsers, setSelectedUsers] = useState<Set<string>>(new Set());
  
  // Form state
  const [groupName, setGroupName] = useState('');
  const [groupDescription, setGroupDescription] = useState('');
  const [courseCode, setCourseCode] = useState('');
  const [courseName, setCourseName] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  
  // Notes form
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');
  const [noteTags, setNoteTags] = useState('');
  const [showNoteModal, setShowNoteModal] = useState(false);
  const [editingNote, setEditingNote] = useState<StudyNote | null>(null);
  
  // Flashcard form
  const [flashcardFront, setFlashcardFront] = useState('');
  const [flashcardBack, setFlashcardBack] = useState('');
  const [flashcardDeck, setFlashcardDeck] = useState('default');
  const [flashcardDifficulty, setFlashcardDifficulty] = useState<'easy' | 'medium' | 'hard'>('medium');
  const [showFlashcardModal, setShowFlashcardModal] = useState(false);
  const [flippedCards, setFlippedCards] = useState<Set<string>>(new Set());
  
  const { user } = useAuth();
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    loadGroups();
    loadInvitations();
    
    if (user) {
      const socket = io(process.env.REACT_APP_API_URL?.replace('/api', '') || 'http://localhost:5001');
      socketRef.current = socket;
      
      socket.emit('join-user-room', user.id);
      
      socket.on('study-group-invitation', handleNewInvitation);
      socket.on('study-group-message', handleNewMessage);
      
      return () => {
        socket.off('study-group-invitation');
        socket.off('study-group-message');
        socket.disconnect();
      };
    }
  }, [user]);

  useEffect(() => {
    if (selectedGroup) {
      loadGroupData();
    }
  }, [selectedGroup, activeTab]);

  const loadGroups = async () => {
    try {
      setLoading(true);
      const data = await studyGroupsAPI.getStudyGroups();
      setGroups(data.groups || []);
    } catch (error) {
      console.error('Error loading study groups:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadInvitations = async () => {
    try {
      const data = await studyGroupsAPI.getMyInvitations();
      setInvitations(data.invitations || []);
    } catch (error) {
      console.error('Error loading invitations:', error);
    }
  };

  const loadGroupData = async () => {
    if (!selectedGroup) return;

    try {
      if (activeTab === 'notes') {
        const data = await studyGroupsAPI.getNotes(selectedGroup._id);
        console.log('Notes data:', data);
        setNotes(data.notes || []);
      } else if (activeTab === 'flashcards') {
        const data = await studyGroupsAPI.getFlashcards(selectedGroup._id);
        setFlashcards(data.flashcards || []);
      } else if (activeTab === 'whiteboard') {
        const data = await studyGroupsAPI.getWhiteboards(selectedGroup._id);
        setWhiteboards(data.whiteboards || []);
        if (data.whiteboards && data.whiteboards.length > 0 && !selectedWhiteboard) {
          setSelectedWhiteboard(data.whiteboards[0]);
        }
      } else if (activeTab === 'chat') {
        const data = await studyGroupsAPI.getChatMessages(selectedGroup._id, 100);
        setChatMessages(data.messages || []);
      }
    } catch (error) {
      console.error('Error loading group data:', error);
      // Reset state on error
      if (activeTab === 'notes') {
        setNotes([]);
      } else if (activeTab === 'flashcards') {
        setFlashcards([]);
      } else if (activeTab === 'whiteboard') {
        setWhiteboards([]);
      } else if (activeTab === 'chat') {
        setChatMessages([]);
      }
    }
  };

  const handleCreateGroup = async () => {
    try {
      const data = await studyGroupsAPI.createStudyGroup({
        name: groupName,
        description: groupDescription,
        course: courseName,
        courseCode,
        isPublic,
        maxMembers: 50
      });
      setShowCreateModal(false);
      setGroupName('');
      setGroupDescription('');
      setCourseCode('');
      setCourseName('');
      setIsPublic(false);
      await loadGroups();
      if (data.group) {
        setSelectedGroup(data.group);
        setActiveTab('files');
      }
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create study group');
    }
  };

  const handleInviteUsers = async () => {
    if (!selectedGroup || selectedUsers.size === 0) return;
    
    try {
      const invitePromises = Array.from(selectedUsers).map(userId =>
        studyGroupsAPI.inviteUser(selectedGroup._id, userId, 'Join our study group!')
      );
      await Promise.all(invitePromises);
      setShowInviteModal(false);
      setSelectedUsers(new Set());
      alert('Invitations sent successfully!');
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to send invitations');
    }
  };

  const handleRespondToInvitation = async (invitationId: string, action: 'accept' | 'reject') => {
    try {
      await studyGroupsAPI.respondToInvitation(invitationId, action);
      await loadInvitations();
      await loadGroups();
      if (action === 'accept') {
        alert('Invitation accepted! You are now a member.');
      }
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to respond to invitation');
    }
  };

  const handleCreateNote = async () => {
    if (!selectedGroup || !noteTitle) return;
    
    try {
      if (editingNote) {
        // Update existing note
        await studyGroupsAPI.updateNote(editingNote._id, {
          title: noteTitle,
          content: noteContent,
          tags: noteTags.split(',').map(t => t.trim()).filter(t => t),
          isPublic: true
        });
      } else {
        // Create new note
        await studyGroupsAPI.createNote(selectedGroup._id, {
          title: noteTitle,
          content: noteContent,
          tags: noteTags.split(',').map(t => t.trim()).filter(t => t),
          isPublic: true
        });
      }
      setShowNoteModal(false);
      setEditingNote(null);
      setNoteTitle('');
      setNoteContent('');
      setNoteTags('');
      await loadGroupData();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to save note');
    }
  };

  const handleEditNote = (note: StudyNote) => {
    setEditingNote(note);
    setNoteTitle(note.title);
    setNoteContent(note.content);
    setNoteTags(note.tags.join(', '));
    setShowNoteModal(true);
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!window.confirm('Are you sure you want to delete this note?')) return;
    
    try {
      await studyGroupsAPI.deleteNote(noteId);
      await loadGroupData();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to delete note');
    }
  };

  const handleCreateFlashcard = async () => {
    if (!selectedGroup || !flashcardFront || !flashcardBack) return;
    
    try {
      await studyGroupsAPI.createFlashcard(selectedGroup._id, {
        front: flashcardFront,
        back: flashcardBack,
        deck: flashcardDeck,
        difficulty: flashcardDifficulty
      });
      setShowFlashcardModal(false);
      setFlashcardFront('');
      setFlashcardBack('');
      setFlashcardDeck('default');
      setFlashcardDifficulty('medium');
      await loadGroupData();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to create flashcard');
    }
  };

  const handleSendMessage = async () => {
    if (!selectedGroup || !newChatMessage.trim()) return;
    
    try {
      await studyGroupsAPI.sendChatMessage(selectedGroup._id, newChatMessage);
      setNewChatMessage('');
      await loadGroupData();
    } catch (error: any) {
      alert(error.response?.data?.message || 'Failed to send message');
    }
  };

  const handleNewInvitation = (data: any) => {
    loadInvitations();
  };

  const handleNewMessage = (data: any) => {
    if (data.groupId === selectedGroup?._id) {
      setChatMessages(prev => [...prev, data.message]);
    }
  };

  const loadAllUsers = async () => {
    try {
      const data = await usersAPI.getAllUsers();
      setAllUsers(data || []);
    } catch (error) {
      console.error('Error loading users:', error);
    }
  };

  const toggleUserSelection = (userId: string) => {
    const newSet = new Set(selectedUsers);
    if (newSet.has(userId)) {
      newSet.delete(userId);
    } else {
      newSet.add(userId);
    }
    setSelectedUsers(newSet);
  };

  const isAdmin = selectedGroup && user && (
    selectedGroup.creator._id === user.id ||
    selectedGroup.members.some(m => 
      m.user._id === user.id && m.role === 'admin'
    )
  );

  if (loading) {
    return <div className="study-groups-loading">Loading study groups...</div>;
  }

  if (selectedGroup) {
    return (
      <div className="study-groups-container">
        <div className="study-group-header">
          <button className="back-button" onClick={() => {
            setSelectedGroup(null);
            setActiveTab('groups');
          }}>
            ← Back to Groups
          </button>
          <div className="group-info">
            <h2>{selectedGroup.name}</h2>
            {selectedGroup.courseCode && (
              <span className="course-badge">{selectedGroup.courseCode}</span>
            )}
            {selectedGroup.description && (
              <p className="group-description">{selectedGroup.description}</p>
            )}
          </div>
        </div>

        <div className="study-group-tabs">
          <button
            className={`tab-button ${activeTab === 'files' ? 'active' : ''}`}
            onClick={() => setActiveTab('files')}
          >
             Files
          </button>
          <button
            className={`tab-button ${activeTab === 'notes' ? 'active' : ''}`}
            onClick={() => setActiveTab('notes')}
          >
            <SummaryIcon size={18} color="currentColor" />
            <span>Notes</span>
          </button>
          <button
            className={`tab-button ${activeTab === 'flashcards' ? 'active' : ''}`}
            onClick={() => setActiveTab('flashcards')}
          >
            <TagIcon size={18} color="currentColor" />
            <span>Flashcards</span>
          </button>
          <button
            className={`tab-button ${activeTab === 'whiteboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('whiteboard')}
          >
            <BookIcon size={18} color="currentColor" />
            <span>Whiteboard</span>
          </button>
          <button
            className={`tab-button ${activeTab === 'chat' ? 'active' : ''}`}
            onClick={() => setActiveTab('chat')}
          >
            <CommentIcon size={18} color="currentColor" />
            <span>Chat</span>
          </button>
          <button
            className={`tab-button ${activeTab === 'members' ? 'active' : ''}`}
            onClick={() => setActiveTab('members')}
          >
            <UsersIcon size={18} color="currentColor" />
            <span>Members</span>
          </button>
        </div>

        <div className="study-group-content">
          {activeTab === 'files' && selectedGroup.folder && (
            <FileBrowser
              currentFolderId={selectedGroup.folder._id}
              onFolderClick={() => {}}
              onNavigateUp={() => {}}
              showTrash={false}
            />
          )}

          {activeTab === 'notes' && (
            <div className="notes-section">
              <div className="section-header">
                <h3>Study Notes</h3>
                <button className="create-button" onClick={() => setShowNoteModal(true)}>
                  + New Note
                </button>
              </div>
              {notes.length === 0 ? (
                <div className="empty-notes-state">
                  <div className="empty-icon">
                    <SummaryIcon size={48} color="#999" />
                  </div>
                  <p>No study notes yet</p>
                  <p className="hint">Create your first note to get started!</p>
                  <button 
                    className="create-button" 
                    onClick={() => setShowNoteModal(true)}
                    style={{ marginTop: '1rem' }}
                  >
                    + Create Your First Note
                  </button>
                </div>
              ) : (
                <div className="notes-grid">
                  {notes.map(note => {
                    const canEdit = user && (note.author?._id === user.id || isAdmin);
                    return (
                      <div key={note._id} className="note-card">
                        <div className="note-card-header">
                          <h4>{note.title}</h4>
                          {canEdit && (
                            <div className="note-actions">
                              <button
                                className="note-action-btn edit-btn"
                                onClick={() => handleEditNote(note)}
                                title="Edit note"
                              >
                                <EditIcon size={16} color="currentColor" />
                              </button>
                              <button
                                className="note-action-btn delete-btn"
                                onClick={() => handleDeleteNote(note._id)}
                                title="Delete note"
                              >
                                <TrashIcon size={16} color="currentColor" />
                              </button>
                            </div>
                          )}
                        </div>
                        <p className="note-content">
                          {note.content && note.content.length > 200 
                            ? note.content.substring(0, 200) + '...' 
                            : note.content || 'No content'}
                        </p>
                        <div className="note-meta">
                          <span>By {note.author?.name || 'Unknown'}</span>
                          <span>{new Date(note.updatedAt).toLocaleDateString()}</span>
                        </div>
                        {note.tags && note.tags.length > 0 && (
                          <div className="note-tags">
                            {note.tags.map(tag => (
                              <span key={tag} className="tag">{tag}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'flashcards' && (
            <div className="flashcards-section">
              <div className="section-header">
                <h3>Flashcards</h3>
                <button className="create-button" onClick={() => setShowFlashcardModal(true)}>
                  + New Flashcard
                </button>
              </div>
              <div className="flashcards-grid">
                {flashcards.map(card => (
                  <div
                    key={card._id}
                    className={`flashcard ${flippedCards.has(card._id) ? 'flipped' : ''}`}
                    onClick={() => {
                      const newSet = new Set(flippedCards);
                      if (newSet.has(card._id)) {
                        newSet.delete(card._id);
                      } else {
                        newSet.add(card._id);
                      }
                      setFlippedCards(newSet);
                    }}
                  >
                    <div className="flashcard-front">
                      <p>{card.front}</p>
                      <span className="flip-hint">Click to flip</span>
                    </div>
                    <div className="flashcard-back">
                      <p>{card.back}</p>
                      <span className="difficulty-badge">{card.difficulty}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'whiteboard' && (
            <div className="whiteboard-section">
              <div className="section-header">
                <h3>Whiteboards</h3>
                <button className="create-button" onClick={async () => {
                  if (!selectedGroup) return;
                  try {
                    const data = await studyGroupsAPI.createWhiteboard(selectedGroup._id, 'New Whiteboard');
                    await loadGroupData();
                    if (data.whiteboard) {
                      setSelectedWhiteboard(data.whiteboard);
                    }
                  } catch (error: any) {
                    alert(error.response?.data?.message || 'Failed to create whiteboard');
                  }
                }}>
                  + New Whiteboard
                </button>
              </div>
              {whiteboards.length > 0 && (
                <div className="whiteboard-selector">
                  {whiteboards.map(wb => (
                    <button
                      key={wb._id}
                      className={`whiteboard-btn ${selectedWhiteboard?._id === wb._id ? 'active' : ''}`}
                      onClick={() => setSelectedWhiteboard(wb)}
                    >
                      {wb.name}
                    </button>
                  ))}
                </div>
              )}
              {selectedWhiteboard && (
                <div className="whiteboard-canvas">
                  <textarea
                    className="whiteboard-textarea"
                    value={selectedWhiteboard.content}
                    onChange={async (e) => {
                      try {
                        await studyGroupsAPI.updateWhiteboard(selectedWhiteboard._id, {
                          content: e.target.value
                        });
                        setSelectedWhiteboard({ ...selectedWhiteboard, content: e.target.value });
                      } catch (error) {
                        console.error('Error updating whiteboard:', error);
                      }
                    }}
                    placeholder="Start drawing or writing your ideas here..."
                  />
                </div>
              )}
            </div>
          )}

          {activeTab === 'chat' && (
            <div className="chat-section">
              <div className="chat-messages">
                {chatMessages.map(msg => (
                  <div key={msg._id} className="chat-message">
                    <div className="message-sender">{msg.sender.name}</div>
                    <div className="message-content">{msg.message}</div>
                    <div className="message-time">
                      {new Date(msg.createdAt).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
              <div className="chat-input">
                <input
                  type="text"
                  value={newChatMessage}
                  onChange={(e) => setNewChatMessage(e.target.value)}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      handleSendMessage();
                    }
                  }}
                  placeholder="Type a message..."
                />
                <button onClick={handleSendMessage}>Send</button>
              </div>
            </div>
          )}

          {activeTab === 'members' && (
            <div className="members-section">
              <div className="section-header">
                <h3>Members ({selectedGroup.members.length + 1})</h3>
                {isAdmin && (
                  <button className="invite-button" onClick={() => {
                    setShowInviteModal(true);
                    loadAllUsers();
                  }}>
                    + Invite Users
                  </button>
                )}
              </div>
              <div className="members-list">
                <div className="member-item creator">
                  <div className="member-avatar">
                    {selectedGroup.creator.name[0].toUpperCase()}
                  </div>
                  <div className="member-info">
                    <div className="member-name">{selectedGroup.creator.name} (Creator)</div>
                    <div className="member-email">{selectedGroup.creator.email}</div>
                  </div>
                </div>
                {selectedGroup.members.map(member => (
                  <div key={member.user._id} className="member-item">
                    <div className="member-avatar">
                      {member.user.name[0].toUpperCase()}
                    </div>
                    <div className="member-info">
                      <div className="member-name">
                        {member.user.name}
                        {member.role === 'admin' && <span className="role-badge">Admin</span>}
                      </div>
                      <div className="member-email">{member.user.email}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Create/Edit Note Modal */}
        {showNoteModal && (
          <div className="modal-overlay" onClick={() => {
            setShowNoteModal(false);
            setEditingNote(null);
            setNoteTitle('');
            setNoteContent('');
            setNoteTags('');
          }}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <h3>{editingNote ? 'Edit Study Note' : 'Create Study Note'}</h3>
              <input
                type="text"
                placeholder="Note title"
                value={noteTitle}
                onChange={(e) => setNoteTitle(e.target.value)}
                className="form-input"
              />
              <textarea
                placeholder="Note content"
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
                className="form-textarea"
                rows={10}
              />
              <input
                type="text"
                placeholder="Tags (comma-separated)"
                value={noteTags}
                onChange={(e) => setNoteTags(e.target.value)}
                className="form-input"
              />
              <div className="modal-actions">
                <button onClick={() => {
                  setShowNoteModal(false);
                  setEditingNote(null);
                  setNoteTitle('');
                  setNoteContent('');
                  setNoteTags('');
                }}>Cancel</button>
                <button onClick={handleCreateNote} disabled={!noteTitle}>
                  {editingNote ? 'Update' : 'Create'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Create Flashcard Modal */}
        {showFlashcardModal && (
          <div className="modal-overlay" onClick={() => setShowFlashcardModal(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <h3>Create Flashcard</h3>
              <input
                type="text"
                placeholder="Front (question)"
                value={flashcardFront}
                onChange={(e) => setFlashcardFront(e.target.value)}
                className="form-input"
              />
              <textarea
                placeholder="Back (answer)"
                value={flashcardBack}
                onChange={(e) => setFlashcardBack(e.target.value)}
                className="form-textarea"
                rows={5}
              />
              <input
                type="text"
                placeholder="Deck name"
                value={flashcardDeck}
                onChange={(e) => setFlashcardDeck(e.target.value)}
                className="form-input"
              />
              <select
                value={flashcardDifficulty}
                onChange={(e) => setFlashcardDifficulty(e.target.value as 'easy' | 'medium' | 'hard')}
                className="form-input"
              >
                <option value="easy">Easy</option>
                <option value="medium">Medium</option>
                <option value="hard">Hard</option>
              </select>
              <div className="modal-actions">
                <button onClick={() => setShowFlashcardModal(false)}>Cancel</button>
                <button onClick={handleCreateFlashcard}>Create</button>
              </div>
            </div>
          </div>
        )}

        {/* Invite Users Modal */}
        {showInviteModal && (
          <div className="modal-overlay" onClick={() => setShowInviteModal(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <h3>Invite Users to Study Group</h3>
              <div className="users-list">
                {allUsers
                  .filter(u => !selectedGroup?.members.some(m => m.user._id === u._id) && 
                               u._id !== selectedGroup?.creator._id)
                  .map(user => (
                    <div
                      key={user._id}
                      className={`user-item ${selectedUsers.has(user._id) ? 'selected' : ''}`}
                      onClick={() => toggleUserSelection(user._id)}
                    >
                      <div className="user-avatar">{user.name[0].toUpperCase()}</div>
                      <div className="user-info">
                        <div className="user-name">{user.name}</div>
                        <div className="user-email">{user.email}</div>
                      </div>
                      {selectedUsers.has(user._id) && <span className="checkmark"></span>}
                    </div>
                  ))}
              </div>
              <div className="modal-actions">
                <button onClick={() => setShowInviteModal(false)}>Cancel</button>
                <button onClick={handleInviteUsers} disabled={selectedUsers.size === 0}>
                  Invite {selectedUsers.size} User(s)
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="study-groups-container">
      <div className="study-groups-header">
        <div>
          <h2>
            <StudyBookIcon size={28} color="currentColor" style={{ display: 'inline-block', marginRight: '0.5rem', verticalAlign: 'middle' }} />
            Study Groups
          </h2>
          <p style={{ margin: '0.5rem 0 0 0', color: 'var(--text-secondary, #666)', fontSize: '0.95rem' }}>
            Collaborate with classmates and study together
          </p>
        </div>
        <button className="create-group-btn" onClick={() => setShowCreateModal(true)}>
          <PlusIcon size={18} color="#ffffff" />
          <span>Create Study Group</span>
        </button>
      </div>

      {invitations.length > 0 && (
        <div className="invitations-section">
          <h3>Pending Invitations ({invitations.length})</h3>
          {invitations.map(inv => (
            <div key={inv._id} className="invitation-card">
              <div className="invitation-info">
                <h4>{inv.group.name}</h4>
                {inv.group.courseCode && <span className="course-badge">{inv.group.courseCode}</span>}
                <p>Invited by {inv.inviter.name}</p>
                {inv.message && <p className="invitation-message">{inv.message}</p>}
              </div>
              <div className="invitation-actions">
                <button
                  className="accept-btn"
                  onClick={() => handleRespondToInvitation(inv._id, 'accept')}
                >
                  Accept
                </button>
                <button
                  className="reject-btn"
                  onClick={() => handleRespondToInvitation(inv._id, 'reject')}
                >
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="groups-grid">
        {groups.map(group => (
          <div key={group._id} className="group-card">
            <div className="group-header">
              <h3>{group.name}</h3>
              {group.courseCode && <span className="course-badge">{group.courseCode}</span>}
            </div>
            {group.description && <p className="group-description">{group.description}</p>}
            <div className="group-meta">
              <span><UsersIcon size={14} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} /> {group.members.length + 1} members</span>
              {group.course && <span><BookIcon size={14} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} /> {group.course}</span>}
            </div>
            <div className="group-actions">
              <button
                className="view-group-btn"
                onClick={() => {
                  setSelectedGroup(group);
                  setActiveTab('files');
                }}
              >
                Open Group
              </button>
            </div>
          </div>
        ))}
      </div>

      {groups.length === 0 && !loading && (
        <div className="empty-state">
          <div className="empty-icon">
            <StudyBookIcon size={64} color="#999" />
          </div>
          <p>No study groups yet</p>
          <p className="hint">Create a study group to collaborate with others!</p>
          <button 
            className="create-group-btn" 
            onClick={() => setShowCreateModal(true)}
            style={{ marginTop: '1.5rem' }}
          >
            <PlusIcon size={18} color="#ffffff" />
            <span>Create Your First Study Group</span>
          </button>
        </div>
      )}

      {/* Create Group Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Create Study Group</h3>
            <input
              type="text"
              placeholder="Group name"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              className="form-input"
            />
            <textarea
              placeholder="Description"
              value={groupDescription}
              onChange={(e) => setGroupDescription(e.target.value)}
              className="form-textarea"
              rows={3}
            />
            <input
              type="text"
              placeholder="Course code (e.g., CSCI340)"
              value={courseCode}
              onChange={(e) => setCourseCode(e.target.value)}
              className="form-input"
            />
            <input
              type="text"
              placeholder="Course name"
              value={courseName}
              onChange={(e) => setCourseName(e.target.value)}
              className="form-input"
            />
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={isPublic}
                onChange={(e) => setIsPublic(e.target.checked)}
              />
              Public group (others can join)
            </label>
            <div className="modal-actions">
              <button onClick={() => setShowCreateModal(false)}>Cancel</button>
              <button onClick={handleCreateGroup} disabled={!groupName}>
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default StudyGroups;

