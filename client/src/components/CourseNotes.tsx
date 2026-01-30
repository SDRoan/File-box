import React, { useState, useEffect } from 'react';
import { courseNotesAPI } from '../services/api';
import { TrashIcon, PlusIcon, SearchIcon, PinIcon } from './Icons';
import './CourseNotes.css';

interface CourseNotesProps {
  courseId: string;
  courseCode: string;
  courseName: string;
}

interface Note {
  _id: string;
  title: string;
  content: string;
  tags: string[];
  topic: string;
  isPinned: boolean;
  createdAt: string;
  updatedAt: string;
}

const CourseNotes: React.FC<CourseNotesProps> = ({ courseId, courseCode, courseName }) => {
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [editingNote, setEditingNote] = useState<Note | null>(null);
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    tags: '',
    topic: '',
    isPinned: false
  });

  useEffect(() => {
    loadNotes();
  }, [courseId]);

  const loadNotes = async () => {
    try {
      setLoading(true);
      const data = await courseNotesAPI.getNotes(courseId);
      setNotes(data.notes || []);
    } catch (error) {
      console.error('Error loading notes:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      loadNotes();
      return;
    }

    try {
      setLoading(true);
      const data = await courseNotesAPI.searchNotes(courseId, { q: searchQuery });
      setNotes(data.notes || []);
    } catch (error) {
      console.error('Error searching notes:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNote = () => {
    setEditingNote(null);
    setFormData({
      title: '',
      content: '',
      tags: '',
      topic: '',
      isPinned: false
    });
    setShowModal(true);
  };

  const handleEditNote = (note: Note) => {
    setEditingNote(note);
    setFormData({
      title: note.title,
      content: note.content,
      tags: note.tags.join(', '),
      topic: note.topic,
      isPinned: note.isPinned
    });
    setShowModal(true);
  };

  const handleSaveNote = async () => {
    try {
      const tagsArray = formData.tags.split(',').map(t => t.trim()).filter(t => t);
      
      if (editingNote) {
        await courseNotesAPI.updateNote(editingNote._id, {
          title: formData.title,
          content: formData.content,
          tags: tagsArray,
          topic: formData.topic,
          isPinned: formData.isPinned
        });
      } else {
        await courseNotesAPI.createNote({
          course: courseId,
          title: formData.title,
          content: formData.content,
          tags: tagsArray,
          topic: formData.topic,
          isPinned: formData.isPinned
        });
      }

      setShowModal(false);
      loadNotes();
    } catch (error: any) {
      console.error('Error saving note:', error);
      alert(error.response?.data?.message || 'Failed to save note');
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!window.confirm('Are you sure you want to delete this note?')) {
      return;
    }

    try {
      await courseNotesAPI.deleteNote(noteId);
      loadNotes();
    } catch (error: any) {
      console.error('Error deleting note:', error);
      alert(error.response?.data?.message || 'Failed to delete note');
    }
  };

  const handleTogglePin = async (note: Note) => {
    try {
      await courseNotesAPI.updateNote(note._id, {
        isPinned: !note.isPinned
      });
      loadNotes();
    } catch (error: any) {
      console.error('Error toggling pin:', error);
    }
  };

  const allTags = Array.from(new Set(notes.flatMap(n => n.tags)));
  const filteredNotes = selectedTag
    ? notes.filter(n => n.tags.includes(selectedTag))
    : notes;

  const sortedNotes = [...filteredNotes].sort((a, b) => {
    if (a.isPinned && !b.isPinned) return -1;
    if (!a.isPinned && b.isPinned) return 1;
    return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
  });

  if (loading && notes.length === 0) {
    return <div className="course-notes-loading">Loading notes...</div>;
  }

  return (
    <div className="course-notes">
      <div className="notes-header">
        <div>
          <h2>Course Notes - {courseCode}</h2>
          <p>Organize your study notes and thoughts</p>
        </div>
        <button className="btn-primary" onClick={handleCreateNote}>
          <PlusIcon size={18} color="currentColor" />
          <span>New Note</span>
        </button>
      </div>

      <div className="notes-toolbar">
        <div className="search-box">
          <SearchIcon size={18} color="currentColor" />
          <input
            type="text"
            placeholder="Search notes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
          />
          <button onClick={handleSearch}>Search</button>
        </div>
        <div className="tags-filter">
          <button
            className={`tag-filter-btn ${selectedTag === null ? 'active' : ''}`}
            onClick={() => setSelectedTag(null)}
          >
            All
          </button>
          {allTags.map(tag => (
            <button
              key={tag}
              className={`tag-filter-btn ${selectedTag === tag ? 'active' : ''}`}
              onClick={() => setSelectedTag(tag)}
            >
              {tag}
            </button>
          ))}
        </div>
      </div>

      <div className="notes-grid">
        {sortedNotes.length > 0 ? (
          sortedNotes.map(note => (
            <div key={note._id} className={`note-card ${note.isPinned ? 'pinned' : ''}`}>
              <div className="note-card-header">
                <div className="note-title-section">
                  {note.isPinned && <PinIcon size={16} color="currentColor" />}
                  <h3>{note.title}</h3>
                </div>
                <div className="note-actions">
                  <button
                    className="icon-btn"
                    onClick={() => handleTogglePin(note)}
                    title={note.isPinned ? 'Unpin' : 'Pin'}
                  >
                    <PinIcon size={16} color={note.isPinned ? '#f59e0b' : 'currentColor'} />
                  </button>
                  <button
                    className="icon-btn"
                    onClick={() => handleEditNote(note)}
                    title="Edit"
                  >
                    ✏️
                  </button>
                  <button
                    className="icon-btn delete-btn"
                    onClick={() => handleDeleteNote(note._id)}
                    title="Delete"
                  >
                    <TrashIcon size={16} color="currentColor" />
                  </button>
                </div>
              </div>
              {note.topic && (
                <div className="note-topic">Topic: {note.topic}</div>
              )}
              <div className="note-content">
                {note.content || <em className="empty-content">No content</em>}
              </div>
              {note.tags.length > 0 && (
                <div className="note-tags">
                  {note.tags.map(tag => (
                    <span key={tag} className="note-tag">{tag}</span>
                  ))}
                </div>
              )}
              <div className="note-footer">
                <span className="note-date">
                  Updated: {new Date(note.updatedAt).toLocaleDateString()}
                </span>
              </div>
            </div>
          ))
        ) : (
          <div className="empty-state">
            <p>No notes yet. Create your first note!</p>
          </div>
        )}
      </div>

      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingNote ? 'Edit Note' : 'Create New Note'}</h3>
              <button className="modal-close" onClick={() => setShowModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Title *</label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="Note title"
                />
              </div>
              <div className="form-group">
                <label>Topic</label>
                <input
                  type="text"
                  value={formData.topic}
                  onChange={(e) => setFormData({ ...formData, topic: e.target.value })}
                  placeholder="e.g., Chapter 5, Midterm Review"
                />
              </div>
              <div className="form-group">
                <label>Content</label>
                <textarea
                  value={formData.content}
                  onChange={(e) => setFormData({ ...formData, content: e.target.value })}
                  placeholder="Write your notes here..."
                  rows={10}
                />
              </div>
              <div className="form-group">
                <label>Tags (comma-separated)</label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  placeholder="e.g., important, exam, homework"
                />
              </div>
              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={formData.isPinned}
                    onChange={(e) => setFormData({ ...formData, isPinned: e.target.checked })}
                  />
                  Pin this note
                </label>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowModal(false)}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={handleSaveNote}
                disabled={!formData.title.trim()}
              >
                {editingNote ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CourseNotes;
