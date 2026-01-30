import React, { useState, useEffect } from 'react';
import { fileMemoryAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import './FileMemory.css';

interface FileMemoryProps {
  fileId: string;
  onClose: () => void;
}

interface FileMemoryData {
  _id: string;
  file: {
    _id: string;
    originalName: string;
    mimeType: string;
    size: number;
    createdAt: string;
  };
  creationContext: {
    timestamp: string;
    source: string;
    userAction: string;
    projectContext: string;
    meetingContext: string;
    deadlineContext: string | null;
    relatedFiles: Array<{ _id: string; originalName: string }>;
    relatedFolders: Array<{ _id: string; name: string }>;
  };
  aiInsights: {
    purpose: string;
    keyTopics: string[];
    importance: string;
    suggestedTags: string[];
  };
  usagePatterns: {
    firstAccess: string | null;
    lastAccess: string | null;
    accessFrequency: string;
    typicalAccessDays: number[];
    typicalAccessTimes: Array<{ hour: number; frequency: number }>;
  };
  userNotes: Array<{
    content: string;
    createdAt: string;
    updatedAt: string;
  }>;
  linkedEntities: {
    projects: string[];
    courses: string[];
    studyGroups: string[];
    assignments: string[];
  };
  contextualQA: Array<{
    question: string;
    answer: string;
    createdAt: string;
  }>;
}

const FileMemory: React.FC<FileMemoryProps> = ({ fileId, onClose }) => {
  const { user } = useAuth();
  const [memory, setMemory] = useState<FileMemoryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [userAction, setUserAction] = useState('');
  const [projectContext, setProjectContext] = useState('');
  const [meetingContext, setMeetingContext] = useState('');
  const [deadlineContext, setDeadlineContext] = useState('');
  const [newNote, setNewNote] = useState('');
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    loadMemory();
  }, [fileId]);

  const loadMemory = async () => {
    try {
      setLoading(true);
      const data = await fileMemoryAPI.getFileMemory(fileId);
      setMemory(data);
      setUserAction(data.creationContext?.userAction || '');
      setProjectContext(data.creationContext?.projectContext || '');
      setMeetingContext(data.creationContext?.meetingContext || '');
      setDeadlineContext(data.creationContext?.deadlineContext ? new Date(data.creationContext.deadlineContext).toISOString().split('T')[0] : '');
    } catch (error) {
      console.error('Error loading file memory:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      await fileMemoryAPI.updateFileMemory(fileId, {
        userAction,
        projectContext,
        meetingContext,
        deadlineContext: deadlineContext || undefined,
        notes: newNote || undefined
      });
      setEditing(false);
      setNewNote('');
      loadMemory();
    } catch (error) {
      console.error('Error saving memory:', error);
      alert('Failed to save memory');
    }
  };

  const handleAsk = async () => {
    if (!question.trim()) return;
    
    try {
      setAsking(true);
      const response = await fileMemoryAPI.askAboutFile(fileId, question);
      setAnswer(response.answer);
      setQuestion('');
      loadMemory(); // Reload to get updated Q&A
    } catch (error) {
      console.error('Error asking question:', error);
      alert('Failed to get answer');
    } finally {
      setAsking(false);
    }
  };

  const getDayName = (day: number) => {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return days[day];
  };

  const getImportanceColor = (importance: string) => {
    switch (importance) {
      case 'critical': return '#e74c3c';
      case 'high': return '#f39c12';
      case 'medium': return '#3498db';
      case 'low': return '#95a5a6';
      default: return '#95a5a6';
    }
  };

  if (loading) {
    return (
      <div className="file-memory-overlay" onClick={onClose}>
        <div className="file-memory-modal" onClick={(e) => e.stopPropagation()}>
          <div className="file-memory-loading">Loading file memory...</div>
        </div>
      </div>
    );
  }

  if (!memory) {
    return (
      <div className="file-memory-overlay" onClick={onClose}>
        <div className="file-memory-modal" onClick={(e) => e.stopPropagation()}>
          <div className="file-memory-header">
            <h2>File Memory</h2>
            <button className="close-btn" onClick={onClose}>×</button>
          </div>
          <div className="file-memory-empty">
            <p>No memory data available for this file yet.</p>
            <button className="action-button" onClick={() => setEditing(true)}>Add Context</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="file-memory-overlay" onClick={onClose}>
      <div className="file-memory-modal" onClick={(e) => e.stopPropagation()}>
        <div className="file-memory-header">
          <h2>🧠 File Memory: {memory.file.originalName}</h2>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="file-memory-content">
          {editing ? (
            <div className="memory-edit-form">
              <h3>Edit Context</h3>
              <div className="form-group">
                <label>Why did you save this file?</label>
                <textarea
                  value={userAction}
                  onChange={(e) => setUserAction(e.target.value)}
                  placeholder="e.g., Working on project X, preparing presentation for meeting Y..."
                  rows={2}
                />
              </div>
              <div className="form-group">
                <label>Project Context</label>
                <input
                  type="text"
                  value={projectContext}
                  onChange={(e) => setProjectContext(e.target.value)}
                  placeholder="e.g., Website Redesign, Q4 Report..."
                />
              </div>
              <div className="form-group">
                <label>Meeting/Event Context</label>
                <input
                  type="text"
                  value={meetingContext}
                  onChange={(e) => setMeetingContext(e.target.value)}
                  placeholder="e.g., Team Meeting Dec 15, Client Presentation..."
                />
              </div>
              <div className="form-group">
                <label>Deadline (if any)</label>
                <input
                  type="date"
                  value={deadlineContext}
                  onChange={(e) => setDeadlineContext(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label>Add a Note</label>
                <textarea
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Any additional context or reminders..."
                  rows={3}
                />
              </div>
              <div className="form-actions">
                <button className="cancel-button" onClick={() => setEditing(false)}>Cancel</button>
                <button className="action-button" onClick={handleSave}>Save</button>
              </div>
            </div>
          ) : (
            <>
              {/* Creation Context */}
              <div className="memory-section">
                <h3> Creation Context</h3>
                <div className="context-grid">
                  {memory.creationContext.userAction && (
                    <div className="context-item">
                      <strong>Why you saved it:</strong>
                      <p>{memory.creationContext.userAction}</p>
                    </div>
                  )}
                  {memory.creationContext.projectContext && (
                    <div className="context-item">
                      <strong>Project:</strong>
                      <p>{memory.creationContext.projectContext}</p>
                    </div>
                  )}
                  {memory.creationContext.meetingContext && (
                    <div className="context-item">
                      <strong>Meeting/Event:</strong>
                      <p>{memory.creationContext.meetingContext}</p>
                    </div>
                  )}
                  {memory.creationContext.deadlineContext && (
                    <div className="context-item">
                      <strong>Deadline:</strong>
                      <p>{new Date(memory.creationContext.deadlineContext).toLocaleDateString()}</p>
                    </div>
                  )}
                  <div className="context-item">
                    <strong>Created:</strong>
                    <p>{new Date(memory.creationContext.timestamp).toLocaleString()}</p>
                  </div>
                  <div className="context-item">
                    <strong>Source:</strong>
                    <p>{memory.creationContext.source}</p>
                  </div>
                </div>
              </div>

              {/* AI Insights */}
              {memory.aiInsights && (memory.aiInsights.purpose || memory.aiInsights.keyTopics.length > 0) && (
                <div className="memory-section">
                  <h3>🤖 AI Insights</h3>
                  {memory.aiInsights.purpose && (
                    <div className="insight-item">
                      <strong>Purpose:</strong> {memory.aiInsights.purpose}
                    </div>
                  )}
                  {memory.aiInsights.keyTopics.length > 0 && (
                    <div className="insight-item">
                      <strong>Key Topics:</strong>
                      <div className="tags">
                        {memory.aiInsights.keyTopics.map((topic, idx) => (
                          <span key={idx} className="tag">{topic}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {memory.aiInsights.importance && (
                    <div className="insight-item">
                      <strong>Importance:</strong>
                      <span 
                        className="importance-badge"
                        style={{ backgroundColor: getImportanceColor(memory.aiInsights.importance) }}
                      >
                        {memory.aiInsights.importance.toUpperCase()}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* Usage Patterns */}
              {memory.usagePatterns && (
                <div className="memory-section">
                  <h3> Usage Patterns</h3>
                  <div className="usage-grid">
                    {memory.usagePatterns.firstAccess && (
                      <div className="usage-item">
                        <strong>First Access:</strong>
                        <p>{new Date(memory.usagePatterns.firstAccess).toLocaleString()}</p>
                      </div>
                    )}
                    {memory.usagePatterns.lastAccess && (
                      <div className="usage-item">
                        <strong>Last Access:</strong>
                        <p>{new Date(memory.usagePatterns.lastAccess).toLocaleString()}</p>
                      </div>
                    )}
                    <div className="usage-item">
                      <strong>Access Frequency:</strong>
                      <p>{memory.usagePatterns.accessFrequency}</p>
                    </div>
                    {memory.usagePatterns.typicalAccessDays.length > 0 && (
                      <div className="usage-item">
                        <strong>Typical Access Days:</strong>
                        <p>{memory.usagePatterns.typicalAccessDays.map(getDayName).join(', ')}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* User Notes */}
              {memory.userNotes && memory.userNotes.length > 0 && (
                <div className="memory-section">
                  <h3> Your Notes</h3>
                  {memory.userNotes.map((note, idx) => (
                    <div key={idx} className="note-item">
                      <p>{note.content}</p>
                      <span className="note-date">{new Date(note.createdAt).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Linked Entities */}
              {(memory.linkedEntities.projects.length > 0 || 
                memory.linkedEntities.courses.length > 0 ||
                memory.linkedEntities.studyGroups.length > 0) && (
                <div className="memory-section">
                  <h3> Linked To</h3>
                  {memory.linkedEntities.projects.length > 0 && (
                    <div className="linked-item">
                      <strong>Projects:</strong> {memory.linkedEntities.projects.join(', ')}
                    </div>
                  )}
                  {memory.linkedEntities.courses.length > 0 && (
                    <div className="linked-item">
                      <strong>Courses:</strong> {memory.linkedEntities.courses.length} course(s)
                    </div>
                  )}
                  {memory.linkedEntities.studyGroups.length > 0 && (
                    <div className="linked-item">
                      <strong>Study Groups:</strong> {memory.linkedEntities.studyGroups.length} group(s)
                    </div>
                  )}
                </div>
              )}

              {/* Ask Question */}
              <div className="memory-section">
                <h3> Ask About This File</h3>
                <div className="ask-form">
                  <input
                    type="text"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    placeholder="e.g., Why did I save this? What project is this for?"
                    onKeyPress={(e) => e.key === 'Enter' && handleAsk()}
                  />
                  <button 
                    className="action-button" 
                    onClick={handleAsk}
                    disabled={asking || !question.trim()}
                  >
                    {asking ? 'Asking...' : 'Ask'}
                  </button>
                </div>
                {answer && (
                  <div className="answer-box">
                    <strong>Answer:</strong>
                    <p>{answer}</p>
                  </div>
                )}
              </div>

              {/* Previous Q&A */}
              {memory.contextualQA && memory.contextualQA.length > 0 && (
                <div className="memory-section">
                  <h3> Previous Questions</h3>
                  {memory.contextualQA.slice(-5).reverse().map((qa, idx) => (
                    <div key={idx} className="qa-item">
                      <div className="qa-question"><strong>Q:</strong> {qa.question}</div>
                      <div className="qa-answer"><strong>A:</strong> {qa.answer.substring(0, 200)}...</div>
                    </div>
                  ))}
                </div>
              )}

              <div className="memory-actions">
                <button className="action-button" onClick={() => setEditing(true)}>
                  Edit Edit Context
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default FileMemory;

