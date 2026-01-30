import React, { useState, useEffect, useRef } from 'react';
import { assignmentsAPI, coursesAPI, filesAPI } from '../services/api';
import { BookIcon, PaperclipIcon, FolderIcon, DocumentIcon, PlusIcon } from './Icons';
import './AssignmentTracker.css';

interface Assignment {
  _id: string;
  title: string;
  description: string;
  course: string;
  courseCode?: string;
  dueDate: string;
  priority: 'Low' | 'Medium' | 'High' | 'Urgent';
  status: 'Not Started' | 'In Progress' | 'Submitted' | 'Graded';
  grade?: number;
  maxPoints?: number;
  attachedFiles?: any[];
  attachedFolders?: any[];
  tags?: string[];
}

interface Course {
  _id: string;
  name: string;
  code: string;
  color: string;
}

interface AssignmentTrackerProps {
  courseFilter?: string;
  courseCode?: string;
}

const AssignmentTracker: React.FC<AssignmentTrackerProps> = ({ courseFilter, courseCode }) => {
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [courses, setCourses] = useState<Course[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'upcoming' | 'Not Started' | 'In Progress' | 'Submitted' | 'Graded'>('all');
  const [selectedCourse, setSelectedCourse] = useState<string>(courseFilter || 'all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedAssignment, setSelectedAssignment] = useState<Assignment | null>(null);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showViewFilesModal, setShowViewFilesModal] = useState(false);
  const [availableFiles, setAvailableFiles] = useState<any[]>([]);

  const loadAvailableFiles = async () => {
    try {
      const response = await filesAPI.getFiles();
      setAvailableFiles([...(response.files || []), ...(response.folders || [])]);
    } catch (error) {
      console.error('Error loading files:', error);
    }
  };

  useEffect(() => {
    loadData();
  }, [filter, selectedCourse, courseFilter]);

  const loadData = async () => {
    try {
      setLoading(true);
      const courseToFilter = courseFilter || (selectedCourse !== 'all' ? selectedCourse : undefined);
      const [assignmentsRes, coursesRes] = await Promise.all([
        assignmentsAPI.getAssignments({
          upcoming: filter === 'upcoming' ? true : undefined,
          status: filter !== 'all' && filter !== 'upcoming' ? filter : undefined,
          course: courseToFilter
        }),
        coursesAPI.getCourses()
      ]);
      setAssignments(assignmentsRes.assignments || []);
      setCourses(coursesRes.courses || []);
    } catch (error) {
      console.error('Error loading data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'Urgent': return '#ef4444';
      case 'High': return '#f59e0b';
      case 'Medium': return '#3b82f6';
      case 'Low': return '#10b981';
      default: return '#6b7280';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Graded': return '#10b981';
      case 'Submitted': return '#3b82f6';
      case 'In Progress': return '#f59e0b';
      case 'Not Started': return '#6b7280';
      default: return '#6b7280';
    }
  };

  const getDaysUntilDue = (dueDate: string) => {
    const due = new Date(dueDate);
    const now = new Date();
    const diff = Math.ceil((due.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return diff;
  };

  const isOverdue = (dueDate: string, status: string) => {
    if (status === 'Submitted' || status === 'Graded') return false;
    return getDaysUntilDue(dueDate) < 0;
  };

  if (loading) {
    return <div className="assignment-tracker-loading">Loading assignments...</div>;
  }

  return (
    <div className="assignment-tracker">
      <div className="assignment-header">
        <h1>
          <BookIcon size={28} color="currentColor" style={{ display: 'inline-block', marginRight: '0.5rem', verticalAlign: 'middle' }} />
          Assignment Tracker{courseCode && ` - ${courseCode}`}
        </h1>
        <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
          <PlusIcon size={18} color="#ffffff" />
          <span>New Assignment</span>
        </button>
      </div>

      <div className="assignment-filters">
        <div className="filter-group">
          <label>Status:</label>
          <select value={filter} onChange={(e) => setFilter(e.target.value as any)}>
            <option value="all">All</option>
            <option value="upcoming">Upcoming</option>
            <option value="Not Started">Not Started</option>
            <option value="In Progress">In Progress</option>
            <option value="Submitted">Submitted</option>
            <option value="Graded">Graded</option>
          </select>
        </div>
        {!courseFilter && (
          <div className="filter-group">
            <label>Course:</label>
            <select value={selectedCourse} onChange={(e) => setSelectedCourse(e.target.value)}>
              <option value="all">All Courses</option>
              {courses.map(course => (
                <option key={course._id} value={course.name}>{course.code} - {course.name}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="assignments-grid">
        {assignments.map(assignment => {
          const daysUntil = getDaysUntilDue(assignment.dueDate);
          const overdue = isOverdue(assignment.dueDate, assignment.status);
          const course = courses.find(c => c.name === assignment.course);

          return (
            <div
              key={assignment._id}
              className={`assignment-card ${overdue ? 'overdue' : ''}`}
              style={{ borderLeftColor: course?.color || '#6366f1' }}
            >
              <div className="assignment-card-header">
                <div className="assignment-title-section">
                  <h3>{assignment.title}</h3>
                  {assignment.courseCode && (
                    <span className="course-badge" style={{ backgroundColor: course?.color || '#6366f1' }}>
                      {assignment.courseCode}
                    </span>
                  )}
                </div>
                <div className="assignment-badges">
                  <span
                    className="priority-badge"
                    style={{ backgroundColor: getPriorityColor(assignment.priority) }}
                  >
                    {assignment.priority}
                  </span>
                  <span
                    className="status-badge"
                    style={{ backgroundColor: getStatusColor(assignment.status) }}
                  >
                    {assignment.status}
                  </span>
                </div>
              </div>

              {assignment.description && (
                <p className="assignment-description">{assignment.description}</p>
              )}

              <div className="assignment-meta">
                <div className="due-date">
                  <span className="label">Due:</span>
                  <span className={`value ${overdue ? 'overdue-text' : ''}`}>
                    {new Date(assignment.dueDate).toLocaleDateString()} 
                    {!overdue && daysUntil >= 0 && (
                      <span className="days-until"> ({daysUntil} days)</span>
                    )}
                    {overdue && <span className="overdue-text"> (Overdue!)</span>}
                  </span>
                </div>

                {assignment.grade !== null && assignment.grade !== undefined && (
                  <div className="grade">
                    <span className="label">Grade:</span>
                    <span className="value">
                      {assignment.grade}{assignment.maxPoints ? ` / ${assignment.maxPoints}` : ''}
                    </span>
                  </div>
                )}
              </div>

              {((assignment.attachedFiles && assignment.attachedFiles.length > 0) || 
                (assignment.attachedFolders && assignment.attachedFolders.length > 0)) && (
                <div className="assignment-attachments">
                  {assignment.attachedFiles && assignment.attachedFiles.length > 0 && (
                    <span>
                      <PaperclipIcon size={14} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
                      {assignment.attachedFiles.length} file(s)
                    </span>
                  )}
                  {assignment.attachedFolders && assignment.attachedFolders.length > 0 && (
                    <span>
                      <FolderIcon size={14} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
                      {assignment.attachedFolders.length} folder(s)
                    </span>
                  )}
                </div>
              )}

              <div className="assignment-actions">
                <button 
                  className="btn-secondary"
                  onClick={() => {
                    setSelectedAssignment(assignment);
                    setShowUploadModal(true);
                    loadAvailableFiles();
                  }}
                >
                  ➜ Upload Files
                </button>
                <button 
                  className="btn-secondary"
                  onClick={() => {
                    setSelectedAssignment(assignment);
                    setShowEditModal(true);
                  }}
                >
                  Edit
                </button>
                {assignment.attachedFiles && assignment.attachedFiles.length > 0 && (
                  <button 
                    className="btn-secondary"
                    onClick={() => {
                      setSelectedAssignment(assignment);
                      setShowViewFilesModal(true);
                    }}
                  >
                    View Files
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {assignments.length === 0 && (
        <div className="empty-state">
          <p>No assignments found. Create your first assignment to get started!</p>
        </div>
      )}

      {showCreateModal && (
        <CreateAssignmentModal
          courses={courses}
          defaultCourse={courseFilter}
          defaultCourseCode={courseCode}
          onClose={() => {
            setShowCreateModal(false);
            loadData();
          }}
        />
      )}

      {showUploadModal && selectedAssignment && (
        <UploadFilesModal
          assignment={selectedAssignment}
          availableFiles={availableFiles}
          onClose={() => {
            setShowUploadModal(false);
            setSelectedAssignment(null);
            loadData();
          }}
          onRefreshFiles={loadAvailableFiles}
        />
      )}

      {showEditModal && selectedAssignment && (
        <EditAssignmentModal
          assignment={selectedAssignment}
          courses={courses}
          onClose={() => {
            setShowEditModal(false);
            setSelectedAssignment(null);
            loadData();
          }}
        />
      )}

      {showViewFilesModal && selectedAssignment && (
        <ViewFilesModal
          assignment={selectedAssignment}
          onClose={() => {
            setShowViewFilesModal(false);
            setSelectedAssignment(null);
          }}
        />
      )}
    </div>
  );
};

// Edit Assignment Modal Component
const EditAssignmentModal: React.FC<{
  assignment: Assignment;
  courses: Course[];
  onClose: () => void;
}> = ({ assignment, courses, onClose }) => {
  const [formData, setFormData] = useState({
    title: assignment.title,
    description: assignment.description || '',
    course: assignment.course,
    courseCode: assignment.courseCode || '',
    dueDate: assignment.dueDate ? new Date(assignment.dueDate).toISOString().slice(0, 16) : '',
    priority: assignment.priority,
    status: assignment.status,
    grade: assignment.grade?.toString() || '',
    maxPoints: assignment.maxPoints?.toString() || '',
    tags: assignment.tags?.join(', ') || ''
  });
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      await assignmentsAPI.updateAssignment(assignment._id, {
        ...formData,
        grade: formData.grade ? parseFloat(formData.grade) : undefined,
        maxPoints: formData.maxPoints ? parseFloat(formData.maxPoints) : undefined,
        tags: formData.tags.split(',').map(t => t.trim()).filter(t => t)
      });
      onClose();
    } catch (error) {
      console.error('Error updating assignment:', error);
      alert('Failed to update assignment');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Edit Assignment</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Title *</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label>Course *</label>
            <select
              value={formData.course}
              onChange={(e) => {
                const course = courses.find(c => c.name === e.target.value);
                setFormData({
                  ...formData,
                  course: e.target.value,
                  courseCode: course?.code || ''
                });
              }}
              required
            >
              {courses.map(course => (
                <option key={course._id} value={course.name}>
                  {course.code} - {course.name}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              rows={4}
            />
          </div>
          <div className="form-group">
            <label>Due Date *</label>
            <input
              type="datetime-local"
              value={formData.dueDate}
              onChange={(e) => setFormData({ ...formData, dueDate: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label>Priority</label>
            <select
              value={formData.priority}
              onChange={(e) => setFormData({ ...formData, priority: e.target.value as any })}
            >
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Urgent">Urgent</option>
            </select>
          </div>
          <div className="form-group">
            <label>Status</label>
            <select
              value={formData.status}
              onChange={(e) => setFormData({ ...formData, status: e.target.value as any })}
            >
              <option value="Not Started">Not Started</option>
              <option value="In Progress">In Progress</option>
              <option value="Submitted">Submitted</option>
              <option value="Graded">Graded</option>
            </select>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Grade</label>
              <input
                type="number"
                step="0.01"
                value={formData.grade}
                onChange={(e) => setFormData({ ...formData, grade: e.target.value })}
                placeholder="e.g., 85"
              />
            </div>
            <div className="form-group">
              <label>Max Points</label>
              <input
                type="number"
                step="0.01"
                value={formData.maxPoints}
                onChange={(e) => setFormData({ ...formData, maxPoints: e.target.value })}
                placeholder="e.g., 100"
              />
            </div>
          </div>
          <div className="form-group">
            <label>Tags</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              placeholder="e.g., essay, group-project, final"
            />
          </div>
          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose} disabled={saving}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={saving}>
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// View Files Modal Component
const ViewFilesModal: React.FC<{
  assignment: Assignment;
  onClose: () => void;
}> = ({ assignment, onClose }) => {
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFiles();
  }, []);

  const loadFiles = () => {
    try {
      setLoading(true);
      const attachedFiles = assignment.attachedFiles || [];
      // Use file data that's already populated in the assignment
      const fileDetails = attachedFiles.map((file: any) => ({
        _id: file._id || file,
        originalName: file.originalName || file.name || 'Unknown',
        size: file.size || 0,
        mimeType: file.mimeType || 'application/octet-stream'
      }));
      setFiles(fileDetails);
    } catch (error) {
      console.error('Error loading files:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (fileId: string, fileName: string) => {
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

  const handleRemoveFile = async (fileId: string) => {
    if (!window.confirm('Are you sure you want to remove this file from the assignment?')) {
      return;
    }
    try {
      await assignmentsAPI.removeFile(assignment._id, fileId);
      loadFiles();
      // Refresh the assignment data
      window.location.reload();
    } catch (error) {
      console.error('Error removing file:', error);
      alert('Failed to remove file');
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content view-files-modal" onClick={(e) => e.stopPropagation()}>
        <h2>Assignment Files</h2>
        <p className="assignment-name">{assignment.title}</p>

        {loading ? (
          <div className="loading-state">Loading files...</div>
        ) : files.length === 0 ? (
          <div className="empty-state">
            <p>No files attached to this assignment</p>
          </div>
        ) : (
          <div className="files-list-view">
            {files.map((file) => (
              <div key={file._id} className="file-item-view">
                <div className="file-icon-view">
                  <DocumentIcon size={24} color="currentColor" />
                </div>
                <div className="file-info-view">
                  <div className="file-name-view">{file.originalName}</div>
                  <div className="file-meta-view">
                    {formatFileSize(file.size)} • {file.mimeType}
                  </div>
                </div>
                <div className="file-actions-view">
                  <button
                    className="btn-secondary btn-small"
                    onClick={() => handleDownload(file._id, file.originalName)}
                  >
                    Download
                  </button>
                  <button
                    className="btn-secondary btn-small btn-danger"
                    onClick={() => handleRemoveFile(file._id)}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="modal-actions">
          <button type="button" className="btn-primary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

// Create Assignment Modal Component
const CreateAssignmentModal: React.FC<{ 
  courses: Course[]; 
  defaultCourse?: string;
  defaultCourseCode?: string;
  onClose: () => void 
}> = ({ courses, defaultCourse, defaultCourseCode, onClose }) => {
  const defaultCourseObj = defaultCourse ? courses.find(c => c.name === defaultCourse) : courses[0];
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    course: defaultCourse || defaultCourseObj?.name || '',
    courseCode: defaultCourseCode || defaultCourseObj?.code || '',
    dueDate: '',
    priority: 'Medium' as const,
    tags: ''
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await assignmentsAPI.createAssignment({
        ...formData,
        tags: formData.tags.split(',').map(t => t.trim()).filter(t => t)
      });
      onClose();
    } catch (error) {
      console.error('Error creating assignment:', error);
      alert('Failed to create assignment');
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Create New Assignment</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Title *</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label>Course *</label>
            <select
              value={formData.course}
              onChange={(e) => {
                const course = courses.find(c => c.name === e.target.value);
                setFormData({
                  ...formData,
                  course: e.target.value,
                  courseCode: course?.code || ''
                });
              }}
              required
              disabled={!!defaultCourse}
            >
              {courses.map(course => (
                <option key={course._id} value={course.name}>
                  {course.code} - {course.name}
                </option>
              ))}
            </select>
            {defaultCourse && (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.25rem' }}>
                Assignment will be created for this course
              </p>
            )}
          </div>
          <div className="form-group">
            <label>Due Date *</label>
            <input
              type="datetime-local"
              value={formData.dueDate}
              onChange={(e) => setFormData({ ...formData, dueDate: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label>Priority</label>
            <select
              value={formData.priority}
              onChange={(e) => setFormData({ ...formData, priority: e.target.value as any })}
            >
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Urgent">Urgent</option>
            </select>
          </div>
          <div className="form-group">
            <label>Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              rows={4}
            />
          </div>
          <div className="form-group">
            <label>Tags (comma-separated)</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              placeholder="e.g., essay, group-project, final"
            />
          </div>
          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary">Create Assignment</button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Upload Files Modal Component
const UploadFilesModal: React.FC<{
  assignment: Assignment;
  availableFiles: any[];
  onClose: () => void;
  onRefreshFiles: () => void;
}> = ({ assignment, availableFiles, onClose, onRefreshFiles }) => {
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploadMode, setUploadMode] = useState<'existing' | 'new'>('existing');

  const handleFileSelect = (fileId: string) => {
    const newSelection = new Set(selectedFiles);
    if (newSelection.has(fileId)) {
      newSelection.delete(fileId);
    } else {
      newSelection.add(fileId);
    }
    setSelectedFiles(newSelection);
  };

  const handleAttachFiles = async () => {
    if (selectedFiles.size === 0) return;

    try {
      setUploading(true);
      const fileIds = Array.from(selectedFiles);
      for (const fileId of fileIds) {
        await assignmentsAPI.attachFile(assignment._id, fileId);
      }
      onClose();
    } catch (error) {
      console.error('Error attaching files:', error);
      alert('Failed to attach files');
    } finally {
      setUploading(false);
    }
  };

  const handleNewFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    try {
      setUploading(true);
      // Upload files first
      const uploadedFileIds: string[] = [];
      for (const file of Array.from(files)) {
        const uploadResponse = await filesAPI.uploadFile(file);
        // Backend returns file object directly: { _id: ..., name: ..., ... }
        const fileId = uploadResponse._id;
        if (fileId) {
          uploadedFileIds.push(fileId);
        }
      }

      // Attach uploaded files to assignment
      for (const fileId of uploadedFileIds) {
        await assignmentsAPI.attachFile(assignment._id, fileId);
      }

      onRefreshFiles();
      onClose();
    } catch (error) {
      console.error('Error uploading files:', error);
      alert('Failed to upload files');
    } finally {
      setUploading(false);
    }
  };

  const attachedFileIds = new Set(
    (assignment.attachedFiles || []).map((f: any) => f._id || f.toString())
  );

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content upload-files-modal" onClick={(e) => e.stopPropagation()}>
        <h2>Upload Files to Assignment</h2>
        <p className="assignment-name">{assignment.title}</p>

        <div className="upload-mode-tabs">
          <button
            className={`upload-mode-tab ${uploadMode === 'existing' ? 'active' : ''}`}
            onClick={() => setUploadMode('existing')}
          >
            Attach Existing Files
          </button>
          <button
            className={`upload-mode-tab ${uploadMode === 'new' ? 'active' : ''}`}
            onClick={() => setUploadMode('new')}
          >
            Upload New Files
          </button>
        </div>

        {uploadMode === 'existing' && (
          <div className="files-selection">
            <div className="files-list">
              {availableFiles
                .filter(file => !attachedFileIds.has(file._id))
                .map(file => (
                  <div
                    key={file._id}
                    className={`file-selection-item ${selectedFiles.has(file._id) ? 'selected' : ''}`}
                    onClick={() => handleFileSelect(file._id)}
                  >
                    <input
                      type="checkbox"
                      checked={selectedFiles.has(file._id)}
                      onChange={() => handleFileSelect(file._id)}
                      onClick={(e) => e.stopPropagation()}
                    />
                    <span className="file-icon">
                      {file.isFolder ? (
                        <FolderIcon size={18} color="currentColor" />
                      ) : (
                        <DocumentIcon size={18} color="currentColor" />
                      )}
                    </span>
                    <span className="file-name">{file.originalName || file.name}</span>
                  </div>
                ))}
            </div>
            {availableFiles.filter(file => !attachedFileIds.has(file._id)).length === 0 && (
              <p className="no-files-message">No files available to attach</p>
            )}
          </div>
        )}

        {uploadMode === 'new' && (
          <div className="new-file-upload">
            <input
              ref={fileInputRef}
              type="file"
              multiple
              onChange={handleNewFileUpload}
              style={{ display: 'none' }}
            />
            <div
              className="upload-dropzone"
              onClick={() => fileInputRef.current?.click()}
            >
              <div className="upload-icon">➜</div>
              <p>Click to select files or drag and drop</p>
              <p className="upload-hint">Files will be uploaded and attached to this assignment</p>
            </div>
          </div>
        )}

        <div className="modal-actions">
          <button type="button" className="btn-secondary" onClick={onClose} disabled={uploading}>
            Cancel
          </button>
          {uploadMode === 'existing' && (
            <button
              type="button"
              className="btn-primary"
              onClick={handleAttachFiles}
              disabled={selectedFiles.size === 0 || uploading}
            >
              {uploading ? 'Attaching...' : `Attach ${selectedFiles.size} File(s)`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default AssignmentTracker;

