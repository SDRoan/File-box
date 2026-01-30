import React, { useState, useEffect } from 'react';
import { coursesAPI, filesAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { BookIcon, PlusIcon, UsersIcon, FolderIcon, TrashIcon } from './Icons';
import './CourseManager.css';

interface Course {
  _id: string;
  name: string;
  code: string;
  semester?: string;
  year?: number;
  instructor?: string;
  color: string;
  folder?: {
    _id: string;
    name: string;
  };
  schedule?: Array<{
    day: string;
    startTime: string;
    endTime: string;
    location?: string;
  }>;
}

interface CourseManagerProps {
  onCourseClick?: (folderId: string, course: Course) => void;
}

const CourseManager: React.FC<CourseManagerProps> = ({ onCourseClick }) => {
  const [courses, setCourses] = useState<Course[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    loadCourses();
  }, []);

  const loadCourses = async () => {
    try {
      const response = await coursesAPI.getCourses();
      setCourses(response.courses || []);
    } catch (error) {
      console.error('Error loading courses:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCourseClick = (course: Course) => {
    if (course.folder && course.folder._id) {
      if (onCourseClick) {
        onCourseClick(course.folder._id, course);
      }
    }
  };

  const handleDeleteCourse = async (e: React.MouseEvent, courseId: string, courseCode: string) => {
    e.stopPropagation(); // Prevent card click
    
    if (!window.confirm(`Are you sure you want to delete ${courseCode}? This will also delete the associated folder and all its contents.`)) {
      return;
    }

    try {
      await coursesAPI.deleteCourse(courseId);
      await loadCourses();
    } catch (error: any) {
      console.error('Error deleting course:', error);
      alert(error.response?.data?.message || 'Failed to delete course');
    }
  };

  if (loading) {
    return <div className="course-manager-loading">Loading courses...</div>;
  }

  return (
    <div className="course-manager">
      <div className="course-header">
        <h1>
          <BookIcon size={28} color="currentColor" style={{ display: 'inline-block', marginRight: '0.5rem', verticalAlign: 'middle' }} />
          My Courses
        </h1>
        <button className="btn-primary add-course-btn" onClick={() => setShowCreateModal(true)}>
          <PlusIcon size={16} color="#ffffff" />
          <span>Add Course</span>
        </button>
      </div>

      <div className="courses-grid">
        {courses.map(course => (
          <div
            key={course._id}
            className="course-card"
            style={{ borderLeftColor: course.color }}
            onClick={() => handleCourseClick(course)}
          >
            <div className="course-card-header">
              <div className="course-code">{course.code}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div className="course-color" style={{ backgroundColor: course.color }}></div>
                <button
                  className="course-delete-btn"
                  onClick={(e) => handleDeleteCourse(e, course._id, course.code)}
                  title="Delete course"
                >
                  <TrashIcon size={18} color="currentColor" />
                </button>
              </div>
            </div>
            <h3 className="course-name">{course.name}</h3>
            {course.instructor && (
              <p className="course-instructor">
                <UsersIcon size={16} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
                {course.instructor}
              </p>
            )}
            {(course.semester || course.year) && (
              <p className="course-term">
                {course.semester} {course.year}
              </p>
            )}
            {course.folder && (
              <div className="course-folder-link">
                <FolderIcon size={16} color="currentColor" style={{ display: 'inline-block', marginRight: '0.25rem', verticalAlign: 'middle' }} />
                {course.folder.name}
              </div>
            )}
            {course.schedule && course.schedule.length > 0 && (
              <div className="course-schedule">
                {course.schedule.map((sched, idx) => (
                  <div key={idx} className="schedule-item">
                    {sched.day} {sched.startTime} - {sched.endTime}
                    {sched.location && ` @ ${sched.location}`}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {courses.length === 0 && (
        <div className="empty-state">
          <p>No courses yet. Add your first course to get started!</p>
        </div>
      )}

      {showCreateModal && (
        <CreateCourseModal
          onClose={() => {
            setShowCreateModal(false);
            loadCourses();
          }}
        />
      )}
    </div>
  );
};

const CreateCourseModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [formData, setFormData] = useState({
    name: '',
    code: '',
    semester: '',
    year: new Date().getFullYear(),
    instructor: '',
    color: '#6366f1'
  });

  const colors = [
    '#6366f1', '#8b5cf6', '#ec4899', '#ef4444',
    '#f59e0b', '#10b981', '#3b82f6', '#06b6d4'
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await coursesAPI.createCourse(formData);
      onClose();
    } catch (error: any) {
      console.error('Error creating course:', error);
      alert(error.response?.data?.message || 'Failed to create course');
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Add New Course</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Course Code *</label>
            <input
              type="text"
              value={formData.code}
              onChange={(e) => setFormData({ ...formData, code: e.target.value.toUpperCase() })}
              placeholder="e.g., CS101"
              required
            />
          </div>
          <div className="form-group">
            <label>Course Name *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="e.g., Introduction to Computer Science"
              required
            />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Semester</label>
              <select
                value={formData.semester}
                onChange={(e) => setFormData({ ...formData, semester: e.target.value })}
              >
                <option value="">Select...</option>
                <option value="Fall">Fall</option>
                <option value="Spring">Spring</option>
                <option value="Summer">Summer</option>
                <option value="Winter">Winter</option>
              </select>
            </div>
            <div className="form-group">
              <label>Year</label>
              <input
                type="number"
                value={formData.year}
                onChange={(e) => setFormData({ ...formData, year: parseInt(e.target.value) })}
                min="2020"
                max="2030"
              />
            </div>
          </div>
          <div className="form-group">
            <label>Instructor</label>
            <input
              type="text"
              value={formData.instructor}
              onChange={(e) => setFormData({ ...formData, instructor: e.target.value })}
              placeholder="Professor Name"
            />
          </div>
          <div className="form-group">
            <label>Color</label>
            <div className="color-picker">
              {colors.map(color => (
                <button
                  key={color}
                  type="button"
                  className={`color-option ${formData.color === color ? 'selected' : ''}`}
                  style={{ backgroundColor: color }}
                  onClick={() => setFormData({ ...formData, color })}
                />
              ))}
            </div>
          </div>
          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary">Create Course</button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CourseManager;

