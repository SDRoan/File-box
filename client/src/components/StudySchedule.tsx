import React, { useState, useEffect } from 'react';
import { studyScheduleAPI } from '../services/api';
import { CalendarIcon, PlusIcon, TrashIcon } from './Icons';
import './StudySchedule.css';

interface StudyScheduleProps {
  courseId: string;
  courseCode: string;
  courseName: string;
}

interface Schedule {
  _id: string;
  title: string;
  description: string;
  startTime: string;
  endTime: string;
  type: string;
  location: string;
  completed: boolean;
}

const StudySchedule: React.FC<StudyScheduleProps> = ({ courseId, courseCode, courseName }) => {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState<Schedule | null>(null);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    startTime: '',
    endTime: '',
    type: 'study_session',
    location: '',
    isRecurring: false,
    reminderMinutes: 15
  });

  useEffect(() => {
    loadSchedules();
  }, [courseId]);

  const loadSchedules = async () => {
    try {
      setLoading(true);
      const today = new Date();
      const nextMonth = new Date(today.getTime() + 30 * 24 * 60 * 60 * 1000);
      const data = await studyScheduleAPI.getSchedules(courseId, {
        startDate: today.toISOString(),
        endDate: nextMonth.toISOString()
      });
      setSchedules(data.schedules || []);
    } catch (error) {
      console.error('Error loading schedules:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSchedule = () => {
    setEditingSchedule(null);
    const now = new Date();
    const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);
    setFormData({
      title: '',
      description: '',
      startTime: now.toISOString().slice(0, 16),
      endTime: oneHourLater.toISOString().slice(0, 16),
      type: 'study_session',
      location: '',
      isRecurring: false,
      reminderMinutes: 15
    });
    setShowModal(true);
  };

  const handleEditSchedule = (schedule: Schedule) => {
    setEditingSchedule(schedule);
    setFormData({
      title: schedule.title,
      description: schedule.description,
      startTime: new Date(schedule.startTime).toISOString().slice(0, 16),
      endTime: new Date(schedule.endTime).toISOString().slice(0, 16),
      type: schedule.type,
      location: schedule.location,
      isRecurring: false,
      reminderMinutes: 15
    });
    setShowModal(true);
  };

  const handleSaveSchedule = async () => {
    try {
      if (editingSchedule) {
        await studyScheduleAPI.updateSchedule(editingSchedule._id, {
          title: formData.title,
          description: formData.description,
          startTime: new Date(formData.startTime).toISOString(),
          endTime: new Date(formData.endTime).toISOString(),
          type: formData.type,
          location: formData.location,
          reminderMinutes: formData.reminderMinutes
        });
      } else {
        await studyScheduleAPI.createSchedule({
          course: courseId,
          title: formData.title,
          description: formData.description,
          startTime: new Date(formData.startTime).toISOString(),
          endTime: new Date(formData.endTime).toISOString(),
          type: formData.type,
          location: formData.location,
          isRecurring: formData.isRecurring,
          reminderMinutes: formData.reminderMinutes
        });
      }

      setShowModal(false);
      loadSchedules();
    } catch (error: any) {
      console.error('Error saving schedule:', error);
      alert(error.response?.data?.message || 'Failed to save schedule');
    }
  };

  const handleDeleteSchedule = async (scheduleId: string) => {
    if (!window.confirm('Are you sure you want to delete this schedule?')) {
      return;
    }

    try {
      await studyScheduleAPI.deleteSchedule(scheduleId);
      loadSchedules();
    } catch (error: any) {
      console.error('Error deleting schedule:', error);
      alert(error.response?.data?.message || 'Failed to delete schedule');
    }
  };

  const handleToggleComplete = async (schedule: Schedule) => {
    try {
      await studyScheduleAPI.updateSchedule(schedule._id, {
        completed: !schedule.completed
      });
      loadSchedules();
    } catch (error: any) {
      console.error('Error updating schedule:', error);
    }
  };

  const sortedSchedules = [...schedules].sort((a, b) => 
    new Date(a.startTime).getTime() - new Date(b.startTime).getTime()
  );

  if (loading) {
    return <div className="study-schedule-loading">Loading schedule...</div>;
  }

  return (
    <div className="study-schedule">
      <div className="schedule-header">
        <div>
          <h2>Study Schedule - {courseCode}</h2>
          <p>Plan and track your study sessions</p>
        </div>
        <button className="btn-primary" onClick={handleCreateSchedule}>
          <PlusIcon size={18} color="currentColor" />
          <span>New Session</span>
        </button>
      </div>

      <div className="schedule-list">
        {sortedSchedules.length > 0 ? (
          sortedSchedules.map(schedule => {
            const startDate = new Date(schedule.startTime);
            const endDate = new Date(schedule.endTime);
            const isPast = endDate < new Date();

            return (
              <div
                key={schedule._id}
                className={`schedule-item ${schedule.completed ? 'completed' : ''} ${isPast && !schedule.completed ? 'past' : ''}`}
              >
                <div className="schedule-item-main">
                  <div className="schedule-time">
                    <CalendarIcon size={18} color="currentColor" />
                    <div>
                      <div className="time-display">
                        {startDate.toLocaleDateString()} {startDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </div>
                      <div className="time-range">
                        {startDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} - {endDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </div>
                  </div>
                  <div className="schedule-details">
                    <h3>{schedule.title}</h3>
                    {schedule.description && <p>{schedule.description}</p>}
                    <div className="schedule-meta">
                      <span className={`type-badge type-${schedule.type}`}>
                        {schedule.type.replace('_', ' ')}
                      </span>
                      {schedule.location && <span className="location-badge">📍 {schedule.location}</span>}
                    </div>
                  </div>
                </div>
                <div className="schedule-actions">
                  <button
                    className={`icon-btn ${schedule.completed ? 'completed-btn' : ''}`}
                    onClick={() => handleToggleComplete(schedule)}
                    title={schedule.completed ? 'Mark incomplete' : 'Mark complete'}
                  >
                    {schedule.completed ? '✓' : '○'}
                  </button>
                  <button
                    className="icon-btn"
                    onClick={() => handleEditSchedule(schedule)}
                    title="Edit"
                  >
                    ✏️
                  </button>
                  <button
                    className="icon-btn delete-btn"
                    onClick={() => handleDeleteSchedule(schedule._id)}
                    title="Delete"
                  >
                    <TrashIcon size={16} color="currentColor" />
                  </button>
                </div>
              </div>
            );
          })
        ) : (
          <div className="empty-state">
            <p>No study sessions scheduled. Create your first one!</p>
          </div>
        )}
      </div>

      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingSchedule ? 'Edit Study Session' : 'Create Study Session'}</h3>
              <button className="modal-close" onClick={() => setShowModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Title *</label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="e.g., Review Chapter 5"
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Additional details..."
                  rows={3}
                />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Start Time *</label>
                  <input
                    type="datetime-local"
                    value={formData.startTime}
                    onChange={(e) => setFormData({ ...formData, startTime: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>End Time *</label>
                  <input
                    type="datetime-local"
                    value={formData.endTime}
                    onChange={(e) => setFormData({ ...formData, endTime: e.target.value })}
                  />
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Type</label>
                  <select
                    value={formData.type}
                    onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  >
                    <option value="study_session">Study Session</option>
                    <option value="review">Review</option>
                    <option value="assignment_work">Assignment Work</option>
                    <option value="exam_prep">Exam Prep</option>
                    <option value="project_work">Project Work</option>
                    <option value="other">Other</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Location</label>
                  <input
                    type="text"
                    value={formData.location}
                    onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                    placeholder="e.g., Library, Room 201"
                  />
                </div>
              </div>
              <div className="form-group">
                <label>Reminder (minutes before)</label>
                <input
                  type="number"
                  value={formData.reminderMinutes}
                  onChange={(e) => setFormData({ ...formData, reminderMinutes: parseInt(e.target.value) || 15 })}
                  min="0"
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowModal(false)}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={handleSaveSchedule}
                disabled={!formData.title.trim() || !formData.startTime || !formData.endTime}
              >
                {editingSchedule ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default StudySchedule;
