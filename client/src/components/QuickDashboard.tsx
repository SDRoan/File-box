import React, { useState, useEffect } from 'react';
import { assignmentsAPI, filesAPI, courseNotesAPI, studyScheduleAPI, progressTrackingAPI } from '../services/api';
import { BookIcon, FolderIcon, SummaryIcon, CalendarIcon } from './Icons';
import './QuickDashboard.css';

interface QuickDashboardProps {
  courseId: string;
  courseCode: string;
  courseName: string;
}

const QuickDashboard: React.FC<QuickDashboardProps> = ({ courseId, courseCode, courseName }) => {
  const [loading, setLoading] = useState(true);
  const [upcomingAssignments, setUpcomingAssignments] = useState<any[]>([]);
  const [recentFiles, setRecentFiles] = useState<any[]>([]);
  const [recentNotes, setRecentNotes] = useState<any[]>([]);
  const [upcomingSchedules, setUpcomingSchedules] = useState<any[]>([]);
  const [progressStats, setProgressStats] = useState<any>(null);

  useEffect(() => {
    loadDashboardData();
  }, [courseId]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load upcoming assignments
      const assignmentsData = await assignmentsAPI.getAssignments({ 
        course: courseName,
        upcoming: true 
      });
      setUpcomingAssignments((assignmentsData.assignments || []).slice(0, 5));

      // Load recent files
      const filesData = await filesAPI.getFiles();
      const allFiles = [...(filesData.files || []), ...(filesData.folders || [])];
      setRecentFiles(allFiles.slice(0, 5));

      // Load recent notes
      const notesData = await courseNotesAPI.getNotes(courseId);
      setRecentNotes((notesData.notes || []).slice(0, 5));

      // Load upcoming study schedules
      const today = new Date();
      const nextWeek = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000);
      const schedulesData = await studyScheduleAPI.getSchedules(courseId, {
        startDate: today.toISOString(),
        endDate: nextWeek.toISOString()
      });
      setUpcomingSchedules((schedulesData.schedules || []).slice(0, 5));

      // Load progress stats
      try {
        const progressData = await progressTrackingAPI.getProgress(courseId);
        setProgressStats(progressData.statistics);
      } catch (e) {
        // Progress tracking might not have data yet
      }
    } catch (error) {
      console.error('Error loading dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="quick-dashboard-loading">Loading dashboard...</div>;
  }

  return (
    <div className="quick-dashboard">
      <div className="dashboard-header">
        <h2>Quick Overview - {courseCode}</h2>
        <p>Everything you need at a glance</p>
      </div>

      <div className="dashboard-grid">
        {/* Upcoming Assignments */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <BookIcon size={20} color="currentColor" />
            <h3>Upcoming Assignments</h3>
          </div>
          <div className="dashboard-card-content">
            {upcomingAssignments.length > 0 ? (
              <ul className="dashboard-list">
                {upcomingAssignments.map(assignment => (
                  <li key={assignment._id}>
                    <div className="list-item-main">
                      <strong>{assignment.title}</strong>
                      {assignment.dueDate && (
                        <span className="list-item-meta">
                          Due: {new Date(assignment.dueDate).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                    <span className={`status-badge status-${assignment.status?.toLowerCase().replace(' ', '-')}`}>
                      {assignment.status}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="empty-message">No upcoming assignments</p>
            )}
          </div>
        </div>

        {/* Recent Files */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <FolderIcon size={20} color="currentColor" />
            <h3>Recent Files</h3>
          </div>
          <div className="dashboard-card-content">
            {recentFiles.length > 0 ? (
              <ul className="dashboard-list">
                {recentFiles.map(file => (
                  <li key={file._id}>
                    <div className="list-item-main">
                      <strong>{file.name || file.originalName}</strong>
                      {file.updatedAt && (
                        <span className="list-item-meta">
                          {new Date(file.updatedAt).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="empty-message">No recent files</p>
            )}
          </div>
        </div>

        {/* Recent Notes */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <SummaryIcon size={20} color="currentColor" />
            <h3>Recent Notes</h3>
          </div>
          <div className="dashboard-card-content">
            {recentNotes.length > 0 ? (
              <ul className="dashboard-list">
                {recentNotes.map(note => (
                  <li key={note._id}>
                    <div className="list-item-main">
                      <strong>{note.title}</strong>
                      {note.updatedAt && (
                        <span className="list-item-meta">
                          {new Date(note.updatedAt).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                    {note.isPinned && <span className="pinned-badge">📌</span>}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="empty-message">No notes yet</p>
            )}
          </div>
        </div>

        {/* Upcoming Study Sessions */}
        <div className="dashboard-card">
          <div className="dashboard-card-header">
            <CalendarIcon size={20} color="currentColor" />
            <h3>Upcoming Study Sessions</h3>
          </div>
          <div className="dashboard-card-content">
            {upcomingSchedules.length > 0 ? (
              <ul className="dashboard-list">
                {upcomingSchedules.map(schedule => (
                  <li key={schedule._id}>
                    <div className="list-item-main">
                      <strong>{schedule.title}</strong>
                      {schedule.startTime && (
                        <span className="list-item-meta">
                          {new Date(schedule.startTime).toLocaleString()}
                        </span>
                      )}
                    </div>
                    {schedule.completed && <span className="completed-badge">✓</span>}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="empty-message">No scheduled study sessions</p>
            )}
          </div>
        </div>

        {/* Progress Overview */}
        {progressStats && (
          <div className="dashboard-card dashboard-card-wide">
            <div className="dashboard-card-header">
              <h3>Progress Overview</h3>
            </div>
            <div className="dashboard-card-content">
              <div className="progress-stats">
                <div className="stat-item">
                  <div className="stat-value">{progressStats.overallPercentage.toFixed(1)}%</div>
                  <div className="stat-label">Overall Grade</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{progressStats.totalPointsEarned}</div>
                  <div className="stat-label">Points Earned</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{progressStats.totalPointsPossible}</div>
                  <div className="stat-label">Total Points</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{progressStats.totalEntries}</div>
                  <div className="stat-label">Assignments</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default QuickDashboard;
