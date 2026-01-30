import React, { useState, useEffect } from 'react';
import { studySessionsAPI } from '../services/api';
import { AnalyticsIcon } from './Icons';
import './StudyAnalytics.css';

interface StudyAnalyticsProps {
  courseId: string;
  courseCode: string;
  courseName: string;
}

interface StudySession {
  _id: string;
  startTime: string;
  endTime: string;
  duration: number;
  topic: string;
  productivity: string;
  notes: string;
}

interface Statistics {
  totalDuration: number;
  totalSessions: number;
  avgDuration: number;
  totalHours: number;
}

const StudyAnalytics: React.FC<StudyAnalyticsProps> = ({ courseId, courseCode, courseName }) => {
  const [sessions, setSessions] = useState<StudySession[]>([]);
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'week' | 'month' | 'all'>('month');

  useEffect(() => {
    loadSessions();
  }, [courseId, timeRange]);

  const loadSessions = async () => {
    try {
      setLoading(true);
      const today = new Date();
      let startDate: Date;

      switch (timeRange) {
        case 'week':
          startDate = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case 'month':
          startDate = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
          break;
        default:
          startDate = new Date(0);
      }

      const data = await studySessionsAPI.getSessions(courseId, {
        startDate: startDate.toISOString(),
        endDate: today.toISOString()
      });
      setSessions(data.sessions || []);
      setStatistics(data.statistics || null);
    } catch (error) {
      console.error('Error loading sessions:', error);
    } finally {
      setLoading(false);
    }
  };

  const getProductivityColor = (productivity: string) => {
    switch (productivity) {
      case 'high': return '#10b981';
      case 'medium': return '#f59e0b';
      case 'low': return '#ef4444';
      default: return '#6b7280';
    }
  };

  if (loading) {
    return <div className="study-analytics-loading">Loading analytics...</div>;
  }

  return (
    <div className="study-analytics">
      <div className="analytics-header">
        <div>
          <h2>Study Analytics - {courseCode}</h2>
          <p>Track your study habits and productivity</p>
        </div>
        <div className="time-range-selector">
          <button
            className={`range-btn ${timeRange === 'week' ? 'active' : ''}`}
            onClick={() => setTimeRange('week')}
          >
            Week
          </button>
          <button
            className={`range-btn ${timeRange === 'month' ? 'active' : ''}`}
            onClick={() => setTimeRange('month')}
          >
            Month
          </button>
          <button
            className={`range-btn ${timeRange === 'all' ? 'active' : ''}`}
            onClick={() => setTimeRange('all')}
          >
            All Time
          </button>
        </div>
      </div>

      {statistics && (
        <div className="analytics-overview">
          <div className="stat-card">
            <div className="stat-icon">⏱️</div>
            <div className="stat-content">
              <div className="stat-value">{statistics.totalHours.toFixed(1)}</div>
              <div className="stat-label">Total Hours</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">📊</div>
            <div className="stat-content">
              <div className="stat-value">{statistics.totalSessions}</div>
              <div className="stat-label">Study Sessions</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">⏰</div>
            <div className="stat-content">
              <div className="stat-value">{statistics.avgDuration}</div>
              <div className="stat-label">Avg Duration (min)</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">📈</div>
            <div className="stat-content">
              <div className="stat-value">{statistics.totalDuration}</div>
              <div className="stat-label">Total Minutes</div>
            </div>
          </div>
        </div>
      )}

      <div className="sessions-section">
        <h3>Recent Study Sessions</h3>
        {sessions.length > 0 ? (
          <div className="sessions-list">
            {sessions.map(session => (
              <div key={session._id} className="session-card">
                <div className="session-main">
                  <div className="session-header">
                    <div className="session-date">
                      {new Date(session.startTime).toLocaleDateString()}
                    </div>
                    <div
                      className="productivity-badge"
                      style={{ color: getProductivityColor(session.productivity) }}
                    >
                      {session.productivity} productivity
                    </div>
                  </div>
                  <div className="session-details">
                    <div className="session-time">
                      {new Date(session.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} - {session.endTime ? new Date(session.endTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Ongoing'}
                    </div>
                    <div className="session-duration">
                      {session.duration || 0} minutes
                    </div>
                  </div>
                  {session.topic && (
                    <div className="session-topic">
                      Topic: {session.topic}
                    </div>
                  )}
                  {session.notes && (
                    <div className="session-notes">
                      {session.notes}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <p>No study sessions recorded yet. Start tracking your study time!</p>
            <p className="empty-hint">
              Tip: Use the Study Schedule tab to plan sessions, and they'll appear here automatically.
            </p>
          </div>
        )}
      </div>

      <div className="insights-section">
        <h3>Insights</h3>
        <div className="insights-grid">
          {statistics && statistics.totalSessions > 0 && (
            <>
              <div className="insight-card">
                <h4>Study Frequency</h4>
                <p>
                  You've studied {statistics.totalSessions} time{statistics.totalSessions !== 1 ? 's' : ''} 
                  {timeRange === 'week' && ' this week'}
                  {timeRange === 'month' && ' this month'}
                  {timeRange === 'all' && ' total'}.
                </p>
              </div>
              <div className="insight-card">
                <h4>Average Session</h4>
                <p>
                  Your average study session lasts {statistics.avgDuration} minutes 
                  ({Math.round(statistics.avgDuration / 60 * 10) / 10} hours).
                </p>
              </div>
              <div className="insight-card">
                <h4>Total Study Time</h4>
                <p>
                  You've spent {statistics.totalHours.toFixed(1)} hours studying 
                  {timeRange === 'week' && ' this week'}
                  {timeRange === 'month' && ' this month'}
                  {timeRange === 'all' && ' total'}.
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default StudyAnalytics;
