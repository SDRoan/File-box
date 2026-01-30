import React, { useState } from 'react';
import AssignmentTracker from './AssignmentTracker';
import CourseManager from './CourseManager';
import FileBrowser from './FileBrowser';
import StudyGroups from './StudyGroups';
import CourseNotes from './CourseNotes';
import StudySchedule from './StudySchedule';
import ProgressTracking from './ProgressTracking';
import StudyTools from './StudyTools';
import QuickDashboard from './QuickDashboard';
import StudyAnalytics from './StudyAnalytics';
import { StudentIcon, FolderIcon, BookIcon, UsersIcon, BackIcon, SummaryIcon, CalendarIcon, AnalyticsIcon, TagIcon } from './Icons';
import './StudentDashboard.css';

interface Course {
  _id: string;
  name: string;
  code: string;
}

const StudentDashboard: React.FC = () => {
  const [selectedCourseFolder, setSelectedCourseFolder] = useState<string | null>(null);
  const [selectedCourse, setSelectedCourse] = useState<Course | null>(null);
  const [folderStack, setFolderStack] = useState<string[]>([]);
  const [activeView, setActiveView] = useState<'files' | 'assignments' | 'study-groups' | 'notes' | 'schedule' | 'progress' | 'tools' | 'dashboard' | 'analytics'>('files');

  return (
    <div className="student-dashboard">
      <div className="student-header">
        <h1>
          <StudentIcon size={32} color="currentColor" style={{ display: 'inline-block', marginRight: '0.5rem', verticalAlign: 'middle' }} />
          Student Dashboard
        </h1>
        <p>Manage your courses, assignments, and academic resources</p>
      </div>

      <div className="student-content">
        {selectedCourseFolder && selectedCourse ? (
          <div className="course-folder-view">
            <div className="course-folder-header">
              <div className="course-header-info">
                <button 
                  className="back-button"
                  onClick={() => {
                    setSelectedCourseFolder(null);
                    setSelectedCourse(null);
                    setFolderStack([]);
                    setActiveView('files');
                  }}
                >
                  <BackIcon size={16} color="currentColor" />
                  <span>Back to Courses</span>
                </button>
                <div className="course-title-section">
                  <h2>{selectedCourse.code} - {selectedCourse.name}</h2>
                </div>
              </div>
              <div className="course-view-tabs">
                <button
                  className={`course-view-tab ${activeView === 'dashboard' ? 'active' : ''}`}
                  onClick={() => setActiveView('dashboard')}
                  title="Quick Dashboard"
                >
                  <span>📊</span>
                  <span>Dashboard</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'files' ? 'active' : ''}`}
                  onClick={() => setActiveView('files')}
                >
                  <FolderIcon size={18} color="currentColor" />
                  <span>Files</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'assignments' ? 'active' : ''}`}
                  onClick={() => setActiveView('assignments')}
                >
                  <BookIcon size={18} color="currentColor" />
                  <span>Assignments</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'notes' ? 'active' : ''}`}
                  onClick={() => setActiveView('notes')}
                >
                  <SummaryIcon size={18} color="currentColor" />
                  <span>Notes</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'schedule' ? 'active' : ''}`}
                  onClick={() => setActiveView('schedule')}
                >
                  <CalendarIcon size={18} color="currentColor" />
                  <span>Schedule</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'progress' ? 'active' : ''}`}
                  onClick={() => setActiveView('progress')}
                >
                  <span>📈</span>
                  <span>Progress</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'tools' ? 'active' : ''}`}
                  onClick={() => setActiveView('tools')}
                >
                  <TagIcon size={18} color="currentColor" />
                  <span>Study Tools</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'study-groups' ? 'active' : ''}`}
                  onClick={() => setActiveView('study-groups')}
                >
                  <UsersIcon size={18} color="currentColor" />
                  <span>Groups</span>
                </button>
                <button
                  className={`course-view-tab ${activeView === 'analytics' ? 'active' : ''}`}
                  onClick={() => setActiveView('analytics')}
                >
                  <AnalyticsIcon size={18} color="currentColor" />
                  <span>Analytics</span>
                </button>
              </div>
            </div>
            {activeView === 'files' && (
              <>
                {folderStack.length > 0 && (
                  <div className="folder-navigation">
                    <button 
                      className="back-button"
                      onClick={() => {
                        const newStack = folderStack.slice(0, -1);
                        setFolderStack(newStack);
                      }}
                    >
                      <BackIcon size={16} color="currentColor" />
                      <span>Up</span>
                    </button>
                  </div>
                )}
                <FileBrowser
                  currentFolderId={folderStack.length > 0 ? folderStack[folderStack.length - 1] : selectedCourseFolder}
                  onFolderClick={(folderId) => {
                    setFolderStack([...(folderStack.length > 0 ? folderStack : [selectedCourseFolder!]), folderId]);
                  }}
                  onNavigateUp={() => {
                    if (folderStack.length > 0) {
                      const newStack = folderStack.slice(0, -1);
                      setFolderStack(newStack);
                    } else {
                      setActiveView('assignments');
                    }
                  }}
                  showTrash={false}
                />
              </>
            )}
            {activeView === 'dashboard' && (
              <QuickDashboard courseId={selectedCourse._id} courseCode={selectedCourse.code} courseName={selectedCourse.name} />
            )}
            {activeView === 'assignments' && (
              <AssignmentTracker courseFilter={selectedCourse.name} courseCode={selectedCourse.code} />
            )}
            {activeView === 'notes' && (
              <CourseNotes courseId={selectedCourse._id} courseCode={selectedCourse.code} courseName={selectedCourse.name} />
            )}
            {activeView === 'schedule' && (
              <StudySchedule courseId={selectedCourse._id} courseCode={selectedCourse.code} courseName={selectedCourse.name} />
            )}
            {activeView === 'progress' && (
              <ProgressTracking courseId={selectedCourse._id} courseCode={selectedCourse.code} courseName={selectedCourse.name} />
            )}
            {activeView === 'tools' && (
              <StudyTools courseId={selectedCourse._id} courseCode={selectedCourse.code} courseName={selectedCourse.name} />
            )}
            {activeView === 'study-groups' && (
              <StudyGroups />
            )}
            {activeView === 'analytics' && (
              <StudyAnalytics courseId={selectedCourse._id} courseCode={selectedCourse.code} courseName={selectedCourse.name} />
            )}
          </div>
        ) : (
          <CourseManager 
            onCourseClick={(folderId, course) => {
              setSelectedCourseFolder(folderId);
              setSelectedCourse(course);
              setFolderStack([]);
              setActiveView('dashboard');
            }}
          />
        )}
      </div>
    </div>
  );
};

export default StudentDashboard;

