import React, { useState, useEffect } from 'react';
import { progressTrackingAPI } from '../services/api';
import { PlusIcon, TrashIcon } from './Icons';
import './ProgressTracking.css';

interface ProgressTrackingProps {
  courseId: string;
  courseCode: string;
  courseName: string;
}

interface ProgressEntry {
  _id: string;
  assignmentName: string;
  pointsEarned: number;
  pointsPossible: number;
  percentage: number;
  category: string;
  dateCompleted: string;
  notes: string;
}

interface Statistics {
  totalPointsEarned: number;
  totalPointsPossible: number;
  overallPercentage: number;
  byCategory: Record<string, any>;
  totalEntries: number;
}

interface GradeEntry {
  id: string;
  assignmentName: string;
  grade: string;
  weight: string;
}

const ProgressTracking: React.FC<ProgressTrackingProps> = ({ courseId, courseCode, courseName }) => {
  const [entries, setEntries] = useState<ProgressEntry[]>([]);
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingEntry, setEditingEntry] = useState<ProgressEntry | null>(null);
  const [formData, setFormData] = useState({
    assignmentName: '',
    pointsEarned: '',
    pointsPossible: '',
    category: 'homework',
    dateCompleted: new Date().toISOString().split('T')[0],
    notes: ''
  });
  const [showGradeCalculator, setShowGradeCalculator] = useState(false);
  const [gradeEntries, setGradeEntries] = useState<GradeEntry[]>([
    { id: '1', assignmentName: '', grade: '', weight: '' }
  ]);
  const [finalGradeGoal, setFinalGradeGoal] = useState('');
  const [remainingWeight, setRemainingWeight] = useState('');

  useEffect(() => {
    loadProgress();
  }, [courseId]);

  const loadProgress = async () => {
    try {
      setLoading(true);
      const data = await progressTrackingAPI.getProgress(courseId);
      setEntries(data.entries || []);
      setStatistics(data.statistics || null);
    } catch (error) {
      console.error('Error loading progress:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateEntry = () => {
    setEditingEntry(null);
    setFormData({
      assignmentName: '',
      pointsEarned: '',
      pointsPossible: '',
      category: 'homework',
      dateCompleted: new Date().toISOString().split('T')[0],
      notes: ''
    });
    setShowModal(true);
  };

  const handleEditEntry = (entry: ProgressEntry) => {
    setEditingEntry(entry);
    setFormData({
      assignmentName: entry.assignmentName,
      pointsEarned: entry.pointsEarned.toString(),
      pointsPossible: entry.pointsPossible.toString(),
      category: entry.category,
      dateCompleted: new Date(entry.dateCompleted).toISOString().split('T')[0],
      notes: entry.notes
    });
    setShowModal(true);
  };

  const handleSaveEntry = async () => {
    try {
      const pointsEarned = parseFloat(formData.pointsEarned) || 0;
      const pointsPossible = parseFloat(formData.pointsPossible);

      if (!formData.assignmentName.trim() || !pointsPossible) {
        alert('Assignment name and points possible are required');
        return;
      }

      if (editingEntry) {
        await progressTrackingAPI.updateEntry(editingEntry._id, {
          assignmentName: formData.assignmentName,
          pointsEarned,
          pointsPossible,
          category: formData.category,
          dateCompleted: formData.dateCompleted,
          notes: formData.notes
        });
      } else {
        await progressTrackingAPI.createEntry({
          course: courseId,
          assignmentName: formData.assignmentName,
          pointsEarned,
          pointsPossible,
          category: formData.category,
          dateCompleted: formData.dateCompleted,
          notes: formData.notes
        });
      }

      setShowModal(false);
      loadProgress();
    } catch (error: any) {
      console.error('Error saving entry:', error);
      alert(error.response?.data?.message || 'Failed to save entry');
    }
  };

  const handleDeleteEntry = async (entryId: string) => {
    if (!window.confirm('Are you sure you want to delete this entry?')) {
      return;
    }

    try {
      await progressTrackingAPI.deleteEntry(entryId);
      loadProgress();
    } catch (error: any) {
      console.error('Error deleting entry:', error);
      alert(error.response?.data?.message || 'Failed to delete entry');
    }
  };

  const getGradeColor = (percentage: number) => {
    if (percentage >= 90) return '#10b981';
    if (percentage >= 80) return '#3b82f6';
    if (percentage >= 70) return '#f59e0b';
    return '#ef4444';
  };

  if (loading) {
    return <div className="progress-tracking-loading">Loading progress...</div>;
  }

  const letterToPercentage = (letter: string): number => {
    const grades: Record<string, number> = {
      'A+': 97.5, 'A': 94.5, 'A-': 91.5,
      'B+': 87.5, 'B': 84.5, 'B-': 81.5,
      'C+': 77.5, 'C': 74.5, 'C-': 71.5,
      'D+': 67.5, 'D': 64.5, 'D-': 61.5,
      'F': 30
    };
    return grades[letter.toUpperCase()] || parseFloat(letter) || 0;
  };

  const percentageToLetter = (percentage: number): string => {
    if (percentage >= 97) return 'A+';
    if (percentage >= 93) return 'A';
    if (percentage >= 90) return 'A-';
    if (percentage >= 87) return 'B+';
    if (percentage >= 83) return 'B';
    if (percentage >= 80) return 'B-';
    if (percentage >= 77) return 'C+';
    if (percentage >= 73) return 'C';
    if (percentage >= 70) return 'C-';
    if (percentage >= 67) return 'D+';
    if (percentage >= 63) return 'D';
    if (percentage >= 60) return 'D-';
    return 'F';
  };

  const calculateCurrentGrade = (): { percentage: number; letter: string } => {
    let totalWeightedPoints = 0;
    let totalWeight = 0;

    gradeEntries.forEach(entry => {
      if (entry.grade && entry.weight) {
        const gradeValue = letterToPercentage(entry.grade);
        const weight = parseFloat(entry.weight) || 0;
        totalWeightedPoints += (gradeValue * weight) / 100;
        totalWeight += weight;
      }
    });

    const percentage = totalWeight > 0 ? (totalWeightedPoints / totalWeight) * 100 : 0;
    return {
      percentage: Math.round(percentage * 100) / 100,
      letter: percentageToLetter(percentage)
    };
  };

  const calculateNeededGrade = (): { percentage: number; letter: string } | null => {
    if (!finalGradeGoal || !remainingWeight) return null;

    const currentGrade = calculateCurrentGrade();
    const goalPercentage = letterToPercentage(finalGradeGoal);
    const remainingWeightNum = parseFloat(remainingWeight) || 0;
    const currentWeight = 100 - remainingWeightNum;

    if (currentWeight <= 0 || remainingWeightNum <= 0) return null;

    const currentContribution = (currentGrade.percentage * currentWeight) / 100;
    const neededTotal = goalPercentage;
    const neededFromRemaining = (neededTotal - currentContribution) / (remainingWeightNum / 100);

    return {
      percentage: Math.round(neededFromRemaining * 100) / 100,
      letter: percentageToLetter(neededFromRemaining)
    };
  };

  const handleAddGradeEntry = () => {
    setGradeEntries([...gradeEntries, { id: Date.now().toString(), assignmentName: '', grade: '', weight: '' }]);
  };

  const handleRemoveGradeEntry = (id: string) => {
    if (gradeEntries.length > 1) {
      setGradeEntries(gradeEntries.filter(e => e.id !== id));
    }
  };

  const handleUpdateGradeEntry = (id: string, field: keyof GradeEntry, value: string) => {
    setGradeEntries(gradeEntries.map(e => 
      e.id === id ? { ...e, [field]: value } : e
    ));
  };

  const currentGrade = calculateCurrentGrade();
  const neededGrade = calculateNeededGrade();

  return (
    <div className="progress-tracking">
      <div className="progress-header">
        <div>
          <h2>Progress Tracking - {courseCode}</h2>
          <p>Track your grades and academic progress</p>
        </div>
        <div className="header-actions">
          <button className="btn-secondary" onClick={() => setShowGradeCalculator(!showGradeCalculator)}>
            📊 Grade Calculator
          </button>
          <button className="btn-primary" onClick={handleCreateEntry}>
            <PlusIcon size={18} color="currentColor" />
            <span>Add Entry</span>
          </button>
        </div>
      </div>

      {showGradeCalculator && (
        <div className="grade-calculator-section">
          <div className="calculator-header">
            <h3>Grade Calculator</h3>
            <p>Calculate your current grade and what you need on remaining assignments</p>
          </div>
          
          <div className="calculator-content">
            <div className="grade-entries">
              <div className="entries-header">
                <span className="col-assignment">Assignment/Exam</span>
                <span className="col-grade">Grade</span>
                <span className="col-weight">Weight (%)</span>
                <span className="col-actions"></span>
              </div>
              {gradeEntries.map((entry, index) => (
                <div key={entry.id} className="grade-entry-row">
                  <input
                    type="text"
                    className="col-assignment"
                    placeholder={`Assignment ${index + 1}`}
                    value={entry.assignmentName}
                    onChange={(e) => handleUpdateGradeEntry(entry.id, 'assignmentName', e.target.value)}
                  />
                  <input
                    type="text"
                    className="col-grade"
                    placeholder="A+ or 95"
                    value={entry.grade}
                    onChange={(e) => handleUpdateGradeEntry(entry.id, 'grade', e.target.value)}
                  />
                  <input
                    type="number"
                    className="col-weight"
                    placeholder="25"
                    value={entry.weight}
                    onChange={(e) => handleUpdateGradeEntry(entry.id, 'weight', e.target.value)}
                  />
                  <div className="col-actions">
                    {gradeEntries.length > 1 && (
                      <button
                        className="remove-entry-btn"
                        onClick={() => handleRemoveGradeEntry(entry.id)}
                        title="Remove"
                      >
                        ×
                      </button>
                    )}
                  </div>
                </div>
              ))}
              <button className="add-entry-btn" onClick={handleAddGradeEntry}>
                + Add More Rows
              </button>
            </div>

            <div className="calculator-results">
              <div className="result-card">
                <div className="result-label">Current Grade</div>
                <div className="result-value" style={{ color: getGradeColor(currentGrade.percentage) }}>
                  {currentGrade.percentage.toFixed(2)}%
                </div>
                <div className="result-letter">{currentGrade.letter}</div>
              </div>

              <div className="final-grade-planning">
                <h4>Final Grade Planning</h4>
                <div className="planning-inputs">
                  <div className="form-group">
                    <label>Grade Goal</label>
                    <input
                      type="text"
                      placeholder="A or 90"
                      value={finalGradeGoal}
                      onChange={(e) => setFinalGradeGoal(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label>Weight of Remaining Tasks (%)</label>
                    <input
                      type="number"
                      placeholder="30"
                      value={remainingWeight}
                      onChange={(e) => setRemainingWeight(e.target.value)}
                    />
                  </div>
                </div>
                {neededGrade && (
                  <div className="needed-grade-result">
                    <div className="result-label">Grade Needed</div>
                    <div className="result-value" style={{ color: getGradeColor(neededGrade.percentage) }}>
                      {neededGrade.percentage.toFixed(2)}%
                    </div>
                    <div className="result-letter">{neededGrade.letter}</div>
                    {neededGrade.percentage > 100 && (
                      <div className="warning-message">
                        ⚠️ This grade is not achievable with current scores
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {statistics && (
        <div className="progress-overview">
          <div className="overview-card">
            <div className="overview-value" style={{ color: getGradeColor(statistics.overallPercentage) }}>
              {statistics.overallPercentage.toFixed(1)}%
            </div>
            <div className="overview-label">Overall Grade</div>
          </div>
          <div className="overview-card">
            <div className="overview-value">{statistics.totalPointsEarned}</div>
            <div className="overview-label">Points Earned</div>
          </div>
          <div className="overview-card">
            <div className="overview-value">{statistics.totalPointsPossible}</div>
            <div className="overview-label">Total Points</div>
          </div>
          <div className="overview-card">
            <div className="overview-value">{statistics.totalEntries}</div>
            <div className="overview-label">Assignments</div>
          </div>
        </div>
      )}

      {statistics && Object.keys(statistics.byCategory).length > 0 && (
        <div className="category-breakdown">
          <h3>By Category</h3>
          <div className="category-stats">
            {Object.entries(statistics.byCategory).map(([category, stats]: [string, any]) => (
              <div key={category} className="category-stat">
                <div className="category-name">{category}</div>
                <div className="category-percentage" style={{ color: getGradeColor(stats.percentage || 0) }}>
                  {stats.percentage?.toFixed(1) || 0}%
                </div>
                <div className="category-details">
                  {stats.earned} / {stats.possible} points ({stats.count} assignments)
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="entries-section">
        <h3>All Entries</h3>
        <div className="entries-list">
          {entries.length > 0 ? (
            entries.map(entry => (
              <div key={entry._id} className="entry-card">
                <div className="entry-main">
                  <div className="entry-header">
                    <h4>{entry.assignmentName}</h4>
                    <span className={`category-badge category-${entry.category}`}>
                      {entry.category}
                    </span>
                  </div>
                  <div className="entry-scores">
                    <div className="score-display">
                      <span className="score-value" style={{ color: getGradeColor(entry.percentage) }}>
                        {entry.percentage.toFixed(1)}%
                      </span>
                      <span className="score-details">
                        {entry.pointsEarned} / {entry.pointsPossible} points
                      </span>
                    </div>
                    <div className="entry-date">
                      {new Date(entry.dateCompleted).toLocaleDateString()}
                    </div>
                  </div>
                  {entry.notes && (
                    <div className="entry-notes">{entry.notes}</div>
                  )}
                </div>
                <div className="entry-actions">
                  <button
                    className="icon-btn"
                    onClick={() => handleEditEntry(entry)}
                    title="Edit"
                  >
                    ✏️
                  </button>
                  <button
                    className="icon-btn delete-btn"
                    onClick={() => handleDeleteEntry(entry._id)}
                    title="Delete"
                  >
                    <TrashIcon size={16} color="currentColor" />
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="empty-state">
              <p>No entries yet. Add your first grade entry!</p>
            </div>
          )}
        </div>
      </div>

      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingEntry ? 'Edit Entry' : 'Add Progress Entry'}</h3>
              <button className="modal-close" onClick={() => setShowModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Assignment Name *</label>
                <input
                  type="text"
                  value={formData.assignmentName}
                  onChange={(e) => setFormData({ ...formData, assignmentName: e.target.value })}
                  placeholder="e.g., Midterm Exam, Homework 5"
                />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Points Earned</label>
                  <input
                    type="number"
                    step="0.01"
                    value={formData.pointsEarned}
                    onChange={(e) => setFormData({ ...formData, pointsEarned: e.target.value })}
                    placeholder="0"
                  />
                </div>
                <div className="form-group">
                  <label>Points Possible *</label>
                  <input
                    type="number"
                    step="0.01"
                    value={formData.pointsPossible}
                    onChange={(e) => setFormData({ ...formData, pointsPossible: e.target.value })}
                    placeholder="100"
                  />
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Category</label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  >
                    <option value="homework">Homework</option>
                    <option value="quiz">Quiz</option>
                    <option value="exam">Exam</option>
                    <option value="project">Project</option>
                    <option value="participation">Participation</option>
                    <option value="lab">Lab</option>
                    <option value="other">Other</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Date Completed</label>
                  <input
                    type="date"
                    value={formData.dateCompleted}
                    onChange={(e) => setFormData({ ...formData, dateCompleted: e.target.value })}
                  />
                </div>
              </div>
              <div className="form-group">
                <label>Notes</label>
                <textarea
                  value={formData.notes}
                  onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                  placeholder="Additional notes..."
                  rows={3}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowModal(false)}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={handleSaveEntry}
                disabled={!formData.assignmentName.trim() || !formData.pointsPossible}
              >
                {editingEntry ? 'Update' : 'Add'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProgressTracking;
