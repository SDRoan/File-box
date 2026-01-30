import React, { useState } from 'react';
import { TagIcon } from './Icons';
import './StudyTools.css';

interface StudyToolsProps {
  courseId: string;
  courseCode: string;
  courseName: string;
}

const StudyTools: React.FC<StudyToolsProps> = ({ courseId, courseCode, courseName }) => {
  const [activeTool, setActiveTool] = useState<'quiz' | 'guide' | null>(null);
  const [quizData, setQuizData] = useState({
    topic: '',
    numQuestions: 5,
    difficulty: 'medium',
    questions: [] as any[]
  });
  const [guideData, setGuideData] = useState({
    topic: '',
    sections: [] as string[]
  });

  const generateQuiz = () => {
    // Simple quiz generator - in a real app, this would use AI or predefined questions
    const questions = [];
    for (let i = 1; i <= quizData.numQuestions; i++) {
      questions.push({
        id: i,
        question: `Sample question ${i} about ${quizData.topic || 'the topic'}`,
        options: ['Option A', 'Option B', 'Option C', 'Option D'],
        correctAnswer: 0,
        explanation: 'This is a sample explanation.'
      });
    }
    setQuizData({ ...quizData, questions });
  };

  const generateStudyGuide = () => {
    // Simple study guide generator
    const sections = [
      `Key Concepts for ${guideData.topic || 'this topic'}`,
      `Important Definitions`,
      `Key Formulas/Theorems`,
      `Common Mistakes to Avoid`,
      `Practice Problems`
    ];
    setGuideData({ ...guideData, sections });
  };

  return (
    <div className="study-tools">
      <div className="tools-header">
        <div>
          <h2>Study Tools - {courseCode}</h2>
          <p>Generate quizzes and study guides to help you prepare</p>
        </div>
      </div>

      <div className="tools-grid">
        <div className="tool-card" onClick={() => setActiveTool('quiz')}>
          <div className="tool-icon">📝</div>
          <h3>Quiz Generator</h3>
          <p>Generate practice quizzes based on course topics</p>
        </div>

        <div className="tool-card" onClick={() => setActiveTool('guide')}>
          <div className="tool-icon">📚</div>
          <h3>Study Guide Generator</h3>
          <p>Create comprehensive study guides for exams</p>
        </div>
      </div>

      {activeTool === 'quiz' && (
        <div className="tool-panel">
          <div className="panel-header">
            <h3>Quiz Generator</h3>
            <button className="close-btn" onClick={() => setActiveTool(null)}>×</button>
          </div>
          <div className="panel-content">
            <div className="form-group">
              <label>Topic</label>
              <input
                type="text"
                value={quizData.topic}
                onChange={(e) => setQuizData({ ...quizData, topic: e.target.value })}
                placeholder="e.g., Chapter 5, Midterm Review"
              />
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Number of Questions</label>
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={quizData.numQuestions}
                  onChange={(e) => setQuizData({ ...quizData, numQuestions: parseInt(e.target.value) || 5 })}
                />
              </div>
              <div className="form-group">
                <label>Difficulty</label>
                <select
                  value={quizData.difficulty}
                  onChange={(e) => setQuizData({ ...quizData, difficulty: e.target.value })}
                >
                  <option value="easy">Easy</option>
                  <option value="medium">Medium</option>
                  <option value="hard">Hard</option>
                </select>
              </div>
            </div>
            <button className="btn-primary" onClick={generateQuiz}>
              Generate Quiz
            </button>

            {quizData.questions.length > 0 && (
              <div className="quiz-results">
                <h4>Generated Quiz</h4>
                {quizData.questions.map((q, idx) => (
                  <div key={q.id} className="quiz-question">
                    <div className="question-number">Question {idx + 1}</div>
                    <div className="question-text">{q.question}</div>
                    <div className="question-options">
                      {q.options.map((opt: string, optIdx: number) => (
                        <label key={optIdx} className="option-label">
                          <input type="radio" name={`question-${q.id}`} value={optIdx} />
                          {opt}
                        </label>
                      ))}
                    </div>
                    <details className="question-explanation">
                      <summary>Show Answer</summary>
                      <p>Correct Answer: {q.options[q.correctAnswer]}</p>
                      <p>{q.explanation}</p>
                    </details>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTool === 'guide' && (
        <div className="tool-panel">
          <div className="panel-header">
            <h3>Study Guide Generator</h3>
            <button className="close-btn" onClick={() => setActiveTool(null)}>×</button>
          </div>
          <div className="panel-content">
            <div className="form-group">
              <label>Topic</label>
              <input
                type="text"
                value={guideData.topic}
                onChange={(e) => setGuideData({ ...guideData, topic: e.target.value })}
                placeholder="e.g., Midterm Exam, Final Review"
              />
            </div>
            <button className="btn-primary" onClick={generateStudyGuide}>
              Generate Study Guide
            </button>

            {guideData.sections.length > 0 && (
              <div className="guide-results">
                <h4>Study Guide: {guideData.topic}</h4>
                {guideData.sections.map((section, idx) => (
                  <div key={idx} className="guide-section">
                    <h5>{section}</h5>
                    <p className="section-placeholder">
                      This section would contain detailed content about {section.toLowerCase()}.
                      In a full implementation, this would be generated using AI or course materials.
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default StudyTools;
