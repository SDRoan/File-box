import React, { useState, useEffect } from 'react';
import { analyticsAPI } from '../services/api';
import { CloseIcon, LineChartIcon, StorageIcon, UnusedIcon } from './Icons';
import './AnalyticsDashboard.css';

interface AnalyticsDashboardProps {
  onClose: () => void;
}

const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({ onClose }) => {
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('30d');
  const [activeTab, setActiveTab] = useState<'overview' | 'storage' | 'unused'>('overview');
  
  const [accessStats, setAccessStats] = useState<any[]>([]);
  const [heatmap, setHeatmap] = useState<any>({});
  const [storageBreakdown, setStorageBreakdown] = useState<any[]>([]);
  const [unusedFiles, setUnusedFiles] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [topTypes, setTopTypes] = useState<any[]>([]);
  const [suggestions, setSuggestions] = useState<any[]>([]);

  useEffect(() => {
    loadData();
  }, [timeRange, activeTab]);

  const loadData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'overview') {
        const [stats, heatmapData, timelineData, topTypesData] = await Promise.all([
          analyticsAPI.getAccessStats(timeRange),
          analyticsAPI.getHeatmap(timeRange),
          analyticsAPI.getActivityTimeline(timeRange === '30d' ? '7d' : timeRange),
          analyticsAPI.getTopFileTypes(timeRange)
        ]);
        setAccessStats(stats);
        setHeatmap(heatmapData);
        setTimeline(timelineData);
        setTopTypes(topTypesData);
      } else if (activeTab === 'storage') {
        const [breakdown, sugg] = await Promise.all([
          analyticsAPI.getStorageBreakdown(),
          analyticsAPI.getSuggestions()
        ]);
        setStorageBreakdown(breakdown);
        setSuggestions(sugg);
      } else if (activeTab === 'unused') {
        const unused = await analyticsAPI.getUnusedFiles(90);
        setUnusedFiles(unused);
      }
    } catch (error) {
      console.error('Error loading analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString();
  };

  const getTotalStorage = () => {
    return storageBreakdown.reduce((sum, item) => sum + item.totalSize, 0);
  };

  // Chart rendering functions
  const renderLineChart = (data: any[]) => {
    if (data.length === 0) return null;
    const maxValue = Math.max(...data.map(d => d.count), 1);
    const chartHeight = 200;
    const chartWidth = 100;
    const points = data.map((d, idx) => {
      const x = (idx / (data.length - 1 || 1)) * chartWidth;
      const y = chartHeight - (d.count / maxValue) * chartHeight;
      return `${x},${y}`;
    }).join(' ');

    return (
      <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} className="line-chart-svg">
        <polyline
          fill="none"
          stroke="#6b7280"
          strokeWidth="2"
          points={points}
        />
        {data.map((d, idx) => {
          const x = (idx / (data.length - 1 || 1)) * chartWidth;
          const y = chartHeight - (d.count / maxValue) * chartHeight;
          return (
            <circle
              key={idx}
              cx={x}
              cy={y}
              r="3"
              fill="#6b7280"
            />
          );
        })}
      </svg>
    );
  };

  const renderBarChart = (data: any[], maxItems = 10) => {
    if (data.length === 0) return null;
    const maxValue = Math.max(...data.slice(0, maxItems).map(d => d.accessCount || d.count || 0), 1);
    const chartData = data.slice(0, maxItems);

    return (
      <div className="bar-chart">
        {chartData.map((item, idx) => {
          const height = ((item.accessCount || item.count || 0) / maxValue) * 100;
          return (
            <div key={idx} className="bar-chart-item">
              <div className="bar-chart-bar-container">
                <div
                  className="bar-chart-bar"
                  style={{ height: `${height}%` }}
                  title={`${item.accessCount || item.count || 0} accesses`}
                ></div>
              </div>
              <div className="bar-chart-label">
                {item._id ? item._id.substring(0, 10) : 'Unknown'}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  const renderPieChart = (data: any[]) => {
    if (data.length === 0) return null;
    const total = getTotalStorage();
    if (total === 0) return null;

    let currentAngle = 0;
    const colors = ['#6b7280', '#4b5563', '#f093fb', '#4facfe', '#43e97b', '#fa709a', '#fee140', '#30cfd0'];
    
    return (
      <svg viewBox="0 0 200 200" className="pie-chart-svg">
        {data.map((item, idx) => {
          const percentage = (item.totalSize / total) * 100;
          const angle = (percentage / 100) * 360;
          const startAngle = currentAngle;
          const endAngle = currentAngle + angle;
          
          const startAngleRad = (startAngle - 90) * (Math.PI / 180);
          const endAngleRad = (endAngle - 90) * (Math.PI / 180);
          
          const x1 = 100 + 80 * Math.cos(startAngleRad);
          const y1 = 100 + 80 * Math.sin(startAngleRad);
          const x2 = 100 + 80 * Math.cos(endAngleRad);
          const y2 = 100 + 80 * Math.sin(endAngleRad);
          
          const largeArcFlag = angle > 180 ? 1 : 0;
          
          const pathData = [
            `M 100 100`,
            `L ${x1} ${y1}`,
            `A 80 80 0 ${largeArcFlag} 1 ${x2} ${y2}`,
            `Z`
          ].join(' ');

          currentAngle += angle;

          return (
            <path
              key={idx}
              d={pathData}
              fill={colors[idx % colors.length]}
              stroke="#1e1e1e"
              strokeWidth="2"
            />
          );
        })}
        <circle cx="100" cy="100" r="50" fill="#1e1e1e" />
        <text x="100" y="95" textAnchor="middle" fill="#fff" fontSize="14" fontWeight="600">
          {formatBytes(total)}
        </text>
        <text x="100" y="110" textAnchor="middle" fill="#999" fontSize="10">
          Total
        </text>
      </svg>
    );
  };

  const renderHeatmap = (heatmapData: any) => {
    if (!heatmapData || Object.keys(heatmapData).length === 0) {
      return (
        <div className="heatmap-empty-state">
          <p>No access data available for the selected time range.</p>
          <p className="heatmap-hint">Start using files to see your access patterns here!</p>
        </div>
      );
    }
    
    // MongoDB $dayOfWeek returns: 1=Sunday, 2=Monday, ..., 7=Saturday
    const days = [
      { num: 1, name: 'Sun' },
      { num: 2, name: 'Mon' },
      { num: 3, name: 'Tue' },
      { num: 4, name: 'Wed' },
      { num: 5, name: 'Thu' },
      { num: 6, name: 'Fri' },
      { num: 7, name: 'Sat' }
    ];
    const hours = Array.from({ length: 24 }, (_, i) => i);
    
    const values = Object.values(heatmapData).map((v: any) => typeof v === 'number' ? v : 0);
    const maxValue = Math.max(...values, 1);

    return (
      <div className="heatmap-container">
        <div className="heatmap-grid">
          <div className="heatmap-y-axis">
            {hours.map(h => (
              <div key={h} className="heatmap-y-label">{h.toString().padStart(2, '0')}:00</div>
            ))}
          </div>
          <div className="heatmap-main">
            {days.map(day => (
              <div key={day.num} className="heatmap-column">
                <div className="heatmap-x-label">{day.name}</div>
                {hours.map(hour => {
                  // Backend returns keys like "1-14" (dayOfWeek-hour)
                  const key = `${day.num}-${hour}`;
                  const value = heatmapData[key] || 0;
                  const intensity = value > 0 ? Math.max(0.2, (value / maxValue)) : 0;
                  return (
                    <div
                      key={key}
                      className="heatmap-cell"
                      style={{
                        backgroundColor: value > 0 
                          ? `rgba(102, 126, 234, ${intensity})` 
                          : '#1e1e1e',
                        borderColor: value > 0 ? '#6b7280' : '#333'
                      }}
                      title={`${day.name} ${hour.toString().padStart(2, '0')}:00 - ${value} access${value !== 1 ? 'es' : ''}`}
                    />
                  );
                })}
              </div>
            ))}
          </div>
        </div>
        <div className="heatmap-legend">
          <span>Less</span>
          <div className="heatmap-legend-gradient"></div>
          <span>More</span>
        </div>
        <div className="heatmap-info">
          <p>Hover over cells to see exact access counts</p>
        </div>
      </div>
    );
  };

  return (
    <div className="analytics-overlay" onClick={onClose}>
      <div className="analytics-container" onClick={(e) => e.stopPropagation()}>
        <div className="analytics-header">
          <h2> File Usage Analytics</h2>
          <div className="header-controls">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="time-range-select"
            >
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
              <option value="1y">Last year</option>
            </select>
            <button onClick={onClose} className="close-btn">
              <CloseIcon size={18} color="currentColor" />
            </button>
          </div>
        </div>

        <div className="analytics-tabs">
          <button
            className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
             Overview
          </button>
          <button
            className={`tab ${activeTab === 'storage' ? 'active' : ''}`}
            onClick={() => setActiveTab('storage')}
          >
            <StorageIcon size={18} color="currentColor" />
            <span>Storage</span>
          </button>
          <button
            className={`tab ${activeTab === 'unused' ? 'active' : ''}`}
            onClick={() => setActiveTab('unused')}
          >
            <UnusedIcon size={18} color="currentColor" />
            <span>Unused Files</span>
          </button>
        </div>

        <div className="analytics-content">
          {loading ? (
            <div className="loading-state">
              <div className="spinner"></div>
              <p>Loading analytics...</p>
            </div>
          ) : (
            <>
              {activeTab === 'overview' && (
                <div className="overview-tab">
                  <div className="stats-grid">
                    <div className="stat-card">
                      <h3>Most Accessed Files</h3>
                      <div className="file-list">
                        {accessStats.slice(0, 10).map((file, idx) => (
                          <div key={file.fileId} className="file-stat">
                            <span className="rank">#{idx + 1}</span>
                            <span className="file-name">{file.fileName}</span>
                            <span className="access-count">{file.accessCount} accesses</span>
                          </div>
                        ))}
                        {accessStats.length === 0 && (
                          <p className="empty-message">No file access data available</p>
                        )}
                      </div>
                    </div>

                    <div className="stat-card">
                      <h3>Top File Types</h3>
                      {topTypes.length > 0 ? (
                        <>
                          <div className="chart-container">
                            {renderBarChart(topTypes, 8)}
                          </div>
                          <div className="type-list">
                            {topTypes.slice(0, 5).map((type, idx) => (
                              <div key={type._id} className="type-stat">
                                <span className="type-name">{type._id || 'Unknown'}</span>
                                <span className="type-count">{type.accessCount} accesses</span>
                              </div>
                            ))}
                          </div>
                        </>
                      ) : (
                        <p className="empty-message">No type data available</p>
                      )}
                    </div>
                  </div>

                  <div className="stat-card full-width">
                    <h3>Activity Timeline</h3>
                    {timeline.length > 0 ? (
                      <>
                        <div className="line-chart-container">
                          {renderLineChart(timeline)}
                        </div>
                        <div className="timeline-chart">
                          {timeline.map((day) => (
                            <div key={day._id} className="timeline-day">
                              <div className="timeline-date">{formatDate(day._id)}</div>
                              <div className="timeline-bar">
                                <div
                                  className="timeline-fill"
                                  style={{ width: `${(day.count / Math.max(...timeline.map(d => d.count), 1)) * 100}%` }}
                                ></div>
                              </div>
                              <div className="timeline-count">{day.count} actions</div>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : (
                      <p className="empty-message">No activity data available</p>
                    )}
                  </div>

                  {Object.keys(heatmap).length > 0 && (
                    <div className="stat-card full-width">
                      <h3>Access Heatmap</h3>
                      <p className="chart-subtitle">File access patterns by day and hour</p>
                      {renderHeatmap(heatmap)}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'storage' && (
                <div className="storage-tab">
                  <div className="stat-card">
                    <h3>Storage Breakdown</h3>
                    {storageBreakdown.length > 0 ? (
                      <>
                        <div className="pie-chart-container">
                          {renderPieChart(storageBreakdown)}
                        </div>
                        <div className="storage-list">
                          {storageBreakdown.map((item) => {
                            const percentage = (item.totalSize / getTotalStorage()) * 100;
                            return (
                              <div key={item._id} className="storage-item">
                                <div className="storage-header">
                                  <span className="storage-type">{item._id}</span>
                                  <span className="storage-size">{formatBytes(item.totalSize)}</span>
                                </div>
                                <div className="storage-bar">
                                  <div
                                    className="storage-fill"
                                    style={{ width: `${percentage}%` }}
                                  ></div>
                                </div>
                                <div className="storage-meta">
                                  {item.fileCount} files • {percentage.toFixed(1)}% of total
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </>
                    ) : (
                      <p className="empty-message">No storage data available</p>
                    )}
                  </div>

                  {suggestions.length > 0 && (
                    <div className="stat-card">
                      <h3> Storage Optimization Suggestions</h3>
                      {suggestions.map((suggestion, idx) => (
                        <div key={idx} className="suggestion-item">
                          <h4>{suggestion.title}</h4>
                          <p>{suggestion.description}</p>
                          {suggestion.potentialSavings && (
                            <p className="savings">
                              Potential savings: <strong>{formatBytes(suggestion.potentialSavings)}</strong>
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'unused' && (
                <div className="unused-tab">
                  <div className="stat-card">
                    <h3>Unused Files (90+ days)</h3>
                    <p className="subtitle">
                      Files that haven't been accessed in the last 90 days
                    </p>
                    <div className="unused-list">
                      {unusedFiles.slice(0, 50).map((file) => (
                        <div key={file.fileId} className="unused-file">
                          <div className="unused-file-info">
                            <span className="unused-file-name">{file.fileName}</span>
                            <span className="unused-file-meta">
                              {formatBytes(file.fileSize)} • {file.daysUnused} days unused
                            </span>
                          </div>
                        </div>
                      ))}
                      {unusedFiles.length === 0 && (
                        <p className="empty-message">No unused files found! </p>
                      )}
                      {unusedFiles.length > 50 && (
                        <p className="more-files">
                          ... and {unusedFiles.length - 50} more files
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default AnalyticsDashboard;


