import React, { useState, useEffect } from 'react';
import { learningAPI } from '../services/api';
import { LearningIcon, LoadingIcon, EyeIcon, CloseIcon } from './Icons';
import './Learning.css';

interface LearningResource {
  _id: string;
  title: string;
  description: string;
  type: 'tutorial' | 'guide' | 'video' | 'article' | 'documentation' | 'faq';
  category: string;
  content: string;
  videoUrl?: string;
  externalUrl?: string;
  thumbnail?: string;
  tags: string[];
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  duration: number;
  views: number;
  rating: number;
  ratingCount: number;
  createdBy?: {
    _id: string;
    name: string;
    email: string;
  };
  createdAt: string;
}

const Learning: React.FC = () => {
  const [resources, setResources] = useState<LearningResource[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedResource, setSelectedResource] = useState<LearningResource | null>(null);
  const [userRating, setUserRating] = useState<number>(0);
  const [ratingSubmitting, setRatingSubmitting] = useState(false);

  useEffect(() => {
    loadResources();
  }, []);

  const loadResources = async () => {
    try {
      setLoading(true);
      const data = await learningAPI.getResources({});
      setResources(data);
    } catch (error) {
      console.error('Error loading resources:', error);
      alert('Failed to load resources');
    } finally {
      setLoading(false);
    }
  };

  const handleViewResource = async (resourceId: string) => {
    try {
      const resource = await learningAPI.getResource(resourceId);
      setSelectedResource(resource);
      setUserRating(0);
      loadResources(); // Refresh list to update views
    } catch (error) {
      console.error('Error loading resource:', error);
      alert('Failed to load resource');
    }
  };

  const handleRate = async (rating: number) => {
    if (!selectedResource || ratingSubmitting) return;

    try {
      setRatingSubmitting(true);
      await learningAPI.rateResource(selectedResource._id, rating);
      const updatedResource = await learningAPI.getResource(selectedResource._id);
      setSelectedResource(updatedResource);
      setUserRating(rating);
      loadResources(); // Refresh list to update ratings
    } catch (error: any) {
      console.error('Error rating resource:', error);
      alert(error.response?.data?.message || 'Failed to submit rating');
    } finally {
      setRatingSubmitting(false);
    }
  };

  const categories = [
    { value: 'all', label: 'All Categories' },
    { value: 'getting-started', label: 'Getting Started' },
    { value: 'file-management', label: 'File Management' },
    { value: 'sharing', label: 'Sharing' },
    { value: 'collaboration', label: 'Collaboration' },
    { value: 'security', label: 'Security' },
    { value: 'advanced', label: 'Advanced' },
    { value: 'api', label: 'API' },
  ];

  const types = [
    { value: 'all', label: 'All Types' },
    { value: 'tutorial', label: 'Tutorials' },
    { value: 'guide', label: 'Guides' },
    { value: 'video', label: 'Videos' },
    { value: 'article', label: 'Articles' },
    { value: 'documentation', label: 'Documentation' },
    { value: 'faq', label: 'FAQ' },
  ];


  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'video':
        return 'Video';
      case 'tutorial':
        return 'Collections';
      case 'guide':
        return 'Book';
      case 'article':
        return '';
      case 'documentation':
        return '';
      case 'faq':
        return 'FAQ';
      default:
        return '';
    }
  };


  const formatDuration = (minutes: number) => {
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  };

  const renderStars = (rating: number, interactive: boolean = false, onRate?: (rating: number) => void) => {
    return (
      <div className="star-rating">
        {[1, 2, 3, 4, 5].map((star) => (
          <span
            key={star}
            className={`star ${star <= rating ? 'filled' : ''} ${interactive ? 'interactive' : ''}`}
            onClick={() => interactive && onRate && onRate(star)}
            style={{ cursor: interactive ? 'pointer' : 'default' }}
          >
            ★
          </span>
        ))}
        {rating > 0 && <span className="rating-value">({rating.toFixed(1)})</span>}
      </div>
    );
  };

  if (selectedResource) {
    return (
      <div className="learning">
        <div className="resource-detail-header">
          <button className="back-button" onClick={() => setSelectedResource(null)}>
            ← Back to Resources
          </button>
        </div>

        <div className="resource-detail">
          <div className="resource-detail-header-info">
            <div className="resource-detail-title-section">
              <h1>{selectedResource.title}</h1>
              <div className="resource-badges">
                <span className={`badge type type-${selectedResource.type}`}>
                  {getTypeIcon(selectedResource.type)} {types.find(t => t.value === selectedResource.type)?.label || selectedResource.type}
                </span>
                {selectedResource.duration > 0 && (
                  <span className="badge duration">{formatDuration(selectedResource.duration)}</span>
                )}
              </div>
            </div>
          </div>

          <div className="resource-meta">
            <span>{categories.find(c => c.value === selectedResource.category)?.label || selectedResource.category}</span>
            {selectedResource.createdBy && (
              <>
                <span>•</span>
                <span>By {selectedResource.createdBy.name}</span>
              </>
            )}
            <span>•</span>
            <span>{formatDate(selectedResource.createdAt)}</span>
            <span>•</span>
            <span><EyeIcon size={14} color="#666" /> {selectedResource.views} views</span>
          </div>

          {selectedResource.tags.length > 0 && (
            <div className="resource-tags">
              {selectedResource.tags.map((tag, idx) => (
                <span key={idx} className="tag">#{tag}</span>
              ))}
            </div>
          )}

          <div className="resource-rating-section">
            <div className="resource-rating-display">
              {renderStars(Math.round(selectedResource.rating))}
              <span className="rating-count">{selectedResource.ratingCount} {selectedResource.ratingCount === 1 ? 'rating' : 'ratings'}</span>
            </div>
            <div className="resource-rating-input">
              <span>Rate this resource:</span>
              {renderStars(userRating || 0, true, handleRate)}
            </div>
          </div>

          <div className="resource-description">
            <h3>Description</h3>
            <p>{selectedResource.description}</p>
          </div>

          {selectedResource.videoUrl && (
            <div className="resource-video">
              <h3>Video</h3>
              <div className="video-container">
                <iframe
                  src={selectedResource.videoUrl}
                  title={selectedResource.title}
                  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                  allowFullScreen
                />
              </div>
            </div>
          )}

          {selectedResource.externalUrl && (
            <div className="resource-external">
              <div className="external-link-container">
                <p className="external-note">This article is from an external source. Click below to read the full article.</p>
                <a href={selectedResource.externalUrl} target="_blank" rel="noopener noreferrer" className="external-link">
                  Read Full Article →
                </a>
              </div>
            </div>
          )}

          {selectedResource.content && (
            <div className="resource-content">
              <h3>Content</h3>
              <div className="content-body" dangerouslySetInnerHTML={{ __html: selectedResource.content }} />
            </div>
          )}

          {selectedResource.externalUrl && (
            <div className="resource-external-preview">
              <h3>Article Preview</h3>
              <p>{selectedResource.description}</p>
            </div>
          )}
          
          {!selectedResource.videoUrl && !selectedResource.externalUrl && !selectedResource.content && (
            <div className="resource-placeholder">
              <p>Content coming soon...</p>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="learning">
      <div className="learning-header">
        <h2><LearningIcon size={24} color="currentColor" /> Learning Resources</h2>
      </div>

      {loading ? (
        <div className="loading-state">
          <LoadingIcon size={40} color="#1e40af" />
          <p>Loading resources...</p>
        </div>
      ) : resources.length === 0 ? (
        <div className="empty-state">
          <LearningIcon size={64} color="#ccc" />
          <h3>No resources found</h3>
          <p>Check back later for new articles</p>
        </div>
      ) : (
        <div className="resources-grid">
          {resources.map((resource) => (
            <div
              key={resource._id}
              className="resource-card"
              onClick={() => handleViewResource(resource._id)}
            >
              <div className="resource-card-header">
                <div className="resource-card-icon">{getTypeIcon(resource.type)}</div>
              </div>
              <h3 className="resource-card-title">{resource.title}</h3>
              <p className="resource-card-description">{resource.description}</p>
              {resource.tags.length > 0 && (
                <div className="resource-card-tags">
                  {resource.tags.slice(0, 3).map((tag, idx) => (
                    <span key={idx} className="tag small">#{tag}</span>
                  ))}
                </div>
              )}
              <div className="resource-card-footer">
                <div className="resource-card-rating">
                  {renderStars(Math.round(resource.rating))}
                </div>
                <div className="resource-card-meta">
                  {resource.duration > 0 && <span>{formatDuration(resource.duration)}</span>}
                  <span>•</span>
                  <span><EyeIcon size={12} color="#666" /> {resource.views}</span>
                  {resource.externalUrl && <span>•</span>}
                  {resource.externalUrl && <span className="external-badge">External</span>}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Learning;
