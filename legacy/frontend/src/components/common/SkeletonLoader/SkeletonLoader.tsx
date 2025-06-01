import React from 'react';
import './SkeletonLoader.css';

interface SkeletonLoaderProps {
  variant?: 'text' | 'title' | 'paragraph' | 'card' | 'image' | 'button';
  lines?: number;
  width?: string;
  height?: string;
  className?: string;
}

const SkeletonLoader: React.FC<SkeletonLoaderProps> = ({
  variant = 'text',
  lines = 1,
  width,
  height,
  className = ''
}) => {
  const renderSkeleton = () => {
    switch (variant) {
      case 'title':
        return <div className="skeleton skeleton-title" style={{ width: width || '60%' }} />;
      
      case 'paragraph':
        return (
          <div className="skeleton-paragraph">
            {Array.from({ length: lines }, (_, i) => (
              <div
                key={i}
                className="skeleton skeleton-text"
                style={{ width: i === lines - 1 ? '80%' : '100%' }}
              />
            ))}
          </div>
        );
      
      case 'card':
        return (
          <div className="skeleton skeleton-card" style={{ width, height }}>
            <div className="skeleton skeleton-card-header" />
            <div className="skeleton skeleton-card-content">
              <div className="skeleton skeleton-text" style={{ width: '80%' }} />
              <div className="skeleton skeleton-text" style={{ width: '60%' }} />
              <div className="skeleton skeleton-text" style={{ width: '70%' }} />
            </div>
          </div>
        );
      
      case 'image':
        return (
          <div 
            className="skeleton skeleton-image" 
            style={{ width: width || '100%', height: height || '200px' }}
          />
        );
      
      case 'button':
        return (
          <div 
            className="skeleton skeleton-button" 
            style={{ width: width || '120px', height: height || '40px' }}
          />
        );
      
      default:
        return (
          <div 
            className="skeleton skeleton-text" 
            style={{ width: width || '100%' }}
          />
        );
    }
  };

  return (
    <div className={`skeleton-loader ${className}`}>
      {renderSkeleton()}
    </div>
  );
};

export const SkeletonDocumentList: React.FC<{ count?: number }> = ({ count = 5 }) => {
  return (
    <div className="skeleton-document-list">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="skeleton-document-item glass-light">
          <div className="skeleton-document-header">
            <SkeletonLoader variant="text" width="60%" />
            <SkeletonLoader variant="text" width="20%" />
          </div>
          <SkeletonLoader variant="paragraph" lines={2} />
          <div className="skeleton-document-footer">
            <SkeletonLoader variant="text" width="30%" />
            <SkeletonLoader variant="text" width="25%" />
          </div>
        </div>
      ))}
    </div>
  );
};

export const SkeletonMapLoading: React.FC = () => {
  return (
    <div className="skeleton-map-container">
      <SkeletonLoader variant="image" width="100%" height="100%" />
      <div className="skeleton-map-overlay">
        <div className="skeleton-map-controls">
          <SkeletonLoader variant="button" width="40px" height="40px" />
          <SkeletonLoader variant="button" width="40px" height="40px" />
        </div>
      </div>
    </div>
  );
};

export const SkeletonChart: React.FC = () => {
  return (
    <div className="skeleton-chart">
      <SkeletonLoader variant="title" width="40%" />
      <div className="skeleton-chart-content">
        <div className="skeleton-chart-bars">
          {Array.from({ length: 5 }, (_, i) => (
            <div key={i} className="skeleton-chart-bar" style={{ height: `${Math.random() * 60 + 40}%` }} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default SkeletonLoader;