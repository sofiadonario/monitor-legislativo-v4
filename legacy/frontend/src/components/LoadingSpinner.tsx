import React from 'react';
import '../styles/components/LoadingSpinner.css';

interface LoadingSpinnerProps {
  message?: string;
  size?: 'small' | 'medium' | 'large';
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  message = 'Loading legislation data...', 
  size = 'medium' 
}) => {
  return (
    <div className={`loading-spinner ${size}`} role="status" aria-live="polite">
      <div className="spinner-animation" aria-hidden="true"></div>
      <span className="loading-message">{message}</span>
    </div>
  );
};