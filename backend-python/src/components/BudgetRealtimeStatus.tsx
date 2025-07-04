import React, { useState, useEffect } from 'react';
import { useBudgetRealtime } from '../hooks/useBudgetRealtime';
import { LegislativeDocument } from '../types';
import '../styles/components/BudgetRealtimeStatus.css';

interface RecentUpdate {
  id: string;
  document: LegislativeDocument;
  timestamp: Date;
}

export const BudgetRealtimeStatus: React.FC = () => {
  const [recentUpdates, setRecentUpdates] = useState<RecentUpdate[]>([]);
  const [showUpdates, setShowUpdates] = useState(false);
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [hasNewUpdates, setHasNewUpdates] = useState(false);

  const {
    isPolling,
    lastCheck,
    nextCheck,
    seenDocuments,
    start,
    stop,
    requestNotifications,
    clearHistory
  } = useBudgetRealtime({
    onNewDocument: (document) => {
      const update: RecentUpdate = {
        id: `update-${Date.now()}-${document.id}`,
        document,
        timestamp: new Date()
      };
      
      setRecentUpdates(prev => [update, ...prev].slice(0, 20)); // Keep last 20
      setHasNewUpdates(true);
      
      // Auto-dismiss after 10 seconds
      setTimeout(() => {
        setRecentUpdates(prev => prev.filter(u => u.id !== update.id));
      }, 10000);
    }
  });

  // Check notification permission on mount
  useEffect(() => {
    if ('Notification' in window) {
      setNotificationsEnabled(Notification.permission === 'granted');
    }
  }, []);

  const handleEnableNotifications = async () => {
    const granted = await requestNotifications();
    setNotificationsEnabled(granted);
  };

  const toggleUpdates = () => {
    setShowUpdates(!showUpdates);
    if (!showUpdates) {
      setHasNewUpdates(false);
    }
  };

  const formatTimeUntil = (date: Date): string => {
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    
    if (diff <= 0) return 'Checking...';
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  const formatRelativeTime = (date: Date): string => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
  };

  // Update countdown
  useEffect(() => {
    if (!isPolling) return;
    
    const timer = setInterval(() => {
      // Force re-render to update countdown
      setShowUpdates(prev => prev);
    }, 1000);
    
    return () => clearInterval(timer);
  }, [isPolling]);

  return (
    <div className="budget-realtime-container">
      {/* Status indicator */}
      <div className="realtime-status-bar">
        <div className="status-info">
          <span className={`status-dot ${isPolling ? 'active' : 'inactive'}`} />
          <span className="status-text">
            {isPolling ? 'Monitoring Active' : 'Monitoring Paused'}
          </span>
          {isPolling && (
            <span className="next-check">
              Next check: {formatTimeUntil(nextCheck)}
            </span>
          )}
        </div>
        
        <div className="status-actions">
          {hasNewUpdates && (
            <span className="update-badge">{recentUpdates.length}</span>
          )}
          <button
            className="status-button"
            onClick={toggleUpdates}
            aria-label="Toggle updates panel"
          >
            📊
          </button>
          <button
            className="status-button"
            onClick={isPolling ? stop : start}
            aria-label={isPolling ? 'Pause monitoring' : 'Start monitoring'}
          >
            {isPolling ? '⏸️' : '▶️'}
          </button>
        </div>
      </div>

      {/* Updates panel */}
      {showUpdates && (
        <div className="realtime-updates-panel">
          <div className="panel-header">
            <h3>Legislative Updates</h3>
            <button className="close-button" onClick={toggleUpdates}>×</button>
          </div>

          <div className="panel-stats">
            <div className="stat">
              <span className="stat-label">Last Check:</span>
              <span className="stat-value">{formatRelativeTime(lastCheck)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Documents Tracked:</span>
              <span className="stat-value">{seenDocuments}</span>
            </div>
          </div>

          {!notificationsEnabled && (
            <div className="notification-prompt">
              <p>Enable notifications to get alerts for new legislation</p>
              <button onClick={handleEnableNotifications}>
                Enable Notifications
              </button>
            </div>
          )}

          <div className="updates-list">
            {recentUpdates.length === 0 ? (
              <div className="no-updates">
                <p>No recent updates</p>
                <p className="subtitle">New legislation will appear here</p>
              </div>
            ) : (
              recentUpdates.map(update => (
                <div key={update.id} className="update-item">
                  <div className="update-icon">📄</div>
                  <div className="update-content">
                    <h4>{update.document.title}</h4>
                    <p className="update-type">{update.document.type}</p>
                    <time>{formatRelativeTime(update.timestamp)}</time>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="panel-footer">
            <button 
              className="clear-button"
              onClick={() => {
                clearHistory();
                setRecentUpdates([]);
              }}
            >
              Clear History
            </button>
          </div>
        </div>
      )}

      {/* Minimalist toast for new updates */}
      {recentUpdates.length > 0 && !showUpdates && (
        <div className="update-toast" onClick={toggleUpdates}>
          <span className="toast-icon">📄</span>
          <span className="toast-text">
            {recentUpdates[0].document.title.substring(0, 50)}...
          </span>
        </div>
      )}
    </div>
  );
};