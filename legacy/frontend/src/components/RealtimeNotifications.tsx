import React, { useState, useEffect } from 'react';
import { useRealtime } from '../hooks/useRealtime';
import { LegislativeDocument, CollectionLog } from '../types';
import '../styles/components/RealtimeNotifications.css';

interface Notification {
  id: string;
  type: 'new' | 'updated' | 'deleted' | 'system' | 'collection';
  title: string;
  message: string;
  timestamp: Date;
  data?: any;
}

export const RealtimeNotifications: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showPanel, setShowPanel] = useState(false);
  const [hasNewNotifications, setHasNewNotifications] = useState(false);
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);

  const { 
    isConnected, 
    connectionType, 
    recentUpdates,
    requestNotifications 
  } = useRealtime({
    onNewDocument: (document: LegislativeDocument) => {
      addNotification({
        type: 'new',
        title: 'New Legislation',
        message: `${document.type}: ${document.title}`,
        data: document
      });
    },
    onDocumentUpdated: (document: LegislativeDocument) => {
      addNotification({
        type: 'updated',
        title: 'Legislation Updated',
        message: `${document.type}: ${document.title}`,
        data: document
      });
    },
    onDocumentDeleted: (documentId: string) => {
      addNotification({
        type: 'deleted',
        title: 'Legislation Removed',
        message: `Document ID: ${documentId}`,
        data: { id: documentId }
      });
    },
    onSystemMessage: (message: any) => {
      addNotification({
        type: 'system',
        title: 'System Message',
        message: message.message || message.text || 'System notification',
        data: message
      });
    },
    onCollectionUpdate: (collection: CollectionLog) => {
      if (collection.status === 'completed') {
        addNotification({
          type: 'collection',
          title: 'Collection Completed',
          message: `"${collection.searchTerm}": ${collection.recordsCollected} documents (${collection.recordsNew} new)`,
          data: collection
        });
      } else if (collection.status === 'failed') {
        addNotification({
          type: 'system',
          title: 'Collection Failed',
          message: `"${collection.searchTerm}": ${collection.errorMessage || 'Unknown error'}`,
          data: collection
        });
      }
    },
    onNewDocuments: (data: { count: number }) => {
      if (data.count > 0) {
        addNotification({
          type: 'new',
          title: 'New Documents Available',
          message: `${data.count} new documents collected in the last hour`,
          data: data
        });
      }
    }
  });

  // Check notification permission on mount
  useEffect(() => {
    if ('Notification' in window) {
      setNotificationsEnabled(Notification.permission === 'granted');
    }
  }, []);

  const addNotification = (notification: Omit<Notification, 'id' | 'timestamp'>) => {
    const newNotification: Notification = {
      ...notification,
      id: `notif-${Date.now()}-${Math.random()}`,
      timestamp: new Date()
    };

    setNotifications(prev => [newNotification, ...prev].slice(0, 100)); // Keep last 100
    setHasNewNotifications(true);

    // Auto-hide notification after 5 seconds
    setTimeout(() => {
      removeNotification(newNotification.id);
    }, 5000);
  };

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const clearAllNotifications = () => {
    setNotifications([]);
    setHasNewNotifications(false);
  };

  const handleEnableNotifications = async () => {
    const granted = await requestNotifications();
    setNotificationsEnabled(granted);
    if (granted) {
      addNotification({
        type: 'system',
        title: 'Notifications Enabled',
        message: 'You will now receive browser notifications for new legislation'
      });
    }
  };

  const togglePanel = () => {
    setShowPanel(!showPanel);
    if (!showPanel) {
      setHasNewNotifications(false);
    }
  };

  // Connection status indicator
  const getConnectionStatusColor = () => {
    if (!isConnected) return '#dc3545'; // red
    switch (connectionType) {
      case 'websocket': return '#28a745'; // green
      case 'sse': return '#17a2b8'; // blue
      case 'polling': return '#ffc107'; // yellow
      default: return '#6c757d'; // gray
    }
  };

  const getConnectionStatusText = () => {
    if (!isConnected) return 'Disconnected';
    switch (connectionType) {
      case 'websocket': return 'Live (WebSocket)';
      case 'sse': return 'Live (SSE)';
      case 'polling': return 'Connected (Polling)';
      default: return 'Unknown';
    }
  };

  return (
    <>
      {/* Floating notification button */}
      <button
        className={`notification-button ${hasNewNotifications ? 'has-new' : ''}`}
        onClick={togglePanel}
        aria-label="Toggle notifications panel"
        aria-expanded={showPanel}
      >
        <span className="notification-icon">🔔</span>
        {hasNewNotifications && <span className="notification-badge" />}
        <span className="notification-count">{notifications.length}</span>
      </button>

      {/* Notification panel */}
      {showPanel && (
        <div className="notification-panel" role="region" aria-label="Notifications">
          <div className="notification-header">
            <h3>Real-time Updates</h3>
            <button 
              className="close-button" 
              onClick={togglePanel}
              aria-label="Close notifications"
            >
              ×
            </button>
          </div>

          <div className="connection-status">
            <span 
              className="status-indicator" 
              style={{ backgroundColor: getConnectionStatusColor() }}
              aria-label={`Connection status: ${getConnectionStatusText()}`}
            />
            <span className="status-text">{getConnectionStatusText()}</span>
          </div>

          {!notificationsEnabled && (
            <div className="notification-permission">
              <p>Enable browser notifications to stay updated</p>
              <button onClick={handleEnableNotifications}>
                Enable Notifications
              </button>
            </div>
          )}

          <div className="notification-actions">
            <button 
              onClick={clearAllNotifications}
              disabled={notifications.length === 0}
            >
              Clear All
            </button>
          </div>

          <div className="notification-list">
            {notifications.length === 0 ? (
              <div className="no-notifications">
                <p>No new updates</p>
                <p className="subtitle">New legislation will appear here</p>
              </div>
            ) : (
              notifications.map(notification => (
                <div 
                  key={notification.id} 
                  className={`notification-item ${notification.type}`}
                >
                  <div className="notification-content">
                    <h4>{notification.title}</h4>
                    <p>{notification.message}</p>
                    <time dateTime={notification.timestamp.toISOString()}>
                      {formatRelativeTime(notification.timestamp)}
                    </time>
                  </div>
                  <button
                    className="notification-close"
                    onClick={() => removeNotification(notification.id)}
                    aria-label="Dismiss notification"
                  >
                    ×
                  </button>
                </div>
              ))
            )}
          </div>

          {recentUpdates.length > 0 && (
            <div className="update-stats">
              <p>Total updates this session: {recentUpdates.length}</p>
            </div>
          )}
        </div>
      )}

      {/* Toast notifications for new updates */}
      <div className="toast-container" aria-live="polite" aria-atomic="true">
        {notifications.slice(0, 3).map(notification => (
          <div 
            key={notification.id} 
            className={`toast-notification ${notification.type}`}
            role="alert"
          >
            <span className="toast-icon">
              {notification.type === 'new' && '📄'}
              {notification.type === 'updated' && '✏️'}
              {notification.type === 'deleted' && '🗑️'}
              {notification.type === 'collection' && '📊'}
              {notification.type === 'system' && 'ℹ️'}
            </span>
            <div className="toast-content">
              <strong>{notification.title}</strong>
              <p>{notification.message}</p>
            </div>
            <button
              className="toast-close"
              onClick={() => removeNotification(notification.id)}
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </>
  );
};

// Helper function to format relative time
function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  
  return date.toLocaleDateString();
}