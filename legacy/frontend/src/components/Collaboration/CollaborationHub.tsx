/**
 * Collaboration Hub
 * Central component for managing collaboration sessions and real-time features
 */
import React, { useState, useEffect, useCallback } from 'react';
import { LegislativeDocument } from '../../types';
import { 
  CollaborationSession, 
  Participant, 
  Activity,
  collaborationService 
} from '../../services/collaborationService';
import { 
  Notification,
  notificationService 
} from '../../services/notificationService';

interface CollaborationHubProps {
  userId: string;
  username: string;
  email: string;
  onSessionSelect?: (session: CollaborationSession) => void;
  onCreateSession?: (session: CollaborationSession) => void;
}

export const CollaborationHub: React.FC<CollaborationHubProps> = ({
  userId,
  username,
  email,
  onSessionSelect,
  onCreateSession
}) => {
  // State management
  const [sessions, setSessions] = useState<CollaborationSession[]>([]);
  const [activeSessions, setActiveSessions] = useState<CollaborationSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<CollaborationSession | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [recentActivities, setRecentActivities] = useState<Activity[]>([]);

  // Create session form state
  const [newSession, setNewSession] = useState({
    name: '',
    description: '',
    maxParticipants: 10,
    allowGuestAccess: false,
    autoSave: true
  });

  // Filter and view state
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [filterStatus, setFilterStatus] = useState<'all' | 'active' | 'archived'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  /**
   * Load user's collaboration sessions
   */
  useEffect(() => {
    loadSessions();
    loadNotifications();
    loadRecentActivities();
  }, [userId]);

  /**
   * Set up real-time updates
   */
  useEffect(() => {
    // WebSocket connection for real-time updates would be established here
    // For now, we'll simulate with periodic updates
    const interval = setInterval(() => {
      loadActiveSessions();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  /**
   * Load collaboration sessions
   */
  const loadSessions = async (): Promise<void> => {
    setIsLoading(true);
    try {
      // In a real implementation, this would fetch from an API
      const userSessions: CollaborationSession[] = [];
      setSessions(userSessions);
      setActiveSessions(userSessions.filter(s => s.status === 'active'));
    } catch (error) {
      console.error('Failed to load sessions:', error);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Load active sessions with real-time participant info
   */
  const loadActiveSessions = async (): Promise<void> => {
    try {
      const active = sessions.filter(s => s.status === 'active');
      setActiveSessions(active);
    } catch (error) {
      console.error('Failed to load active sessions:', error);
    }
  };

  /**
   * Load recent notifications
   */
  const loadNotifications = async (): Promise<void> => {
    try {
      const userNotifications = notificationService.getUserNotifications(userId, {
        limit: 10,
        category: 'collaboration'
      });
      setNotifications(userNotifications);
    } catch (error) {
      console.error('Failed to load notifications:', error);
    }
  };

  /**
   * Load recent activities
   */
  const loadRecentActivities = async (): Promise<void> => {
    try {
      // Aggregate activities from all user sessions
      const allActivities = sessions.flatMap(session => 
        session.activities.map(activity => ({ ...activity, sessionName: session.name }))
      );
      
      const recent = allActivities
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
        .slice(0, 20);
      
      setRecentActivities(recent);
    } catch (error) {
      console.error('Failed to load activities:', error);
    }
  };

  /**
   * Create new collaboration session
   */
  const handleCreateSession = useCallback(async (): Promise<void> => {
    if (!newSession.name.trim()) return;

    setIsLoading(true);
    try {
      const session = await collaborationService.createSession(
        newSession.name,
        newSession.description,
        userId,
        {
          maxParticipants: newSession.maxParticipants,
          allowGuestAccess: newSession.allowGuestAccess,
          autoSave: newSession.autoSave
        }
      );

      setSessions(prev => [session, ...prev]);
      setActiveSessions(prev => [session, ...prev]);
      setShowCreateModal(false);
      setNewSession({
        name: '',
        description: '',
        maxParticipants: 10,
        allowGuestAccess: false,
        autoSave: true
      });

      if (onCreateSession) {
        onCreateSession(session);
      }
    } catch (error) {
      console.error('Failed to create session:', error);
    } finally {
      setIsLoading(false);
    }
  }, [newSession, userId, onCreateSession]);

  /**
   * Join existing session
   */
  const handleJoinSession = useCallback(async (session: CollaborationSession): Promise<void> => {
    try {
      const updatedSession = await collaborationService.joinSession(
        session.id,
        userId,
        username,
        email
      );

      setSelectedSession(updatedSession);
      if (onSessionSelect) {
        onSessionSelect(updatedSession);
      }
    } catch (error) {
      console.error('Failed to join session:', error);
    }
  }, [userId, username, email, onSessionSelect]);

  /**
   * Filter sessions based on current filters
   */
  const filteredSessions = sessions.filter(session => {
    // Status filter
    if (filterStatus !== 'all' && session.status !== filterStatus) {
      return false;
    }

    // Search filter
    if (searchQuery && !session.name.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !session.description.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }

    return true;
  });

  /**
   * Get session status color
   */
  const getSessionStatusColor = (status: CollaborationSession['status']): string => {
    switch (status) {
      case 'active': return '#10b981';
      case 'paused': return '#f59e0b';
      case 'archived': return '#6b7280';
      default: return '#6b7280';
    }
  };

  /**
   * Get participant count display
   */
  const getParticipantInfo = (participants: Participant[]): { online: number; total: number } => {
    return {
      online: participants.filter(p => p.isOnline).length,
      total: participants.length
    };
  };

  /**
   * Format time ago
   */
  const formatTimeAgo = (date: Date): string => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
  };

  return (
    <div className="collaboration-hub">
      {/* Header */}
      <div className="hub-header">
        <div className="header-content">
          <h1>Collaboration Hub</h1>
          <p>Manage your research collaboration sessions and real-time teamwork</p>
        </div>
        <div className="header-actions">
          <button
            onClick={() => setShowCreateModal(true)}
            className="create-session-btn"
            disabled={isLoading}
          >
            ➕ New Session
          </button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="quick-stats">
        <div className="stat-card">
          <div className="stat-value">{activeSessions.length}</div>
          <div className="stat-label">Active Sessions</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {activeSessions.reduce((sum, s) => sum + s.participants.filter(p => p.isOnline).length, 0)}
          </div>
          <div className="stat-label">Online Collaborators</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{notifications.filter(n => !n.read).length}</div>
          <div className="stat-label">Unread Notifications</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{sessions.reduce((sum, s) => sum + s.documents.length, 0)}</div>
          <div className="stat-label">Shared Documents</div>
        </div>
      </div>

      {/* Main Content */}
      <div className="hub-content">
        <div className="content-main">
          {/* Filters and Controls */}
          <div className="content-controls">
            <div className="search-bar">
              <input
                type="text"
                placeholder="Search sessions..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input"
              />
            </div>
            
            <div className="filter-controls">
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value as any)}
                className="filter-select"
              >
                <option value="all">All Sessions</option>
                <option value="active">Active</option>
                <option value="paused">Paused</option>
                <option value="archived">Archived</option>
              </select>

              <div className="view-toggle">
                <button
                  className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}
                  onClick={() => setViewMode('grid')}
                >
                  🔳 Grid
                </button>
                <button
                  className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}
                  onClick={() => setViewMode('list')}
                >
                  📋 List
                </button>
              </div>
            </div>
          </div>

          {/* Sessions Display */}
          {isLoading ? (
            <div className="loading-state">
              <div className="loading-spinner"></div>
              <p>Loading collaboration sessions...</p>
            </div>
          ) : filteredSessions.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">🤝</div>
              <h3>No collaboration sessions found</h3>
              <p>Create your first collaboration session to start working with your team.</p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="create-first-session-btn"
              >
                Create Your First Session
              </button>
            </div>
          ) : (
            <div className={`sessions-${viewMode}`}>
              {filteredSessions.map((session) => {
                const participantInfo = getParticipantInfo(session.participants);
                
                return (
                  <div key={session.id} className="session-card">
                    <div className="session-header">
                      <div className="session-info">
                        <h3 className="session-name">{session.name}</h3>
                        <p className="session-description">{session.description}</p>
                      </div>
                      <div className="session-status">
                        <span
                          className="status-indicator"
                          style={{ backgroundColor: getSessionStatusColor(session.status) }}
                        ></span>
                        <span className="status-text">{session.status}</span>
                      </div>
                    </div>

                    <div className="session-metrics">
                      <div className="metric">
                        <span className="metric-icon">👥</span>
                        <span className="metric-text">
                          {participantInfo.online}/{participantInfo.total} online
                        </span>
                      </div>
                      <div className="metric">
                        <span className="metric-icon">📄</span>
                        <span className="metric-text">{session.documents.length} documents</span>
                      </div>
                      <div className="metric">
                        <span className="metric-icon">💬</span>
                        <span className="metric-text">{session.annotations.length} annotations</span>
                      </div>
                      <div className="metric">
                        <span className="metric-icon">🕒</span>
                        <span className="metric-text">{formatTimeAgo(session.updatedAt)}</span>
                      </div>
                    </div>

                    <div className="session-participants">
                      <div className="participant-avatars">
                        {session.participants.slice(0, 5).map((participant) => (
                          <div
                            key={participant.userId}
                            className={`participant-avatar ${participant.isOnline ? 'online' : 'offline'}`}
                            title={`${participant.name} (${participant.role})`}
                          >
                            {participant.name.charAt(0).toUpperCase()}
                          </div>
                        ))}
                        {session.participants.length > 5 && (
                          <div className="participant-avatar more">
                            +{session.participants.length - 5}
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="session-actions">
                      <button
                        onClick={() => handleJoinSession(session)}
                        className="join-session-btn"
                        disabled={session.status !== 'active'}
                      >
                        {session.participants.some(p => p.userId === userId) ? '🔄 Rejoin' : '🚀 Join'}
                      </button>
                      <button className="session-menu-btn">⋯</button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="content-sidebar">
          {/* Recent Notifications */}
          <div className="sidebar-section">
            <h3>Recent Notifications</h3>
            <div className="notifications-list">
              {notifications.slice(0, 5).map((notification) => (
                <div key={notification.id} className={`notification-item ${notification.read ? 'read' : 'unread'}`}>
                  <div className="notification-content">
                    <div className="notification-title">{notification.title}</div>
                    <div className="notification-message">{notification.message}</div>
                    <div className="notification-time">{formatTimeAgo(notification.timestamp)}</div>
                  </div>
                  {!notification.read && <div className="unread-indicator"></div>}
                </div>
              ))}
              {notifications.length === 0 && (
                <div className="empty-notifications">
                  <p>No recent notifications</p>
                </div>
              )}
            </div>
          </div>

          {/* Recent Activities */}
          <div className="sidebar-section">
            <h3>Recent Activities</h3>
            <div className="activities-list">
              {recentActivities.slice(0, 10).map((activity) => (
                <div key={activity.id} className="activity-item">
                  <div className="activity-icon">
                    {activity.action === 'joined_session' && '🚪'}
                    {activity.action === 'added_document' && '📄'}
                    {activity.action === 'created_annotation' && '💬'}
                    {activity.action === 'started_discussion' && '🗣️'}
                  </div>
                  <div className="activity-content">
                    <div className="activity-text">
                      <strong>{activity.username}</strong> {activity.action.replace('_', ' ')} {activity.target.name}
                    </div>
                    <div className="activity-time">{formatTimeAgo(activity.timestamp)}</div>
                  </div>
                </div>
              ))}
              {recentActivities.length === 0 && (
                <div className="empty-activities">
                  <p>No recent activities</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Create Session Modal */}
      {showCreateModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2>Create New Collaboration Session</h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="modal-close-btn"
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div className="form-group">
                <label htmlFor="session-name">Session Name *</label>
                <input
                  id="session-name"
                  type="text"
                  value={newSession.name}
                  onChange={(e) => setNewSession(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Enter session name..."
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="session-description">Description</label>
                <textarea
                  id="session-description"
                  value={newSession.description}
                  onChange={(e) => setNewSession(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Describe the purpose of this collaboration session..."
                  rows={3}
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="max-participants">Max Participants</label>
                  <input
                    id="max-participants"
                    type="number"
                    min="2"
                    max="100"
                    value={newSession.maxParticipants}
                    onChange={(e) => setNewSession(prev => ({ ...prev, maxParticipants: parseInt(e.target.value) }))}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={newSession.allowGuestAccess}
                    onChange={(e) => setNewSession(prev => ({ ...prev, allowGuestAccess: e.target.checked }))}
                  />
                  Allow guest access (users without accounts can participate)
                </label>
              </div>

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={newSession.autoSave}
                    onChange={(e) => setNewSession(prev => ({ ...prev, autoSave: e.target.checked }))}
                  />
                  Enable auto-save for annotations and discussions
                </label>
              </div>
            </div>

            <div className="modal-footer">
              <button
                onClick={() => setShowCreateModal(false)}
                className="cancel-btn"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateSession}
                className="create-btn"
                disabled={!newSession.name.trim() || isLoading}
              >
                {isLoading ? 'Creating...' : 'Create Session'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};