/**
 * Notification Service
 * Real-time notification system for collaboration and system events
 */
import { LegislativeDocument } from '../types';

export interface Notification {
  id: string;
  userId: string;
  type: NotificationType;
  title: string;
  message: string;
  timestamp: Date;
  read: boolean;
  priority: 'low' | 'medium' | 'high' | 'urgent';
  category: NotificationCategory;
  data: NotificationData;
  actions: NotificationAction[];
  expiresAt?: Date;
  channels: NotificationChannel[];
}

export type NotificationType = 
  | 'collaboration_invitation' | 'annotation_mention' | 'discussion_reply'
  | 'document_added' | 'document_updated' | 'document_shared'
  | 'analysis_complete' | 'comparison_ready' | 'export_ready'
  | 'system_update' | 'maintenance_alert' | 'quota_warning'
  | 'research_insight' | 'trending_document' | 'deadline_reminder';

export type NotificationCategory = 
  | 'collaboration' | 'document' | 'analysis' | 'system' | 'research';

export type NotificationChannel = 
  | 'in_app' | 'email' | 'push' | 'sms' | 'slack' | 'teams';

export interface NotificationData {
  sessionId?: string;
  documentId?: string;
  annotationId?: string;
  discussionId?: string;
  userId?: string;
  url?: string;
  metadata?: Record<string, any>;
}

export interface NotificationAction {
  id: string;
  label: string;
  action: 'navigate' | 'api_call' | 'dismiss' | 'mark_read';
  url?: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  data?: any;
  style: 'primary' | 'secondary' | 'danger' | 'success';
}

export interface NotificationPreferences {
  userId: string;
  channels: {
    in_app: boolean;
    email: boolean;
    push: boolean;
    sms: boolean;
    slack: boolean;
    teams: boolean;
  };
  categories: {
    collaboration: NotificationSetting;
    document: NotificationSetting;
    analysis: NotificationSetting;
    system: NotificationSetting;
    research: NotificationSetting;
  };
  quietHours: {
    enabled: boolean;
    start: string; // HH:mm format
    end: string;
    timezone: string;
  };
  frequency: {
    immediate: boolean;
    digest: 'none' | 'hourly' | 'daily' | 'weekly';
    digestTime: string; // HH:mm format
  };
  filters: {
    minimumPriority: 'low' | 'medium' | 'high' | 'urgent';
    keywords: string[];
    senders: string[];
  };
}

export interface NotificationSetting {
  enabled: boolean;
  channels: NotificationChannel[];
  priority: 'low' | 'medium' | 'high' | 'urgent';
  immediate: boolean;
}

export interface NotificationTemplate {
  type: NotificationType;
  category: NotificationCategory;
  title: string;
  messageTemplate: string;
  defaultPriority: 'low' | 'medium' | 'high' | 'urgent';
  defaultChannels: NotificationChannel[];
  variables: string[];
  actions: Omit<NotificationAction, 'id'>[];
}

export interface NotificationStats {
  userId: string;
  period: { start: Date; end: Date };
  total: number;
  byCategory: Record<NotificationCategory, number>;
  byType: Record<NotificationType, number>;
  byChannel: Record<NotificationChannel, number>;
  readRate: number;
  actionRate: number;
  averageReadTime: number; // minutes
}

export interface NotificationDigest {
  userId: string;
  type: 'hourly' | 'daily' | 'weekly';
  period: { start: Date; end: Date };
  notifications: Notification[];
  summary: {
    total: number;
    highPriority: number;
    unread: number;
    categories: Record<NotificationCategory, number>;
  };
  highlights: NotificationHighlight[];
}

export interface NotificationHighlight {
  type: 'trending' | 'important' | 'collaborative' | 'deadline';
  title: string;
  description: string;
  notifications: string[]; // notification IDs
  priority: number;
}

export interface PushSubscription {
  userId: string;
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
  userAgent: string;
  createdAt: Date;
  lastUsed: Date;
}

class NotificationService {
  private notifications: Map<string, Notification> = new Map();
  private preferences: Map<string, NotificationPreferences> = new Map();
  private templates: Map<NotificationType, NotificationTemplate> = new Map();
  private pushSubscriptions: Map<string, PushSubscription[]> = new Map();
  private webhooks: Map<string, string> = new Map();

  constructor() {
    this.initializeTemplates();
  }

  /**
   * Send notification
   */
  async sendNotification(
    userId: string,
    type: NotificationType,
    data: NotificationData,
    customization: {
      title?: string;
      message?: string;
      priority?: 'low' | 'medium' | 'high' | 'urgent';
      channels?: NotificationChannel[];
      actions?: NotificationAction[];
      expiresAt?: Date;
    } = {}
  ): Promise<Notification> {
    const template = this.templates.get(type);
    if (!template) {
      throw new Error(`No template found for notification type: ${type}`);
    }

    const preferences = this.preferences.get(userId) || this.getDefaultPreferences(userId);
    
    // Check if user wants this type of notification
    if (!this.shouldSendNotification(preferences, template.category, customization.priority || template.defaultPriority)) {
      console.log(`Notification filtered out for user ${userId}: ${type}`);
      return null;
    }

    // Generate notification
    const notification: Notification = {
      id: this.generateId(),
      userId,
      type,
      title: customization.title || this.processTemplate(template.title, data),
      message: customization.message || this.processTemplate(template.messageTemplate, data),
      timestamp: new Date(),
      read: false,
      priority: customization.priority || template.defaultPriority,
      category: template.category,
      data,
      actions: customization.actions || template.actions.map(action => ({
        ...action,
        id: this.generateId()
      })),
      expiresAt: customization.expiresAt,
      channels: customization.channels || this.getEnabledChannels(preferences, template.category)
    };

    // Store notification
    this.notifications.set(notification.id, notification);

    // Send through enabled channels
    await this.deliverNotification(notification, preferences);

    return notification;
  }

  /**
   * Send collaboration invitation
   */
  async sendCollaborationInvitation(
    userId: string,
    sessionId: string,
    sessionName: string,
    invitedBy: string,
    invitedByName: string
  ): Promise<void> {
    await this.sendNotification(userId, 'collaboration_invitation', {
      sessionId,
      userId: invitedBy,
      metadata: {
        sessionName,
        invitedByName
      }
    }, {
      title: `Invitation to collaborate: ${sessionName}`,
      message: `${invitedByName} has invited you to collaborate on "${sessionName}". Join the session to start working together.`,
      priority: 'high',
      actions: [
        {
          id: 'accept',
          label: 'Accept Invitation',
          action: 'navigate',
          url: `/collaboration/${sessionId}`,
          style: 'primary'
        },
        {
          id: 'decline',
          label: 'Decline',
          action: 'api_call',
          method: 'POST',
          url: `/api/collaboration/${sessionId}/decline`,
          style: 'secondary'
        }
      ]
    });
  }

  /**
   * Send annotation mention notification
   */
  async sendAnnotationMention(
    userId: string,
    annotationId: string,
    documentId: string,
    documentTitle: string,
    mentionedBy: string,
    mentionedByName: string,
    annotationText: string
  ): Promise<void> {
    await this.sendNotification(userId, 'annotation_mention', {
      annotationId,
      documentId,
      userId: mentionedBy,
      metadata: {
        documentTitle,
        mentionedByName,
        annotationText: annotationText.substring(0, 100)
      }
    }, {
      title: `You were mentioned in an annotation`,
      message: `${mentionedByName} mentioned you in an annotation on "${documentTitle}": "${annotationText.substring(0, 100)}..."`,
      priority: 'medium'
    });
  }

  /**
   * Send analysis completion notification
   */
  async sendAnalysisComplete(
    userId: string,
    documentId: string,
    documentTitle: string,
    analysisType: string
  ): Promise<void> {
    await this.sendNotification(userId, 'analysis_complete', {
      documentId,
      metadata: {
        documentTitle,
        analysisType
      }
    }, {
      title: `${analysisType} analysis complete`,
      message: `Your ${analysisType.toLowerCase()} analysis for "${documentTitle}" is ready to view.`,
      priority: 'medium'
    });
  }

  /**
   * Send trending document notification
   */
  async sendTrendingDocument(
    userId: string,
    documentId: string,
    documentTitle: string,
    reason: string
  ): Promise<void> {
    await this.sendNotification(userId, 'trending_document', {
      documentId,
      metadata: {
        documentTitle,
        reason
      }
    }, {
      title: `Trending document: ${documentTitle}`,
      message: `"${documentTitle}" is trending ${reason}. This might be relevant to your research.`,
      priority: 'low'
    });
  }

  /**
   * Get user notifications
   */
  getUserNotifications(
    userId: string,
    options: {
      limit?: number;
      offset?: number;
      unreadOnly?: boolean;
      category?: NotificationCategory;
      priority?: 'low' | 'medium' | 'high' | 'urgent';
      since?: Date;
    } = {}
  ): Notification[] {
    let notifications = Array.from(this.notifications.values())
      .filter(n => n.userId === userId);

    // Apply filters
    if (options.unreadOnly) {
      notifications = notifications.filter(n => !n.read);
    }

    if (options.category) {
      notifications = notifications.filter(n => n.category === options.category);
    }

    if (options.priority) {
      const priorityOrder = { low: 0, medium: 1, high: 2, urgent: 3 };
      const minPriority = priorityOrder[options.priority];
      notifications = notifications.filter(n => priorityOrder[n.priority] >= minPriority);
    }

    if (options.since) {
      notifications = notifications.filter(n => n.timestamp >= options.since);
    }

    // Sort by timestamp (newest first)
    notifications.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply pagination
    const start = options.offset || 0;
    const end = start + (options.limit || 50);
    
    return notifications.slice(start, end);
  }

  /**
   * Mark notification as read
   */
  async markAsRead(notificationId: string): Promise<void> {
    const notification = this.notifications.get(notificationId);
    if (notification) {
      notification.read = true;
    }
  }

  /**
   * Mark all notifications as read for user
   */
  async markAllAsRead(userId: string, category?: NotificationCategory): Promise<void> {
    Array.from(this.notifications.values())
      .filter(n => n.userId === userId && (!category || n.category === category))
      .forEach(n => n.read = true);
  }

  /**
   * Update notification preferences
   */
  async updatePreferences(userId: string, preferences: Partial<NotificationPreferences>): Promise<void> {
    const currentPreferences = this.preferences.get(userId) || this.getDefaultPreferences(userId);
    this.preferences.set(userId, { ...currentPreferences, ...preferences });
  }

  /**
   * Get notification preferences
   */
  getPreferences(userId: string): NotificationPreferences {
    return this.preferences.get(userId) || this.getDefaultPreferences(userId);
  }

  /**
   * Subscribe to push notifications
   */
  async subscribeToPush(userId: string, subscription: Omit<PushSubscription, 'userId' | 'createdAt' | 'lastUsed'>): Promise<void> {
    const pushSubscription: PushSubscription = {
      ...subscription,
      userId,
      createdAt: new Date(),
      lastUsed: new Date()
    };

    const userSubscriptions = this.pushSubscriptions.get(userId) || [];
    userSubscriptions.push(pushSubscription);
    this.pushSubscriptions.set(userId, userSubscriptions);
  }

  /**
   * Generate notification digest
   */
  async generateDigest(
    userId: string,
    type: 'hourly' | 'daily' | 'weekly'
  ): Promise<NotificationDigest> {
    const now = new Date();
    let start: Date;

    switch (type) {
      case 'hourly':
        start = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case 'daily':
        start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'weekly':
        start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
    }

    const notifications = this.getUserNotifications(userId, { since: start });
    
    const summary = {
      total: notifications.length,
      highPriority: notifications.filter(n => ['high', 'urgent'].includes(n.priority)).length,
      unread: notifications.filter(n => !n.read).length,
      categories: notifications.reduce((acc, n) => {
        acc[n.category] = (acc[n.category] || 0) + 1;
        return acc;
      }, {} as Record<NotificationCategory, number>)
    };

    const highlights = this.generateHighlights(notifications);

    return {
      userId,
      type,
      period: { start, end: now },
      notifications,
      summary,
      highlights
    };
  }

  /**
   * Get notification statistics
   */
  getNotificationStats(userId: string, period: { start: Date; end: Date }): NotificationStats {
    const notifications = this.getUserNotifications(userId, { since: period.start })
      .filter(n => n.timestamp <= period.end);

    const total = notifications.length;
    const readNotifications = notifications.filter(n => n.read);
    const actedNotifications = notifications.filter(n => 
      n.actions.some(action => 
        // This would be tracked in a real implementation
        false // placeholder
      )
    );

    return {
      userId,
      period,
      total,
      byCategory: notifications.reduce((acc, n) => {
        acc[n.category] = (acc[n.category] || 0) + 1;
        return acc;
      }, {} as Record<NotificationCategory, number>),
      byType: notifications.reduce((acc, n) => {
        acc[n.type] = (acc[n.type] || 0) + 1;
        return acc;
      }, {} as Record<NotificationType, number>),
      byChannel: notifications.reduce((acc, n) => {
        n.channels.forEach(channel => {
          acc[channel] = (acc[channel] || 0) + 1;
        });
        return acc;
      }, {} as Record<NotificationChannel, number>),
      readRate: total > 0 ? readNotifications.length / total : 0,
      actionRate: total > 0 ? actedNotifications.length / total : 0,
      averageReadTime: 2.5 // placeholder - would calculate from actual read times
    };
  }

  /**
   * Private helper methods
   */
  private initializeTemplates(): void {
    const templates: NotificationTemplate[] = [
      {
        type: 'collaboration_invitation',
        category: 'collaboration',
        title: 'Collaboration Invitation',
        messageTemplate: '{{invitedByName}} has invited you to collaborate on "{{sessionName}}"',
        defaultPriority: 'high',
        defaultChannels: ['in_app', 'email'],
        variables: ['invitedByName', 'sessionName'],
        actions: [
          { label: 'Accept', action: 'navigate', style: 'primary' },
          { label: 'Decline', action: 'api_call', style: 'secondary' }
        ]
      },
      {
        type: 'annotation_mention',
        category: 'collaboration',
        title: 'You were mentioned',
        messageTemplate: '{{mentionedByName}} mentioned you in an annotation on "{{documentTitle}}"',
        defaultPriority: 'medium',
        defaultChannels: ['in_app', 'push'],
        variables: ['mentionedByName', 'documentTitle'],
        actions: [
          { label: 'View Annotation', action: 'navigate', style: 'primary' }
        ]
      },
      {
        type: 'analysis_complete',
        category: 'analysis',
        title: 'Analysis Complete',
        messageTemplate: 'Your {{analysisType}} analysis for "{{documentTitle}}" is ready',
        defaultPriority: 'medium',
        defaultChannels: ['in_app'],
        variables: ['analysisType', 'documentTitle'],
        actions: [
          { label: 'View Results', action: 'navigate', style: 'primary' }
        ]
      },
      {
        type: 'trending_document',
        category: 'research',
        title: 'Trending Document',
        messageTemplate: '"{{documentTitle}}" is trending {{reason}}',
        defaultPriority: 'low',
        defaultChannels: ['in_app'],
        variables: ['documentTitle', 'reason'],
        actions: [
          { label: 'View Document', action: 'navigate', style: 'primary' }
        ]
      }
    ];

    templates.forEach(template => {
      this.templates.set(template.type, template);
    });
  }

  private getDefaultPreferences(userId: string): NotificationPreferences {
    return {
      userId,
      channels: {
        in_app: true,
        email: true,
        push: false,
        sms: false,
        slack: false,
        teams: false
      },
      categories: {
        collaboration: { enabled: true, channels: ['in_app', 'email'], priority: 'medium', immediate: true },
        document: { enabled: true, channels: ['in_app'], priority: 'low', immediate: false },
        analysis: { enabled: true, channels: ['in_app'], priority: 'medium', immediate: false },
        system: { enabled: true, channels: ['in_app', 'email'], priority: 'high', immediate: true },
        research: { enabled: true, channels: ['in_app'], priority: 'low', immediate: false }
      },
      quietHours: {
        enabled: false,
        start: '22:00',
        end: '08:00',
        timezone: 'America/Sao_Paulo'
      },
      frequency: {
        immediate: true,
        digest: 'daily',
        digestTime: '09:00'
      },
      filters: {
        minimumPriority: 'low',
        keywords: [],
        senders: []
      }
    };
  }

  private shouldSendNotification(
    preferences: NotificationPreferences,
    category: NotificationCategory,
    priority: 'low' | 'medium' | 'high' | 'urgent'
  ): boolean {
    const categorySettings = preferences.categories[category];
    if (!categorySettings.enabled) return false;

    const priorityOrder = { low: 0, medium: 1, high: 2, urgent: 3 };
    const minPriority = priorityOrder[preferences.filters.minimumPriority];
    const notificationPriority = priorityOrder[priority];

    return notificationPriority >= minPriority;
  }

  private getEnabledChannels(
    preferences: NotificationPreferences,
    category: NotificationCategory
  ): NotificationChannel[] {
    const categorySettings = preferences.categories[category];
    return categorySettings.channels.filter(channel => preferences.channels[channel]);
  }

  private processTemplate(template: string, data: NotificationData): string {
    let processed = template;
    
    // Replace variables with actual data
    if (data.metadata) {
      Object.entries(data.metadata).forEach(([key, value]) => {
        processed = processed.replace(new RegExp(`{{${key}}}`, 'g'), String(value));
      });
    }

    return processed;
  }

  private async deliverNotification(
    notification: Notification,
    preferences: NotificationPreferences
  ): Promise<void> {
    const promises = notification.channels.map(channel => {
      switch (channel) {
        case 'in_app':
          return this.deliverInApp(notification);
        case 'email':
          return this.deliverEmail(notification);
        case 'push':
          return this.deliverPush(notification);
        case 'sms':
          return this.deliverSMS(notification);
        case 'slack':
          return this.deliverSlack(notification);
        case 'teams':
          return this.deliverTeams(notification);
        default:
          return Promise.resolve();
      }
    });

    await Promise.allSettled(promises);
  }

  private async deliverInApp(notification: Notification): Promise<void> {
    // In-app notifications are already stored
    console.log(`In-app notification delivered: ${notification.id}`);
  }

  private async deliverEmail(notification: Notification): Promise<void> {
    // Email delivery implementation
    console.log(`Email notification sent: ${notification.id}`);
  }

  private async deliverPush(notification: Notification): Promise<void> {
    const subscriptions = this.pushSubscriptions.get(notification.userId) || [];
    
    const pushPayload = {
      title: notification.title,
      body: notification.message,
      icon: '/icon-192x192.png',
      badge: '/badge-72x72.png',
      data: {
        notificationId: notification.id,
        url: notification.data.url
      }
    };

    // Send to all user's devices
    const promises = subscriptions.map(async (subscription) => {
      try {
        // Implementation would use web-push library
        console.log(`Push notification sent to ${subscription.endpoint}`);
      } catch (error) {
        console.error('Push notification failed:', error);
      }
    });

    await Promise.allSettled(promises);
  }

  private async deliverSMS(notification: Notification): Promise<void> {
    // SMS delivery implementation
    console.log(`SMS notification sent: ${notification.id}`);
  }

  private async deliverSlack(notification: Notification): Promise<void> {
    // Slack webhook implementation
    const webhook = this.webhooks.get(`slack_${notification.userId}`);
    if (webhook) {
      console.log(`Slack notification sent: ${notification.id}`);
    }
  }

  private async deliverTeams(notification: Notification): Promise<void> {
    // Teams webhook implementation
    const webhook = this.webhooks.get(`teams_${notification.userId}`);
    if (webhook) {
      console.log(`Teams notification sent: ${notification.id}`);
    }
  }

  private generateHighlights(notifications: Notification[]): NotificationHighlight[] {
    const highlights: NotificationHighlight[] = [];

    // High priority notifications
    const highPriority = notifications.filter(n => ['high', 'urgent'].includes(n.priority));
    if (highPriority.length > 0) {
      highlights.push({
        type: 'important',
        title: `${highPriority.length} High Priority Notifications`,
        description: 'Important notifications that require your attention',
        notifications: highPriority.map(n => n.id),
        priority: 10
      });
    }

    // Collaboration highlights
    const collaborationNotifications = notifications.filter(n => n.category === 'collaboration');
    if (collaborationNotifications.length > 5) {
      highlights.push({
        type: 'collaborative',
        title: 'Active Collaboration',
        description: `${collaborationNotifications.length} collaboration updates`,
        notifications: collaborationNotifications.slice(0, 5).map(n => n.id),
        priority: 8
      });
    }

    return highlights.sort((a, b) => b.priority - a.priority);
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }
}

export const notificationService = new NotificationService();