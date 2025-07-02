/**
 * Collaboration Service
 * Real-time collaboration features for team research and document analysis
 */
import { LegislativeDocument, DocumentType } from '../types';

export interface CollaborationSession {
  id: string;
  name: string;
  description: string;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
  participants: Participant[];
  permissions: SessionPermissions;
  status: 'active' | 'paused' | 'archived';
  documents: CollaborativeDocument[];
  annotations: Annotation[];
  discussions: Discussion[];
  activities: Activity[];
  settings: SessionSettings;
}

export interface Participant {
  userId: string;
  name: string;
  email: string;
  role: 'owner' | 'admin' | 'collaborator' | 'viewer';
  joinedAt: Date;
  lastActive: Date;
  isOnline: boolean;
  permissions: ParticipantPermissions;
  preferences: ParticipantPreferences;
}

export interface SessionPermissions {
  canInviteParticipants: boolean;
  canModifyDocuments: boolean;
  canDeleteAnnotations: boolean;
  canExportData: boolean;
  requireApprovalForChanges: boolean;
  allowAnonymousAnnotations: boolean;
}

export interface ParticipantPermissions {
  canAnnotate: boolean;
  canComment: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canInvite: boolean;
  canManageSession: boolean;
}

export interface ParticipantPreferences {
  notificationSettings: {
    emailNotifications: boolean;
    pushNotifications: boolean;
    annotationNotifications: boolean;
    discussionNotifications: boolean;
  };
  displaySettings: {
    showOtherCursors: boolean;
    showLiveAnnotations: boolean;
    highlightOwnAnnotations: boolean;
  };
}

export interface CollaborativeDocument {
  documentId: string;
  document: LegislativeDocument;
  addedBy: string;
  addedAt: Date;
  lastModified: Date;
  version: number;
  annotations: Annotation[];
  discussions: Discussion[];
  collaborativeAnalysis: CollaborativeAnalysis;
  accessHistory: AccessRecord[];
}

export interface Annotation {
  id: string;
  documentId: string;
  userId: string;
  username: string;
  text: string;
  type: 'highlight' | 'comment' | 'note' | 'question' | 'suggestion' | 'critique';
  position: AnnotationPosition;
  timestamp: Date;
  lastModified: Date;
  replies: AnnotationReply[];
  tags: string[];
  priority: 'low' | 'medium' | 'high';
  status: 'open' | 'resolved' | 'archived';
  visibility: 'public' | 'private' | 'team';
  reactions: Reaction[];
  mentions: string[];
}

export interface AnnotationPosition {
  startOffset: number;
  endOffset: number;
  selectedText: string;
  context: string;
  section?: string;
  paragraph?: number;
  coordinates?: { x: number; y: number };
}

export interface AnnotationReply {
  id: string;
  annotationId: string;
  userId: string;
  username: string;
  text: string;
  timestamp: Date;
  reactions: Reaction[];
}

export interface Reaction {
  userId: string;
  type: 'like' | 'dislike' | 'agree' | 'disagree' | 'important' | 'question';
  timestamp: Date;
}

export interface Discussion {
  id: string;
  title: string;
  documentId?: string;
  initiatedBy: string;
  initiatedAt: Date;
  lastActivity: Date;
  participants: string[];
  messages: DiscussionMessage[];
  topic: string;
  status: 'active' | 'resolved' | 'archived';
  priority: 'low' | 'medium' | 'high';
  tags: string[];
  relatedAnnotations: string[];
}

export interface DiscussionMessage {
  id: string;
  discussionId: string;
  userId: string;
  username: string;
  text: string;
  timestamp: Date;
  edited?: Date;
  attachments: MessageAttachment[];
  mentions: string[];
  reactions: Reaction[];
  quotedMessage?: string;
}

export interface MessageAttachment {
  id: string;
  name: string;
  type: 'image' | 'document' | 'link' | 'data';
  url: string;
  size: number;
  uploadedAt: Date;
}

export interface CollaborativeAnalysis {
  documentId: string;
  consensusRating: number;
  collaborativeInsights: CollaborativeInsight[];
  teamAnnotationSummary: AnnotationSummary;
  disagreementPoints: DisagreementPoint[];
  convergenceMetrics: ConvergenceMetrics;
}

export interface CollaborativeInsight {
  id: string;
  insight: string;
  confidence: number;
  supportingAnnotations: string[];
  contributors: string[];
  timestamp: Date;
  category: 'interpretation' | 'implication' | 'connection' | 'critique' | 'suggestion';
}

export interface AnnotationSummary {
  totalAnnotations: number;
  annotationsByType: Record<string, number>;
  annotationsByUser: Record<string, number>;
  mostAnnotatedSections: Array<{ section: string; count: number }>;
  averageAnnotationLength: number;
  consensusLevel: number;
}

export interface DisagreementPoint {
  id: string;
  section: string;
  description: string;
  perspectives: Array<{
    userId: string;
    viewpoint: string;
    supportingEvidence: string[];
  }>;
  resolutionStatus: 'unresolved' | 'consensus' | 'majority' | 'deferred';
  importance: 'low' | 'medium' | 'high';
}

export interface ConvergenceMetrics {
  overallConvergence: number;
  topicConvergence: Record<string, number>;
  participantAlignment: Record<string, Record<string, number>>;
  convergenceTrend: Array<{ timestamp: Date; convergence: number }>;
}

export interface Activity {
  id: string;
  sessionId: string;
  userId: string;
  username: string;
  action: ActivityAction;
  target: ActivityTarget;
  timestamp: Date;
  details: Record<string, any>;
  visibility: 'public' | 'private';
}

export type ActivityAction = 
  | 'joined_session' | 'left_session' | 'added_document' | 'removed_document'
  | 'created_annotation' | 'updated_annotation' | 'deleted_annotation'
  | 'started_discussion' | 'replied_to_discussion' | 'resolved_discussion'
  | 'invited_participant' | 'changed_permissions' | 'exported_data'
  | 'created_insight' | 'updated_analysis';

export interface ActivityTarget {
  type: 'session' | 'document' | 'annotation' | 'discussion' | 'participant';
  id: string;
  name: string;
}

export interface SessionSettings {
  autoSave: boolean;
  saveInterval: number; // minutes
  maxParticipants: number;
  allowGuestAccess: boolean;
  sessionTimeout: number; // hours
  dataRetention: number; // days
  exportFormats: string[];
  integrations: {
    slack: boolean;
    teams: boolean;
    email: boolean;
  };
}

export interface AccessRecord {
  userId: string;
  action: 'view' | 'edit' | 'annotate' | 'export';
  timestamp: Date;
  duration: number; // seconds
  location?: { country: string; city: string };
}

export interface RealTimeUpdate {
  sessionId: string;
  type: 'participant_joined' | 'participant_left' | 'annotation_added' | 'annotation_updated' | 'discussion_message' | 'cursor_moved';
  userId: string;
  data: any;
  timestamp: Date;
}

export interface CursorPosition {
  userId: string;
  username: string;
  documentId: string;
  position: { x: number; y: number };
  selection?: { start: number; end: number };
  timestamp: Date;
}

class CollaborationService {
  private sessions: Map<string, CollaborationSession> = new Map();
  private activeConnections: Map<string, WebSocket> = new Map();
  private cursorPositions: Map<string, CursorPosition> = new Map();

  /**
   * Create a new collaboration session
   */
  async createSession(
    name: string,
    description: string,
    createdBy: string,
    settings: Partial<SessionSettings> = {}
  ): Promise<CollaborationSession> {
    const session: CollaborationSession = {
      id: this.generateId(),
      name,
      description,
      createdBy,
      createdAt: new Date(),
      updatedAt: new Date(),
      participants: [{
        userId: createdBy,
        name: 'Session Creator',
        email: '',
        role: 'owner',
        joinedAt: new Date(),
        lastActive: new Date(),
        isOnline: true,
        permissions: {
          canAnnotate: true,
          canComment: true,
          canEdit: true,
          canDelete: true,
          canInvite: true,
          canManageSession: true
        },
        preferences: {
          notificationSettings: {
            emailNotifications: true,
            pushNotifications: true,
            annotationNotifications: true,
            discussionNotifications: true
          },
          displaySettings: {
            showOtherCursors: true,
            showLiveAnnotations: true,
            highlightOwnAnnotations: true
          }
        }
      }],
      permissions: {
        canInviteParticipants: true,
        canModifyDocuments: true,
        canDeleteAnnotations: true,
        canExportData: true,
        requireApprovalForChanges: false,
        allowAnonymousAnnotations: false
      },
      status: 'active',
      documents: [],
      annotations: [],
      discussions: [],
      activities: [],
      settings: {
        autoSave: true,
        saveInterval: 5,
        maxParticipants: 50,
        allowGuestAccess: false,
        sessionTimeout: 24,
        dataRetention: 30,
        exportFormats: ['json', 'csv', 'pdf'],
        integrations: {
          slack: false,
          teams: false,
          email: true
        },
        ...settings
      }
    };

    this.sessions.set(session.id, session);
    
    // Log activity
    await this.logActivity(session.id, createdBy, 'Session Creator', 'joined_session', {
      type: 'session',
      id: session.id,
      name: session.name
    });

    return session;
  }

  /**
   * Join an existing session
   */
  async joinSession(
    sessionId: string,
    userId: string,
    username: string,
    email: string
  ): Promise<CollaborationSession> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    // Check if user is already a participant
    const existingParticipant = session.participants.find(p => p.userId === userId);
    if (existingParticipant) {
      existingParticipant.isOnline = true;
      existingParticipant.lastActive = new Date();
    } else {
      // Add new participant
      const participant: Participant = {
        userId,
        name: username,
        email,
        role: 'collaborator',
        joinedAt: new Date(),
        lastActive: new Date(),
        isOnline: true,
        permissions: {
          canAnnotate: true,
          canComment: true,
          canEdit: false,
          canDelete: false,
          canInvite: false,
          canManageSession: false
        },
        preferences: {
          notificationSettings: {
            emailNotifications: true,
            pushNotifications: true,
            annotationNotifications: true,
            discussionNotifications: true
          },
          displaySettings: {
            showOtherCursors: true,
            showLiveAnnotations: true,
            highlightOwnAnnotations: true
          }
        }
      };

      session.participants.push(participant);
    }

    session.updatedAt = new Date();

    // Log activity
    await this.logActivity(sessionId, userId, username, 'joined_session', {
      type: 'session',
      id: sessionId,
      name: session.name
    });

    // Broadcast to other participants
    this.broadcastUpdate(sessionId, {
      sessionId,
      type: 'participant_joined',
      userId,
      data: { username },
      timestamp: new Date()
    });

    return session;
  }

  /**
   * Add document to session
   */
  async addDocument(
    sessionId: string,
    document: LegislativeDocument,
    userId: string
  ): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    const collaborativeDoc: CollaborativeDocument = {
      documentId: document.id,
      document,
      addedBy: userId,
      addedAt: new Date(),
      lastModified: new Date(),
      version: 1,
      annotations: [],
      discussions: [],
      collaborativeAnalysis: {
        documentId: document.id,
        consensusRating: 0,
        collaborativeInsights: [],
        teamAnnotationSummary: {
          totalAnnotations: 0,
          annotationsByType: {},
          annotationsByUser: {},
          mostAnnotatedSections: [],
          averageAnnotationLength: 0,
          consensusLevel: 0
        },
        disagreementPoints: [],
        convergenceMetrics: {
          overallConvergence: 0,
          topicConvergence: {},
          participantAlignment: {},
          convergenceTrend: []
        }
      },
      accessHistory: []
    };

    session.documents.push(collaborativeDoc);
    session.updatedAt = new Date();

    // Log activity
    const participant = session.participants.find(p => p.userId === userId);
    await this.logActivity(sessionId, userId, participant?.name || 'Unknown', 'added_document', {
      type: 'document',
      id: document.id,
      name: document.title
    });
  }

  /**
   * Create annotation
   */
  async createAnnotation(
    sessionId: string,
    documentId: string,
    userId: string,
    text: string,
    type: Annotation['type'],
    position: AnnotationPosition,
    options: {
      tags?: string[];
      priority?: 'low' | 'medium' | 'high';
      visibility?: 'public' | 'private' | 'team';
      mentions?: string[];
    } = {}
  ): Promise<Annotation> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    const participant = session.participants.find(p => p.userId === userId);
    if (!participant) {
      throw new Error('User not in session');
    }

    const annotation: Annotation = {
      id: this.generateId(),
      documentId,
      userId,
      username: participant.name,
      text,
      type,
      position,
      timestamp: new Date(),
      lastModified: new Date(),
      replies: [],
      tags: options.tags || [],
      priority: options.priority || 'medium',
      status: 'open',
      visibility: options.visibility || 'public',
      reactions: [],
      mentions: options.mentions || []
    };

    // Add to session and document
    session.annotations.push(annotation);
    const document = session.documents.find(d => d.documentId === documentId);
    if (document) {
      document.annotations.push(annotation);
      document.lastModified = new Date();
    }

    session.updatedAt = new Date();

    // Log activity
    await this.logActivity(sessionId, userId, participant.name, 'created_annotation', {
      type: 'annotation',
      id: annotation.id,
      name: `${type} annotation`
    });

    // Broadcast to other participants
    this.broadcastUpdate(sessionId, {
      sessionId,
      type: 'annotation_added',
      userId,
      data: { annotation },
      timestamp: new Date()
    });

    // Update collaborative analysis
    await this.updateCollaborativeAnalysis(sessionId, documentId);

    return annotation;
  }

  /**
   * Start discussion
   */
  async startDiscussion(
    sessionId: string,
    title: string,
    topic: string,
    initiatedBy: string,
    documentId?: string,
    relatedAnnotations: string[] = []
  ): Promise<Discussion> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    const participant = session.participants.find(p => p.userId === initiatedBy);
    if (!participant) {
      throw new Error('User not in session');
    }

    const discussion: Discussion = {
      id: this.generateId(),
      title,
      documentId,
      initiatedBy,
      initiatedAt: new Date(),
      lastActivity: new Date(),
      participants: [initiatedBy],
      messages: [],
      topic,
      status: 'active',
      priority: 'medium',
      tags: [],
      relatedAnnotations
    };

    session.discussions.push(discussion);
    session.updatedAt = new Date();

    // Log activity
    await this.logActivity(sessionId, initiatedBy, participant.name, 'started_discussion', {
      type: 'discussion',
      id: discussion.id,
      name: title
    });

    return discussion;
  }

  /**
   * Real-time cursor tracking
   */
  updateCursorPosition(
    sessionId: string,
    userId: string,
    username: string,
    documentId: string,
    position: { x: number; y: number },
    selection?: { start: number; end: number }
  ): void {
    const cursorPosition: CursorPosition = {
      userId,
      username,
      documentId,
      position,
      selection,
      timestamp: new Date()
    };

    this.cursorPositions.set(`${sessionId}-${userId}`, cursorPosition);

    // Broadcast cursor position
    this.broadcastUpdate(sessionId, {
      sessionId,
      type: 'cursor_moved',
      userId,
      data: { cursorPosition },
      timestamp: new Date()
    });
  }

  /**
   * Export session data
   */
  async exportSession(
    sessionId: string,
    format: 'json' | 'csv' | 'pdf' | 'xlsx',
    options: {
      includeAnnotations?: boolean;
      includeDiscussions?: boolean;
      includeActivities?: boolean;
      includeAnalytics?: boolean;
    } = {}
  ): Promise<string> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    const exportData = {
      session: {
        id: session.id,
        name: session.name,
        description: session.description,
        createdAt: session.createdAt,
        participants: session.participants.length,
        documents: session.documents.length
      },
      documents: session.documents.map(doc => ({
        id: doc.documentId,
        title: doc.document.title,
        type: doc.document.type,
        addedAt: doc.addedAt,
        annotationCount: doc.annotations.length
      })),
      ...(options.includeAnnotations && {
        annotations: session.annotations.map(ann => ({
          id: ann.id,
          text: ann.text,
          type: ann.type,
          user: ann.username,
          timestamp: ann.timestamp,
          position: ann.position.selectedText
        }))
      }),
      ...(options.includeDiscussions && {
        discussions: session.discussions.map(disc => ({
          id: disc.id,
          title: disc.title,
          topic: disc.topic,
          messageCount: disc.messages.length,
          participants: disc.participants.length
        }))
      }),
      ...(options.includeActivities && {
        activities: session.activities.map(act => ({
          action: act.action,
          user: act.username,
          timestamp: act.timestamp,
          target: act.target.name
        }))
      })
    };

    // Format export based on requested format
    switch (format) {
      case 'json':
        return JSON.stringify(exportData, null, 2);
      case 'csv':
        return this.formatAsCSV(exportData);
      case 'pdf':
        return await this.formatAsPDF(exportData);
      case 'xlsx':
        return await this.formatAsXLSX(exportData);
      default:
        throw new Error('Unsupported export format');
    }
  }

  /**
   * Get session analytics
   */
  getSessionAnalytics(sessionId: string): any {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    const now = new Date();
    const sessionDuration = now.getTime() - session.createdAt.getTime();
    const annotationsByUser = session.annotations.reduce((acc, ann) => {
      acc[ann.username] = (acc[ann.username] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      sessionInfo: {
        duration: Math.round(sessionDuration / (1000 * 60 * 60)), // hours
        participants: session.participants.length,
        activeParticipants: session.participants.filter(p => p.isOnline).length,
        documents: session.documents.length,
        totalAnnotations: session.annotations.length,
        totalDiscussions: session.discussions.length,
        totalActivities: session.activities.length
      },
      engagement: {
        annotationsPerUser: annotationsByUser,
        averageAnnotationsPerUser: session.annotations.length / session.participants.length,
        mostActiveUser: Object.entries(annotationsByUser).sort(([,a], [,b]) => b - a)[0]?.[0] || 'None',
        discussionParticipation: session.discussions.reduce((acc, disc) => acc + disc.participants.length, 0) / session.discussions.length || 0
      },
      collaboration: {
        consensusLevel: this.calculateOverallConsensus(session),
        convergenceScore: this.calculateConvergenceScore(session),
        disagreementPoints: session.documents.reduce((acc, doc) => acc + doc.collaborativeAnalysis.disagreementPoints.length, 0)
      }
    };
  }

  /**
   * Private helper methods
   */
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }

  private async logActivity(
    sessionId: string,
    userId: string,
    username: string,
    action: ActivityAction,
    target: ActivityTarget,
    details: Record<string, any> = {}
  ): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    const activity: Activity = {
      id: this.generateId(),
      sessionId,
      userId,
      username,
      action,
      target,
      timestamp: new Date(),
      details,
      visibility: 'public'
    };

    session.activities.push(activity);
  }

  private broadcastUpdate(sessionId: string, update: RealTimeUpdate): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    // Broadcast to all online participants except the sender
    session.participants
      .filter(p => p.isOnline && p.userId !== update.userId)
      .forEach(participant => {
        const connection = this.activeConnections.get(participant.userId);
        if (connection && connection.readyState === WebSocket.OPEN) {
          connection.send(JSON.stringify(update));
        }
      });
  }

  private async updateCollaborativeAnalysis(sessionId: string, documentId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    const document = session.documents.find(d => d.documentId === documentId);
    if (!document) return;

    // Update annotation summary
    const annotations = document.annotations;
    document.collaborativeAnalysis.teamAnnotationSummary = {
      totalAnnotations: annotations.length,
      annotationsByType: annotations.reduce((acc, ann) => {
        acc[ann.type] = (acc[ann.type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
      annotationsByUser: annotations.reduce((acc, ann) => {
        acc[ann.username] = (acc[ann.username] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
      mostAnnotatedSections: this.getMostAnnotatedSections(annotations),
      averageAnnotationLength: annotations.reduce((sum, ann) => sum + ann.text.length, 0) / annotations.length || 0,
      consensusLevel: this.calculateConsensusLevel(annotations)
    };

    // Update convergence metrics
    document.collaborativeAnalysis.convergenceMetrics.overallConvergence = this.calculateConvergence(annotations);
  }

  private getMostAnnotatedSections(annotations: Annotation[]): Array<{ section: string; count: number }> {
    const sectionCounts = annotations.reduce((acc, ann) => {
      const section = ann.position.section || 'General';
      acc[section] = (acc[section] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(sectionCounts)
      .map(([section, count]) => ({ section, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  private calculateConsensusLevel(annotations: Annotation[]): number {
    if (annotations.length === 0) return 0;
    
    // Simple consensus calculation based on annotation agreement
    const positiveAnnotations = annotations.filter(ann => 
      ann.reactions.filter(r => ['like', 'agree'].includes(r.type)).length > 
      ann.reactions.filter(r => ['dislike', 'disagree'].includes(r.type)).length
    );
    
    return positiveAnnotations.length / annotations.length;
  }

  private calculateConvergence(annotations: Annotation[]): number {
    // Calculate convergence based on annotation clustering and agreement
    if (annotations.length < 2) return 1;
    
    // Simple convergence metric based on annotation density in sections
    const sectionDensity = this.getMostAnnotatedSections(annotations);
    const maxDensity = sectionDensity[0]?.count || 0;
    const totalAnnotations = annotations.length;
    
    return maxDensity / totalAnnotations;
  }

  private calculateOverallConsensus(session: CollaborationSession): number {
    if (session.documents.length === 0) return 0;
    
    const consensusLevels = session.documents.map(doc => 
      doc.collaborativeAnalysis.teamAnnotationSummary.consensusLevel
    );
    
    return consensusLevels.reduce((sum, level) => sum + level, 0) / consensusLevels.length;
  }

  private calculateConvergenceScore(session: CollaborationSession): number {
    if (session.documents.length === 0) return 0;
    
    const convergenceScores = session.documents.map(doc => 
      doc.collaborativeAnalysis.convergenceMetrics.overallConvergence
    );
    
    return convergenceScores.reduce((sum, score) => sum + score, 0) / convergenceScores.length;
  }

  private formatAsCSV(data: any): string {
    // Simple CSV formatter - would need more sophisticated implementation
    const rows = [];
    rows.push(['Type', 'ID', 'Name', 'Timestamp', 'User']);
    
    if (data.annotations) {
      data.annotations.forEach((ann: any) => {
        rows.push(['Annotation', ann.id, ann.text.substring(0, 50), ann.timestamp, ann.user]);
      });
    }
    
    return rows.map(row => row.join(',')).join('\n');
  }

  private async formatAsPDF(data: any): Promise<string> {
    // Placeholder for PDF generation
    return 'PDF export not implemented';
  }

  private async formatAsXLSX(data: any): Promise<string> {
    // Placeholder for XLSX generation
    return 'XLSX export not implemented';
  }
}

export const collaborationService = new CollaborationService();