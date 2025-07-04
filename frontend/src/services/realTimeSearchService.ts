/**
 * Real-Time Search Service
 * WebSocket-based real-time search with live updates and collaborative features
 */
import { LegislativeDocument, DocumentType } from '../types';
import { advancedSearchService, SearchResponse } from './advancedSearchService';

export interface RealtimeSearchParams {
  query: string;
  sessionId: string;
  userId?: string;
  filters?: {
    documentTypes?: DocumentType[];
    states?: string[];
    dateRange?: { start: Date; end: Date };
  };
  enableLiveUpdates?: boolean;
  shareResults?: boolean;
}

export interface SearchUpdate {
  type: 'new_document' | 'updated_document' | 'query_suggestion' | 'user_activity' | 'system_status';
  timestamp: Date;
  data: any;
  sessionId: string;
  userId?: string;
}

export interface CollaborativeSession {
  id: string;
  title: string;
  createdAt: Date;
  participants: Array<{
    userId: string;
    name: string;
    joinedAt: Date;
    isActive: boolean;
    lastActivity: Date;
  }>;
  sharedQueries: Array<{
    query: string;
    results: number;
    timestamp: Date;
    userId: string;
  }>;
  annotations: Array<{
    id: string;
    documentUrn: string;
    text: string;
    userId: string;
    timestamp: Date;
    resolved: boolean;
  }>;
  bookmarks: Array<{
    documentUrn: string;
    title: string;
    userId: string;
    timestamp: Date;
    tags: string[];
  }>;
}

export interface RealtimeSearchResult extends SearchResponse {
  isLive: boolean;
  updateFrequency: number;
  lastUpdate: Date;
  collaborativeData?: {
    viewCount: number;
    bookmarkCount: number;
    annotationCount: number;
    recentActivity: SearchUpdate[];
  };
}

export class RealTimeSearchService {
  private static instance: RealTimeSearchService;
  private websocket: WebSocket | null = null;
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private searchSessions: Map<string, RealtimeSearchParams> = new Map();
  private updateCallbacks: Map<string, (update: SearchUpdate) => void> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;

  private constructor() {}

  public static getInstance(): RealTimeSearchService {
    if (!RealTimeSearchService.instance) {
      RealTimeSearchService.instance = new RealTimeSearchService();
    }
    return RealTimeSearchService.instance;
  }

  /**
   * Initialize WebSocket connection
   */
  public async connect(wsUrl?: string): Promise<boolean> {
    if (this.isConnected) return true;

    const defaultWsUrl = 'wss://api.monitorlegislativo.gov.br/ws/search';
    const url = wsUrl || defaultWsUrl;

    try {
      this.websocket = new WebSocket(url);
      
      return new Promise((resolve, reject) => {
        if (!this.websocket) return reject(new Error('WebSocket not initialized'));

        this.websocket.onopen = () => {
          console.log('Real-time search WebSocket connected');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          this.startHeartbeat();
          resolve(true);
        };

        this.websocket.onmessage = (event) => {
          this.handleMessage(event);
        };

        this.websocket.onclose = (event) => {
          console.log('WebSocket connection closed:', event.code, event.reason);
          this.isConnected = false;
          this.stopHeartbeat();
          
          if (!event.wasClean && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
          }
        };

        this.websocket.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(new Error('WebSocket connection failed'));
        };

        // Timeout after 10 seconds
        setTimeout(() => {
          if (!this.isConnected) {
            reject(new Error('WebSocket connection timeout'));
          }
        }, 10000);
      });

    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      return false;
    }
  }

  /**
   * Start real-time search session
   */
  public async startSearch(params: RealtimeSearchParams): Promise<RealtimeSearchResult> {
    // Store session parameters
    this.searchSessions.set(params.sessionId, params);

    // Subscribe to real-time updates if WebSocket is available
    if (this.isConnected && params.enableLiveUpdates) {
      this.subscribeToUpdates(params);
    }

    // Execute initial search
    const initialResults = await advancedSearchService.search({
      query: params.query,
      enableSemanticExpansion: true,
      transportFocus: true,
      filters: params.filters,
      searchMode: 'hybrid',
      resultLimit: 20,
      sortBy: 'relevance',
      includeRelated: true
    });

    // Enhance with real-time data
    const realtimeResult: RealtimeSearchResult = {
      ...initialResults,
      isLive: this.isConnected && !!params.enableLiveUpdates,
      updateFrequency: 30, // seconds
      lastUpdate: new Date(),
      collaborativeData: params.shareResults ? {
        viewCount: Math.floor(Math.random() * 100),
        bookmarkCount: Math.floor(Math.random() * 20),
        annotationCount: Math.floor(Math.random() * 10),
        recentActivity: []
      } : undefined
    };

    return realtimeResult;
  }

  /**
   * Subscribe to search updates
   */
  public onSearchUpdate(sessionId: string, callback: (update: SearchUpdate) => void): void {
    this.updateCallbacks.set(sessionId, callback);
  }

  /**
   * Unsubscribe from search updates
   */
  public offSearchUpdate(sessionId: string): void {
    this.updateCallbacks.delete(sessionId);
  }

  /**
   * Create collaborative search session
   */
  public async createCollaborativeSession(title: string, userId: string): Promise<CollaborativeSession> {
    const session: CollaborativeSession = {
      id: `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      title,
      createdAt: new Date(),
      participants: [{
        userId,
        name: `User ${userId}`,
        joinedAt: new Date(),
        isActive: true,
        lastActivity: new Date()
      }],
      sharedQueries: [],
      annotations: [],
      bookmarks: []
    };

    // Register session with WebSocket if connected
    if (this.isConnected) {
      this.sendMessage({
        type: 'create_session',
        sessionId: session.id,
        data: { title, userId }
      });
    }

    return session;
  }

  /**
   * Join collaborative session
   */
  public async joinCollaborativeSession(sessionId: string, userId: string): Promise<CollaborativeSession | null> {
    if (this.isConnected) {
      this.sendMessage({
        type: 'join_session',
        sessionId,
        data: { userId }
      });

      // In a real implementation, this would wait for server response
      // For now, return a mock session
      return {
        id: sessionId,
        title: 'Shared Research Session',
        createdAt: new Date(Date.now() - 3600000), // 1 hour ago
        participants: [
          {
            userId,
            name: `User ${userId}`,
            joinedAt: new Date(),
            isActive: true,
            lastActivity: new Date()
          }
        ],
        sharedQueries: [],
        annotations: [],
        bookmarks: []
      };
    }

    return null;
  }

  /**
   * Share search query in collaborative session
   */
  public shareQuery(sessionId: string, query: string, userId: string, results: number): void {
    if (this.isConnected) {
      this.sendMessage({
        type: 'share_query',
        sessionId,
        data: { query, userId, results, timestamp: new Date() }
      });
    }
  }

  /**
   * Add annotation to document
   */
  public addAnnotation(
    sessionId: string,
    documentUrn: string,
    text: string,
    userId: string
  ): void {
    if (this.isConnected) {
      this.sendMessage({
        type: 'add_annotation',
        sessionId,
        data: {
          id: `annotation_${Date.now()}`,
          documentUrn,
          text,
          userId,
          timestamp: new Date(),
          resolved: false
        }
      });
    }
  }

  /**
   * Bookmark document
   */
  public bookmarkDocument(
    sessionId: string,
    documentUrn: string,
    title: string,
    userId: string,
    tags: string[] = []
  ): void {
    if (this.isConnected) {
      this.sendMessage({
        type: 'bookmark_document',
        sessionId,
        data: {
          documentUrn,
          title,
          userId,
          timestamp: new Date(),
          tags
        }
      });
    }
  }

  /**
   * Get live search suggestions based on current activity
   */
  public async getLiveSuggestions(partialQuery: string, sessionId?: string): Promise<{
    suggestions: string[];
    trending: string[];
    collaborative: string[];
    sourceMetrics: Array<{
      suggestion: string;
      popularity: number;
      recentUse: Date;
      userCount: number;
    }>;
  }> {
    // Combine static suggestions with real-time data
    const staticSuggestions = await advancedSearchService.getSearchSuggestions(partialQuery);
    
    // Mock trending and collaborative data
    const trending = [
      'transporte sustentável 2024',
      'mobilidade urbana pós-pandemia',
      'marco regulatório transportes',
      'infraestrutura rodoviária investimentos'
    ];

    const collaborative = sessionId ? [
      'segurança transporte cargas',
      'regulamentação apps transporte',
      'política nacional mobilidade'
    ] : [];

    const sourceMetrics = staticSuggestions.map(suggestion => ({
      suggestion,
      popularity: Math.random(),
      recentUse: new Date(Date.now() - Math.random() * 86400000),
      userCount: Math.floor(Math.random() * 50) + 1
    }));

    return {
      suggestions: staticSuggestions,
      trending,
      collaborative,
      sourceMetrics
    };
  }

  /**
   * Monitor document changes for specific URNs
   */
  public monitorDocuments(urns: string[], callback: (update: SearchUpdate) => void): void {
    if (this.isConnected) {
      const monitorId = `monitor_${Date.now()}`;
      this.updateCallbacks.set(monitorId, callback);
      
      this.sendMessage({
        type: 'monitor_documents',
        sessionId: monitorId,
        data: { urns }
      });
    }
  }

  /**
   * Get real-time search analytics
   */
  public getSearchAnalytics(timeRange: 'hour' | 'day' | 'week' = 'day'): Promise<{
    totalSearches: number;
    popularQueries: Array<{ query: string; count: number }>;
    activeUsers: number;
    documentsViewed: number;
    avgSessionDuration: number;
    peakHours: Array<{ hour: number; searches: number }>;
    sourceUsage: Array<{ source: string; usage: number }>;
  }> {
    // Mock analytics data
    return Promise.resolve({
      totalSearches: Math.floor(Math.random() * 1000) + 500,
      popularQueries: [
        { query: 'transporte urbano', count: 45 },
        { query: 'marco legal cargas', count: 38 },
        { query: 'mobilidade sustentável', count: 32 },
        { query: 'segurança viária', count: 28 },
        { query: 'infraestrutura rodoviária', count: 24 }
      ],
      activeUsers: Math.floor(Math.random() * 100) + 20,
      documentsViewed: Math.floor(Math.random() * 500) + 200,
      avgSessionDuration: Math.floor(Math.random() * 600) + 180, // seconds
      peakHours: Array.from({ length: 24 }, (_, hour) => ({
        hour,
        searches: Math.floor(Math.random() * 50)
      })),
      sourceUsage: [
        { source: 'Planalto', usage: 35 },
        { source: 'Câmara dos Deputados', usage: 28 },
        { source: 'ANTT', usage: 22 },
        { source: 'Senado Federal', usage: 15 }
      ]
    });
  }

  /**
   * Disconnect WebSocket
   */
  public disconnect(): void {
    if (this.websocket) {
      this.websocket.close(1000, 'Client disconnect');
      this.websocket = null;
    }
    this.isConnected = false;
    this.stopHeartbeat();
    this.searchSessions.clear();
    this.updateCallbacks.clear();
  }

  /**
   * Check connection status
   */
  public isConnectedToRealtime(): boolean {
    return this.isConnected;
  }

  // Private helper methods

  private handleMessage(event: MessageEvent): void {
    try {
      const message = JSON.parse(event.data);
      
      switch (message.type) {
        case 'search_update':
          this.handleSearchUpdate(message);
          break;
        case 'document_change':
          this.handleDocumentChange(message);
          break;
        case 'collaborative_update':
          this.handleCollaborativeUpdate(message);
          break;
        case 'system_notification':
          this.handleSystemNotification(message);
          break;
        case 'pong':
          // Heartbeat response
          break;
        default:
          console.log('Unknown message type:', message.type);
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  }

  private handleSearchUpdate(message: any): void {
    const update: SearchUpdate = {
      type: 'new_document',
      timestamp: new Date(message.timestamp),
      data: message.data,
      sessionId: message.sessionId,
      userId: message.userId
    };

    // Notify relevant callbacks
    const callback = this.updateCallbacks.get(message.sessionId);
    if (callback) {
      callback(update);
    }

    // Notify all session callbacks for collaborative updates
    if (message.collaborative) {
      this.updateCallbacks.forEach((callback, sessionId) => {
        if (sessionId !== message.sessionId) {
          callback(update);
        }
      });
    }
  }

  private handleDocumentChange(message: any): void {
    const update: SearchUpdate = {
      type: 'updated_document',
      timestamp: new Date(message.timestamp),
      data: message.data,
      sessionId: message.sessionId
    };

    // Notify all monitoring callbacks
    this.updateCallbacks.forEach(callback => callback(update));
  }

  private handleCollaborativeUpdate(message: any): void {
    const update: SearchUpdate = {
      type: 'user_activity',
      timestamp: new Date(message.timestamp),
      data: message.data,
      sessionId: message.sessionId,
      userId: message.userId
    };

    const callback = this.updateCallbacks.get(message.sessionId);
    if (callback) {
      callback(update);
    }
  }

  private handleSystemNotification(message: any): void {
    const update: SearchUpdate = {
      type: 'system_status',
      timestamp: new Date(message.timestamp),
      data: message.data,
      sessionId: 'system'
    };

    // Notify all callbacks for system notifications
    this.updateCallbacks.forEach(callback => callback(update));
  }

  private sendMessage(message: any): void {
    if (this.websocket && this.isConnected) {
      this.websocket.send(JSON.stringify(message));
    }
  }

  private subscribeToUpdates(params: RealtimeSearchParams): void {
    this.sendMessage({
      type: 'subscribe_search',
      sessionId: params.sessionId,
      data: {
        query: params.query,
        filters: params.filters,
        userId: params.userId
      }
    });
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected) {
        this.sendMessage({ type: 'ping', timestamp: Date.now() });
      }
    }, 30000); // 30 seconds
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  private scheduleReconnect(): void {
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    console.log(`Scheduling WebSocket reconnect attempt ${this.reconnectAttempts} in ${delay}ms`);
    
    setTimeout(() => {
      if (!this.isConnected) {
        this.connect();
      }
    }, delay);
  }
}

export const realTimeSearchService = RealTimeSearchService.getInstance();