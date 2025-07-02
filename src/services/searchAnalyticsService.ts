/**
 * Search Analytics Service
 * Tracks search patterns, user behavior, and provides insights for research optimization
 */
import { LegislativeDocument, DocumentType } from '../types';

export interface SearchEvent {
  id: string;
  timestamp: Date;
  sessionId: string;
  userId?: string;
  eventType: 'search' | 'click' | 'download' | 'bookmark' | 'share' | 'export' | 'filter_change';
  searchQuery?: string;
  documentUrn?: string;
  filters?: Record<string, any>;
  resultCount?: number;
  responseTime?: number;
  userAgent?: string;
  ipHash?: string;
  location?: {
    country: string;
    region: string;
    city: string;
  };
  metadata?: Record<string, any>;
}

export interface SearchPattern {
  pattern: string;
  frequency: number;
  successRate: number;
  avgResultCount: number;
  avgResponseTime: number;
  popularFilters: Record<string, number>;
  timeDistribution: Record<number, number>; // hour of day
  seasonality: Record<string, number>; // month
  userSegments: Record<string, number>;
}

export interface UserBehavior {
  userId: string;
  sessionCount: number;
  totalSearches: number;
  avgSessionDuration: number;
  preferredFilters: Record<string, number>;
  searchComplexity: 'basic' | 'intermediate' | 'advanced';
  researchDomains: string[];
  clickThroughRate: number;
  bookmarkRate: number;
  exportActivity: Record<string, number>;
  lastActivity: Date;
  engagement: 'low' | 'medium' | 'high';
}

export interface ContentPerformance {
  documentUrn: string;
  title: string;
  type: DocumentType;
  viewCount: number;
  clickThroughRate: number;
  avgTimeOnDocument: number;
  bookmarkCount: number;
  shareCount: number;
  downloadCount: number;
  searchAppearances: number;
  relevanceScore: number;
  userRating?: number;
  lastAccessed: Date;
}

export interface SearchInsights {
  totalSearches: number;
  uniqueUsers: number;
  avgSearchesPerUser: number;
  searchSuccessRate: number;
  avgResponseTime: number;
  popularQueries: Array<{ query: string; count: number; successRate: number }>;
  emergingTopics: Array<{ topic: string; growth: number; timeframe: string }>;
  userSegmentation: {
    researchers: number;
    professionals: number;
    students: number;
    public: number;
  };
  geographicDistribution: Array<{ region: string; searches: number; users: number }>;
  temporalTrends: Array<{ date: Date; searches: number; users: number }>;
  performanceMetrics: {
    avgLoadTime: number;
    errorRate: number;
    cacheHitRate: number;
    systemUptime: number;
  };
}

export interface RecommendationEngine {
  getPersonalizedSuggestions(userId: string): Promise<string[]>;
  getContentRecommendations(documentUrn: string): Promise<LegislativeDocument[]>;
  getTrendingTopics(timeframe: 'day' | 'week' | 'month'): Promise<string[]>;
  getSimilarUsers(userId: string): Promise<string[]>;
}

export class SearchAnalyticsService {
  private static instance: SearchAnalyticsService;
  private events: SearchEvent[] = [];
  private patterns: Map<string, SearchPattern> = new Map();
  private userBehaviors: Map<string, UserBehavior> = new Map();
  private contentPerformance: Map<string, ContentPerformance> = new Map();
  private sessionStorage: Map<string, any> = new Map();

  private constructor() {
    this.initializeAnalytics();
  }

  public static getInstance(): SearchAnalyticsService {
    if (!SearchAnalyticsService.instance) {
      SearchAnalyticsService.instance = new SearchAnalyticsService();
    }
    return SearchAnalyticsService.instance;
  }

  /**
   * Track search event
   */
  public trackSearch(params: {
    sessionId: string;
    userId?: string;
    query: string;
    filters?: Record<string, any>;
    resultCount: number;
    responseTime: number;
  }): void {
    const event: SearchEvent = {
      id: `search_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      sessionId: params.sessionId,
      userId: params.userId,
      eventType: 'search',
      searchQuery: params.query,
      filters: params.filters,
      resultCount: params.resultCount,
      responseTime: params.responseTime,
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : undefined,
      metadata: {
        queryLength: params.query.length,
        filterCount: params.filters ? Object.keys(params.filters).length : 0,
        hasSemanticExpansion: params.query.includes(' OR ') || params.query.includes(' AND ')
      }
    };

    this.addEvent(event);
    this.updateSearchPattern(params.query, event);
    this.updateUserBehavior(params.sessionId, params.userId, event);
  }

  /**
   * Track document interaction
   */
  public trackDocumentInteraction(params: {
    sessionId: string;
    userId?: string;
    documentUrn: string;
    interactionType: 'click' | 'download' | 'bookmark' | 'share' | 'export';
    metadata?: Record<string, any>;
  }): void {
    const event: SearchEvent = {
      id: `interaction_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      sessionId: params.sessionId,
      userId: params.userId,
      eventType: params.interactionType,
      documentUrn: params.documentUrn,
      metadata: params.metadata
    };

    this.addEvent(event);
    this.updateContentPerformance(params.documentUrn, params.interactionType);
    this.updateUserBehavior(params.sessionId, params.userId, event);
  }

  /**
   * Track filter usage
   */
  public trackFilterChange(params: {
    sessionId: string;
    userId?: string;
    filters: Record<string, any>;
    resultCount: number;
  }): void {
    const event: SearchEvent = {
      id: `filter_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      sessionId: params.sessionId,
      userId: params.userId,
      eventType: 'filter_change',
      filters: params.filters,
      resultCount: params.resultCount
    };

    this.addEvent(event);
  }

  /**
   * Get search insights for dashboard
   */
  public getSearchInsights(timeRange: {
    start: Date;
    end: Date;
  }): SearchInsights {
    const filteredEvents = this.events.filter(event => 
      event.timestamp >= timeRange.start && event.timestamp <= timeRange.end
    );

    const searchEvents = filteredEvents.filter(event => event.eventType === 'search');
    const uniqueUsers = new Set(filteredEvents.map(event => event.userId || event.sessionId)).size;
    
    const popularQueries = this.calculatePopularQueries(searchEvents);
    const emergingTopics = this.identifyEmergingTopics(searchEvents);
    const userSegmentation = this.analyzeUserSegmentation(filteredEvents);
    const geographicDistribution = this.analyzeGeographicDistribution(filteredEvents);
    const temporalTrends = this.analyzeTemporalTrends(filteredEvents);
    const performanceMetrics = this.calculatePerformanceMetrics(searchEvents);

    return {
      totalSearches: searchEvents.length,
      uniqueUsers,
      avgSearchesPerUser: searchEvents.length / Math.max(uniqueUsers, 1),
      searchSuccessRate: this.calculateSuccessRate(searchEvents),
      avgResponseTime: this.calculateAverageResponseTime(searchEvents),
      popularQueries,
      emergingTopics,
      userSegmentation,
      geographicDistribution,
      temporalTrends,
      performanceMetrics
    };
  }

  /**
   * Get user behavior analysis
   */
  public getUserBehavior(userId: string): UserBehavior | null {
    return this.userBehaviors.get(userId) || null;
  }

  /**
   * Get content performance metrics
   */
  public getContentPerformance(documentUrn?: string): ContentPerformance[] {
    if (documentUrn) {
      const performance = this.contentPerformance.get(documentUrn);
      return performance ? [performance] : [];
    }

    return Array.from(this.contentPerformance.values())
      .sort((a, b) => b.viewCount - a.viewCount);
  }

  /**
   * Get search patterns
   */
  public getSearchPatterns(limit: number = 20): SearchPattern[] {
    return Array.from(this.patterns.values())
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, limit);
  }

  /**
   * Get personalized search suggestions
   */
  public getPersonalizedSuggestions(
    userId: string,
    currentQuery?: string
  ): string[] {
    const userBehavior = this.userBehaviors.get(userId);
    if (!userBehavior) {
      return this.getGenericSuggestions(currentQuery);
    }

    const suggestions: string[] = [];
    
    // Based on user's research domains
    userBehavior.researchDomains.forEach(domain => {
      suggestions.push(...this.getSuggestionsForDomain(domain));
    });

    // Based on user's preferred filters
    const preferredFilters = Object.keys(userBehavior.preferredFilters)
      .sort((a, b) => userBehavior.preferredFilters[b] - userBehavior.preferredFilters[a])
      .slice(0, 3);

    preferredFilters.forEach(filter => {
      suggestions.push(...this.getSuggestionsForFilter(filter));
    });

    // Remove duplicates and limit
    return [...new Set(suggestions)].slice(0, 10);
  }

  /**
   * Get trending search topics
   */
  public getTrendingTopics(timeframe: 'day' | 'week' | 'month' = 'week'): Array<{
    topic: string;
    searches: number;
    growth: number;
    users: number;
  }> {
    const now = new Date();
    const startTime = new Date();
    
    switch (timeframe) {
      case 'day':
        startTime.setDate(now.getDate() - 1);
        break;
      case 'week':
        startTime.setDate(now.getDate() - 7);
        break;
      case 'month':
        startTime.setDate(now.getDate() - 30);
        break;
    }

    const recentEvents = this.events.filter(event => 
      event.eventType === 'search' && 
      event.timestamp >= startTime &&
      event.searchQuery
    );

    const topicCounts: Record<string, { searches: number; users: Set<string> }> = {};
    
    recentEvents.forEach(event => {
      const topics = this.extractTopicsFromQuery(event.searchQuery!);
      topics.forEach(topic => {
        if (!topicCounts[topic]) {
          topicCounts[topic] = { searches: 0, users: new Set() };
        }
        topicCounts[topic].searches++;
        topicCounts[topic].users.add(event.userId || event.sessionId);
      });
    });

    return Object.entries(topicCounts)
      .map(([topic, data]) => ({
        topic,
        searches: data.searches,
        growth: this.calculateTopicGrowth(topic, timeframe),
        users: data.users.size
      }))
      .sort((a, b) => b.searches - a.searches)
      .slice(0, 10);
  }

  /**
   * Generate analytics report
   */
  public generateAnalyticsReport(timeRange: {
    start: Date;
    end: Date;
  }): {
    summary: SearchInsights;
    userAnalysis: Array<{
      segment: string;
      count: number;
      avgEngagement: number;
      topQueries: string[];
    }>;
    contentAnalysis: Array<{
      type: DocumentType;
      totalViews: number;
      avgCTR: number;
      topDocuments: ContentPerformance[];
    }>;
    recommendations: {
      searchOptimization: string[];
      contentStrategy: string[];
      userExperience: string[];
    };
  } {
    const summary = this.getSearchInsights(timeRange);
    
    const userAnalysis = this.generateUserAnalysis();
    const contentAnalysis = this.generateContentAnalysis();
    const recommendations = this.generateRecommendations(summary);

    return {
      summary,
      userAnalysis,
      contentAnalysis,
      recommendations
    };
  }

  /**
   * Export analytics data
   */
  public exportAnalyticsData(
    format: 'csv' | 'json' | 'xlsx',
    timeRange: { start: Date; end: Date }
  ): string {
    const filteredEvents = this.events.filter(event => 
      event.timestamp >= timeRange.start && event.timestamp <= timeRange.end
    );

    switch (format) {
      case 'json':
        return JSON.stringify({
          events: filteredEvents,
          patterns: Array.from(this.patterns.entries()),
          userBehaviors: Array.from(this.userBehaviors.entries()),
          contentPerformance: Array.from(this.contentPerformance.entries())
        }, null, 2);

      case 'csv':
        return this.convertToCSV(filteredEvents);

      default:
        return JSON.stringify(filteredEvents);
    }
  }

  // Private helper methods

  private initializeAnalytics(): void {
    // Initialize with sample data if no existing data
    if (this.events.length === 0) {
      this.generateSampleData();
    }
  }

  private addEvent(event: SearchEvent): void {
    this.events.push(event);
    
    // Keep only last 10,000 events to manage memory
    if (this.events.length > 10000) {
      this.events = this.events.slice(-10000);
    }
  }

  private updateSearchPattern(query: string, event: SearchEvent): void {
    const normalizedQuery = query.toLowerCase().trim();
    const existing = this.patterns.get(normalizedQuery);
    
    if (existing) {
      existing.frequency++;
      existing.avgResultCount = (existing.avgResultCount + (event.resultCount || 0)) / 2;
      existing.avgResponseTime = (existing.avgResponseTime + (event.responseTime || 0)) / 2;
      
      // Update time distribution
      const hour = event.timestamp.getHours();
      existing.timeDistribution[hour] = (existing.timeDistribution[hour] || 0) + 1;
      
      // Update filters
      if (event.filters) {
        Object.keys(event.filters).forEach(filter => {
          existing.popularFilters[filter] = (existing.popularFilters[filter] || 0) + 1;
        });
      }
    } else {
      const newPattern: SearchPattern = {
        pattern: normalizedQuery,
        frequency: 1,
        successRate: (event.resultCount || 0) > 0 ? 1 : 0,
        avgResultCount: event.resultCount || 0,
        avgResponseTime: event.responseTime || 0,
        popularFilters: event.filters ? { ...event.filters } : {},
        timeDistribution: { [event.timestamp.getHours()]: 1 },
        seasonality: { [event.timestamp.getMonth()]: 1 },
        userSegments: {}
      };
      
      this.patterns.set(normalizedQuery, newPattern);
    }
  }

  private updateUserBehavior(sessionId: string, userId?: string, event?: SearchEvent): void {
    const id = userId || sessionId;
    const existing = this.userBehaviors.get(id);
    
    if (existing) {
      existing.totalSearches++;
      existing.lastActivity = new Date();
      
      if (event?.filters) {
        Object.keys(event.filters).forEach(filter => {
          existing.preferredFilters[filter] = (existing.preferredFilters[filter] || 0) + 1;
        });
      }
    } else {
      const newBehavior: UserBehavior = {
        userId: id,
        sessionCount: 1,
        totalSearches: 1,
        avgSessionDuration: 0,
        preferredFilters: event?.filters || {},
        searchComplexity: this.determineSearchComplexity(event?.searchQuery || ''),
        researchDomains: this.extractResearchDomains(event?.searchQuery || ''),
        clickThroughRate: 0,
        bookmarkRate: 0,
        exportActivity: {},
        lastActivity: new Date(),
        engagement: 'medium'
      };
      
      this.userBehaviors.set(id, newBehavior);
    }
  }

  private updateContentPerformance(documentUrn: string, interactionType: string): void {
    const existing = this.contentPerformance.get(documentUrn);
    
    if (existing) {
      existing.viewCount++;
      existing.lastAccessed = new Date();
      
      switch (interactionType) {
        case 'bookmark':
          existing.bookmarkCount++;
          break;
        case 'share':
          existing.shareCount++;
          break;
        case 'download':
          existing.downloadCount++;
          break;
      }
    } else {
      const newPerformance: ContentPerformance = {
        documentUrn,
        title: `Document ${documentUrn}`,
        type: 'lei', // Default type
        viewCount: 1,
        clickThroughRate: 0,
        avgTimeOnDocument: 0,
        bookmarkCount: interactionType === 'bookmark' ? 1 : 0,
        shareCount: interactionType === 'share' ? 1 : 0,
        downloadCount: interactionType === 'download' ? 1 : 0,
        searchAppearances: 0,
        relevanceScore: 0.5,
        lastAccessed: new Date()
      };
      
      this.contentPerformance.set(documentUrn, newPerformance);
    }
  }

  private calculatePopularQueries(searchEvents: SearchEvent[]): Array<{ query: string; count: number; successRate: number }> {
    const queryCounts: Record<string, { count: number; successes: number }> = {};
    
    searchEvents.forEach(event => {
      if (event.searchQuery) {
        const query = event.searchQuery.toLowerCase();
        if (!queryCounts[query]) {
          queryCounts[query] = { count: 0, successes: 0 };
        }
        queryCounts[query].count++;
        if ((event.resultCount || 0) > 0) {
          queryCounts[query].successes++;
        }
      }
    });

    return Object.entries(queryCounts)
      .map(([query, data]) => ({
        query,
        count: data.count,
        successRate: data.count > 0 ? data.successes / data.count : 0
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  private identifyEmergingTopics(searchEvents: SearchEvent[]): Array<{ topic: string; growth: number; timeframe: string }> {
    // Simple implementation - identify topics with increasing frequency
    const topicGrowth: Record<string, number[]> = {};
    
    searchEvents.forEach(event => {
      if (event.searchQuery) {
        const topics = this.extractTopicsFromQuery(event.searchQuery);
        topics.forEach(topic => {
          if (!topicGrowth[topic]) {
            topicGrowth[topic] = [];
          }
          topicGrowth[topic].push(event.timestamp.getTime());
        });
      }
    });

    return Object.entries(topicGrowth)
      .map(([topic, timestamps]) => ({
        topic,
        growth: this.calculateGrowthRate(timestamps),
        timeframe: 'week'
      }))
      .filter(item => item.growth > 0.1)
      .sort((a, b) => b.growth - a.growth)
      .slice(0, 5);
  }

  private analyzeUserSegmentation(events: SearchEvent[]) {
    // Mock user segmentation
    return {
      researchers: Math.floor(Math.random() * 100) + 50,
      professionals: Math.floor(Math.random() * 150) + 100,
      students: Math.floor(Math.random() * 200) + 150,
      public: Math.floor(Math.random() * 50) + 25
    };
  }

  private analyzeGeographicDistribution(events: SearchEvent[]) {
    // Mock geographic distribution
    return [
      { region: 'Sudeste', searches: Math.floor(Math.random() * 500) + 300, users: Math.floor(Math.random() * 100) + 60 },
      { region: 'Sul', searches: Math.floor(Math.random() * 300) + 200, users: Math.floor(Math.random() * 80) + 40 },
      { region: 'Nordeste', searches: Math.floor(Math.random() * 400) + 250, users: Math.floor(Math.random() * 90) + 50 },
      { region: 'Norte', searches: Math.floor(Math.random() * 200) + 100, users: Math.floor(Math.random() * 60) + 30 },
      { region: 'Centro-Oeste', searches: Math.floor(Math.random() * 250) + 150, users: Math.floor(Math.random() * 70) + 35 }
    ];
  }

  private analyzeTemporalTrends(events: SearchEvent[]) {
    const dailyTrends: Record<string, { searches: number; users: Set<string> }> = {};
    
    events.forEach(event => {
      const date = event.timestamp.toDateString();
      if (!dailyTrends[date]) {
        dailyTrends[date] = { searches: 0, users: new Set() };
      }
      dailyTrends[date].searches++;
      dailyTrends[date].users.add(event.userId || event.sessionId);
    });

    return Object.entries(dailyTrends)
      .map(([date, data]) => ({
        date: new Date(date),
        searches: data.searches,
        users: data.users.size
      }))
      .sort((a, b) => a.date.getTime() - b.date.getTime());
  }

  private calculatePerformanceMetrics(searchEvents: SearchEvent[]) {
    const responseTimes = searchEvents
      .filter(event => event.responseTime)
      .map(event => event.responseTime!);

    return {
      avgLoadTime: responseTimes.length > 0 ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length : 0,
      errorRate: Math.random() * 0.05, // Mock error rate
      cacheHitRate: 0.75 + Math.random() * 0.2, // Mock cache hit rate
      systemUptime: 0.995 + Math.random() * 0.004 // Mock uptime
    };
  }

  private calculateSuccessRate(searchEvents: SearchEvent[]): number {
    const successfulSearches = searchEvents.filter(event => (event.resultCount || 0) > 0).length;
    return searchEvents.length > 0 ? successfulSearches / searchEvents.length : 0;
  }

  private calculateAverageResponseTime(searchEvents: SearchEvent[]): number {
    const responseTimes = searchEvents
      .filter(event => event.responseTime)
      .map(event => event.responseTime!);
    
    return responseTimes.length > 0 ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length : 0;
  }

  private extractTopicsFromQuery(query: string): string[] {
    const topics = [];
    const transportTerms = ['transporte', 'mobilidade', 'rodoviário', 'ferroviário', 'aéreo', 'aquaviário'];
    const legalTerms = ['lei', 'decreto', 'portaria', 'resolução'];
    
    transportTerms.forEach(term => {
      if (query.toLowerCase().includes(term)) {
        topics.push(term);
      }
    });
    
    legalTerms.forEach(term => {
      if (query.toLowerCase().includes(term)) {
        topics.push(term);
      }
    });
    
    return topics;
  }

  private calculateTopicGrowth(topic: string, timeframe: string): number {
    // Mock growth calculation
    return Math.random() * 0.5;
  }

  private determineSearchComplexity(query: string): 'basic' | 'intermediate' | 'advanced' {
    if (query.length < 20 && !query.includes('AND') && !query.includes('OR')) {
      return 'basic';
    }
    if (query.includes('AND') || query.includes('OR') || query.includes('"')) {
      return 'advanced';
    }
    return 'intermediate';
  }

  private extractResearchDomains(query: string): string[] {
    const domains = [];
    if (query.toLowerCase().includes('transport')) domains.push('transport');
    if (query.toLowerCase().includes('environment')) domains.push('environment');
    if (query.toLowerCase().includes('urban')) domains.push('urban_planning');
    return domains;
  }

  private calculateGrowthRate(timestamps: number[]): number {
    if (timestamps.length < 2) return 0;
    
    timestamps.sort((a, b) => a - b);
    const firstHalf = timestamps.slice(0, Math.floor(timestamps.length / 2));
    const secondHalf = timestamps.slice(Math.floor(timestamps.length / 2));
    
    return secondHalf.length > firstHalf.length ? (secondHalf.length - firstHalf.length) / firstHalf.length : 0;
  }

  private getGenericSuggestions(currentQuery?: string): string[] {
    return [
      'transporte urbano sustentável',
      'marco legal transportes',
      'segurança no trânsito',
      'mobilidade metropolitana',
      'infraestrutura rodoviária'
    ];
  }

  private getSuggestionsForDomain(domain: string): string[] {
    const domainSuggestions: Record<string, string[]> = {
      transport: ['modal rodoviário', 'transporte de cargas', 'logística urbana'],
      environment: ['sustentabilidade ambiental', 'emissões veiculares', 'impacto ambiental'],
      urban_planning: ['planejamento urbano', 'zoneamento', 'desenvolvimento urbano']
    };
    
    return domainSuggestions[domain] || [];
  }

  private getSuggestionsForFilter(filter: string): string[] {
    // Mock suggestions based on filters
    return [`suggestion for ${filter}`];
  }

  private generateUserAnalysis() {
    return [
      {
        segment: 'Academic Researchers',
        count: 150,
        avgEngagement: 0.8,
        topQueries: ['transport policy', 'regulatory framework', 'impact analysis']
      },
      {
        segment: 'Legal Professionals',
        count: 200,
        avgEngagement: 0.9,
        topQueries: ['jurisprudence', 'legal precedent', 'regulatory compliance']
      },
      {
        segment: 'Policy Makers',
        count: 75,
        avgEngagement: 0.85,
        topQueries: ['policy development', 'legislative trends', 'regulatory impact']
      }
    ];
  }

  private generateContentAnalysis() {
    const documentTypes: DocumentType[] = ['lei', 'decreto', 'portaria', 'resolucao'];
    
    return documentTypes.map(type => ({
      type,
      totalViews: Math.floor(Math.random() * 1000) + 500,
      avgCTR: Math.random() * 0.3 + 0.1,
      topDocuments: Array.from(this.contentPerformance.values())
        .filter(doc => doc.type === type)
        .slice(0, 5)
    }));
  }

  private generateRecommendations(insights: SearchInsights) {
    return {
      searchOptimization: [
        'Improve response time for complex queries',
        'Enhance semantic search capabilities',
        'Add more transport-specific filters'
      ],
      contentStrategy: [
        'Focus on high-demand legal document types',
        'Improve metadata quality for better discoverability',
        'Add more recent transport legislation'
      ],
      userExperience: [
        'Simplify advanced search interface',
        'Add guided search tutorials',
        'Improve mobile search experience'
      ]
    };
  }

  private convertToCSV(events: SearchEvent[]): string {
    const headers = ['timestamp', 'eventType', 'searchQuery', 'resultCount', 'responseTime', 'userId'];
    const rows = events.map(event => [
      event.timestamp.toISOString(),
      event.eventType,
      event.searchQuery || '',
      event.resultCount || 0,
      event.responseTime || 0,
      event.userId || event.sessionId
    ]);
    
    return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
  }

  private generateSampleData(): void {
    // Generate sample events for demonstration
    const sampleQueries = [
      'transporte urbano',
      'marco legal cargas',
      'segurança viária',
      'mobilidade sustentável',
      'infraestrutura rodoviária'
    ];

    for (let i = 0; i < 100; i++) {
      const query = sampleQueries[Math.floor(Math.random() * sampleQueries.length)];
      this.trackSearch({
        sessionId: `session_${i}`,
        userId: `user_${Math.floor(i / 3)}`,
        query,
        resultCount: Math.floor(Math.random() * 50) + 1,
        responseTime: Math.floor(Math.random() * 2000) + 500
      });
    }
  }
}

export const searchAnalyticsService = SearchAnalyticsService.getInstance();