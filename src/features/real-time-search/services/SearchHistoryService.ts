/**
 * Search History Service
 * Manages user search history, saved queries, and intelligent query suggestions
 */

interface SearchHistoryEntry {
  id: string;
  query: string;
  cqlQuery?: string;
  filters: Record<string, any>;
  timestamp: number;
  resultCount: number;
  searchTime: number;
  dataSource: 'live-api' | 'cached-api' | 'csv-fallback';
  userInteraction: {
    documentsViewed: number;
    timeSpent: number;
    exported: boolean;
    shared: boolean;
  };
}

interface SavedQuery {
  id: string;
  name: string;
  description?: string;
  query: string;
  cqlQuery?: string;
  filters: Record<string, any>;
  category: 'research' | 'monitoring' | 'analysis' | 'custom';
  tags: string[];
  isPublic: boolean;
  createdAt: number;
  lastUsed: number;
  useCount: number;
  creator?: string;
}

interface QueryTemplate {
  id: string;
  name: string;
  description: string;
  cqlTemplate: string;
  parameters: Array<{
    name: string;
    type: 'text' | 'select' | 'date' | 'multiselect';
    label: string;
    placeholder?: string;
    options?: Array<{ value: string; label: string }>;
    required: boolean;
  }>;
  category: string;
  popularity: number;
}

interface SearchSuggestion {
  text: string;
  type: 'history' | 'saved' | 'template' | 'trending';
  frequency: number;
  lastUsed?: number;
  resultPreview?: {
    estimatedResults: number;
    recentResults: number;
    avgSearchTime: number;
  };
}

export class SearchHistoryService {
  private maxHistoryEntries = 1000;
  private maxSuggestions = 10;
  private storageKeys = {
    history: 'lexml_search_history',
    savedQueries: 'lexml_saved_queries',
    queryTemplates: 'lexml_query_templates',
    userPreferences: 'lexml_user_preferences'
  };

  constructor() {
    this.initializeDefaultTemplates();
    this.startPeriodicCleanup();
  }

  /**
   * Add a search to history
   */
  addToHistory(entry: Omit<SearchHistoryEntry, 'id' | 'timestamp'>): void {
    const historyEntry: SearchHistoryEntry = {
      ...entry,
      id: this.generateId(),
      timestamp: Date.now()
    };

    const history = this.getHistory();
    
    // Check for duplicate recent searches
    const isDuplicate = history.some(h => 
      h.query === entry.query && 
      JSON.stringify(h.filters) === JSON.stringify(entry.filters) &&
      Date.now() - h.timestamp < 300000 // 5 minutes
    );

    if (!isDuplicate) {
      history.unshift(historyEntry);
      
      // Keep only max entries
      if (history.length > this.maxHistoryEntries) {
        history.splice(this.maxHistoryEntries);
      }

      this.saveHistory(history);
      this.updateSearchMetrics(historyEntry);
    }
  }

  /**
   * Get search history with optional filtering
   */
  getHistory(options: {
    limit?: number;
    query?: string;
    dateFrom?: Date;
    dateTo?: Date;
    dataSource?: string;
  } = {}): SearchHistoryEntry[] {
    const history = this.loadHistory();
    let filtered = history;

    // Apply filters
    if (options.query) {
      const searchTerm = options.query.toLowerCase();
      filtered = filtered.filter(entry => 
        entry.query.toLowerCase().includes(searchTerm) ||
        (entry.cqlQuery && entry.cqlQuery.toLowerCase().includes(searchTerm))
      );
    }

    if (options.dateFrom) {
      filtered = filtered.filter(entry => entry.timestamp >= options.dateFrom!.getTime());
    }

    if (options.dateTo) {
      filtered = filtered.filter(entry => entry.timestamp <= options.dateTo!.getTime());
    }

    if (options.dataSource) {
      filtered = filtered.filter(entry => entry.dataSource === options.dataSource);
    }

    // Apply limit
    if (options.limit) {
      filtered = filtered.slice(0, options.limit);
    }

    return filtered;
  }

  /**
   * Save a query for later use
   */
  saveQuery(query: Omit<SavedQuery, 'id' | 'createdAt' | 'lastUsed' | 'useCount'>): string {
    const savedQuery: SavedQuery = {
      ...query,
      id: this.generateId(),
      createdAt: Date.now(),
      lastUsed: Date.now(),
      useCount: 0
    };

    const savedQueries = this.getSavedQueries();
    savedQueries.unshift(savedQuery);
    
    this.saveSavedQueries(savedQueries);
    return savedQuery.id;
  }

  /**
   * Get saved queries
   */
  getSavedQueries(category?: string): SavedQuery[] {
    const queries = this.loadSavedQueries();
    
    if (category) {
      return queries.filter(q => q.category === category);
    }
    
    return queries.sort((a, b) => b.lastUsed - a.lastUsed);
  }

  /**
   * Use a saved query (increment usage statistics)
   */
  useSavedQuery(queryId: string): SavedQuery | null {
    const queries = this.getSavedQueries();
    const query = queries.find(q => q.id === queryId);
    
    if (query) {
      query.lastUsed = Date.now();
      query.useCount++;
      this.saveSavedQueries(queries);
    }
    
    return query || null;
  }

  /**
   * Delete a saved query
   */
  deleteSavedQuery(queryId: string): boolean {
    const queries = this.getSavedQueries();
    const index = queries.findIndex(q => q.id === queryId);
    
    if (index !== -1) {
      queries.splice(index, 1);
      this.saveSavedQueries(queries);
      return true;
    }
    
    return false;
  }

  /**
   * Get intelligent search suggestions based on history and patterns
   */
  getSearchSuggestions(currentInput: string): SearchSuggestion[] {
    const suggestions: SearchSuggestion[] = [];
    const inputLower = currentInput.toLowerCase();

    if (inputLower.length < 2) {
      return this.getPopularSuggestions();
    }

    // History-based suggestions
    const historySuggestions = this.getHistorySuggestions(inputLower);
    suggestions.push(...historySuggestions);

    // Saved query suggestions
    const savedSuggestions = this.getSavedQuerySuggestions(inputLower);
    suggestions.push(...savedSuggestions);

    // Template suggestions
    const templateSuggestions = this.getTemplateSuggestions(inputLower);
    suggestions.push(...templateSuggestions);

    // Trending suggestions
    const trendingSuggestions = this.getTrendingSuggestions(inputLower);
    suggestions.push(...trendingSuggestions);

    // Remove duplicates and sort by relevance
    const uniqueSuggestions = this.deduplicateAndRank(suggestions);
    
    return uniqueSuggestions.slice(0, this.maxSuggestions);
  }

  /**
   * Get suggestions from search history
   */
  private getHistorySuggestions(input: string): SearchSuggestion[] {
    const history = this.getHistory({ limit: 100 });
    const suggestions: SearchSuggestion[] = [];
    
    for (const entry of history) {
      if (entry.query.toLowerCase().includes(input)) {
        const frequency = this.calculateQueryFrequency(entry.query);
        
        suggestions.push({
          text: entry.query,
          type: 'history',
          frequency,
          lastUsed: entry.timestamp,
          resultPreview: {
            estimatedResults: entry.resultCount,
            recentResults: entry.resultCount,
            avgSearchTime: entry.searchTime
          }
        });
      }
    }
    
    return suggestions;
  }

  /**
   * Get suggestions from saved queries
   */
  private getSavedQuerySuggestions(input: string): SearchSuggestion[] {
    const savedQueries = this.getSavedQueries();
    const suggestions: SearchSuggestion[] = [];
    
    for (const query of savedQueries) {
      if (query.name.toLowerCase().includes(input) || 
          query.query.toLowerCase().includes(input) ||
          query.description?.toLowerCase().includes(input)) {
        
        suggestions.push({
          text: query.name,
          type: 'saved',
          frequency: query.useCount,
          lastUsed: query.lastUsed
        });
      }
    }
    
    return suggestions;
  }

  /**
   * Get suggestions from query templates
   */
  private getTemplateSuggestions(input: string): SearchSuggestion[] {
    const templates = this.getQueryTemplates();
    const suggestions: SearchSuggestion[] = [];
    
    for (const template of templates) {
      if (template.name.toLowerCase().includes(input) || 
          template.description.toLowerCase().includes(input)) {
        
        suggestions.push({
          text: template.name,
          type: 'template',
          frequency: template.popularity
        });
      }
    }
    
    return suggestions;
  }

  /**
   * Get trending search suggestions
   */
  private getTrendingSuggestions(input: string): SearchSuggestion[] {
    // Analyze recent searches for trending patterns
    const recentHistory = this.getHistory({ 
      limit: 200,
      dateFrom: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // Last 7 days
    });

    const queryFrequency = new Map<string, number>();
    
    for (const entry of recentHistory) {
      const words = entry.query.toLowerCase().split(/\s+/);
      for (const word of words) {
        if (word.length > 3 && word.includes(input)) {
          queryFrequency.set(word, (queryFrequency.get(word) || 0) + 1);
        }
      }
    }

    const trending: SearchSuggestion[] = [];
    for (const [word, frequency] of queryFrequency.entries()) {
      if (frequency >= 3) { // Minimum frequency for trending
        trending.push({
          text: word,
          type: 'trending',
          frequency
        });
      }
    }

    return trending.sort((a, b) => b.frequency - a.frequency);
  }

  /**
   * Get popular suggestions when no input
   */
  private getPopularSuggestions(): SearchSuggestion[] {
    const history = this.getHistory({ limit: 100 });
    const queryCount = new Map<string, number>();
    
    for (const entry of history) {
      queryCount.set(entry.query, (queryCount.get(entry.query) || 0) + 1);
    }
    
    const popular = Array.from(queryCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([query, frequency]) => ({
        text: query,
        type: 'history' as const,
        frequency
      }));

    // Add some default popular searches
    const defaultSuggestions: SearchSuggestion[] = [
      { text: 'transporte urbano', type: 'trending', frequency: 10 },
      { text: 'mobilidade', type: 'trending', frequency: 8 },
      { text: 'trânsito', type: 'trending', frequency: 7 },
      { text: 'infraestrutura', type: 'trending', frequency: 6 }
    ];

    return [...popular, ...defaultSuggestions].slice(0, this.maxSuggestions);
  }

  /**
   * Calculate frequency of a query in history
   */
  private calculateQueryFrequency(query: string): number {
    const history = this.getHistory();
    return history.filter(entry => entry.query === query).length;
  }

  /**
   * Remove duplicates and rank suggestions
   */
  private deduplicateAndRank(suggestions: SearchSuggestion[]): SearchSuggestion[] {
    const uniqueMap = new Map<string, SearchSuggestion>();
    
    for (const suggestion of suggestions) {
      const existing = uniqueMap.get(suggestion.text);
      if (!existing || suggestion.frequency > existing.frequency) {
        uniqueMap.set(suggestion.text, suggestion);
      }
    }
    
    return Array.from(uniqueMap.values()).sort((a, b) => {
      // Sort by type priority first
      const typePriority = { saved: 4, history: 3, trending: 2, template: 1 };
      const priorityDiff = typePriority[b.type] - typePriority[a.type];
      
      if (priorityDiff !== 0) return priorityDiff;
      
      // Then by frequency
      return b.frequency - a.frequency;
    });
  }

  /**
   * Get query templates
   */
  getQueryTemplates(category?: string): QueryTemplate[] {
    const templates = this.loadQueryTemplates();
    
    if (category) {
      return templates.filter(t => t.category === category);
    }
    
    return templates.sort((a, b) => b.popularity - a.popularity);
  }

  /**
   * Create query from template with parameters
   */
  createQueryFromTemplate(templateId: string, parameters: Record<string, any>): string {
    const templates = this.getQueryTemplates();
    const template = templates.find(t => t.id === templateId);
    
    if (!template) {
      throw new Error(`Template not found: ${templateId}`);
    }
    
    let cqlQuery = template.cqlTemplate;
    
    // Replace parameters in template
    for (const [key, value] of Object.entries(parameters)) {
      const placeholder = `{{${key}}}`;
      cqlQuery = cqlQuery.replace(new RegExp(placeholder, 'g'), value);
    }
    
    // Update template popularity
    template.popularity++;
    this.saveQueryTemplates(this.getQueryTemplates());
    
    return cqlQuery;
  }

  /**
   * Initialize default query templates
   */
  private initializeDefaultTemplates(): void {
    const existing = this.loadQueryTemplates();
    if (existing.length > 0) return;

    const defaultTemplates: QueryTemplate[] = [
      {
        id: 'transport-laws',
        name: 'Transport Laws by Type',
        description: 'Find transportation legislation by document type and jurisdiction',
        cqlTemplate: 'tipoDocumento exact "{{docType}}" AND (title any "transporte" OR subject any "transporte") AND autoridade exact "{{authority}}"',
        parameters: [
          {
            name: 'docType',
            type: 'select',
            label: 'Document Type',
            options: [
              { value: 'Lei', label: 'Lei (Law)' },
              { value: 'Decreto', label: 'Decreto (Decree)' },
              { value: 'Portaria', label: 'Portaria (Ordinance)' }
            ],
            required: true
          },
          {
            name: 'authority',
            type: 'select',
            label: 'Authority Level',
            options: [
              { value: 'federal', label: 'Federal' },
              { value: 'estadual', label: 'State' },
              { value: 'municipal', label: 'Municipal' }
            ],
            required: true
          }
        ],
        category: 'Transportation',
        popularity: 0
      },
      {
        id: 'recent-legislation',
        name: 'Recent Legislation',
        description: 'Find recent legislation within a specific time period',
        cqlTemplate: 'date >= "{{startYear}}" AND date <= "{{endYear}}" AND ({{searchTerms}})',
        parameters: [
          {
            name: 'startYear',
            type: 'date',
            label: 'Start Year',
            placeholder: '2020',
            required: true
          },
          {
            name: 'endYear',
            type: 'date',
            label: 'End Year',
            placeholder: '2024',
            required: true
          },
          {
            name: 'searchTerms',
            type: 'text',
            label: 'Search Terms',
            placeholder: 'title any "keywords"',
            required: true
          }
        ],
        category: 'General',
        popularity: 0
      },
      {
        id: 'location-specific',
        name: 'Location-Specific Laws',
        description: 'Find legislation specific to a particular location',
        cqlTemplate: 'localidade any "{{location}}" AND ({{searchTerms}})',
        parameters: [
          {
            name: 'location',
            type: 'select',
            label: 'Location',
            options: [
              { value: 'sao.paulo', label: 'São Paulo' },
              { value: 'rio.de.janeiro', label: 'Rio de Janeiro' },
              { value: 'minas.gerais', label: 'Minas Gerais' },
              { value: 'distrito.federal', label: 'Distrito Federal' }
            ],
            required: true
          },
          {
            name: 'searchTerms',
            type: 'text',
            label: 'Search Terms',
            placeholder: 'title any "keywords"',
            required: true
          }
        ],
        category: 'Geographic',
        popularity: 0
      }
    ];

    this.saveQueryTemplates(defaultTemplates);
  }

  /**
   * Update search metrics and user behavior
   */
  private updateSearchMetrics(entry: SearchHistoryEntry): void {
    // Update session metrics
    const sessionMetrics = this.getSessionMetrics();
    sessionMetrics.searchCount = (sessionMetrics.searchCount || 0) + 1;
    sessionMetrics.totalSearchTime = (sessionMetrics.totalSearchTime || 0) + entry.searchTime;
    sessionMetrics.averageSearchTime = sessionMetrics.totalSearchTime / sessionMetrics.searchCount;
    
    this.saveSessionMetrics(sessionMetrics);
  }

  /**
   * Get session metrics
   */
  private getSessionMetrics(): any {
    try {
      const stored = sessionStorage.getItem('lexml_session_metrics');
      return stored ? JSON.parse(stored) : {};
    } catch {
      return {};
    }
  }

  /**
   * Save session metrics
   */
  private saveSessionMetrics(metrics: any): void {
    try {
      sessionStorage.setItem('lexml_session_metrics', JSON.stringify(metrics));
    } catch (error) {
      console.warn('Failed to save session metrics:', error);
    }
  }

  /**
   * Start periodic cleanup of old data
   */
  private startPeriodicCleanup(): void {
    // Clean up old history entries once per hour
    setInterval(() => {
      this.cleanupOldHistory();
    }, 60 * 60 * 1000);
  }

  /**
   * Clean up old history entries
   */
  private cleanupOldHistory(): void {
    const cutoffDate = Date.now() - (90 * 24 * 60 * 60 * 1000); // 90 days
    const history = this.getHistory();
    const filtered = history.filter(entry => entry.timestamp > cutoffDate);
    
    if (filtered.length !== history.length) {
      this.saveHistory(filtered);
    }
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Storage methods
  private loadHistory(): SearchHistoryEntry[] {
    try {
      const stored = localStorage.getItem(this.storageKeys.history);
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  }

  private saveHistory(history: SearchHistoryEntry[]): void {
    try {
      localStorage.setItem(this.storageKeys.history, JSON.stringify(history));
    } catch (error) {
      console.warn('Failed to save search history:', error);
    }
  }

  private loadSavedQueries(): SavedQuery[] {
    try {
      const stored = localStorage.getItem(this.storageKeys.savedQueries);
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  }

  private saveSavedQueries(queries: SavedQuery[]): void {
    try {
      localStorage.setItem(this.storageKeys.savedQueries, JSON.stringify(queries));
    } catch (error) {
      console.warn('Failed to save saved queries:', error);
    }
  }

  private loadQueryTemplates(): QueryTemplate[] {
    try {
      const stored = localStorage.getItem(this.storageKeys.queryTemplates);
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  }

  private saveQueryTemplates(templates: QueryTemplate[]): void {
    try {
      localStorage.setItem(this.storageKeys.queryTemplates, JSON.stringify(templates));
    } catch (error) {
      console.warn('Failed to save query templates:', error);
    }
  }

  /**
   * Export search history for backup
   */
  exportHistory(): string {
    const data = {
      history: this.getHistory(),
      savedQueries: this.getSavedQueries(),
      templates: this.getQueryTemplates(),
      exportedAt: new Date().toISOString()
    };
    
    return JSON.stringify(data, null, 2);
  }

  /**
   * Import search history from backup
   */
  importHistory(jsonData: string): boolean {
    try {
      const data = JSON.parse(jsonData);
      
      if (data.history) {
        this.saveHistory(data.history);
      }
      
      if (data.savedQueries) {
        this.saveSavedQueries(data.savedQueries);
      }
      
      if (data.templates) {
        this.saveQueryTemplates(data.templates);
      }
      
      return true;
    } catch (error) {
      console.error('Failed to import history:', error);
      return false;
    }
  }

  /**
   * Get search analytics
   */
  getAnalytics(days: number = 30): any {
    const cutoffDate = Date.now() - (days * 24 * 60 * 60 * 1000);
    const history = this.getHistory({ 
      dateFrom: new Date(cutoffDate) 
    });

    const analytics = {
      totalSearches: history.length,
      uniqueQueries: new Set(history.map(h => h.query)).size,
      averageResultCount: history.reduce((sum, h) => sum + h.resultCount, 0) / history.length || 0,
      averageSearchTime: history.reduce((sum, h) => sum + h.searchTime, 0) / history.length || 0,
      dataSourceBreakdown: {
        'live-api': history.filter(h => h.dataSource === 'live-api').length,
        'cached-api': history.filter(h => h.dataSource === 'cached-api').length,
        'csv-fallback': history.filter(h => h.dataSource === 'csv-fallback').length
      },
      topQueries: this.getTopQueries(history, 10),
      searchTrends: this.getSearchTrends(history)
    };

    return analytics;
  }

  private getTopQueries(history: SearchHistoryEntry[], limit: number): Array<{query: string, count: number}> {
    const queryCount = new Map<string, number>();
    
    for (const entry of history) {
      queryCount.set(entry.query, (queryCount.get(entry.query) || 0) + 1);
    }
    
    return Array.from(queryCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([query, count]) => ({ query, count }));
  }

  private getSearchTrends(history: SearchHistoryEntry[]): Array<{date: string, searches: number}> {
    const dailyCount = new Map<string, number>();
    
    for (const entry of history) {
      const date = new Date(entry.timestamp).toISOString().split('T')[0];
      dailyCount.set(date, (dailyCount.get(date) || 0) + 1);
    }
    
    return Array.from(dailyCount.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, searches]) => ({ date, searches }));
  }
}

// Global service instance
export const searchHistoryService = new SearchHistoryService();

// Export utility functions
export const addSearchToHistory = (query: string, results: any, searchTime: number) => {
  searchHistoryService.addToHistory({
    query,
    filters: {},
    resultCount: results.total_found || results.documents?.length || 0,
    searchTime,
    dataSource: results.data_source || 'live-api',
    userInteraction: {
      documentsViewed: 0,
      timeSpent: 0,
      exported: false,
      shared: false
    }
  });
};

export const getSearchSuggestions = (input: string) => {
  return searchHistoryService.getSearchSuggestions(input);
};

export const saveCurrentQuery = (name: string, query: string, filters: any, category: string = 'custom') => {
  return searchHistoryService.saveQuery({
    name,
    description: `Saved query: ${query}`,
    query,
    filters,
    category: category as any,
    tags: [],
    isPublic: false
  });
};