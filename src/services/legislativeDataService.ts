import { loadCSVLegislativeData } from '../data/csv-legislative-data';
import { LegislativeDocument, SearchFilters, DocumentType, DocumentStatus, CollectionLog } from '../types';
import apiClient from './apiClient';
import { getApiBaseUrl } from '../config/api';
import { multiLayerCache } from './multiLayerCache';

// Check environment variables for data source configuration
const forceCSVOnly = import.meta.env.VITE_FORCE_CSV_ONLY === 'true';

export class LegislativeDataService {
  private static instance: LegislativeDataService;
  private csvDataCache: LegislativeDocument[] | null = null;
  private requestCache = new Map<string, Promise<{ documents: LegislativeDocument[], usingFallback: boolean }>>();
  
  // Cache key prefixes for different data types
  private static readonly CACHE_KEYS = {
    DOCUMENTS: 'legislative_docs',
    SEARCH_RESULTS: 'search_results',
    DOCUMENT_BY_ID: 'document_id',
    COLLECTION_STATUS: 'collection_status',
    LATEST_COLLECTION: 'latest_collection',
    CSV_DATA: 'csv_data'
  } as const;
  
  private constructor() {}
  
  static getInstance(): LegislativeDataService {
    if (!LegislativeDataService.instance) {
      LegislativeDataService.instance = new LegislativeDataService();
    }
    return LegislativeDataService.instance;
  }
  
  private async testBackendConnectivity(): Promise<{ available: boolean; reason?: string }> {
    try {
      // Quick health check with short timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
      
      const baseUrl = getApiBaseUrl();
      
      const response = await fetch(`${baseUrl}/health`, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        return { available: true };
      } else {
        return { available: false, reason: `HTTP ${response.status}` };
      }
    } catch (error) {
      console.log(`Backend connectivity check failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { available: false, reason: 'Connection failed' };
    }
  }
  
  private async getLocalCsvData(): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    // Check multi-layer cache first
    const cacheKey = LegislativeDataService.CACHE_KEYS.CSV_DATA;
    const cachedData = await multiLayerCache.get<{ documents: LegislativeDocument[], usingFallback: boolean }>(cacheKey);
    
    if (cachedData) {
      console.log('📦 Using multi-layer cached CSV data');
      return cachedData;
    }
    
    // Fallback to memory cache
    if (this.csvDataCache && this.csvDataCache.length > 0) {
      console.log('Using in-memory cached real CSV data.');
      const result = { documents: this.csvDataCache, usingFallback: true };
      // Store in multi-layer cache for future use
      await multiLayerCache.set(cacheKey, result, 24 * 60 * 60 * 1000); // 24 hours
      return result;
    }

    try {
      console.log('Attempting to load real CSV legislative data...');
      const csvDocs = await loadCSVLegislativeData();
      if (csvDocs && Array.isArray(csvDocs) && csvDocs.length > 0) {
        console.log(`Loaded ${csvDocs.length} real documents from CSV`);
        this.csvDataCache = csvDocs;
        const result = { documents: csvDocs, usingFallback: true };
        
        // Cache the result in multi-layer cache
        await multiLayerCache.set(cacheKey, result, 24 * 60 * 60 * 1000); // 24 hours
        
        return result;
      }
      throw new Error('CSV file was loaded but contained no documents or invalid data.');
    } catch (error) {
      console.error('Critical error: Failed to load or parse real CSV data.', error);
      console.error('🚨 NO MOCK FALLBACK: Academic integrity requires real data sources only');
      // NO MOCK FALLBACK - return empty array to force proper error handling
      throw new Error(`Cannot load legislative data: ${error instanceof Error ? error.message : 'Unknown CSV error'}. Real data source required.`);
    }
  }
  
  async fetchDocuments(filters?: SearchFilters): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    // Generate cache key from filters
    const filterKey = JSON.stringify(filters || {});
    const cacheKey = `${LegislativeDataService.CACHE_KEYS.DOCUMENTS}_${filterKey}`;
    
    // Check multi-layer cache first
    const cachedResult = await multiLayerCache.get<{ documents: LegislativeDocument[], usingFallback: boolean }>(
      cacheKey,
      async () => {
        console.log('🔄 Cache miss - fetching fresh data');
        return await this._performFetch(filters);
      }
    );
    
    if (cachedResult) {
      console.log('🎯 Cache hit - returning cached documents');
      return cachedResult;
    }
    
    // Fallback to request deduplication for concurrent requests
    if (this.requestCache.has(filterKey)) {
      console.log('⚡ Request deduped: Using existing pending request');
      return this.requestCache.get(filterKey)!;
    }

    // Create new request
    const requestPromise = this._performFetch(filters);
    
    // Cache the promise for deduplication
    this.requestCache.set(filterKey, requestPromise);
    console.log(`📊 Active requests: ${this.requestCache.size}`);
    
    // Auto-cleanup after completion and cache result
    requestPromise.then(async (result) => {
      // Cache the successful result
      await multiLayerCache.set(cacheKey, result, 10 * 60 * 1000); // 10 minutes for API results
    }).finally(() => {
      this.requestCache.delete(filterKey);
      console.log(`🧹 Cache cleanup - Active requests: ${this.requestCache.size}`);
    });
    
    return requestPromise;
  }

  private async _performFetch(filters?: SearchFilters): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    if (forceCSVOnly) {
      console.log('Force CSV-only mode. Using real CSV data exclusively.');
      try {
        const localData = await this.getLocalCsvData();
        return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
      } catch (error) {
        console.error('Failed to load CSV data in CSV-only mode:', error);
        throw error; // Don't hide CSV loading errors
      }
    }
    
    try {
      console.log('🔬 Connecting to LexML Enhanced Research Engine...');
      
      // Quick connectivity test first
      const healthCheck = await this.testBackendConnectivity();
      
      if (healthCheck.available) {
        console.log('✅ Backend connectivity confirmed, proceeding with enhanced search...');
        
        const params = this.buildQueryParams(filters);
        
        // Add LexML-specific parameters for vocabulary enhancement
        const enhancedParams = {
          ...params,
          sources: 'lexml,camara,senado,planalto'  // Prioritize LexML
        };
        
        console.log('🔍 API Search Parameters:', enhancedParams);
        
        const response = await apiClient.get<any>('/search', enhancedParams);
        
        console.log('📡 API Response Analysis:');
        console.log('  - Query:', response?.query);
        console.log('  - Total Count:', response?.total_count);
        console.log('  - Results Length:', response?.results?.length || 0);
        console.log('  - Sources:', response?.sources);
        console.log('  - Enhanced Search:', response?.enhanced_search);
        console.log('  - Filters Applied:', response?.filters);
        console.log('  - Metadata:', response?.metadata);
        
        if (response?.total_count === 0) {
          console.warn('🚨 Backend API found 0 results for query:', response?.query);
          console.log('🔧 This suggests the backend search needs investigation');
        }
        const documents = this.transformSearchResponse(response);
        
        if (documents.length === 0) {
          console.warn('🔄 Enhanced API returned no results, falling back to embedded real data');
          const localData = await this.getLocalCsvData();
          return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
        }
        
        // Log vocabulary enhancement information
        if (response.metadata?.vocabulary_expansion) {
          console.log(`📚 Vocabulary enhanced search: '${response.metadata.vocabulary_expansion.original_term}' → ${response.metadata.vocabulary_expansion.expansion_count} terms`);
        }
        
        console.log(`✅ Successfully fetched ${documents.length} documents from LexML Enhanced API`);
        return { documents: documents, usingFallback: false };
      } else {
        console.warn('⚠️ Backend not available, using embedded real data immediately');
        const localData = await this.getLocalCsvData();
        return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
      }
    } catch (error) {
      console.warn('⚠️ Enhanced API fetch failed, attempting fallback to embedded real data:', error);
      try {
        const localData = await this.getLocalCsvData();
        return { documents: this.filterLocalData(localData.documents, filters), usingFallback: localData.usingFallback };
      } catch (csvError) {
        console.error('❌ Both Enhanced API and embedded data sources failed:', { apiError: error, csvError });
        throw new Error('Unable to load legislative data from any real source (Enhanced API or embedded data). Please check data availability.');
      }
    }
  }
  
  async fetchDocumentById(id: string): Promise<LegislativeDocument | null> {
    const cacheKey = `${LegislativeDataService.CACHE_KEYS.DOCUMENT_BY_ID}_${id}`;
    
    // Check cache first
    const cachedDoc = await multiLayerCache.get<LegislativeDocument>(cacheKey);
    if (cachedDoc) {
      console.log(`🎯 Cache hit for document ID: ${id}`);
      return cachedDoc;
    }
    
    // Fetch from all documents if not cached
    const allDocs = await this.fetchDocuments();
    const document = allDocs.documents.find(doc => doc.id === id) || null;
    
    // Cache the result if found
    if (document) {
      await multiLayerCache.set(cacheKey, document, 30 * 60 * 1000); // 30 minutes
    }
    
    return document;
  }
  
  async searchDocuments(searchTerm: string): Promise<LegislativeDocument[]> {
    const cacheKey = `${LegislativeDataService.CACHE_KEYS.SEARCH_RESULTS}_${searchTerm.toLowerCase()}`;
    
    // Check cache first
    const cachedResults = await multiLayerCache.get<LegislativeDocument[]>(cacheKey);
    if (cachedResults) {
      console.log(`🎯 Cache hit for search term: ${searchTerm}`);
      return cachedResults;
    }
    
    // Perform search
    const allDocs = await this.fetchDocuments();
    const lowerSearchTerm = searchTerm.toLowerCase();
    const results = allDocs.documents.filter(doc => 
      doc.title.toLowerCase().includes(lowerSearchTerm) ||
      doc.summary.toLowerCase().includes(lowerSearchTerm) ||
      (doc.keywords && doc.keywords.some(keyword => keyword.toLowerCase().includes(lowerSearchTerm)))
    );
    
    // Cache the results
    await multiLayerCache.set(cacheKey, results, 15 * 60 * 1000); // 15 minutes
    
    return results;
  }
  
  private filterLocalData(data: LegislativeDocument[], filters?: SearchFilters): LegislativeDocument[] {
    if (!filters) return data;
    
    return data.filter(doc => {
      if (filters.searchTerm && 
          !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) &&
          !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase()) &&
          !doc.keywords.some(keyword => keyword.toLowerCase().includes(filters.searchTerm.toLowerCase()))) {
        return false;
      }
      
      if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
        return false;
      }
      
      if (filters.states.length > 0 && doc.state && !filters.states.includes(doc.state)) {
        return false;
      }
      
      if (filters.municipalities.length > 0 && doc.municipality && !filters.municipalities.includes(doc.municipality)) {
        return false;
      }
      
      if (filters.chambers.length > 0 && doc.chamber && !filters.chambers.includes(doc.chamber)) {
        return false;
      }
      
      if (filters.dateFrom && new Date(doc.date) < filters.dateFrom) {
        return false;
      }
      
      if (filters.dateTo && new Date(doc.date) > filters.dateTo) {
        return false;
      }
      
      return true;
    });
  }
  
  private buildQueryParams(filters?: SearchFilters): Record<string, string> {
    const params: Record<string, string> = {};
    
    // q parameter is required - use a default if not provided
    params.q = filters?.searchTerm || 'transporte';
    
    if (filters?.states && filters.states.length > 0) {
      params.states = filters.states.join(',');
    }
    if (filters?.dateFrom) {
      params.start_date = this.formatDate(filters.dateFrom);
    }
    if (filters?.dateTo) {
      params.end_date = this.formatDate(filters.dateTo);
    }
    
    // Add default sources (can be made configurable later)
    params.sources = 'CAMARA,SENADO,PLANALTO';
    
    return params;
  }
  
  private formatDate(date: Date): string {
    return date.toISOString().split('T')[0]; // YYYY-MM-DD format
  }
  
  private transformSearchResponse(response: any): LegislativeDocument[] {
    if (!response.results || !Array.isArray(response.results)) {
      return [];
    }
    return response.results.map((item: any) => this.transformProposition(item));
  }
  
  private transformProposition(prop: any): LegislativeDocument {
    // Map backend Proposition to frontend LegislativeDocument
    const documentTypeMap: Record<string, DocumentType> = {
      'PL': 'projeto_lei',
      'PLP': 'projeto_lei',
      'PEC': 'projeto_lei',
      'MPV': 'medida_provisoria',
      'PLV': 'projeto_lei',
      'PDL': 'decreto',
      'PRC': 'resolucao',
      'DECRETO': 'decreto',
      'PORTARIA': 'portaria',
      'RESOLUCAO': 'resolucao',
      'INSTRUCAO_NORMATIVA': 'instrucao_normativa',
      'LEI': 'lei'
    };
    
    const statusMap: Record<string, DocumentStatus> = {
      'ACTIVE': 'em_tramitacao',
      'APPROVED': 'aprovado',
      'REJECTED': 'rejeitado',
      'ARCHIVED': 'arquivado',
      'WITHDRAWN': 'arquivado',
      'PUBLISHED': 'sancionado'
    };
    
    // Extract state from authors if available
    let state = '';
    if (prop.authors && Array.isArray(prop.authors) && prop.authors.length > 0) {
      state = prop.authors[0].state || '';
    }
    
    return {
      id: prop.id,
      title: prop.title,
      summary: prop.summary || '',
      type: documentTypeMap[prop.type] || 'projeto_lei',
      date: prop.publication_date || prop.date || new Date().toISOString(),
      keywords: prop.keywords || [],
      state: state,
      municipality: prop.municipality || '',
      url: prop.url || '',
      status: statusMap[prop.status] || 'em_tramitacao',
      author: prop.authors?.[0]?.name || '',
      chamber: prop.source === 'CAMARA' ? 'Câmara dos Deputados' : prop.source === 'SENADO' ? 'Senado Federal' : '',
      number: prop.number,
      source: prop.source,
      citation: prop.citation
    };
  }
  
  async fetchCollectionStatus(): Promise<CollectionLog[]> {
    const cacheKey = LegislativeDataService.CACHE_KEYS.COLLECTION_STATUS;
    
    // Check cache first
    const cachedStatus = await multiLayerCache.get<CollectionLog[]>(cacheKey);
    if (cachedStatus) {
      console.log('🎯 Cache hit for collection status');
      return cachedStatus;
    }
    
    try {
      const response = await apiClient.get<any>('/collections/recent');
      const results = this.transformCollectionLogs(response);
      
      // Cache the results
      await multiLayerCache.set(cacheKey, results, 5 * 60 * 1000); // 5 minutes
      
      return results;
    } catch (error) {
      console.error('Failed to fetch collection status:', error);
      return [];
    }
  }
  
  async fetchLatestCollection(): Promise<CollectionLog | null> {
    const cacheKey = LegislativeDataService.CACHE_KEYS.LATEST_COLLECTION;
    
    // Check cache first
    const cachedLatest = await multiLayerCache.get<CollectionLog | null>(cacheKey);
    if (cachedLatest !== null) {
      console.log('🎯 Cache hit for latest collection');
      return cachedLatest;
    }
    
    try {
      const response = await apiClient.get<any>('/collections/latest');
      let result: CollectionLog | null = null;
      
      if (response && response.id) {
        result = this.transformCollectionLog(response);
      }
      
      // Cache the result (even if null)
      await multiLayerCache.set(cacheKey, result, 3 * 60 * 1000); // 3 minutes
      
      return result;
    } catch (error) {
      console.error('Failed to fetch latest collection:', error);
      return null;
    }
  }
  
  private transformCollectionLogs(response: any): CollectionLog[] {
    if (!response || !Array.isArray(response)) {
      return [];
    }
    return response.map(log => this.transformCollectionLog(log));
  }
  
  private transformCollectionLog(log: any): CollectionLog {
    return {
      id: log.id,
      searchTermId: log.search_term_id,
      searchTerm: log.search_term,
      status: log.status,
      recordsCollected: log.records_collected || 0,
      recordsNew: log.records_new || 0,
      recordsUpdated: log.records_updated || 0,
      recordsSkipped: log.records_skipped || 0,
      executionTimeMs: log.execution_time_ms || 0,
      errorMessage: log.error_message,
      startedAt: log.started_at,
      completedAt: log.completed_at,
      sourcesUsed: log.sources_used || []
    };
  }
  
  // Cache management methods
  async invalidateCache(type?: 'all' | 'documents' | 'search' | 'collections'): Promise<void> {
    const patterns: string[] = [];
    
    switch (type) {
      case 'documents':
        patterns.push(LegislativeDataService.CACHE_KEYS.DOCUMENTS);
        patterns.push(LegislativeDataService.CACHE_KEYS.DOCUMENT_BY_ID);
        patterns.push(LegislativeDataService.CACHE_KEYS.CSV_DATA);
        break;
      case 'search':
        patterns.push(LegislativeDataService.CACHE_KEYS.SEARCH_RESULTS);
        break;
      case 'collections':
        patterns.push(LegislativeDataService.CACHE_KEYS.COLLECTION_STATUS);
        patterns.push(LegislativeDataService.CACHE_KEYS.LATEST_COLLECTION);
        break;
      case 'all':
      default:
        // Clear all cache layers
        await multiLayerCache.clear();
        console.log('🧹 All caches cleared');
        return;
    }
    
    // For specific types, we'd need a pattern-based deletion
    // For now, clear all since multiLayerCache doesn't support pattern deletion
    console.log(`🧹 Invalidating cache for type: ${type}`);
    await multiLayerCache.clear();
  }
  
  async getCacheStats() {
    return multiLayerCache.getStats();
  }
  
  async getCacheSizes() {
    return multiLayerCache.getCacheSizes();
  }
  
  // Force refresh specific data
  async forceRefreshDocuments(filters?: SearchFilters): Promise<{ documents: LegislativeDocument[], usingFallback: boolean }> {
    const filterKey = JSON.stringify(filters || {});
    const cacheKey = `${LegislativeDataService.CACHE_KEYS.DOCUMENTS}_${filterKey}`;
    
    // Remove from cache
    await multiLayerCache.delete(cacheKey);
    
    // Fetch fresh data
    return this.fetchDocuments(filters);
  }
}

// Export singleton instance
export const legislativeDataService = LegislativeDataService.getInstance();