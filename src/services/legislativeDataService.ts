import { loadCSVLegislativeData } from '../data/csv-legislative-data';
import { LegislativeDocument, SearchFilters, DocumentType, DocumentStatus } from '../types';
import apiClient from './apiClient';
import { getApiBaseUrl } from '../config/api';

// Check environment variables for data source configuration
const forceCSVOnly = import.meta.env.VITE_FORCE_CSV_ONLY === 'true';

export class LegislativeDataService {
  private static instance: LegislativeDataService;
  private csvDataCache: LegislativeDocument[] | null = null;
  private requestCache = new Map<string, Promise<{ documents: LegislativeDocument[], usingFallback: boolean }>>();
  
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
    if (this.csvDataCache && this.csvDataCache.length > 0) {
      console.log('Using cached real CSV data.');
      return { documents: this.csvDataCache, usingFallback: true };
    }

    try {
      console.log('Attempting to load real CSV legislative data...');
      const csvDocs = await loadCSVLegislativeData();
      if (csvDocs && Array.isArray(csvDocs) && csvDocs.length > 0) {
        console.log(`Loaded ${csvDocs.length} real documents from CSV`);
        this.csvDataCache = csvDocs;
        return { documents: csvDocs, usingFallback: true };
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
    const cacheKey = JSON.stringify(filters || {});
    
    // Check if identical request is already in progress
    if (this.requestCache.has(cacheKey)) {
      console.log('⚡ Request deduped: Using existing pending request');
      return this.requestCache.get(cacheKey)!;
    }

    // Create new request
    const requestPromise = this._performFetch(filters);
    
    // Cache the promise
    this.requestCache.set(cacheKey, requestPromise);
    console.log(`📊 Active requests: ${this.requestCache.size}`);
    
    // Auto-cleanup after completion
    requestPromise.finally(() => {
      this.requestCache.delete(cacheKey);
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
        
        console.log('📡 API Response Details:');
        console.log('  - Status:', response?.status || 'unknown');
        console.log('  - Response Keys:', Object.keys(response || {}));
        console.log('  - Results field exists:', !!response?.results);
        console.log('  - Results length:', response?.results?.length || 0);
        console.log('  - Response.data exists:', !!response?.data);
        console.log('  - Response.documents exists:', !!response?.documents);
        console.log('  - Response.items exists:', !!response?.items);
        console.log('  - All response fields:');
        Object.keys(response || {}).forEach(key => {
          const value = response[key];
          console.log(`    ${key}:`, Array.isArray(value) ? `Array(${value.length})` : typeof value);
        });
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
    const allDocs = await this.fetchDocuments();
    return allDocs.documents.find(doc => doc.id === id) || null;
  }
  
  async searchDocuments(searchTerm: string): Promise<LegislativeDocument[]> {
    const allDocs = await this.fetchDocuments();
    const lowerSearchTerm = searchTerm.toLowerCase();
    return allDocs.documents.filter(doc => 
      doc.title.toLowerCase().includes(lowerSearchTerm) ||
      doc.summary.toLowerCase().includes(lowerSearchTerm) ||
      (doc.keywords && doc.keywords.some(keyword => keyword.toLowerCase().includes(lowerSearchTerm)))
    );
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
}

// Export singleton instance
export const legislativeDataService = LegislativeDataService.getInstance();