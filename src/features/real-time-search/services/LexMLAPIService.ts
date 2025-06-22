/**
 * LexML Brasil API service for frontend
 * Handles communication with backend LexML endpoints
 */

import { 
  LexMLSearchRequest, 
  LexMLSearchResponse, 
  SearchSuggestion,
  APIHealthStatus,
  DocumentContentResponse,
  SearchFilters,
  DataSource
} from '../types/lexml-api.types';

export class LexMLAPIService {
  private baseURL: string;
  private defaultTimeout = 10000; // 10 seconds
  
  constructor(baseURL: string = '') {
    // Handle different environments
    if (typeof window !== 'undefined') {
      // Browser environment
      this.baseURL = baseURL || window.location.origin;
    } else {
      // Server environment or build time
      this.baseURL = baseURL || 'http://localhost:8000';
    }
  }

  /**
   * Search LexML documents with live API integration
   */
  async searchDocuments(request: Partial<LexMLSearchRequest>): Promise<LexMLSearchResponse> {
    const searchParams = new URLSearchParams();
    
    // Add query parameters
    if (request.query) {
      searchParams.append('q', request.query);
    }
    
    if (request.cql_query) {
      searchParams.append('cql', request.cql_query);
    }
    
    // Add filters
    if (request.filters) {
      const filters = request.filters;
      
      if (filters.tipoDocumento.length > 0) {
        filters.tipoDocumento.forEach(tipo => {
          searchParams.append('tipo_documento', tipo);
        });
      }
      
      if (filters.autoridade.length > 0) {
        filters.autoridade.forEach(auth => {
          searchParams.append('autoridade', auth);
        });
      }
      
      if (filters.localidade.length > 0) {
        filters.localidade.forEach(loc => {
          searchParams.append('localidade', loc);
        });
      }
      
      if (filters.date_from) {
        searchParams.append('date_from', filters.date_from);
      }
      
      if (filters.date_to) {
        searchParams.append('date_to', filters.date_to);
      }
      
      if (filters.subject.length > 0) {
        filters.subject.forEach(subj => {
          searchParams.append('subject', subj);
        });
      }
    }
    
    // Add pagination
    if (request.start_record) {
      searchParams.append('start_record', request.start_record.toString());
    }
    
    if (request.max_records) {
      searchParams.append('max_records', request.max_records.toString());
    }
    
    if (request.include_content !== undefined) {
      searchParams.append('include_content', request.include_content.toString());
    }
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.defaultTimeout);
      
      const response = await fetch(`${this.baseURL}/api/lexml/search?${searchParams}`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`Search failed: ${response.status} ${response.statusText}`);
      }
      
      const result: LexMLSearchResponse = await response.json();
      
      // Add frontend-specific enhancements
      return {
        ...result,
        // Ensure we have proper defaults
        total_found: result.total_found || result.documents.length,
        cache_hit: result.cache_hit || false,
        api_status: result.api_status || 'unknown'
      };
      
    } catch (error) {
      console.error('LexML search error:', error);
      
      // Return fallback response on error
      return {
        documents: [],
        total_found: 0,
        start_record: request.start_record || 1,
        records_returned: 0,
        search_time_ms: 0,
        data_source: 'csv-fallback' as DataSource,
        cache_hit: false,
        api_status: 'error'
      };
    }
  }

  /**
   * Get search suggestions for auto-complete
   */
  async getSuggestions(term: string, maxSuggestions: number = 10): Promise<SearchSuggestion[]> {
    if (term.length < 2) {
      return [];
    }
    
    try {
      const response = await fetch(
        `${this.baseURL}/api/lexml/suggest?term=${encodeURIComponent(term)}&max_suggestions=${maxSuggestions}`,
        {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
          }
        }
      );
      
      if (!response.ok) {
        throw new Error(`Suggestions failed: ${response.status}`);
      }
      
      const result = await response.json();
      return result.suggestions || [];
      
    } catch (error) {
      console.error('Suggestions error:', error);
      return [];
    }
  }

  /**
   * Get full document content by URN
   */
  async getDocumentContent(urn: string): Promise<DocumentContentResponse | null> {
    try {
      const response = await fetch(
        `${this.baseURL}/api/lexml/document/${encodeURIComponent(urn)}`,
        {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
          }
        }
      );
      
      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`Document retrieval failed: ${response.status}`);
      }
      
      return await response.json();
      
    } catch (error) {
      console.error('Document content error:', error);
      return null;
    }
  }

  /**
   * Get API health status
   */
  async getHealthStatus(): Promise<APIHealthStatus | null> {
    try {
      const response = await fetch(`${this.baseURL}/api/lexml/health`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        }
      });
      
      if (!response.ok) {
        throw new Error(`Health check failed: ${response.status}`);
      }
      
      return await response.json();
      
    } catch (error) {
      console.error('Health check error:', error);
      return null;
    }
  }

  /**
   * Parse and validate CQL query
   */
  async parseCQLQuery(query: string): Promise<{ isValid: boolean; error?: string }> {
    try {
      const response = await fetch(`${this.baseURL}/api/lexml/cql/parse`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `query=${encodeURIComponent(query)}`
      });
      
      if (response.ok) {
        return { isValid: true };
      } else {
        const error = await response.json();
        return { isValid: false, error: error.detail };
      }
      
    } catch (error) {
      console.error('CQL parsing error:', error);
      return { isValid: false, error: 'Network error' };
    }
  }

  /**
   * Get common CQL patterns for legal research
   */
  async getCommonPatterns(): Promise<Record<string, string>> {
    try {
      const response = await fetch(`${this.baseURL}/api/lexml/patterns`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        }
      });
      
      if (!response.ok) {
        throw new Error(`Patterns failed: ${response.status}`);
      }
      
      const result = await response.json();
      return result.patterns || {};
      
    } catch (error) {
      console.error('Patterns error:', error);
      return {};
    }
  }

  /**
   * Build CQL query from search term and filters
   */
  buildSimpleQuery(searchTerm: string, filters?: Partial<SearchFilters>): string {
    const queryParts: string[] = [];
    
    // Main search term
    if (searchTerm.trim()) {
      queryParts.push(`title any "${searchTerm}" OR description any "${searchTerm}"`);
    }
    
    // Add filters if provided
    if (filters) {
      if (filters.tipoDocumento && filters.tipoDocumento.length > 0) {
        const typeQueries = filters.tipoDocumento.map(type => `tipoDocumento exact "${type}"`);
        queryParts.push(`(${typeQueries.join(' OR ')})`);
      }
      
      if (filters.autoridade && filters.autoridade.length > 0) {
        const authQueries = filters.autoridade.map(auth => `autoridade exact "${auth}"`);
        queryParts.push(`(${authQueries.join(' OR ')})`);
      }
      
      if (filters.localidade && filters.localidade.length > 0) {
        const locQueries = filters.localidade.map(loc => `localidade any "${loc}"`);
        queryParts.push(`(${locQueries.join(' OR ')})`);
      }
    }
    
    return queryParts.length > 0 ? queryParts.join(' AND ') : '*';
  }

  /**
   * Quick search utility for transport legislation
   */
  async searchTransportLegislation(term: string = ''): Promise<LexMLSearchResponse> {
    const transportQuery = term 
      ? `(title any "${term}" OR description any "${term}") AND (title any "transporte" OR description any "transporte" OR subject any "transporte")`
      : 'title any "transporte" OR description any "transporte" OR subject any "transporte"';
    
    return this.searchDocuments({
      cql_query: transportQuery,
      start_record: 1,
      max_records: 50,
      include_content: false,
      filters: {
        tipoDocumento: [],
        autoridade: [],
        localidade: [],
        subject: []
      }
    });
  }
}

// Create singleton instance
export const lexmlAPI = new LexMLAPIService();

// Export utility functions
export const searchLexML = (request: Partial<LexMLSearchRequest>) => lexmlAPI.searchDocuments(request);
export const getSuggestions = (term: string) => lexmlAPI.getSuggestions(term);
export const getDocumentContent = (urn: string) => lexmlAPI.getDocumentContent(urn);
export const getAPIHealth = () => lexmlAPI.getHealthStatus();