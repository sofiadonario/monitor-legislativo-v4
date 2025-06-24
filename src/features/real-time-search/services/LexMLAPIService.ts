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
import { 
  cacheService, 
  getCachedSearchResults, 
  setCachedSearchResults,
  getCachedDocument,
  setCachedDocument,
  getCachedSuggestions,
  setCachedSuggestions
} from './CacheService';
import { getApiBaseUrl } from '../../../config/api';

export class LexMLAPIService {
  private baseURL: string;
  private defaultTimeout = 10000; // 10 seconds
  
  constructor(baseURL: string = '') {
    // Use provided URL or get from API configuration
    this.baseURL = baseURL || getApiBaseUrl();
    console.log(`🔧 LexMLAPIService initialized with baseURL: ${this.baseURL}`);
  }

  /**
   * Search LexML documents with live API integration and caching
   */
  async searchDocuments(request: Partial<LexMLSearchRequest>): Promise<LexMLSearchResponse> {
    // Check cache first
    const query = request.query || request.cql_query || '';
    const startRecord = request.start_record || 1;
    const maxRecords = request.max_records || 50;
    
    const cachedResult = getCachedSearchResults(query, request.filters, startRecord, maxRecords);
    if (cachedResult) {
      return {
        ...cachedResult,
        cache_hit: true,
        search_time_ms: 0 // Cached response is instant
      };
    }
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
      
      const fullUrl = `${this.baseURL}/api/lexml/search?${searchParams}`;
      console.log('🌐 Making API request to:', fullUrl);
      
      const response = await fetch(fullUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      console.log('📡 Response received:', {
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        headers: Object.fromEntries(response.headers.entries())
      });
      
      if (!response.ok) {
        throw new Error(`Search failed: ${response.status} ${response.statusText}`);
      }
      
      const result: any = await response.json();
      
      // Debug logging to see what we're actually getting
      console.log('🔍 Raw API Response:', {
        url: `${this.baseURL}/api/lexml/search?${searchParams}`,
        status: response.status,
        result: result,
        total_found: result.total_found,
        documents_length: result.documents?.length,
        keys: Object.keys(result)
      });
      
      // Transform backend response to frontend expected structure
      const transformedDocuments = (result.documents || []).map((doc: any) => ({
        metadata: {
          urn: doc.urn,
          title: doc.title,
          description: doc.description || '',
          date: doc.metadata?.date || new Date().toISOString().split('T')[0],
          tipoDocumento: doc.metadata?.type || 'Lei',
          autoridade: doc.metadata?.chamber?.toLowerCase() || 'federal',
          localidade: doc.metadata?.state || 'BR',
          subject: doc.metadata?.keywords || [],
          identifier: doc.urn,
          source_url: doc.url
        },
        full_text: doc.full_text,
        structure: doc.structure,
        last_modified: doc.metadata?.date || new Date().toISOString(),
        data_source: result.data_source || 'csv-fallback',
        cache_key: doc.urn
      }));
      
      // Add frontend-specific enhancements
      const enhancedResult: LexMLSearchResponse = {
        documents: transformedDocuments,
        total_found: result.total_found || result.documents?.length || 0,
        start_record: result.start_record || 1,
        records_returned: transformedDocuments.length,
        next_start_record: result.next_start_record,
        search_time_ms: result.search_time_ms || 0,
        data_source: result.data_source || 'csv-fallback',
        cache_hit: result.cache_hit || false,
        api_status: result.api_status || 'unknown'
      };
      
      console.log('🔄 Transformed Response:', {
        originalCount: result.documents?.length || 0,
        transformedCount: transformedDocuments.length,
        sampleDocument: transformedDocuments[0] || null
      });
      
      // Cache the successful result
      setCachedSearchResults(query, request.filters, startRecord, maxRecords, enhancedResult);
      
      return enhancedResult;
      
    } catch (error) {
      console.error('🚨 LexML search error details:', {
        error: error,
        message: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : 'No stack trace',
        name: error instanceof Error ? error.name : 'Unknown error type',
        baseURL: this.baseURL,
        searchParams: searchParams.toString()
      });
      
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
   * Get search suggestions for auto-complete with LexML taxonomy integration and caching
   */
  async getSuggestions(term: string, maxSuggestions: number = 10): Promise<SearchSuggestion[]> {
    if (term.length < 2) {
      return [];
    }
    
    // Check cache first
    const cachedSuggestions = getCachedSuggestions(term);
    if (cachedSuggestions) {
      return cachedSuggestions.slice(0, maxSuggestions);
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
      const suggestions = result.suggestions || [];
      
      // Cache the successful result
      setCachedSuggestions(term, suggestions);
      
      return suggestions;
      
    } catch (error) {
      console.error('Suggestions error:', error);
      
      // Fallback to local taxonomy-based suggestions
      return this.getLocalTaxonomySuggestions(term, maxSuggestions);
    }
  }

  /**
   * Get taxonomy-based suggestions using local LexML vocabulary
   */
  private getLocalTaxonomySuggestions(term: string, maxSuggestions: number = 10): SearchSuggestion[] {
    const lowercaseTerm = term.toLowerCase();
    
    // LexML Brasil taxonomy terms for transport legislation
    const taxonomyTerms: Record<string, { category: string; description: string }> = {
      // Document Types
      'lei': { category: 'Document Type', description: 'Federal, state, or municipal laws' },
      'decreto': { category: 'Document Type', description: 'Executive decrees and regulations' },
      'portaria': { category: 'Document Type', description: 'Administrative ordinances' },
      'resolução': { category: 'Document Type', description: 'Administrative resolutions' },
      'medida provisória': { category: 'Document Type', description: 'Provisional measures (federal)' },
      'instrução normativa': { category: 'Document Type', description: 'Normative instructions' },
      
      // Transport-specific terms
      'transporte': { category: 'Subject', description: 'General transportation legislation' },
      'transporte urbano': { category: 'Subject', description: 'Urban transportation systems' },
      'mobilidade urbana': { category: 'Subject', description: 'Urban mobility and accessibility' },
      'trânsito': { category: 'Subject', description: 'Traffic and transit regulations' },
      'infraestrutura': { category: 'Subject', description: 'Transportation infrastructure' },
      'logística': { category: 'Subject', description: 'Logistics and cargo transport' },
      'transporte público': { category: 'Subject', description: 'Public transportation systems' },
      'transporte coletivo': { category: 'Subject', description: 'Collective transportation' },
      'metrô': { category: 'Subject', description: 'Subway and metro systems' },
      'ônibus': { category: 'Subject', description: 'Bus transportation' },
      'brt': { category: 'Subject', description: 'Bus Rapid Transit systems' },
      'vlt': { category: 'Subject', description: 'Light Rail Transit (VLT)' },
      'trem': { category: 'Subject', description: 'Train and railway transport' },
      'aeroporto': { category: 'Subject', description: 'Airport infrastructure and regulation' },
      'porto': { category: 'Subject', description: 'Port and maritime transport' },
      'rodovia': { category: 'Subject', description: 'Highway and road infrastructure' },
      'ciclovia': { category: 'Subject', description: 'Bicycle lanes and cycling infrastructure' },
      'acessibilidade': { category: 'Subject', description: 'Transportation accessibility' },
      'sustentabilidade': { category: 'Subject', description: 'Sustainable transportation' },
      
      // Authorities
      'federal': { category: 'Authority', description: 'Federal government legislation' },
      'estadual': { category: 'Authority', description: 'State government legislation' },
      'municipal': { category: 'Authority', description: 'Municipal government legislation' },
      'distrital': { category: 'Authority', description: 'Federal District legislation' },
      
      // Common locations
      'são paulo': { category: 'Location', description: 'São Paulo state or city' },
      'rio de janeiro': { category: 'Location', description: 'Rio de Janeiro state or city' },
      'minas gerais': { category: 'Location', description: 'Minas Gerais state' },
      'brasília': { category: 'Location', description: 'Federal District (Brasília)' },
      'paraná': { category: 'Location', description: 'Paraná state' },
      'rio grande do sul': { category: 'Location', description: 'Rio Grande do Sul state' },
      'bahia': { category: 'Location', description: 'Bahia state' },
      'santa catarina': { category: 'Location', description: 'Santa Catarina state' },
      
      // Legal concepts
      'regulamentação': { category: 'Legal Concept', description: 'Regulatory provisions' },
      'licenciamento': { category: 'Legal Concept', description: 'Licensing and permits' },
      'fiscalização': { category: 'Legal Concept', description: 'Inspection and enforcement' },
      'concessão': { category: 'Legal Concept', description: 'Concessions and franchises' },
      'licitação': { category: 'Legal Concept', description: 'Public procurement and bidding' },
      'tarifa': { category: 'Legal Concept', description: 'Tariffs and pricing' },
      'subsídio': { category: 'Legal Concept', description: 'Subsidies and financial support' }
    };
    
    // Find matching terms
    const matches: SearchSuggestion[] = [];
    
    for (const [termKey, termData] of Object.entries(taxonomyTerms)) {
      if (termKey.toLowerCase().includes(lowercaseTerm) || 
          termData.description.toLowerCase().includes(lowercaseTerm)) {
        matches.push({
          text: termKey,
          category: termData.category,
          description: termData.description,
          count: Math.floor(Math.random() * 100) + 1 // Simulated count
        });
      }
    }
    
    // Sort by relevance (exact matches first, then partial matches)
    matches.sort((a, b) => {
      const aExact = a.text.toLowerCase() === lowercaseTerm;
      const bExact = b.text.toLowerCase() === lowercaseTerm;
      const aStarts = a.text.toLowerCase().startsWith(lowercaseTerm);
      const bStarts = b.text.toLowerCase().startsWith(lowercaseTerm);
      
      if (aExact && !bExact) return -1;
      if (!aExact && bExact) return 1;
      if (aStarts && !bStarts) return -1;
      if (!aStarts && bStarts) return 1;
      
      return b.count - a.count; // Higher count first
    });
    
    return matches.slice(0, maxSuggestions);
  }

  /**
   * Get field-specific suggestions based on LexML schema
   */
  async getFieldSuggestions(field: string, term: string, maxSuggestions: number = 10): Promise<SearchSuggestion[]> {
    const lowercaseTerm = term.toLowerCase();
    
    switch (field) {
      case 'tipoDocumento':
        return [
          { text: 'Lei', category: 'Document Type', description: 'Laws and statutes', count: 1500 },
          { text: 'Decreto', category: 'Document Type', description: 'Executive decrees', count: 800 },
          { text: 'Portaria', category: 'Document Type', description: 'Administrative ordinances', count: 600 },
          { text: 'Resolução', category: 'Document Type', description: 'Administrative resolutions', count: 400 },
          { text: 'Medida Provisória', category: 'Document Type', description: 'Provisional measures', count: 200 },
          { text: 'Instrução Normativa', category: 'Document Type', description: 'Normative instructions', count: 300 }
        ].filter(item => item.text.toLowerCase().includes(lowercaseTerm))
         .slice(0, maxSuggestions);
         
      case 'autoridade':
        return [
          { text: 'federal', category: 'Authority', description: 'Federal government', count: 2000 },
          { text: 'estadual', category: 'Authority', description: 'State governments', count: 1500 },
          { text: 'municipal', category: 'Authority', description: 'Municipal governments', count: 1200 },
          { text: 'distrital', category: 'Authority', description: 'Federal District', count: 300 }
        ].filter(item => item.text.toLowerCase().includes(lowercaseTerm))
         .slice(0, maxSuggestions);
         
      case 'localidade':
        const locations = [
          'São Paulo', 'Rio de Janeiro', 'Minas Gerais', 'Paraná', 'Rio Grande do Sul',
          'Bahia', 'Santa Catarina', 'Distrito Federal', 'Goiás', 'Espírito Santo',
          'Ceará', 'Pernambuco', 'Pará', 'Maranhão', 'Amazonas'
        ];
        return locations
          .filter(loc => loc.toLowerCase().includes(lowercaseTerm))
          .map(loc => ({
            text: loc,
            category: 'Location',
            description: `Legislation from ${loc}`,
            count: Math.floor(Math.random() * 500) + 50
          }))
          .slice(0, maxSuggestions);
          
      case 'subject':
        const subjects = [
          'transporte', 'transporte urbano', 'mobilidade urbana', 'trânsito',
          'infraestrutura', 'logística', 'transporte público', 'metrô',
          'ônibus', 'brt', 'vlt', 'trem', 'aeroporto', 'porto', 'rodovia',
          'ciclovia', 'acessibilidade', 'sustentabilidade'
        ];
        return subjects
          .filter(subj => subj.toLowerCase().includes(lowercaseTerm))
          .map(subj => ({
            text: subj,
            category: 'Subject',
            description: `Documents about ${subj}`,
            count: Math.floor(Math.random() * 300) + 20
          }))
          .slice(0, maxSuggestions);
          
      default:
        return this.getLocalTaxonomySuggestions(term, maxSuggestions);
    }
  }

  /**
   * Get full document content by URN with caching
   */
  async getDocumentContent(urn: string): Promise<DocumentContentResponse | null> {
    // Check cache first
    const cachedDocument = getCachedDocument(urn);
    if (cachedDocument) {
      return {
        ...cachedDocument,
        cached: true
      };
    }
    
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
      
      const document = await response.json();
      
      // Cache the successful result
      setCachedDocument(urn, document);
      
      return document;
      
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

  /**
   * Find cross-references within document content with caching
   */
  async findCrossReferences(documentUrn: string): Promise<{ 
    references: Array<{
      type: 'law' | 'decree' | 'regulation' | 'article' | 'paragraph';
      text: string;
      urn?: string;
      url?: string;
      description?: string;
    }>;
    related_documents: Array<{
      urn: string;
      title: string;
      relationship: 'amends' | 'revokes' | 'references' | 'implements';
    }>;
  }> {
    // Check cache first
    const cacheKey = cacheService.createCrossReferencesKey(documentUrn);
    const cachedRefs = cacheService.get(cacheKey);
    if (cachedRefs) {
      return cachedRefs;
    }
    
    try {
      const response = await fetch(
        `${this.baseURL}/api/lexml/document/${encodeURIComponent(documentUrn)}/references`,
        {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
          }
        }
      );
      
      if (!response.ok) {
        throw new Error(`Cross-reference discovery failed: ${response.status}`);
      }
      
      const references = await response.json();
      
      // Cache the successful result
      cacheService.set(cacheKey, references);
      
      return references;
      
    } catch (error) {
      console.error('Cross-reference discovery error:', error);
      
      // Fallback to local pattern matching if API is unavailable
      const fallbackRefs = await this.extractLocalCrossReferences(documentUrn);
      
      // Cache the fallback result with shorter TTL
      cacheService.set(cacheKey, fallbackRefs, 10 * 60 * 1000); // 10 minutes
      
      return fallbackRefs;
    }
  }

  /**
   * Extract cross-references using local pattern matching
   */
  private async extractLocalCrossReferences(documentUrn: string): Promise<{
    references: Array<{
      type: 'law' | 'decree' | 'regulation' | 'article' | 'paragraph';
      text: string;
      urn?: string;
      url?: string;
      description?: string;
    }>;
    related_documents: Array<{
      urn: string;
      title: string;
      relationship: 'amends' | 'revokes' | 'references' | 'implements';
    }>;
  }> {
    // Get document content for analysis
    const content = await this.getDocumentContent(documentUrn);
    if (!content || !content.full_text) {
      return { references: [], related_documents: [] };
    }
    
    const text = content.full_text;
    const references: Array<{
      type: 'law' | 'decree' | 'regulation' | 'article' | 'paragraph';
      text: string;
      urn?: string;
      url?: string;
      description?: string;
    }> = [];
    
    // Patterns for Brazilian legal references
    const patterns = [
      // Lei patterns
      {
        regex: /Lei\s+(?:nº\s*|n\.?\s*)?(\d+(?:[.,]\d+)?)\s*,?\s*de\s+(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})/gi,
        type: 'law' as const,
        extract: (match: RegExpMatchArray) => ({
          text: match[0],
          description: `Lei ${match[1]} de ${match[2]} de ${match[3]} de ${match[4]}`
        })
      },
      
      // Decreto patterns
      {
        regex: /Decreto\s+(?:nº\s*|n\.?\s*)?(\d+(?:[.,]\d+)?)\s*,?\s*de\s+(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})/gi,
        type: 'decree' as const,
        extract: (match: RegExpMatchArray) => ({
          text: match[0],
          description: `Decreto ${match[1]} de ${match[2]} de ${match[3]} de ${match[4]}`
        })
      },
      
      // Article patterns
      {
        regex: /art\.?\s*(\d+(?:-[A-Z])?)/gi,
        type: 'article' as const,
        extract: (match: RegExpMatchArray) => ({
          text: match[0],
          description: `Artigo ${match[1]}`
        })
      },
      
      // Paragraph patterns
      {
        regex: /§\s*(\d+)º?/gi,
        type: 'paragraph' as const,
        extract: (match: RegExpMatchArray) => ({
          text: match[0],
          description: `Parágrafo ${match[1]}`
        })
      },
      
      // Inciso patterns
      {
        regex: /inciso\s+([IVX]+)/gi,
        type: 'paragraph' as const,
        extract: (match: RegExpMatchArray) => ({
          text: match[0],
          description: `Inciso ${match[1]}`
        })
      }
    ];
    
    // Extract references using patterns
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.regex.exec(text)) !== null) {
        const extracted = pattern.extract(match);
        references.push({
          type: pattern.type,
          ...extracted
        });
      }
    }
    
    // Remove duplicates
    const uniqueReferences = references.filter((ref, index, self) => 
      index === self.findIndex(r => r.text === ref.text)
    );
    
    return {
      references: uniqueReferences.slice(0, 20), // Limit to 20 references
      related_documents: [] // Would need API for related documents
    };
  }

  /**
   * Get related documents based on content similarity and citations with caching
   */
  async getRelatedDocuments(documentUrn: string, maxResults: number = 10): Promise<LexMLSearchResponse> {
    // Check cache first
    const cacheKey = cacheService.createRelatedDocumentsKey(documentUrn, maxResults);
    const cachedRelated = cacheService.get<LexMLSearchResponse>(cacheKey);
    if (cachedRelated) {
      return {
        ...cachedRelated,
        cache_hit: true
      };
    }
    
    try {
      const response = await fetch(
        `${this.baseURL}/api/lexml/document/${encodeURIComponent(documentUrn)}/related?max_results=${maxResults}`,
        {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
          }
        }
      );
      
      if (!response.ok) {
        throw new Error(`Related documents failed: ${response.status}`);
      }
      
      const relatedDocs = await response.json();
      
      // Cache the successful result
      cacheService.set(cacheKey, relatedDocs);
      
      return relatedDocs;
      
    } catch (error) {
      console.error('Related documents error:', error);
      
      // Fallback to simple subject-based search
      const fallbackRelated = await this.findSimilarDocumentsBySubject(documentUrn, maxResults);
      
      // Cache the fallback result with shorter TTL
      cacheService.set(cacheKey, fallbackRelated, 10 * 60 * 1000); // 10 minutes
      
      return fallbackRelated;
    }
  }

  /**
   * Find similar documents by subject and document type
   */
  private async findSimilarDocumentsBySubject(documentUrn: string, maxResults: number): Promise<LexMLSearchResponse> {
    // Get the source document to analyze its subjects
    const content = await this.getDocumentContent(documentUrn);
    if (!content || !content.metadata) {
      return {
        documents: [],
        total_found: 0,
        start_record: 1,
        records_returned: 0,
        search_time_ms: 0,
        data_source: 'csv-fallback',
        cache_hit: false,
        api_status: 'no-content'
      };
    }
    
    const subjects = content.metadata.subject || [];
    if (subjects.length === 0) {
      return {
        documents: [],
        total_found: 0,
        start_record: 1,
        records_returned: 0,
        search_time_ms: 0,
        data_source: 'csv-fallback',
        cache_hit: false,
        api_status: 'no-subjects'
      };
    }
    
    // Build a query to find documents with similar subjects
    const subjectQueries = subjects.slice(0, 3).map(subject => 
      `subject any "${subject}"`
    );
    const cqlQuery = `(${subjectQueries.join(' OR ')}) AND NOT urn exact "${documentUrn}"`;
    
    return this.searchDocuments({
      cql_query: cqlQuery,
      start_record: 1,
      max_records: maxResults,
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
export const getFieldSuggestions = (field: string, term: string) => lexmlAPI.getFieldSuggestions(field, term);
export const getDocumentContent = (urn: string) => lexmlAPI.getDocumentContent(urn);
export const getAPIHealth = () => lexmlAPI.getHealthStatus();
export const findCrossReferences = (urn: string) => lexmlAPI.findCrossReferences(urn);
export const getRelatedDocuments = (urn: string, maxResults?: number) => lexmlAPI.getRelatedDocuments(urn, maxResults);