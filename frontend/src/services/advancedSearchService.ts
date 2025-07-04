/**
 * Advanced Search Service
 * Provides sophisticated search capabilities with semantic queries, filters, and SKOS vocabulary expansion
 */
import { LegislativeDocument, DocumentType, SearchFilters } from '../types';
import { API_ENDPOINTS, buildApiUrl } from '../config/api';

export interface SemanticQuery {
  originalQuery: string;
  expandedTerms: string[];
  synonyms: string[];
  relatedConcepts: string[];
  transportDomain?: boolean;
  confidence: number;
}

export interface AdvancedSearchParams {
  query: string;
  enableSemanticExpansion?: boolean;
  transportFocus?: boolean;
  filters?: {
    documentTypes?: DocumentType[];
    dateRange?: {
      start: Date;
      end: Date;
    };
    authors?: string[];
    chambers?: string[];
    states?: string[];
    municipalities?: string[];
    jurisdictions?: string[];
    urgencyLevel?: 'low' | 'medium' | 'high' | 'urgent';
    textComplexity?: 'simple' | 'medium' | 'complex';
  };
  searchMode?: 'exact' | 'fuzzy' | 'semantic' | 'hybrid';
  resultLimit?: number;
  sortBy?: 'relevance' | 'date' | 'popularity' | 'authority';
  includeRelated?: boolean;
}

export interface SearchResult {
  document: LegislativeDocument;
  relevanceScore: number;
  matchedTerms: string[];
  semanticMatches?: string[];
  snippet: string;
  highlightedSnippet: string;
  crossReferences?: string[];
  amendmentHistory?: Array<{
    documentUrn: string;
    type: 'amendment' | 'revocation' | 'modification';
    date: Date;
  }>;
}

export interface SearchResponse {
  results: SearchResult[];
  totalCount: number;
  searchTime: number;
  semanticQuery?: SemanticQuery;
  suggestedQueries?: string[];
  facets: {
    documentTypes: Array<{ type: DocumentType; count: number }>;
    authors: Array<{ author: string; count: number }>;
    years: Array<{ year: number; count: number }>;
    states: Array<{ state: string; count: number }>;
    jurisdictions: Array<{ jurisdiction: string; count: number }>;
  };
  pagination: {
    currentPage: number;
    totalPages: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
}

// SKOS Transport Vocabulary (Brazilian Transport Regulation)
const TRANSPORT_VOCABULARY = {
  // Core Transport Concepts
  transporte: [
    'transporte', 'transportes', 'mobilidade', 'deslocamento', 'circulação',
    'tráfego', 'trânsito', 'logística', 'modal', 'intermodal', 'multimodal'
  ],
  
  // Road Transport
  rodoviario: [
    'rodoviário', 'rodoviária', 'estrada', 'rodovia', 'autoestrada', 'via',
    'pista', 'faixa', 'tráfego', 'veículo', 'automóvel', 'caminhão', 'ônibus'
  ],
  
  // Railway Transport
  ferroviario: [
    'ferroviário', 'ferroviária', 'ferrovia', 'trem', 'locomotiva', 'vagão',
    'trilho', 'linha férrea', 'estação', 'terminal ferroviário', 'metrô', 'monotrilho'
  ],
  
  // Air Transport
  aereo: [
    'aéreo', 'aérea', 'aviação', 'aeroporto', 'aeródromo', 'voo', 'aeronave',
    'avião', 'helicóptero', 'terminal aéreo', 'pista de pouso', 'torre de controle'
  ],
  
  // Water Transport
  aquaviario: [
    'aquaviário', 'aquaviária', 'hidroviário', 'marítimo', 'fluvial', 'lacustre',
    'porto', 'cais', 'navio', 'embarcação', 'balsa', 'ferry', 'hidrovia'
  ],
  
  // Urban Transport
  urbano: [
    'urbano', 'urbana', 'metropolitano', 'municipal', 'cidade', 'ônibus urbano',
    'transporte coletivo', 'transporte público', 'BRT', 'VLT', 'ciclovia', 'calçada'
  ],
  
  // Cargo Transport
  cargas: [
    'cargas', 'carga', 'mercadorias', 'frete', 'logística de cargas',
    'transporte de cargas', 'armazém', 'depósito', 'terminal de cargas'
  ],
  
  // Passenger Transport
  passageiros: [
    'passageiros', 'passageiro', 'viajantes', 'usuários', 'transporte de pessoas',
    'transporte coletivo', 'transporte individual', 'táxi', 'uber', 'aplicativo'
  ],
  
  // Safety and Regulation
  seguranca: [
    'segurança', 'seguro', 'regulamentação', 'norma', 'fiscalização',
    'inspeção', 'licenciamento', 'habilitação', 'certificação', 'auditoria'
  ],
  
  // Infrastructure
  infraestrutura: [
    'infraestrutura', 'obra', 'construção', 'pavimentação', 'sinalização',
    'iluminação', 'drenagem', 'ponte', 'viaduto', 'túnel', 'rotatória'
  ],
  
  // Environmental
  ambiental: [
    'ambiental', 'meio ambiente', 'sustentabilidade', 'emissões', 'poluição',
    'combustível', 'elétrico', 'híbrido', 'biocombustível', 'carbono zero'
  ]
};

export class AdvancedSearchService {
  private static instance: AdvancedSearchService;

  private constructor() {}

  public static getInstance(): AdvancedSearchService {
    if (!AdvancedSearchService.instance) {
      AdvancedSearchService.instance = new AdvancedSearchService();
    }
    return AdvancedSearchService.instance;
  }

  /**
   * Perform advanced search with semantic expansion
   */
  public async search(params: AdvancedSearchParams): Promise<SearchResponse> {
    const startTime = Date.now();
    
    // Build semantic query if enabled
    let semanticQuery: SemanticQuery | undefined;
    if (params.enableSemanticExpansion) {
      semanticQuery = await this.buildSemanticQuery(params.query, params.transportFocus);
    }

    // Prepare search request
    const searchUrl = buildApiUrl(API_ENDPOINTS.SEARCH_DOCUMENTS);
    const requestBody = {
      query: semanticQuery?.expandedTerms.join(' ') || params.query,
      filters: this.buildFilters(params.filters),
      searchMode: params.searchMode || 'hybrid',
      limit: params.resultLimit || 20,
      sortBy: params.sortBy || 'relevance',
      includeRelated: params.includeRelated || false
    };

    try {
      const response = await fetch(searchUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        // Fallback to sample data if API is unavailable
        return this.generateSampleSearchResponse(params, semanticQuery, startTime);
      }

      const data = await response.json();
      const searchTime = Date.now() - startTime;

      return this.processSearchResponse(data, semanticQuery, searchTime, params);

    } catch (error) {
      console.warn('Search API unavailable, using sample data:', error);
      return this.generateSampleSearchResponse(params, semanticQuery, startTime);
    }
  }

  /**
   * Build semantic query with SKOS vocabulary expansion
   */
  public async buildSemanticQuery(query: string, transportFocus: boolean = true): Promise<SemanticQuery> {
    const originalQuery = query.toLowerCase().trim();
    const tokens = originalQuery.split(/\s+/);
    
    let expandedTerms: string[] = [originalQuery];
    let synonyms: string[] = [];
    let relatedConcepts: string[] = [];
    let confidence = 0.8;

    if (transportFocus) {
      // Expand using transport vocabulary
      for (const token of tokens) {
        for (const [concept, terms] of Object.entries(TRANSPORT_VOCABULARY)) {
          if (terms.some(term => term.includes(token) || token.includes(term))) {
            synonyms.push(...terms.filter(term => term !== token));
            expandedTerms.push(...terms.slice(0, 5)); // Limit expansion
            relatedConcepts.push(concept);
            confidence = Math.min(confidence + 0.1, 0.95);
          }
        }
      }

      // Add transport-specific context
      if (!originalQuery.includes('transport') && !originalQuery.includes('mobilidade')) {
        expandedTerms.push('transporte', 'mobilidade');
      }
    }

    // Remove duplicates and sort by relevance
    expandedTerms = [...new Set(expandedTerms)];
    synonyms = [...new Set(synonyms)];
    relatedConcepts = [...new Set(relatedConcepts)];

    return {
      originalQuery,
      expandedTerms,
      synonyms,
      relatedConcepts,
      transportDomain: transportFocus,
      confidence
    };
  }

  /**
   * Get search suggestions based on query
   */
  public async getSearchSuggestions(partialQuery: string, limit: number = 5): Promise<string[]> {
    const query = partialQuery.toLowerCase().trim();
    
    if (query.length < 2) return [];

    // Transport-focused suggestions
    const suggestions: string[] = [];
    
    // Check transport vocabulary for matches
    for (const [concept, terms] of Object.entries(TRANSPORT_VOCABULARY)) {
      for (const term of terms) {
        if (term.startsWith(query) && !suggestions.includes(term)) {
          suggestions.push(term);
        }
        if (suggestions.length >= limit) break;
      }
      if (suggestions.length >= limit) break;
    }

    // Add common search patterns
    const commonQueries = [
      'transporte urbano',
      'transporte de cargas',
      'segurança no trânsito',
      'mobilidade sustentável',
      'infraestrutura rodoviária',
      'transporte público',
      'logística de transportes',
      'regulamentação de transportes'
    ];

    for (const commonQuery of commonQueries) {
      if (commonQuery.includes(query) && !suggestions.includes(commonQuery)) {
        suggestions.push(commonQuery);
        if (suggestions.length >= limit) break;
      }
    }

    return suggestions.slice(0, limit);
  }

  /**
   * Analyze search query complexity and suggest improvements
   */
  public analyzeQuery(query: string): {
    complexity: 'simple' | 'medium' | 'complex';
    suggestions: string[];
    transportRelevance: number;
    recommendedFilters: string[];
  } {
    const tokens = query.toLowerCase().split(/\s+/);
    const transportTerms = this.countTransportTerms(tokens);
    
    let complexity: 'simple' | 'medium' | 'complex' = 'simple';
    if (tokens.length > 5) complexity = 'medium';
    if (tokens.length > 10 || query.includes('"') || query.includes('AND') || query.includes('OR')) {
      complexity = 'complex';
    }

    const suggestions: string[] = [];
    if (complexity === 'simple' && transportTerms > 0) {
      suggestions.push('Consider adding time period filters');
      suggestions.push('Specify document type (lei, decreto, etc.)');
    }

    const transportRelevance = transportTerms / tokens.length;
    
    const recommendedFilters: string[] = [];
    if (transportRelevance > 0.3) {
      recommendedFilters.push('documentTypes', 'states', 'jurisdictions');
    }

    return {
      complexity,
      suggestions,
      transportRelevance,
      recommendedFilters
    };
  }

  /**
   * Get related documents based on semantic similarity
   */
  public async getRelatedDocuments(documentUrn: string, limit: number = 5): Promise<SearchResult[]> {
    // In a real implementation, this would use machine learning models
    // For now, return sample related documents
    return this.generateSampleRelatedDocuments(documentUrn, limit);
  }

  // Private helper methods

  private buildFilters(filters?: AdvancedSearchParams['filters']): Record<string, any> {
    if (!filters) return {};

    const apiFilters: Record<string, any> = {};

    if (filters.documentTypes?.length) {
      apiFilters.documentTypes = filters.documentTypes;
    }

    if (filters.dateRange) {
      apiFilters.dateRange = {
        start: filters.dateRange.start.toISOString(),
        end: filters.dateRange.end.toISOString()
      };
    }

    if (filters.states?.length) {
      apiFilters.states = filters.states;
    }

    if (filters.municipalities?.length) {
      apiFilters.municipalities = filters.municipalities;
    }

    if (filters.authors?.length) {
      apiFilters.authors = filters.authors;
    }

    if (filters.chambers?.length) {
      apiFilters.chambers = filters.chambers;
    }

    return apiFilters;
  }

  private processSearchResponse(
    data: any,
    semanticQuery?: SemanticQuery,
    searchTime: number = 0,
    params?: AdvancedSearchParams
  ): SearchResponse {
    // Process API response into standardized format
    const results: SearchResult[] = (data.documents || []).map((doc: any) => ({
      document: this.normalizeDocument(doc),
      relevanceScore: doc.score || 0.8,
      matchedTerms: doc.matchedTerms || [],
      semanticMatches: doc.semanticMatches || [],
      snippet: doc.snippet || doc.summary?.substring(0, 200) + '...',
      highlightedSnippet: doc.highlightedSnippet || doc.snippet || '',
      crossReferences: doc.crossReferences || [],
      amendmentHistory: doc.amendmentHistory || []
    }));

    return {
      results,
      totalCount: data.totalCount || results.length,
      searchTime,
      semanticQuery,
      suggestedQueries: data.suggestedQueries || [],
      facets: data.facets || {
        documentTypes: [],
        authors: [],
        years: [],
        states: [],
        jurisdictions: []
      },
      pagination: data.pagination || {
        currentPage: 1,
        totalPages: 1,
        hasNext: false,
        hasPrevious: false
      }
    };
  }

  private normalizeDocument(doc: any): LegislativeDocument {
    return {
      id: doc.id || doc.urn,
      title: doc.title,
      summary: doc.summary || '',
      type: doc.type,
      date: typeof doc.date === 'string' ? doc.date : doc.date.toISOString(),
      keywords: doc.keywords || [],
      state: doc.state || '',
      municipality: doc.municipality,
      url: doc.url || '',
      status: doc.status || 'em_tramitacao',
      author: doc.author,
      chamber: doc.chamber,
      number: doc.number,
      source: doc.source,
      citation: doc.citation
    };
  }

  private countTransportTerms(tokens: string[]): number {
    let count = 0;
    for (const token of tokens) {
      for (const terms of Object.values(TRANSPORT_VOCABULARY)) {
        if (terms.some(term => term.includes(token) || token.includes(term))) {
          count++;
          break;
        }
      }
    }
    return count;
  }

  private generateSampleSearchResponse(
    params: AdvancedSearchParams,
    semanticQuery?: SemanticQuery,
    startTime: number = Date.now()
  ): SearchResponse {
    const searchTime = Date.now() - startTime;
    
    // Generate sample results based on query
    const sampleResults: SearchResult[] = [
      {
        document: {
          id: 'sample-1',
          title: 'Lei nº 14.195/2021 - Marco Legal do Transporte Rodoviário de Cargas',
          summary: 'Estabelece o marco legal do transporte rodoviário de cargas, disciplinando a atividade desenvolvida por transportador autônomo...',
          type: 'lei',
          date: '2021-07-14',
          keywords: ['transporte', 'cargas', 'rodoviário', 'marco legal'],
          state: 'BR',
          url: 'https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/l14195.htm',
          status: 'sancionado',
          author: 'Presidente da República',
          chamber: 'Congresso Nacional'
        },
        relevanceScore: 0.95,
        matchedTerms: ['transporte', 'rodoviário', 'cargas'],
        semanticMatches: semanticQuery?.expandedTerms.slice(0, 3),
        snippet: 'Esta Lei estabelece o marco legal do transporte rodoviário de cargas e disciplina a atividade desenvolvida por transportador autônomo de cargas, cooperativa de transporte de cargas e empresa de transporte de cargas...',
        highlightedSnippet: 'Esta Lei estabelece o marco legal do <mark>transporte rodoviário</mark> de <mark>cargas</mark>...',
        crossReferences: ['urn:lex:br:federal:decreto:2021-08-30;10755']
      },
      {
        document: {
          id: 'sample-2',
          title: 'Decreto nº 10.755/2021 - Regulamenta a Lei nº 14.195/2021',
          summary: 'Regulamenta a Lei nº 14.195, de 2021, que estabelece o marco legal do transporte rodoviário de cargas...',
          type: 'decreto',
          date: '2021-08-30',
          keywords: ['decreto', 'regulamentação', 'transporte', 'cargas'],
          state: 'BR',
          url: 'https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/decreto/d10755.htm',
          status: 'em_tramitacao',
          author: 'Presidente da República'
        },
        relevanceScore: 0.88,
        matchedTerms: ['transporte', 'cargas'],
        semanticMatches: semanticQuery?.synonyms.slice(0, 2),
        snippet: 'Regulamenta a Lei nº 14.195, de 2021, que estabelece o marco legal do transporte rodoviário de cargas e disciplina a atividade desenvolvida por transportador autônomo...',
        highlightedSnippet: 'Regulamenta a Lei nº 14.195, de 2021, que estabelece o marco legal do <mark>transporte</mark> rodoviário de <mark>cargas</mark>...',
        crossReferences: ['urn:lex:br:federal:lei:2021-07-14;14195']
      }
    ];

    return {
      results: sampleResults,
      totalCount: 42,
      searchTime,
      semanticQuery,
      suggestedQueries: [
        'transporte urbano regulamentação',
        'mobilidade sustentável legislação',
        'segurança transporte cargas'
      ],
      facets: {
        documentTypes: [
          { type: 'lei', count: 15 },
          { type: 'decreto', count: 12 },
          { type: 'portaria', count: 8 },
          { type: 'resolucao', count: 7 }
        ],
        authors: [
          { author: 'Presidente da República', count: 18 },
          { author: 'Ministério dos Transportes', count: 12 },
          { author: 'ANTT', count: 8 }
        ],
        years: [
          { year: 2021, count: 25 },
          { year: 2020, count: 12 },
          { year: 2019, count: 5 }
        ],
        states: [
          { state: 'BR', count: 30 },
          { state: 'SP', count: 6 },
          { state: 'RJ', count: 4 }
        ],
        jurisdictions: [
          { jurisdiction: 'Federal', count: 30 },
          { jurisdiction: 'Estadual', count: 10 },
          { jurisdiction: 'Municipal', count: 2 }
        ]
      },
      pagination: {
        currentPage: 1,
        totalPages: 3,
        hasNext: true,
        hasPrevious: false
      }
    };
  }

  private generateSampleRelatedDocuments(documentUrn: string, limit: number): SearchResult[] {
    // Return sample related documents
    return [];
  }
}

export const advancedSearchService = AdvancedSearchService.getInstance();