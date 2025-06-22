/**
 * TypeScript types for LexML Brasil API integration
 * Frontend types that match backend LexML models
 */

export type DocumentType = 
  | 'Lei'
  | 'Decreto'
  | 'Decreto-Lei'
  | 'Medida Provisória'
  | 'Portaria'
  | 'Resolução'
  | 'Instrução Normativa'
  | 'Emenda Constitucional'
  | 'Acórdão'
  | 'Parecer';

export type Autoridade = 
  | 'federal'
  | 'estadual'
  | 'municipal'
  | 'distrital';

export type DataSource = 
  | 'live-api'
  | 'cached-api'
  | 'csv-fallback';

export interface LexMLMetadata {
  urn: string;
  title: string;
  description?: string;
  date: string;
  tipoDocumento: DocumentType;
  autoridade: Autoridade;
  localidade: string;
  subject: string[];
  identifier: string;
  source_url?: string;
}

export interface LexMLDocument {
  metadata: LexMLMetadata;
  full_text?: string;
  structure?: Record<string, any>;
  last_modified: string;
  data_source: DataSource;
  cache_key?: string;
}

export interface SearchFilters {
  tipoDocumento: DocumentType[];
  autoridade: Autoridade[];
  localidade: string[];
  date_from?: string;
  date_to?: string;
  subject: string[];
  search_term?: string;
}

export interface LexMLSearchRequest {
  query?: string;
  cql_query?: string;
  filters: SearchFilters;
  start_record: number;
  max_records: number;
  include_content: boolean;
}

export interface LexMLSearchResponse {
  documents: LexMLDocument[];
  total_found?: number;
  start_record: number;
  records_returned: number;
  next_start_record?: number;
  search_time_ms: number;
  data_source: DataSource;
  cache_hit: boolean;
  api_status: string;
}

export interface SearchSuggestion {
  text: string;
  type: 'tipoDocumento' | 'autoridade' | 'localidade' | 'subject' | 'urn' | 'skos' | 'history' | 'cql';
  frequency?: number;
  cql_query?: string;
  metadata: {
    document_count?: number;
    source_type: 'live-api' | 'cached' | 'local';
    related_terms: string[];
    hierarchy_path?: string[];
  };
  source: 'lexml-api' | 'skos-vocabulary' | 'search-history' | 'cql-templates';
}

export interface APIHealthStatus {
  is_healthy: boolean;
  response_time_ms: number;
  success_rate: number;
  last_checked: string;
  circuit_breaker: {
    status: string;
    failure_count: number;
    last_failure_time?: string;
    total_requests: number;
    successful_requests: number;
    failed_requests: number;
  };
  error_message?: string;
}

export interface SearchState {
  query: string;
  results: LexMLDocument[];
  isLoading: boolean;
  resultCount: number;
  totalAvailable: number | 'unlimited';
  searchTime: number;
  dataSource: DataSource;
  apiStatus: 'connected' | 'fallback' | 'error';
  filters: SearchFilters;
  currentPage: number;
  hasNextPage: boolean;
}

export interface DocumentContentResponse {
  urn: string;
  content?: any;
  document?: LexMLDocument;
  cached: boolean;
  retrieved_at: string;
  data_source?: string;
  note?: string;
  full_text_url?: string;
}