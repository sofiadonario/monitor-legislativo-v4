/**
 * Real-time Search Feature Exports
 * LexML Brasil API Integration
 */

// Main Container Component
export { default as LexMLSearchContainer } from './components/LexMLSearchContainer';

// Individual Components
export { default as LexMLSearchBar } from './components/LexMLSearchBar';
export { default as LexMLFilters } from './components/LexMLFilters';
export { default as SearchResults } from './components/SearchResults';
export { default as DataSourceIndicator } from './components/DataSourceIndicator';
export { default as DocumentViewer } from './components/DocumentViewer';
export { default as CQLQueryBuilder } from './components/CQLQueryBuilder';
export { default as CacheStatusIndicator } from './components/CacheStatusIndicator';

// Hooks
export { useLexMLSearch } from './hooks/useLexMLSearch';

// Services
export { LexMLAPIService, lexmlAPI, searchLexML, getSuggestions, getDocumentContent, getAPIHealth } from './services/LexMLAPIService';
export { cacheService, getCachedSearchResults, setCachedSearchResults, getCachedDocument, setCachedDocument } from './services/CacheService';

// Types
export type {
  DocumentType,
  Autoridade,
  DataSource,
  LexMLMetadata,
  LexMLDocument,
  SearchFilters,
  LexMLSearchRequest,
  LexMLSearchResponse,
  SearchSuggestion,
  APIHealthStatus,
  SearchState,
  DocumentContentResponse
} from './types/lexml-api.types';