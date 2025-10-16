/**
 * TypeScript types for Monitor Legislativo API responses
 * Matches the R Plumber API structure
 */

// ============================================================================
// SEARCH TYPES
// ============================================================================

export interface SearchItem {
  id: string;
  title: string;
  jurisdiction: 'federal' | 'state' | 'municipal';
  date: string;
  snippet?: string;
  score?: number;
}

export interface SearchResponse {
  meta: {
    page: number;
    page_size: number;
    total: number;
  };
  items: SearchItem[];
}

export interface SearchParams {
  q: string;
  scope?: 'federal' | 'state' | 'municipal';
  date_from?: string;
  date_to?: string;
  page?: number;
  page_size?: number;
  sort?: 'relevance' | 'recency';
}

// ============================================================================
// DOCUMENT TYPES
// ============================================================================

export interface Document {
  id: string;
  title: string;
  full_text: string;
  summary: string | null;
  jurisdiction: 'federal' | 'state' | 'municipal';
  status: 'draft' | 'published' | 'revoked' | 'amended';
  dates: {
    presented: string;
    last_movement: string;
  };
}

// ============================================================================
// AGGREGATION TYPES
// ============================================================================

export interface AggregationBucket {
  key: string | number;
  count: number;
}

export interface AggregationResponse {
  buckets: AggregationBucket[];
}

export interface AggregationParams {
  group_by: 'year' | 'jurisdiction' | 'state';
  date_from?: string;
  date_to?: string;
}

// ============================================================================
// MAP TYPES
// ============================================================================

export interface ChoroplethFeature {
  id: string;
  value: number;
}

export interface ChoroplethResponse {
  meta: {
    geo: 'estado' | 'municipio';
    metric: 'n_docs' | 'bills_per_100k';
    year?: number;
  };
  features: ChoroplethFeature[];
}

export interface ChoroplethParams {
  geo?: 'estado' | 'municipio';
  metric?: 'n_docs' | 'bills_per_100k';
  year?: number;
}

// ============================================================================
// ERROR TYPES
// ============================================================================

export interface ApiError {
  error: string;
  message: string;
  request_id?: string;
  status?: number;
}
