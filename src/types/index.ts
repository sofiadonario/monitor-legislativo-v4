export type DocumentType = 
  | 'lei'
  | 'decreto'
  | 'portaria'
  | 'resolucao'
  | 'instrucao_normativa'
  | 'projeto_lei'
  | 'medida_provisoria';

export type DocumentStatus = 
  | 'em_tramitacao'
  | 'aprovado'
  | 'rejeitado'
  | 'sancionado'
  | 'vetado'
  | 'arquivado';

export interface LegislativeDocument {
  id: string;
  title: string;
  summary: string;
  type: DocumentType;
  date: Date | string;
  keywords: string[];
  state: string;
  municipality?: string;
  url: string;
  status: DocumentStatus;
  author?: string;
  chamber?: string;
  number?: string;
  source?: string;
  citation?: string;
}

export interface StateData {
  id: string;
  name: string;
  abbreviation: string;
  region: string;
  capital: string;
  population?: number;
  area?: number;
  coordinates: [number, number];
  boundaries?: GeoJSON.Geometry;
}

export interface MunicipalityData {
  id: string;
  name: string;
  stateId: string;
  stateAbbreviation: string;
  population?: number;
  area?: number;
  coordinates: [number, number];
  boundaries?: GeoJSON.Geometry;
}

export interface SearchFilters {
  searchTerm: string;
  documentTypes: DocumentType[];
  states: string[];
  municipalities: string[];
  chambers: string[];
  keywords: string[];
  dateFrom?: Date;
  dateTo?: Date;
}

export interface MapLocation {
  lat: number;
  lng: number;
  zoom: number;
}

export interface ExportOptions {
  format: 'csv' | 'xml' | 'html' | 'bibtex' | 'png' | 'json' | 'pdf';
  includeMap?: boolean;
  includeMetadata?: boolean;
  dateRange?: { from: string; to: string };
  fields?: string[];
  includeImages?: boolean;
}

export interface LocationData {
  id: string;
  name: string;
  type: 'state' | 'municipality';
  coordinates: [number, number];
  documentCount: number;
}

export interface MapData {
  states: LocationData[];
  municipalities: LocationData[];
}

export type CollectionStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface CollectionLog {
  id: number;
  searchTermId: number;
  searchTerm: string;
  status: CollectionStatus;
  recordsCollected: number;
  recordsNew: number;
  recordsUpdated: number;
  recordsSkipped: number;
  executionTimeMs: number;
  errorMessage?: string;
  startedAt: string;
  completedAt?: string;
  sourcesUsed: string[];
}

export interface SavedQuery {
  id: string;
  name: string;
  description?: string;
  filters: SearchFilters;
  createdAt: string;
  updatedAt: string;
  timesUsed: number;
  isPublic: boolean;
  tags: string[];
}

// Vocabulary and SKOS types
export interface Concept {
  uri: string;
  prefLabel: Record<string, string>;
  altLabels: Record<string, string[]>;
  definition: Record<string, string>;
  conceptScheme?: string;
  broader: string[];
  narrower: string[];
  related: string[];
  notation?: string;
}

export interface ConceptSearchResult {
  concept: Concept;
  matchType: string;
  score: number;
  matchedLabel: string;
  context?: string;
}

export interface ConceptHierarchy {
  concept: Concept;
  path: string[];
  children: Concept[];
  parent?: Concept;
  siblings: Concept[];
  depth: number;
  isRoot: boolean;
  isLeaf: boolean;
}

export interface QueryExpansion {
  original: string[];
  narrower: string[];
  broader: string[];
  related: string[];
  synonyms: string[];
}

export interface ConceptSchemeOverview {
  scheme: string;
  totalConcepts: number;
  maxDepth: number;
  rootConcepts: Array<{uri: string; label: string}>;
  topLevelCategories: number;
}

export interface VocabularyHealth {
  status: string;
  service: string;
  components: Record<string, string>;
  dataCoverage: {
    totalConcepts: number;
    conceptSchemes: number;
    languagesSupported: string[];
    relationshipTypes: string[];
  };
  performance: {
    labelIndexSize: number;
    averageHierarchyDepth: number;
  };
}