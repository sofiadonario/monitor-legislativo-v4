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

// Document Analysis types for Sprint 2
export interface DocumentContent {
  urn: string;
  title: string;
  content: string;
  htmlContent?: string;
  plainText: string;
  metadata: DocumentMetadata;
  sections: DocumentSection[];
  attachments: DocumentAttachment[];
}

export interface DocumentMetadata {
  urn: string;
  title: string;
  type: DocumentType;
  authority: string;
  publicationDate: string;
  effectiveDate?: string;
  status: DocumentStatus;
  subject: string[];
  keywords: string[];
  language: string;
  jurisdiction: string;
  source: string;
  lastModified: string;
  version: string;
  qualityScore: QualityScore;
}

export interface DocumentSection {
  id: string;
  title: string;
  content: string;
  level: number;
  order: number;
  type: 'article' | 'chapter' | 'section' | 'paragraph' | 'item';
  references: string[];
}

export interface DocumentAttachment {
  id: string;
  name: string;
  type: string;
  size: number;
  url: string;
  description?: string;
}

export interface QualityScore {
  overall: number;
  completeness: number;
  accuracy: number;
  consistency: number;
  timeliness: number;
  details: QualityDetails;
}

export interface QualityDetails {
  missingFields: string[];
  validationErrors: ValidationError[];
  warnings: string[];
  lastValidated: string;
}

export interface ValidationError {
  field: string;
  error: string;
  severity: 'error' | 'warning' | 'info';
}

export interface CrossReference {
  id: string;
  sourceUrn: string;
  targetUrn: string;
  type: CrossReferenceType;
  description: string;
  context: string;
  bidirectional: boolean;
  strength: number;
}

export type CrossReferenceType = 
  | 'citation' 
  | 'amendment' 
  | 'repeal' 
  | 'reference' 
  | 'implementation' 
  | 'supersedes' 
  | 'related';

export interface SimilarDocument {
  urn: string;
  title: string;
  similarity: number;
  matchType: 'content' | 'metadata' | 'structure' | 'keywords';
  commonElements: string[];
  explanation: string;
}

export interface Citation {
  format: CitationFormat;
  text: string;
  bibtex?: string;
  ris?: string;
  endnote?: string;
  metadata: CitationMetadata;
}

export type CitationFormat = 'ABNT' | 'APA' | 'Chicago' | 'Vancouver' | 'MLA' | 'IEEE';

export interface CitationMetadata {
  authors: string[];
  title: string;
  publisher: string;
  publicationDate: string;
  url: string;
  accessDate: string;
  doi?: string;
  isbn?: string;
}

export interface ComparisonResult {
  documents: DocumentMetadata[];
  similarities: SimilarityMetrics;
  differences: Difference[];
  summary: ComparisonSummary;
}

export interface SimilarityMetrics {
  contentSimilarity: number;
  structureSimilarity: number;
  metadataSimilarity: number;
  overallSimilarity: number;
  commonSections: number;
  uniqueSections: { doc1: number; doc2: number };
}

export interface Difference {
  type: 'content' | 'structure' | 'metadata';
  field: string;
  document1Value: string;
  document2Value: string;
  significance: 'high' | 'medium' | 'low';
  description: string;
}

export interface ComparisonSummary {
  primaryDifferences: string[];
  keyInsights: string[];
  recommendations: string[];
}