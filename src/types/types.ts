// TypeScript interfaces for Monitor Legislativo v4
// Brazilian Legislative Monitoring System

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

export interface SearchFilters {
  searchTerm: string;
  documentTypes: DocumentType[];
  states: string[];
  municipalities: string[];
  keywords: string[];
  dateFrom?: Date;
  dateTo?: Date;
}

export interface ExportOptions {
  format: 'csv' | 'json' | 'pdf';
  fields: string[];
  includeImages: boolean;
  includeMetadata: boolean;
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