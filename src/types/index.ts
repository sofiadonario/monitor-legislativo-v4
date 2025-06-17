export interface LegislativeDocument {
  id: string;
  title: string;
  type: 'lei' | 'decreto' | 'portaria' | 'resolucao' | 'medida_provisoria';
  number: string;
  date: string;
  summary: string;
  fullText?: string;
  state?: string;
  municipality?: string;
  keywords: string[];
  source: string;
  citation: string;
  url?: string;
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
  dateFrom?: string;
  dateTo?: string;
  documentTypes: string[];
  states: string[];
  municipalities: string[];
  keywords: string[];
}

export interface MapLocation {
  lat: number;
  lng: number;
  zoom: number;
}

export interface ExportOptions {
  format: 'csv' | 'xml' | 'html' | 'bibtex' | 'png';
  includeMap: boolean;
  includeMetadata: boolean;
  dateRange?: {
    from: string;
    to: string;
  };
}