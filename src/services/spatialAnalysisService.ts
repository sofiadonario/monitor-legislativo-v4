import { apiConfig } from '../config/api';

export interface GeoLocation {
  latitude: number;
  longitude: number;
  municipality: string;
  state: string;
  state_code: string;
  region: string;
  ibge_code: string;
  population?: number;
  area_km2?: number;
  confidence: number;
}

export interface SpatialAnalysis {
  document_id: string;
  extracted_locations: GeoLocation[];
  primary_location?: GeoLocation;
  jurisdiction_level: string;
  coverage_area: string[];
  spatial_keywords: string[];
  geographic_scope: string;
  related_locations: GeoLocation[];
  confidence_score: number;
}

export interface SpatialCluster {
  cluster_id: string;
  centroid: GeoLocation;
  documents: string[];
  radius_km: number;
  document_count: number;
  themes: string[];
  temporal_span: string[];
  regulatory_density: number;
  cluster_strength: number;
}

export interface SpatialRelationship {
  document1_id: string;
  document2_id: string;
  relationship_type: string;
  distance_km: number;
  shared_locations: string[];
  correlation_strength: number;
  temporal_overlap: boolean;
}

export interface DocumentInput {
  id: string;
  title: string;
  summary: string;
  data_evento?: string;
  tipo_documento?: string;
  fonte?: string;
}

class SpatialAnalysisService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${apiConfig.baseURL}/api/v1/spatial`;
  }

  async analyzeDocumentSpatialContext(document: DocumentInput): Promise<SpatialAnalysis> {
    try {
      const response = await fetch(`${this.baseUrl}/analyze-document`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(document),
      });

      if (!response.ok) {
        throw new Error(`Spatial analysis failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error analyzing document spatial context:', error);
      throw error;
    }
  }

  async findSpatialClusters(documents: DocumentInput[], maxDistanceKm: number = 100): Promise<SpatialCluster[]> {
    try {
      const response = await fetch(`${this.baseUrl}/find-clusters?max_distance_km=${maxDistanceKm}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(documents),
      });

      if (!response.ok) {
        throw new Error(`Spatial clustering failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error finding spatial clusters:', error);
      throw error;
    }
  }

  async reverseGeocode(latitude: number, longitude: number): Promise<GeoLocation | null> {
    try {
      const response = await fetch(`${this.baseUrl}/reverse-geocode`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ latitude, longitude }),
      });

      if (!response.ok) {
        throw new Error(`Reverse geocoding failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error reverse geocoding:', error);
      throw error;
    }
  }

  async analyzeSpatialRelationships(documents: DocumentInput[]): Promise<{
    total_relationships: number;
    relationships: SpatialRelationship[];
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/analyze-relationships`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(documents),
      });

      if (!response.ok) {
        throw new Error(`Spatial relationship analysis failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error analyzing spatial relationships:', error);
      throw error;
    }
  }

  async getBrazilianGeographyData(): Promise<{
    states: Record<string, any>;
    major_municipalities: Record<string, any>;
    regional_boundaries: Record<string, any>;
    total_states: number;
    total_major_cities: number;
    regions: string[];
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/brazilian-geography`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get geography data: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting Brazilian geography data:', error);
      throw error;
    }
  }

  async getServiceHealth(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Health check failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting service health:', error);
      throw error;
    }
  }
}

export const spatialAnalysisService = new SpatialAnalysisService();