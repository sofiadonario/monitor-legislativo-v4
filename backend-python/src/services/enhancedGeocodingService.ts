/**
 * Enhanced Geocoding Service - Frontend integration for IBGE CNEFE geocoding
 * Provides geographic analysis and transport corridor mapping for Brazilian legislative documents
 */

import { API_BASE_URL } from '../config/api';

export interface GeographicEntity {
  name: string;
  normalized_name: string;
  level: GeographicLevel;
  ibge_code?: string;
  coordinates?: [number, number]; // [lat, lon]
  state_code?: string;
  region?: string;
  area_km2?: number;
  population?: number;
  transport_hubs: string[];
  administrative_info: Record<string, any>;
  confidence: number;
}

export interface TransportCorridor {
  name: string;
  corridor_type: TransportMode;
  start_municipality: string;
  end_municipality: string;
  intermediate_cities: string[];
  total_length_km?: number;
  regulatory_authority?: string;
  highway_codes: string[];
  rail_lines: string[];
  waterways: string[];
  strategic_importance: string;
}

export interface SpatialAnalysis {
  document_id: string;
  geographic_entities: GeographicEntity[];
  transport_corridors: TransportCorridor[];
  affected_municipalities: string[];
  affected_states: string[];
  coverage_analysis: CoverageAnalysis;
  spatial_patterns: SpatialPatterns;
  processing_time: number;
}

export interface CoverageAnalysis {
  total_entities: number;
  by_level: Record<string, number>;
  by_region: Record<string, number>;
  by_state: Record<string, number>;
  national_scope: boolean;
  multi_regional: boolean;
  multi_state: boolean;
}

export interface SpatialPatterns {
  urban_focus: boolean;
  rural_focus: boolean;
  coastal_areas: boolean;
  border_regions: boolean;
  metropolitan_areas: string[];
  transport_integration: boolean;
  corridor_types: string[];
}

export enum GeographicLevel {
  COUNTRY = 'country',
  REGION = 'region',
  STATE = 'state',
  MESOREGION = 'mesoregion',
  MICROREGION = 'microregion',
  MUNICIPALITY = 'municipality',
  DISTRICT = 'district',
  NEIGHBORHOOD = 'neighborhood',
  TRANSPORT_CORRIDOR = 'transport_corridor'
}

export enum TransportMode {
  ROAD = 'road',
  RAIL = 'rail',
  WATERWAY = 'waterway',
  AIRPORT = 'airport',
  PORT = 'port',
  MULTIMODAL = 'multimodal'
}

export interface GeocodingRequest {
  text: string;
  document_id: string;
  include_transport_analysis?: boolean;
  include_ibge_data?: boolean;
  confidence_threshold?: number;
}

export interface TransportCorridorRequest {
  start_city: string;
  end_city: string;
  transport_modes?: TransportMode[];
}

/**
 * Enhanced Geocoding Service Class
 */
class EnhancedGeocodingService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${API_BASE_URL}/api/v1/enhanced-geocoding`;
  }

  /**
   * Analyze geographic entities and transport corridors in document
   */
  async analyzeDocumentGeography(request: GeocodingRequest): Promise<SpatialAnalysis | null> {
    try {
      const response = await fetch(`${this.baseUrl}/analyze-document`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          text: request.text,
          document_id: request.document_id,
          include_transport_analysis: request.include_transport_analysis ?? true,
          include_ibge_data: request.include_ibge_data ?? true,
          confidence_threshold: request.confidence_threshold ?? 0.7
        })
      });

      if (!response.ok) {
        throw new Error(`Geographic analysis failed: ${response.statusText}`);
      }

      const data = await response.json();
      return data.success ? data.data : null;
    } catch (error) {
      console.error('Failed to analyze document geography:', error);
      return null;
    }
  }

  /**
   * Find transport corridors between cities
   */
  async findTransportCorridor(request: TransportCorridorRequest): Promise<TransportCorridor[] | null> {
    try {
      const response = await fetch(`${this.baseUrl}/find-corridor`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          start_city: request.start_city,
          end_city: request.end_city,
          transport_modes: request.transport_modes ?? [TransportMode.ROAD]
        })
      });

      if (!response.ok) {
        throw new Error(`Corridor search failed: ${response.statusText}`);
      }

      const data = await response.json();
      return data.success ? data.data.corridors : null;
    } catch (error) {
      console.error('Failed to find transport corridor:', error);
      return null;
    }
  }

  /**
   * Get detailed municipality information from IBGE
   */
  async getMunicipalityInfo(municipalityName: string, stateCode?: string): Promise<GeographicEntity | null> {
    try {
      const params = new URLSearchParams();
      if (stateCode) {
        params.append('state_code', stateCode);
      }
      
      const url = `${this.baseUrl}/municipality/${encodeURIComponent(municipalityName)}${params.toString() ? '?' + params.toString() : ''}`;
      
      const response = await fetch(url);

      if (!response.ok) {
        throw new Error(`Municipality lookup failed: ${response.statusText}`);
      }

      const data = await response.json();
      return data.success ? data.data : null;
    } catch (error) {
      console.error('Failed to get municipality info:', error);
      return null;
    }
  }

  /**
   * Extract geographic entities from text
   */
  async extractGeographicEntities(
    text: string, 
    documentId: string,
    includeIbgeData: boolean = true
  ): Promise<GeographicEntity[]> {
    const analysis = await this.analyzeDocumentGeography({
      text,
      document_id: documentId,
      include_transport_analysis: false,
      include_ibge_data: includeIbgeData
    });

    return analysis?.geographic_entities || [];
  }

  /**
   * Analyze transport infrastructure in text
   */
  async analyzeTransportInfrastructure(
    text: string,
    documentId: string
  ): Promise<{
    corridors: TransportCorridor[];
    patterns: SpatialPatterns;
  }> {
    const analysis = await this.analyzeDocumentGeography({
      text,
      document_id: documentId,
      include_transport_analysis: true,
      include_ibge_data: false
    });

    return {
      corridors: analysis?.transport_corridors || [],
      patterns: analysis?.spatial_patterns || {} as SpatialPatterns
    };
  }

  /**
   * Get coverage analysis for geographic scope
   */
  async analyzeCoverage(
    text: string,
    documentId: string
  ): Promise<CoverageAnalysis | null> {
    const analysis = await this.analyzeDocumentGeography({
      text,
      document_id: documentId,
      include_transport_analysis: false,
      include_ibge_data: true
    });

    return analysis?.coverage_analysis || null;
  }

  /**
   * Format geographic entity for display
   */
  formatGeographicEntity(entity: GeographicEntity): string {
    const parts = [entity.name];
    
    if (entity.state_code) {
      parts.push(entity.state_code);
    }
    
    if (entity.region && entity.level !== GeographicLevel.STATE) {
      parts.push(`(${entity.region})`);
    }
    
    return parts.join(' - ');
  }

  /**
   * Format transport corridor for display
   */
  formatTransportCorridor(corridor: TransportCorridor): string {
    const parts = [corridor.name];
    
    if (corridor.total_length_km) {
      parts.push(`${corridor.total_length_km}km`);
    }
    
    if (corridor.regulatory_authority) {
      parts.push(`(${corridor.regulatory_authority})`);
    }
    
    return parts.join(' - ');
  }

  /**
   * Get geographic level display name
   */
  getGeographicLevelName(level: GeographicLevel): string {
    const levelNames = {
      [GeographicLevel.COUNTRY]: 'País',
      [GeographicLevel.REGION]: 'Região',
      [GeographicLevel.STATE]: 'Estado',
      [GeographicLevel.MESOREGION]: 'Mesorregião',
      [GeographicLevel.MICROREGION]: 'Microrregião',
      [GeographicLevel.MUNICIPALITY]: 'Município',
      [GeographicLevel.DISTRICT]: 'Distrito',
      [GeographicLevel.NEIGHBORHOOD]: 'Bairro',
      [GeographicLevel.TRANSPORT_CORRIDOR]: 'Corredor de Transporte'
    };
    
    return levelNames[level] || level;
  }

  /**
   * Get transport mode display name
   */
  getTransportModeName(mode: TransportMode): string {
    const modeNames = {
      [TransportMode.ROAD]: 'Rodoviário',
      [TransportMode.RAIL]: 'Ferroviário',
      [TransportMode.WATERWAY]: 'Hidroviário',
      [TransportMode.AIRPORT]: 'Aeroviário',
      [TransportMode.PORT]: 'Portuário',
      [TransportMode.MULTIMODAL]: 'Multimodal'
    };
    
    return modeNames[mode] || mode;
  }

  /**
   * Generate geographic summary
   */
  generateGeographicSummary(analysis: SpatialAnalysis): string {
    const summary: string[] = [];
    
    // Geographic scope
    if (analysis.coverage_analysis.national_scope) {
      summary.push('Abrangência nacional');
    } else if (analysis.coverage_analysis.multi_regional) {
      summary.push('Abrangência multi-regional');
    } else if (analysis.coverage_analysis.multi_state) {
      summary.push('Abrangência multi-estadual');
    } else {
      summary.push('Abrangência local/estadual');
    }
    
    // Entity counts
    const totalEntities = analysis.coverage_analysis.total_entities;
    const municipalities = analysis.coverage_analysis.by_level.municipality || 0;
    const states = analysis.coverage_analysis.by_level.state || 0;
    
    if (municipalities > 0) {
      summary.push(`${municipalities} município${municipalities > 1 ? 's' : ''}`);
    }
    
    if (states > 0) {
      summary.push(`${states} estado${states > 1 ? 's' : ''}`);
    }
    
    // Transport integration
    if (analysis.spatial_patterns.transport_integration) {
      const corridorCount = analysis.transport_corridors.length;
      summary.push(`${corridorCount} corredor${corridorCount > 1 ? 'es' : ''} de transporte`);
    }
    
    // Urban/metropolitan focus
    if (analysis.spatial_patterns.metropolitan_areas.length > 0) {
      summary.push('Foco em áreas metropolitanas');
    }
    
    return summary.join(', ');
  }

  /**
   * Get affected regions list
   */
  getAffectedRegions(analysis: SpatialAnalysis): string[] {
    return Object.keys(analysis.coverage_analysis.by_region);
  }

  /**
   * Get affected states list
   */
  getAffectedStates(analysis: SpatialAnalysis): string[] {
    return Object.keys(analysis.coverage_analysis.by_state);
  }

  /**
   * Check if document has national impact
   */
  hasNationalImpact(analysis: SpatialAnalysis): boolean {
    return analysis.coverage_analysis.national_scope;
  }

  /**
   * Check if document involves transport corridors
   */
  hasTransportCorridors(analysis: SpatialAnalysis): boolean {
    return analysis.transport_corridors.length > 0;
  }

  /**
   * Get transport corridor types
   */
  getTransportCorridorTypes(analysis: SpatialAnalysis): TransportMode[] {
    const types = new Set<TransportMode>();
    analysis.transport_corridors.forEach(corridor => {
      types.add(corridor.corridor_type);
    });
    return Array.from(types);
  }

  /**
   * Get system health status
   */
  async getHealthStatus(): Promise<{
    status: string;
    ibge_municipalities_loaded: number;
    transport_corridors_loaded: number;
    pandas_available: boolean;
    geopy_available: boolean;
    session_active: boolean;
  } | null> {
    try {
      const response = await fetch(`${this.baseUrl}/health`);
      
      if (!response.ok) {
        throw new Error(`Health check failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to get geocoding health status:', error);
      return null;
    }
  }

  /**
   * Check if service is available
   */
  async isServiceAvailable(): Promise<boolean> {
    const health = await this.getHealthStatus();
    return health?.status === 'healthy';
  }
}

// Create and export singleton instance
export const enhancedGeocodingService = new EnhancedGeocodingService();

// Export service
export default enhancedGeocodingService;