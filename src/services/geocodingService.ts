/**
 * Advanced Geocoding Service
 * Frontend service for Brazilian geocoding with 6-level precision
 */

import apiClient from './apiClient';
import { API_ENDPOINTS } from '../config/api';

export interface GeocodingRequest {
  address: string;
  precision_level?: number;
  include_coordinates?: boolean;
  include_administrative?: boolean;
}

export interface ReverseGeocodingRequest {
  latitude: number;
  longitude: number;
  precision_level?: number;
  radius_km?: number;
}

export interface GeocodingResult {
  address: string;
  coordinates?: {
    latitude: number;
    longitude: number;
    coordinate_system: string;
  };
  administrative_info: {
    municipality?: string;
    state?: string;
    region?: string;
    country: string;
  };
  precision_info: {
    level: number;
    description: string;
    accuracy_estimate_meters: number;
  };
  confidence_score: number;
  processing_time_ms: number;
}

export interface AddressValidationRequest {
  address: string;
  components?: {
    street?: string;
    number?: string;
    neighborhood?: string;
    city?: string;
    state?: string;
    postal_code?: string;
  };
}

export interface AddressValidationResult {
  is_valid: boolean;
  validation_score: number;
  standardized_address: string;
  components: Record<string, string>;
  corrections_applied: string[];
  validation_details: Record<string, any>;
  processing_time_ms: number;
}

export interface MunicipalityInfo {
  ibge_code: string;
  name: string;
  state: string;
  region: string;
  coordinates: {
    latitude: number;
    longitude: number;
  };
  area_km2: number;
  population?: number;
  metropolitan_area?: string;
}

export interface PrecisionLevel {
  level: number;
  name: string;
  description: string;
  accuracy_range: string;
  use_cases: string[];
}

export interface BatchGeocodingRequest {
  addresses: string[];
  precision_level?: number;
  max_results_per_address?: number;
}

export interface BatchGeocodingResult {
  total_addresses: number;
  successful_geocoded: number;
  failed_geocoded: number;
  results: Array<{
    input_address: string;
    geocoding_result?: GeocodingResult;
    error?: string;
  }>;
  processing_summary: Record<string, any>;
}

export class GeocodingService {
  /**
   * Forward geocoding - address to coordinates
   */
  async geocodeAddress(request: GeocodingRequest): Promise<GeocodingResult> {
    return apiClient.post(API_ENDPOINTS.geocoding.forward, request);
  }

  /**
   * Reverse geocoding - coordinates to address
   */
  async reverseGeocode(request: ReverseGeocodingRequest): Promise<GeocodingResult> {
    return apiClient.post(API_ENDPOINTS.geocoding.reverse, request);
  }

  /**
   * Validate and standardize Brazilian address
   */
  async validateAddress(request: AddressValidationRequest): Promise<AddressValidationResult> {
    return apiClient.post(API_ENDPOINTS.geocoding.validate, request);
  }

  /**
   * Search municipalities by name or criteria
   */
  async searchMunicipalities(query: string, state?: string): Promise<{
    municipalities: MunicipalityInfo[];
    total_results: number;
    search_query: string;
  }> {
    const params: Record<string, string> = { q: query };
    if (state) params.state = state;
    return apiClient.get(API_ENDPOINTS.geocoding.municipalities, params);
  }

  /**
   * Get precision level information
   */
  async getPrecisionLevels(): Promise<{
    precision_levels: PrecisionLevel[];
    default_level: number;
    total_levels: number;
  }> {
    return apiClient.get(API_ENDPOINTS.geocoding.precision);
  }

  /**
   * Batch geocoding for multiple addresses
   */
  async geocodeBatch(request: BatchGeocodingRequest): Promise<BatchGeocodingResult> {
    return apiClient.post(API_ENDPOINTS.geocoding.batch, request);
  }

  /**
   * Get geocoding service statistics
   */
  async getStatistics(): Promise<{
    status: string;
    geocoding_statistics: Record<string, any>;
  }> {
    return apiClient.get(API_ENDPOINTS.geocoding.statistics);
  }

  /**
   * Check geocoding service health
   */
  async checkHealth(): Promise<{
    status: string;
    geocoding_available: boolean;
    precision_levels_available?: number;
    cnefe_data_loaded?: boolean;
    features_available?: string[];
    message?: string;
    error?: string;
  }> {
    return apiClient.get(API_ENDPOINTS.geocoding.health);
  }

  /**
   * Helper method for high-precision geocoding
   */
  async geocodeHighPrecision(address: string): Promise<GeocodingResult> {
    return this.geocodeAddress({
      address,
      precision_level: 1, // Highest precision
      include_coordinates: true,
      include_administrative: true
    });
  }

  /**
   * Helper method for city-level geocoding
   */
  async geocodeCity(cityName: string, state?: string): Promise<GeocodingResult> {
    const address = state ? `${cityName}, ${state}` : cityName;
    return this.geocodeAddress({
      address,
      precision_level: 4, // City-level precision
      include_coordinates: true,
      include_administrative: true
    });
  }

  /**
   * Helper method to find nearest municipality
   */
  async findNearestMunicipality(latitude: number, longitude: number): Promise<{
    geocoding: GeocodingResult;
    municipality: MunicipalityInfo | null;
    distance_km?: number;
  }> {
    const geocoding = await this.reverseGeocode({
      latitude,
      longitude,
      precision_level: 4, // Municipality level
      radius_km: 50
    });

    let municipality: MunicipalityInfo | null = null;
    let distance_km: number | undefined;

    if (geocoding.administrative_info.municipality) {
      try {
        const municipalitySearch = await this.searchMunicipalities(
          geocoding.administrative_info.municipality,
          geocoding.administrative_info.state
        );
        
        if (municipalitySearch.municipalities.length > 0) {
          municipality = municipalitySearch.municipalities[0];
          
          // Calculate distance using Haversine formula
          distance_km = this.calculateDistance(
            latitude, longitude,
            municipality.coordinates.latitude,
            municipality.coordinates.longitude
          );
        }
      } catch (error) {
        console.warn('Could not fetch municipality details:', error);
      }
    }

    return {
      geocoding,
      municipality,
      distance_km
    };
  }

  /**
   * Helper method for CEP (postal code) validation
   */
  async validateCEP(cep: string): Promise<{
    validation: AddressValidationResult;
    isValid: boolean;
    standardizedCEP: string;
    municipality?: string;
    state?: string;
  }> {
    // Clean CEP format
    const cleanCEP = cep.replace(/\D/g, '');
    
    const validation = await this.validateAddress({
      components: {
        postal_code: cleanCEP
      }
    });

    const standardizedCEP = cleanCEP.replace(/(\d{5})(\d{3})/, '$1-$2');

    return {
      validation,
      isValid: validation.is_valid,
      standardizedCEP,
      municipality: validation.components.city,
      state: validation.components.state
    };
  }

  /**
   * Helper method for batch geocoding with progress tracking
   */
  async geocodeBatchWithProgress(
    addresses: string[],
    onProgress?: (processed: number, total: number) => void,
    options: { precision_level?: number; batch_size?: number } = {}
  ): Promise<BatchGeocodingResult> {
    const batchSize = options.batch_size || 50;
    const results: Array<{ input_address: string; geocoding_result?: GeocodingResult; error?: string }> = [];
    let processed = 0;

    for (let i = 0; i < addresses.length; i += batchSize) {
      const batch = addresses.slice(i, i + batchSize);
      
      try {
        const batchResult = await this.geocodeBatch({
          addresses: batch,
          precision_level: options.precision_level || 3
        });
        
        results.push(...batchResult.results);
        processed += batch.length;
        
        if (onProgress) {
          onProgress(processed, addresses.length);
        }
      } catch (error) {
        // Add failed batch to results
        batch.forEach(address => {
          results.push({
            input_address: address,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        });
        processed += batch.length;
        
        if (onProgress) {
          onProgress(processed, addresses.length);
        }
      }
    }

    // Calculate final statistics
    const successful = results.filter(r => r.geocoding_result).length;
    const failed = results.length - successful;

    return {
      total_addresses: results.length,
      successful_geocoded: successful,
      failed_geocoded: failed,
      results,
      processing_summary: {
        batch_size: batchSize,
        processing_time_total: 0, // Would be calculated in real implementation
        success_rate: (successful / results.length) * 100
      }
    };
  }

  /**
   * Calculate distance between two coordinates using Haversine formula
   */
  private calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371; // Earth's radius in kilometers
    const dLat = this.toRadians(lat2 - lat1);
    const dLon = this.toRadians(lon2 - lon1);
    
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180);
  }
}

export const geocodingService = new GeocodingService();