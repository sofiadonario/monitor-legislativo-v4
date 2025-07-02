/**
 * Geographic Service
 * Provides location-based search, geocoding, and Brazilian municipality data
 */
import { API_ENDPOINTS, buildApiUrl, API_CONFIG } from '../config/api';
import {
  Coordinates,
  Address,
  Municipality,
  DocumentLocation,
  GeographicSearchParams,
  LegislativeDocument,
  StateData
} from '../types';

export class GeographicService {
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor() {
    this.baseUrl = API_CONFIG.baseUrl;
    this.headers = API_CONFIG.headers;
  }

  /**
   * Search documents by geographic location and radius
   */
  async searchByLocation(
    coordinates: Coordinates,
    radius: number,
    params?: GeographicSearchParams
  ): Promise<LegislativeDocument[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geographic.search, {
        lat: coordinates.lat.toString(),
        lng: coordinates.lng.toString(),
        radius: radius.toString(),
        ...(params?.states && { states: params.states.join(',') }),
        ...(params?.municipalities && { municipalities: params.municipalities.join(',') }),
        ...(params?.includeNearby && { include_nearby: 'true' })
      });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Geographic search failed: ${response.status}`);
      }

      const data = await response.json();
      return this.transformDocuments(data.documents || data);
    } catch (error) {
      console.error('Error in geographic search:', error);
      throw new Error(`Geographic search failed: ${error}`);
    }
  }

  /**
   * Get document locations with coordinates
   */
  async getDocumentLocations(urns: string[]): Promise<DocumentLocation[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geographic.search);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...this.headers,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ urns }),
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get document locations: ${response.status}`);
      }

      const data = await response.json();
      return this.transformDocumentLocations(data.locations || data);
    } catch (error) {
      console.error('Error getting document locations:', error);
      throw new Error(`Failed to get document locations: ${error}`);
    }
  }

  /**
   * Get all Brazilian states
   */
  async getStates(): Promise<StateData[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geographic.states);

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get states: ${response.status}`);
      }

      const data = await response.json();
      return this.transformStates(data.states || data);
    } catch (error) {
      console.error('Error getting states:', error);
      // Fallback to local data if API fails
      return this.getBrazilianStatesOffline();
    }
  }

  /**
   * Get municipalities, optionally filtered by state
   */
  async getMunicipalities(state?: string): Promise<Municipality[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geographic.municipalities, {
        ...(state && { state })
      });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get municipalities: ${response.status}`);
      }

      const data = await response.json();
      return this.transformMunicipalities(data.municipalities || data);
    } catch (error) {
      console.error('Error getting municipalities:', error);
      throw new Error(`Failed to get municipalities: ${error}`);
    }
  }

  /**
   * Geocode an address to coordinates
   */
  async geocodeAddress(address: string): Promise<Coordinates | null> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geocoding.forward, {
        address: encodeURIComponent(address),
        country: 'BR'
      });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`Geocoding failed: ${response.status}`);
      }

      const data = await response.json();
      if (data.results && data.results.length > 0) {
        const result = data.results[0];
        return {
          lat: result.geometry?.location?.lat || result.lat,
          lng: result.geometry?.location?.lng || result.lng
        };
      }

      return null;
    } catch (error) {
      console.error('Error geocoding address:', error);
      throw new Error(`Geocoding failed: ${error}`);
    }
  }

  /**
   * Reverse geocode coordinates to address
   */
  async reverseGeocode(coordinates: Coordinates): Promise<Address | null> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geocoding.reverse, {
        lat: coordinates.lat.toString(),
        lng: coordinates.lng.toString()
      });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`Reverse geocoding failed: ${response.status}`);
      }

      const data = await response.json();
      return this.transformAddress(data);
    } catch (error) {
      console.error('Error reverse geocoding:', error);
      throw new Error(`Reverse geocoding failed: ${error}`);
    }
  }

  /**
   * Get geographic statistics
   */
  async getGeographicStatistics(): Promise<any> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geographic.statistics);

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get geographic statistics: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting geographic statistics:', error);
      throw new Error(`Failed to get geographic statistics: ${error}`);
    }
  }

  /**
   * Batch geocode multiple addresses
   */
  async batchGeocode(addresses: string[]): Promise<(Coordinates | null)[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geocoding.batch);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          ...this.headers,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ addresses }),
        signal: AbortSignal.timeout(API_CONFIG.timeout * 2) // Longer timeout for batch
      });

      if (!response.ok) {
        throw new Error(`Batch geocoding failed: ${response.status}`);
      }

      const data = await response.json();
      return data.results.map((result: any) => {
        if (result.coordinates) {
          return {
            lat: result.coordinates.lat,
            lng: result.coordinates.lng
          };
        }
        return null;
      });
    } catch (error) {
      console.error('Error batch geocoding:', error);
      throw new Error(`Batch geocoding failed: ${error}`);
    }
  }

  /**
   * Search documents within bounding box
   */
  async searchByBoundingBox(
    northeast: Coordinates,
    southwest: Coordinates,
    params?: GeographicSearchParams
  ): Promise<LegislativeDocument[]> {
    try {
      const url = buildApiUrl(API_ENDPOINTS.geographic.search, {
        ne_lat: northeast.lat.toString(),
        ne_lng: northeast.lng.toString(),
        sw_lat: southwest.lat.toString(),
        sw_lng: southwest.lng.toString(),
        ...(params?.states && { states: params.states.join(',') }),
        ...(params?.municipalities && { municipalities: params.municipalities.join(',') })
      });

      const response = await fetch(url, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(API_CONFIG.timeout)
      });

      if (!response.ok) {
        throw new Error(`Bounding box search failed: ${response.status}`);
      }

      const data = await response.json();
      return this.transformDocuments(data.documents || data);
    } catch (error) {
      console.error('Error in bounding box search:', error);
      throw new Error(`Bounding box search failed: ${error}`);
    }
  }

  /**
   * Calculate distance between two coordinates (Haversine formula)
   */
  calculateDistance(coord1: Coordinates, coord2: Coordinates): number {
    const R = 6371; // Earth's radius in kilometers
    const dLat = this.toRad(coord2.lat - coord1.lat);
    const dLng = this.toRad(coord2.lng - coord1.lng);
    
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(this.toRad(coord1.lat)) * Math.cos(this.toRad(coord2.lat)) *
              Math.sin(dLng / 2) * Math.sin(dLng / 2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c; // Distance in kilometers
  }

  // Private helper methods
  private toRad(degrees: number): number {
    return degrees * (Math.PI / 180);
  }

  private transformDocuments(data: any[]): LegislativeDocument[] {
    return data.map(doc => ({
      id: doc.id || doc.urn || '',
      title: doc.title || '',
      summary: doc.summary || doc.description || '',
      type: doc.type || 'lei',
      date: doc.date || doc.publicationDate || new Date().toISOString(),
      keywords: doc.keywords || [],
      state: doc.state || doc.jurisdiction?.state || '',
      municipality: doc.municipality || doc.jurisdiction?.municipality,
      url: doc.url || doc.link || '',
      status: doc.status || 'em_tramitacao',
      author: doc.author,
      chamber: doc.chamber || doc.source,
      number: doc.number,
      source: doc.source,
      citation: doc.citation
    }));
  }

  private transformDocumentLocations(data: any[]): DocumentLocation[] {
    return data.map(loc => ({
      urn: loc.urn || loc.id || '',
      title: loc.title || '',
      type: loc.type || 'lei',
      coordinates: {
        lat: loc.coordinates?.lat || loc.latitude || 0,
        lng: loc.coordinates?.lng || loc.longitude || 0
      },
      municipality: loc.municipality || '',
      state: loc.state || '',
      address: loc.address ? this.transformAddress(loc.address) : undefined,
      precision: loc.precision || 'approximate',
      confidence: loc.confidence || 0.5
    }));
  }

  private transformStates(data: any[]): StateData[] {
    return data.map(state => ({
      id: state.id || state.code || '',
      name: state.name || '',
      abbreviation: state.abbreviation || state.uf || '',
      region: state.region || '',
      capital: state.capital || '',
      population: state.population,
      area: state.area,
      coordinates: [
        state.coordinates?.lat || state.latitude || 0,
        state.coordinates?.lng || state.longitude || 0
      ],
      boundaries: state.boundaries || state.geometry
    }));
  }

  private transformMunicipalities(data: any[]): Municipality[] {
    return data.map(muni => ({
      id: muni.id || muni.code || '',
      name: muni.name || '',
      stateId: muni.stateId || muni.state_id || '',
      stateAbbreviation: muni.stateAbbreviation || muni.state || '',
      stateName: muni.stateName || muni.state_name || '',
      region: muni.region || '',
      microregion: muni.microregion,
      mesoregion: muni.mesoregion,
      population: muni.population,
      area: muni.area,
      coordinates: {
        lat: muni.coordinates?.lat || muni.latitude || 0,
        lng: muni.coordinates?.lng || muni.longitude || 0
      },
      boundaries: muni.boundaries || muni.geometry,
      ibgeCode: muni.ibgeCode || muni.ibge_code || muni.code || ''
    }));
  }

  private transformAddress(data: any): Address {
    return {
      street: data.street || data.logradouro,
      number: data.number || data.numero,
      complement: data.complement || data.complemento,
      neighborhood: data.neighborhood || data.bairro,
      municipality: data.municipality || data.municipio || data.city || '',
      state: data.state || data.estado || data.uf || '',
      postalCode: data.postalCode || data.cep,
      country: data.country || 'Brasil',
      formattedAddress: data.formattedAddress || data.formatted_address || 
                       `${data.street || ''}, ${data.number || ''} - ${data.municipality || ''}, ${data.state || ''}`
    };
  }

  // Offline fallback for Brazilian states
  private getBrazilianStatesOffline(): StateData[] {
    return [
      { id: 'AC', name: 'Acre', abbreviation: 'AC', region: 'Norte', capital: 'Rio Branco', coordinates: [-9.0238, -70.8120] },
      { id: 'AL', name: 'Alagoas', abbreviation: 'AL', region: 'Nordeste', capital: 'Maceió', coordinates: [-9.5713, -36.7820] },
      { id: 'AP', name: 'Amapá', abbreviation: 'AP', region: 'Norte', capital: 'Macapá', coordinates: [1.4110, -51.7700] },
      { id: 'AM', name: 'Amazonas', abbreviation: 'AM', region: 'Norte', capital: 'Manaus', coordinates: [-3.4168, -65.8561] },
      { id: 'BA', name: 'Bahia', abbreviation: 'BA', region: 'Nordeste', capital: 'Salvador', coordinates: [-12.5797, -41.7007] },
      { id: 'CE', name: 'Ceará', abbreviation: 'CE', region: 'Nordeste', capital: 'Fortaleza', coordinates: [-5.4984, -39.3206] },
      { id: 'DF', name: 'Distrito Federal', abbreviation: 'DF', region: 'Centro-Oeste', capital: 'Brasília', coordinates: [-15.8267, -47.9218] },
      { id: 'ES', name: 'Espírito Santo', abbreviation: 'ES', region: 'Sudeste', capital: 'Vitória', coordinates: [-19.1834, -40.3089] },
      { id: 'GO', name: 'Goiás', abbreviation: 'GO', region: 'Centro-Oeste', capital: 'Goiânia', coordinates: [-15.8270, -49.8362] },
      { id: 'MA', name: 'Maranhão', abbreviation: 'MA', region: 'Nordeste', capital: 'São Luís', coordinates: [-4.9609, -45.2744] },
      { id: 'MT', name: 'Mato Grosso', abbreviation: 'MT', region: 'Centro-Oeste', capital: 'Cuiabá', coordinates: [-12.6819, -56.9211] },
      { id: 'MS', name: 'Mato Grosso do Sul', abbreviation: 'MS', region: 'Centro-Oeste', capital: 'Campo Grande', coordinates: [-20.7722, -54.7852] },
      { id: 'MG', name: 'Minas Gerais', abbreviation: 'MG', region: 'Sudeste', capital: 'Belo Horizonte', coordinates: [-18.5122, -44.5550] },
      { id: 'PA', name: 'Pará', abbreviation: 'PA', region: 'Norte', capital: 'Belém', coordinates: [-5.8945, -52.3763] },
      { id: 'PB', name: 'Paraíba', abbreviation: 'PB', region: 'Nordeste', capital: 'João Pessoa', coordinates: [-7.2400, -36.7820] },
      { id: 'PR', name: 'Paraná', abbreviation: 'PR', region: 'Sul', capital: 'Curitiba', coordinates: [-24.8945, -51.5553] },
      { id: 'PE', name: 'Pernambuco', abbreviation: 'PE', region: 'Nordeste', capital: 'Recife', coordinates: [-8.8137, -36.9541] },
      { id: 'PI', name: 'Piauí', abbreviation: 'PI', region: 'Nordeste', capital: 'Teresina', coordinates: [-7.7183, -42.7289] },
      { id: 'RJ', name: 'Rio de Janeiro', abbreviation: 'RJ', region: 'Sudeste', capital: 'Rio de Janeiro', coordinates: [-22.9099, -43.2095] },
      { id: 'RN', name: 'Rio Grande do Norte', abbreviation: 'RN', region: 'Nordeste', capital: 'Natal', coordinates: [-5.4026, -36.9541] },
      { id: 'RS', name: 'Rio Grande do Sul', abbreviation: 'RS', region: 'Sul', capital: 'Porto Alegre', coordinates: [-29.6883, -53.8181] },
      { id: 'RO', name: 'Rondônia', abbreviation: 'RO', region: 'Norte', capital: 'Porto Velho', coordinates: [-10.8305, -63.8315] },
      { id: 'RR', name: 'Roraima', abbreviation: 'RR', region: 'Norte', capital: 'Boa Vista', coordinates: [1.9913, -61.3332] },
      { id: 'SC', name: 'Santa Catarina', abbreviation: 'SC', region: 'Sul', capital: 'Florianópolis', coordinates: [-27.2423, -50.2189] },
      { id: 'SP', name: 'São Paulo', abbreviation: 'SP', region: 'Sudeste', capital: 'São Paulo', coordinates: [-22.2154, -48.7903] },
      { id: 'SE', name: 'Sergipe', abbreviation: 'SE', region: 'Nordeste', capital: 'Aracaju', coordinates: [-10.5741, -37.3857] },
      { id: 'TO', name: 'Tocantins', abbreviation: 'TO', region: 'Norte', capital: 'Palmas', coordinates: [-10.1753, -48.2982] }
    ];
  }
}

// Export singleton instance
export const geographicService = new GeographicService();