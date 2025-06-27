import { apiConfig } from '../config/api';

export interface BrazilianMunicipality {
  name: string;
  state_code: string;
  state_name: string;
  ibge_code: string;
  latitude: number;
  longitude: number;
  region: string;
  population?: number;
  area_km2?: number;
}

export interface BrazilianState {
  code: string;
  name: string;
  region: string;
  capital: string;
  latitude: number;
  longitude: number;
  municipalities: BrazilianMunicipality[];
}

export interface GeographicAnalysis {
  municipality: string;
  state: string;
  document_count: number;
  legislation_types: string[];
  recent_activity: {
    last_30_days: number;
    last_90_days: number;
    last_year: number;
  };
  coordinates: [number, number];
}

export interface LegislativeHeatmapData {
  state_code: string;
  state_name: string;
  document_count: number;
  activity_level: 'low' | 'medium' | 'high' | 'very_high';
  coordinates: [number, number];
  municipalities: Array<{
    name: string;
    count: number;
    coordinates: [number, number];
  }>;
}

class BrazilianGeographyService {
  private baseUrl: string;
  private municipalitiesCache: BrazilianMunicipality[] | null = null;
  private statesCache: BrazilianState[] | null = null;

  constructor() {
    this.baseUrl = apiConfig.baseUrl;
  }

  // Load Brazilian municipalities data (from datasets-br/city-codes)
  async loadBrazilianMunicipalities(): Promise<BrazilianMunicipality[]> {
    if (this.municipalitiesCache) {
      return this.municipalitiesCache;
    }

    try {
      // In a real implementation, this would load from the actual datasets-br CSV
      // For now, we'll use a representative sample of major Brazilian cities
      const municipalities: BrazilianMunicipality[] = [
        // São Paulo
        { name: 'São Paulo', state_code: 'SP', state_name: 'São Paulo', ibge_code: '3550308', latitude: -23.5505, longitude: -46.6333, region: 'Sudeste', population: 12325232 },
        { name: 'Guarulhos', state_code: 'SP', state_name: 'São Paulo', ibge_code: '3518800', latitude: -23.4625, longitude: -46.5335, region: 'Sudeste', population: 1392121 },
        { name: 'Campinas', state_code: 'SP', state_name: 'São Paulo', ibge_code: '3509502', latitude: -22.9056, longitude: -47.0608, region: 'Sudeste', population: 1213792 },
        { name: 'São Bernardo do Campo', state_code: 'SP', state_name: 'São Paulo', ibge_code: '3548708', latitude: -23.6939, longitude: -46.5640, region: 'Sudeste', population: 844483 },
        
        // Rio de Janeiro
        { name: 'Rio de Janeiro', state_code: 'RJ', state_name: 'Rio de Janeiro', ibge_code: '3304557', latitude: -22.9068, longitude: -43.1729, region: 'Sudeste', population: 6747815 },
        { name: 'São Gonçalo', state_code: 'RJ', state_name: 'Rio de Janeiro', ibge_code: '3304904', latitude: -22.8268, longitude: -43.0533, region: 'Sudeste', population: 1091737 },
        { name: 'Duque de Caxias', state_code: 'RJ', state_name: 'Rio de Janeiro', ibge_code: '3301702', latitude: -22.7856, longitude: -43.3123, region: 'Sudeste', population: 924624 },
        
        // Minas Gerais
        { name: 'Belo Horizonte', state_code: 'MG', state_name: 'Minas Gerais', ibge_code: '3106200', latitude: -19.9167, longitude: -43.9345, region: 'Sudeste', population: 2521564 },
        { name: 'Uberlândia', state_code: 'MG', state_name: 'Minas Gerais', ibge_code: '3170206', latitude: -18.9113, longitude: -48.2622, region: 'Sudeste', population: 699097 },
        { name: 'Contagem', state_code: 'MG', state_name: 'Minas Gerais', ibge_code: '3118601', latitude: -19.9317, longitude: -44.0536, region: 'Sudeste', population: 668949 },
        
        // Bahia
        { name: 'Salvador', state_code: 'BA', state_name: 'Bahia', ibge_code: '2927408', latitude: -12.9714, longitude: -38.5014, region: 'Nordeste', population: 2886698 },
        { name: 'Feira de Santana', state_code: 'BA', state_name: 'Bahia', ibge_code: '2910800', latitude: -12.2664, longitude: -38.9663, region: 'Nordeste', population: 619609 },
        { name: 'Vitória da Conquista', state_code: 'BA', state_name: 'Bahia', ibge_code: '2933307', latitude: -14.8619, longitude: -40.8444, region: 'Nordeste', population: 343230 },
        
        // Paraná
        { name: 'Curitiba', state_code: 'PR', state_name: 'Paraná', ibge_code: '4106902', latitude: -25.4244, longitude: -49.2654, region: 'Sul', population: 1963726 },
        { name: 'Londrina', state_code: 'PR', state_name: 'Paraná', ibge_code: '4113700', latitude: -23.3105, longitude: -51.1628, region: 'Sul', population: 575377 },
        { name: 'Maringá', state_code: 'PR', state_name: 'Paraná', ibge_code: '4115200', latitude: -23.4273, longitude: -51.9375, region: 'Sul', population: 430157 },
        
        // Rio Grande do Sul
        { name: 'Porto Alegre', state_code: 'RS', state_name: 'Rio Grande do Sul', ibge_code: '4314902', latitude: -30.0346, longitude: -51.2177, region: 'Sul', population: 1492530 },
        { name: 'Caxias do Sul', state_code: 'RS', state_name: 'Rio Grande do Sul', ibge_code: '4305108', latitude: -29.1678, longitude: -51.1794, region: 'Sul', population: 517451 },
        { name: 'Pelotas', state_code: 'RS', state_name: 'Rio Grande do Sul', ibge_code: '4314407', latitude: -31.7654, longitude: -52.3376, region: 'Sul', population: 343651 },
        
        // Ceará
        { name: 'Fortaleza', state_code: 'CE', state_name: 'Ceará', ibge_code: '2304400', latitude: -3.7319, longitude: -38.5267, region: 'Nordeste', population: 2686612 },
        { name: 'Caucaia', state_code: 'CE', state_name: 'Ceará', ibge_code: '2303709', latitude: -3.7258, longitude: -38.6531, region: 'Nordeste', population: 368534 },
        { name: 'Juazeiro do Norte', state_code: 'CE', state_name: 'Ceará', ibge_code: '2307650', latitude: -7.2131, longitude: -39.3151, region: 'Nordeste', population: 276264 },
        
        // Pernambuco
        { name: 'Recife', state_code: 'PE', state_name: 'Pernambuco', ibge_code: '2611606', latitude: -8.0476, longitude: -34.8770, region: 'Nordeste', population: 1653461 },
        { name: 'Jaboatão dos Guararapes', state_code: 'PE', state_name: 'Pernambuco', ibge_code: '2607901', latitude: -8.1127, longitude: -35.0147, region: 'Nordeste', population: 702621 },
        { name: 'Olinda', state_code: 'PE', state_name: 'Pernambuco', ibge_code: '2609600', latitude: -7.9989, longitude: -34.8553, region: 'Nordeste', population: 393115 },
        
        // Distrito Federal
        { name: 'Brasília', state_code: 'DF', state_name: 'Distrito Federal', ibge_code: '5300108', latitude: -15.7939, longitude: -47.8828, region: 'Centro-Oeste', population: 3055149 },
        
        // Goiás
        { name: 'Goiânia', state_code: 'GO', state_name: 'Goiás', ibge_code: '5208707', latitude: -16.6869, longitude: -49.2648, region: 'Centro-Oeste', population: 1536097 },
        { name: 'Aparecida de Goiânia', state_code: 'GO', state_name: 'Goiás', ibge_code: '5201108', latitude: -16.8239, longitude: -49.2439, region: 'Centro-Oeste', population: 542090 },
        
        // Amazonas
        { name: 'Manaus', state_code: 'AM', state_name: 'Amazonas', ibge_code: '1302603', latitude: -3.1190, longitude: -60.0217, region: 'Norte', population: 2219580 },
        { name: 'Parintins', state_code: 'AM', state_name: 'Amazonas', ibge_code: '1303403', latitude: -2.6287, longitude: -56.7357, region: 'Norte', population: 114273 },
        
        // Pará
        { name: 'Belém', state_code: 'PA', state_name: 'Pará', ibge_code: '1501402', latitude: -1.4558, longitude: -48.5044, region: 'Norte', population: 1499641 },
        { name: 'Ananindeua', state_code: 'PA', state_name: 'Pará', ibge_code: '1500800', latitude: -1.3656, longitude: -48.3722, region: 'Norte', population: 535547 },
        
        // Maranhão
        { name: 'São Luís', state_code: 'MA', state_name: 'Maranhão', ibge_code: '2111300', latitude: -2.5387, longitude: -44.2825, region: 'Nordeste', population: 1108975 },
        { name: 'Imperatriz', state_code: 'MA', state_name: 'Maranhão', ibge_code: '2105302', latitude: -5.5264, longitude: -47.4918, region: 'Nordeste', population: 259337 },
        
        // Santa Catarina
        { name: 'Florianópolis', state_code: 'SC', state_name: 'Santa Catarina', ibge_code: '4205407', latitude: -27.5954, longitude: -48.5480, region: 'Sul', population: 508826 },
        { name: 'Joinville', state_code: 'SC', state_name: 'Santa Catarina', ibge_code: '4209102', latitude: -26.3045, longitude: -48.8487, region: 'Sul', population: 597658 },
        
        // Espírito Santo
        { name: 'Vitória', state_code: 'ES', state_name: 'Espírito Santo', ibge_code: '3205309', latitude: -20.3155, longitude: -40.3128, region: 'Sudeste', population: 365855 },
        { name: 'Vila Velha', state_code: 'ES', state_name: 'Espírito Santo', ibge_code: '3205200', latitude: -20.3297, longitude: -40.2925, region: 'Sudeste', population: 501325 },
      ];

      this.municipalitiesCache = municipalities;
      return municipalities;
    } catch (error) {
      console.error('Error loading Brazilian municipalities:', error);
      return [];
    }
  }

  // Load Brazilian states data
  async loadBrazilianStates(): Promise<BrazilianState[]> {
    if (this.statesCache) {
      return this.statesCache;
    }

    try {
      const municipalities = await this.loadBrazilianMunicipalities();
      
      const statesData: BrazilianState[] = [
        { code: 'AC', name: 'Acre', region: 'Norte', capital: 'Rio Branco', latitude: -9.0238, longitude: -70.8120, municipalities: [] },
        { code: 'AL', name: 'Alagoas', region: 'Nordeste', capital: 'Maceió', latitude: -9.5713, longitude: -36.7820, municipalities: [] },
        { code: 'AP', name: 'Amapá', region: 'Norte', capital: 'Macapá', latitude: 1.4061, longitude: -51.7705, municipalities: [] },
        { code: 'AM', name: 'Amazonas', region: 'Norte', capital: 'Manaus', latitude: -3.1190, longitude: -60.0217, municipalities: [] },
        { code: 'BA', name: 'Bahia', region: 'Nordeste', capital: 'Salvador', latitude: -12.9714, longitude: -38.5014, municipalities: [] },
        { code: 'CE', name: 'Ceará', region: 'Nordeste', capital: 'Fortaleza', latitude: -3.7319, longitude: -38.5267, municipalities: [] },
        { code: 'DF', name: 'Distrito Federal', region: 'Centro-Oeste', capital: 'Brasília', latitude: -15.7939, longitude: -47.8828, municipalities: [] },
        { code: 'ES', name: 'Espírito Santo', region: 'Sudeste', capital: 'Vitória', latitude: -20.3155, longitude: -40.3128, municipalities: [] },
        { code: 'GO', name: 'Goiás', region: 'Centro-Oeste', capital: 'Goiânia', latitude: -16.6869, longitude: -49.2648, municipalities: [] },
        { code: 'MA', name: 'Maranhão', region: 'Nordeste', capital: 'São Luís', latitude: -2.5387, longitude: -44.2825, municipalities: [] },
        { code: 'MT', name: 'Mato Grosso', region: 'Centro-Oeste', capital: 'Cuiabá', latitude: -15.6014, longitude: -56.0979, municipalities: [] },
        { code: 'MS', name: 'Mato Grosso do Sul', region: 'Centro-Oeste', capital: 'Campo Grande', latitude: -20.4697, longitude: -54.6201, municipalities: [] },
        { code: 'MG', name: 'Minas Gerais', region: 'Sudeste', capital: 'Belo Horizonte', latitude: -19.9167, longitude: -43.9345, municipalities: [] },
        { code: 'PA', name: 'Pará', region: 'Norte', capital: 'Belém', latitude: -1.4558, longitude: -48.5044, municipalities: [] },
        { code: 'PB', name: 'Paraíba', region: 'Nordeste', capital: 'João Pessoa', latitude: -7.1195, longitude: -34.8450, municipalities: [] },
        { code: 'PR', name: 'Paraná', region: 'Sul', capital: 'Curitiba', latitude: -25.4244, longitude: -49.2654, municipalities: [] },
        { code: 'PE', name: 'Pernambuco', region: 'Nordeste', capital: 'Recife', latitude: -8.0476, longitude: -34.8770, municipalities: [] },
        { code: 'PI', name: 'Piauí', region: 'Nordeste', capital: 'Teresina', latitude: -5.0892, longitude: -42.8016, municipalities: [] },
        { code: 'RJ', name: 'Rio de Janeiro', region: 'Sudeste', capital: 'Rio de Janeiro', latitude: -22.9068, longitude: -43.1729, municipalities: [] },
        { code: 'RN', name: 'Rio Grande do Norte', region: 'Nordeste', capital: 'Natal', latitude: -5.7945, longitude: -35.2110, municipalities: [] },
        { code: 'RS', name: 'Rio Grande do Sul', region: 'Sul', capital: 'Porto Alegre', latitude: -30.0346, longitude: -51.2177, municipalities: [] },
        { code: 'RO', name: 'Rondônia', region: 'Norte', capital: 'Porto Velho', latitude: -8.7612, longitude: -63.9006, municipalities: [] },
        { code: 'RR', name: 'Roraima', region: 'Norte', capital: 'Boa Vista', latitude: 2.8235, longitude: -60.6758, municipalities: [] },
        { code: 'SC', name: 'Santa Catarina', region: 'Sul', capital: 'Florianópolis', latitude: -27.5954, longitude: -48.5480, municipalities: [] },
        { code: 'SP', name: 'São Paulo', region: 'Sudeste', capital: 'São Paulo', latitude: -23.5505, longitude: -46.6333, municipalities: [] },
        { code: 'SE', name: 'Sergipe', region: 'Nordeste', capital: 'Aracaju', latitude: -10.9472, longitude: -37.0731, municipalities: [] },
        { code: 'TO', name: 'Tocantins', region: 'Norte', capital: 'Palmas', latitude: -10.1753, longitude: -48.2982, municipalities: [] }
      ];

      // Group municipalities by state
      for (const municipality of municipalities) {
        const state = statesData.find(s => s.code === municipality.state_code);
        if (state) {
          state.municipalities.push(municipality);
        }
      }

      this.statesCache = statesData;
      return statesData;
    } catch (error) {
      console.error('Error loading Brazilian states:', error);
      return [];
    }
  }

  // Get geographic analysis for legislative documents
  async getGeographicAnalysis(query?: string): Promise<GeographicAnalysis[]> {
    try {
      const url = new URL(`${this.baseUrl}/api/v1/geographic/analysis`);
      if (query) {
        url.searchParams.append('query', query);
      }

      const response = await fetch(url.toString());
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data.data || [];
    } catch (error) {
      console.error('Error fetching geographic analysis:', error);
      return [];
    }
  }

  // Get legislative heatmap data
  async getLegislativeHeatmapData(timeRange?: string): Promise<LegislativeHeatmapData[]> {
    try {
      const municipalities = await this.loadBrazilianMunicipalities();
      
      // Simulate legislative activity data
      // In a real implementation, this would come from the backend API
      const heatmapData: LegislativeHeatmapData[] = [];
      const states = await this.loadBrazilianStates();

      for (const state of states) {
        const documentCount = Math.floor(Math.random() * 100) + 1;
        
        let activityLevel: 'low' | 'medium' | 'high' | 'very_high';
        if (documentCount < 20) activityLevel = 'low';
        else if (documentCount < 50) activityLevel = 'medium';
        else if (documentCount < 80) activityLevel = 'high';
        else activityLevel = 'very_high';

        const municipalityData = state.municipalities.map(municipality => ({
          name: municipality.name,
          count: Math.floor(Math.random() * 20) + 1,
          coordinates: [municipality.latitude, municipality.longitude] as [number, number]
        }));

        heatmapData.push({
          state_code: state.code,
          state_name: state.name,
          document_count: documentCount,
          activity_level: activityLevel,
          coordinates: [state.latitude, state.longitude],
          municipalities: municipalityData
        });
      }

      return heatmapData;
    } catch (error) {
      console.error('Error generating heatmap data:', error);
      return [];
    }
  }

  // Search municipalities by name
  searchMunicipalities(query: string): Promise<BrazilianMunicipality[]> {
    return this.loadBrazilianMunicipalities().then(municipalities => {
      const searchTerm = query.toLowerCase();
      return municipalities.filter(municipality =>
        municipality.name.toLowerCase().includes(searchTerm) ||
        municipality.state_name.toLowerCase().includes(searchTerm)
      );
    });
  }

  // Get municipalities by state
  getMunicipalitiesByState(stateCode: string): Promise<BrazilianMunicipality[]> {
    return this.loadBrazilianMunicipalities().then(municipalities => 
      municipalities.filter(municipality => municipality.state_code === stateCode)
    );
  }

  // Get state by code
  getStateByCode(stateCode: string): Promise<BrazilianState | null> {
    return this.loadBrazilianStates().then(states => 
      states.find(state => state.code === stateCode) || null
    );
  }

  // Get geographic bounds for Brazil
  getBrazilBounds(): { north: number; south: number; east: number; west: number } {
    return {
      north: 5.272,    // Northernmost point (Roraima)
      south: -33.742,  // Southernmost point (Rio Grande do Sul)
      east: -32.393,   // Easternmost point (Paraíba)
      west: -73.985    // Westernmost point (Acre)
    };
  }

  // Calculate distance between two coordinates
  calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371; // Earth's radius in kilometers
    const dLat = this.toRadians(lat2 - lat1);
    const dLon = this.toRadians(lon2 - lon1);
    const a = 
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180);
  }
}

export const brazilianGeographyService = new BrazilianGeographyService();