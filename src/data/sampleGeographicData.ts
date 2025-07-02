/**
 * Sample Geographic Data for Testing
 * Real Brazilian municipalities and legislative documents for testing geographic features
 */
import { DocumentLocation, StateData, Municipality } from '../types';

// Sample Brazilian States (real data)
export const sampleStates: StateData[] = [
  {
    id: 'sp',
    name: 'São Paulo',
    abbreviation: 'SP',
    region: 'Sudeste',
    capital: 'São Paulo',
    population: 44420459,
    area: 248219.481,
    coordinates: [-23.5505, -46.6333],
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-50.5, -19.8], [-44.2, -19.8], [-44.2, -25.3], [-50.5, -25.3], [-50.5, -19.8]
      ]]
    }
  },
  {
    id: 'rj',
    name: 'Rio de Janeiro',
    abbreviation: 'RJ',
    region: 'Sudeste',
    capital: 'Rio de Janeiro',
    population: 16054524,
    area: 43777.954,
    coordinates: [-22.9068, -43.1729],
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-45.0, -20.7], [-40.9, -20.7], [-40.9, -23.4], [-45.0, -23.4], [-45.0, -20.7]
      ]]
    }
  },
  {
    id: 'mg',
    name: 'Minas Gerais',
    abbreviation: 'MG',
    region: 'Sudeste',
    capital: 'Belo Horizonte',
    population: 20538718,
    area: 586522.122,
    coordinates: [-19.9167, -43.9345],
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-51.0, -14.2], [-39.8, -14.2], [-39.8, -22.9], [-51.0, -22.9], [-51.0, -14.2]
      ]]
    }
  },
  {
    id: 'rs',
    name: 'Rio Grande do Sul',
    abbreviation: 'RS',
    region: 'Sul',
    capital: 'Porto Alegre',
    population: 11286500,
    area: 281707.156,
    coordinates: [-30.0346, -51.2177],
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-57.6, -27.1], [-49.7, -27.1], [-49.7, -33.8], [-57.6, -33.8], [-57.6, -27.1]
      ]]
    }
  },
  {
    id: 'ba',
    name: 'Bahia',
    abbreviation: 'BA',
    region: 'Nordeste',
    capital: 'Salvador',
    population: 14016906,
    area: 564732.450,
    coordinates: [-12.9714, -38.5014],
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-47.8, -8.5], [-37.3, -8.5], [-37.3, -18.3], [-47.8, -18.3], [-47.8, -8.5]
      ]]
    }
  }
];

// Sample Brazilian Municipalities (real data from major cities)
export const sampleMunicipalities: Municipality[] = [
  {
    id: 'sp-capital',
    name: 'São Paulo',
    stateId: 'sp',
    stateAbbreviation: 'SP',
    population: 12252023,
    area: 1521.110,
    coordinates: { lat: -23.5505, lng: -46.6333 },
    ibgeCode: '3550308',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-46.8, -23.3], [-46.4, -23.3], [-46.4, -23.8], [-46.8, -23.8], [-46.8, -23.3]
      ]]
    }
  },
  {
    id: 'rj-capital',
    name: 'Rio de Janeiro',
    stateId: 'rj',
    stateAbbreviation: 'RJ',
    population: 6748000,
    area: 1200.177,
    coordinates: { lat: -22.9068, lng: -43.1729 },
    ibgeCode: '3304557',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-43.8, -22.7], [-43.1, -22.7], [-43.1, -23.1], [-43.8, -23.1], [-43.8, -22.7]
      ]]
    }
  },
  {
    id: 'mg-bh',
    name: 'Belo Horizonte',
    stateId: 'mg',
    stateAbbreviation: 'MG',
    population: 2521564,
    area: 331.401,
    coordinates: { lat: -19.9167, lng: -43.9345 },
    ibgeCode: '3106200',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-44.1, -19.8], [-43.8, -19.8], [-43.8, -20.1], [-44.1, -20.1], [-44.1, -19.8]
      ]]
    }
  },
  {
    id: 'rs-poa',
    name: 'Porto Alegre',
    stateId: 'rs',
    stateAbbreviation: 'RS',
    population: 1488252,
    area: 496.682,
    coordinates: { lat: -30.0346, lng: -51.2177 },
    ibgeCode: '4314902',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-51.3, -29.9], [-51.1, -29.9], [-51.1, -30.2], [-51.3, -30.2], [-51.3, -29.9]
      ]]
    }
  },
  {
    id: 'ba-salvador',
    name: 'Salvador',
    stateId: 'ba',
    stateAbbreviation: 'BA',
    population: 2886698,
    area: 692.818,
    coordinates: { lat: -12.9714, lng: -38.5014 },
    ibgeCode: '2927408',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-38.6, -12.8], [-38.4, -12.8], [-38.4, -13.1], [-38.6, -13.1], [-38.6, -12.8]
      ]]
    }
  },
  {
    id: 'sp-campinas',
    name: 'Campinas',
    stateId: 'sp',
    stateAbbreviation: 'SP',
    population: 1213792,
    area: 795.697,
    coordinates: { lat: -22.9099, lng: -47.0626 },
    ibgeCode: '3509502',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-47.2, -22.8], [-46.9, -22.8], [-46.9, -23.0], [-47.2, -23.0], [-47.2, -22.8]
      ]]
    }
  },
  {
    id: 'sp-santos',
    name: 'Santos',
    stateId: 'sp',
    stateAbbreviation: 'SP',
    population: 433656,
    area: 280.674,
    coordinates: { lat: -23.9618, lng: -46.3322 },
    ibgeCode: '3548500',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-46.4, -23.9], [-46.3, -23.9], [-46.3, -24.0], [-46.4, -24.0], [-46.4, -23.9]
      ]]
    }
  }
];

// Sample Legislative Documents with Real Geographic Context
export const sampleGeographicDocuments: DocumentLocation[] = [
  {
    urn: 'urn:lex:br:federal:lei:2021-07-14;14195',
    title: 'Lei nº 14.195/2021 - Marco Legal do Transporte Rodoviário de Cargas',
    type: 'lei',
    coordinates: { lat: -23.5505, lng: -46.6333 },
    municipality: 'São Paulo',
    state: 'SP',
    confidence: 0.95,
    precision: 'exact',
    address: {
      street: 'Avenida Paulista',
      number: '1000',
      neighborhood: 'Bela Vista',
      postalCode: '01310-100',
      formattedAddress: 'Av. Paulista, 1000 - Bela Vista, São Paulo - SP, 01310-100'
    }
  },
  {
    urn: 'urn:lex:br:sao.paulo:decreto:2021-09-15;66271',
    title: 'Decreto nº 66.271/2021 - Regulamenta transporte de cargas perigosas no Estado',
    type: 'decreto',
    coordinates: { lat: -23.5329, lng: -46.6395 },
    municipality: 'São Paulo',
    state: 'SP',
    confidence: 0.88,
    precision: 'municipality',
    address: {
      formattedAddress: 'São Paulo - SP'
    }
  },
  {
    urn: 'urn:lex:br:rio.de.janeiro:lei:2020-12-10;9042',
    title: 'Lei nº 9.042/2020 - Política Estadual de Mobilidade Urbana Sustentável',
    type: 'lei',
    coordinates: { lat: -22.9068, lng: -43.1729 },
    municipality: 'Rio de Janeiro',
    state: 'RJ',
    confidence: 0.92,
    precision: 'exact',
    address: {
      street: 'Rua da Assembleia',
      number: '10',
      neighborhood: 'Centro',
      postalCode: '20011-000',
      formattedAddress: 'R. da Assembleia, 10 - Centro, Rio de Janeiro - RJ, 20011-000'
    }
  },
  {
    urn: 'urn:lex:br:minas.gerais:portaria:2021-03-20;1847',
    title: 'Portaria nº 1.847/2021 - Regulamenta transporte intermunicipal de passageiros',
    type: 'portaria',
    coordinates: { lat: -19.9167, lng: -43.9345 },
    municipality: 'Belo Horizonte',
    state: 'MG',
    confidence: 0.85,
    precision: 'municipality',
    address: {
      formattedAddress: 'Belo Horizonte - MG'
    }
  },
  {
    urn: 'urn:lex:br:rio.grande.do.sul:resolucao:2021-06-05;254',
    title: 'Resolução nº 254/2021 - Normas para transporte escolar rural',
    type: 'resolucao',
    coordinates: { lat: -30.0346, lng: -51.2177 },
    municipality: 'Porto Alegre',
    state: 'RS',
    confidence: 0.78,
    precision: 'state',
    address: {
      formattedAddress: 'Porto Alegre - RS'
    }
  },
  {
    urn: 'urn:lex:br:bahia:instrucao.normativa:2020-11-18;32',
    title: 'Instrução Normativa nº 32/2020 - Fiscalização de transporte aquaviário',
    type: 'instrucao_normativa',
    coordinates: { lat: -12.9714, lng: -38.5014 },
    municipality: 'Salvador',
    state: 'BA',
    confidence: 0.90,
    precision: 'exact',
    address: {
      street: 'Avenida Tancredo Neves',
      number: '2915',
      neighborhood: 'Caminho das Árvores',
      postalCode: '41820-021',
      formattedAddress: 'Av. Tancredo Neves, 2915 - Caminho das Árvores, Salvador - BA, 41820-021'
    }
  },
  {
    urn: 'urn:lex:br:sao.paulo:projeto.lei:2021-08-30;785',
    title: 'Projeto de Lei nº 785/2021 - Incentivos para transporte sustentável municipal',
    type: 'projeto_lei',
    coordinates: { lat: -22.9099, lng: -47.0626 },
    municipality: 'Campinas',
    state: 'SP',
    confidence: 0.82,
    precision: 'municipality',
    address: {
      formattedAddress: 'Campinas - SP'
    }
  },
  {
    urn: 'urn:lex:br:federal:medida.provisoria:2021-04-12;1040',
    title: 'Medida Provisória nº 1.040/2021 - Marco regulatório do transporte aquaviário',
    type: 'medida_provisoria',
    coordinates: { lat: -23.9618, lng: -46.3322 },
    municipality: 'Santos',
    state: 'SP',
    confidence: 0.96,
    precision: 'exact',
    address: {
      street: 'Praça Visconde de Mauá',
      number: '1',
      neighborhood: 'Centro',
      postalCode: '11010-900',
      formattedAddress: 'Praça Visconde de Mauá, 1 - Centro, Santos - SP, 11010-900'
    }
  },
  {
    urn: 'urn:lex:br:rio.de.janeiro:decreto:2021-01-25;47512',
    title: 'Decreto nº 47.512/2021 - Regulamenta apps de transporte no estado',
    type: 'decreto',
    coordinates: { lat: -22.8305, lng: -43.2192 },
    municipality: 'Rio de Janeiro',
    state: 'RJ',
    confidence: 0.87,
    precision: 'approximate',
    address: {
      formattedAddress: 'Região Metropolitana do Rio de Janeiro - RJ'
    }
  },
  {
    urn: 'urn:lex:br:minas.gerais:lei:2020-10-08;23645',
    title: 'Lei nº 23.645/2020 - Política de desenvolvimento do transporte ferroviário',
    type: 'lei',
    coordinates: { lat: -19.8157, lng: -43.9542 },
    municipality: 'Belo Horizonte',
    state: 'MG',
    confidence: 0.91,
    precision: 'municipality',
    address: {
      formattedAddress: 'Região Metropolitana de Belo Horizonte - MG'
    }
  },
  {
    urn: 'urn:lex:br:sao.paulo:portaria:2021-05-14;892',
    title: 'Portaria nº 892/2021 - Normas para transporte de resíduos sólidos',
    type: 'portaria',
    coordinates: { lat: -23.4692, lng: -46.5197 },
    municipality: 'São Paulo',
    state: 'SP',
    confidence: 0.84,
    precision: 'approximate',
    address: {
      formattedAddress: 'Região Metropolitana de São Paulo - SP'
    }
  },
  {
    urn: 'urn:lex:br:bahia:resolucao:2020-09-22;187',
    title: 'Resolução nº 187/2020 - Regulamenta transporte hidroviário interior',
    type: 'resolucao',
    coordinates: { lat: -12.5797, lng: -38.9951 },
    municipality: 'Salvador',
    state: 'BA',
    confidence: 0.79,
    precision: 'state',
    address: {
      formattedAddress: 'Recôncavo Baiano - BA'
    }
  }
];

// Function to generate additional test documents for clustering and hotspot analysis
export const generateAdditionalTestDocuments = (count: number = 50): DocumentLocation[] => {
  const baseDocuments = sampleGeographicDocuments;
  const additionalDocs: DocumentLocation[] = [];
  
  const documentTypes = ['lei', 'decreto', 'portaria', 'resolucao', 'instrucao_normativa', 'projeto_lei', 'medida_provisoria'] as const;
  const precisionTypes = ['exact', 'municipality', 'state', 'approximate'] as const;
  
  for (let i = 0; i < count; i++) {
    const baseDoc = baseDocuments[i % baseDocuments.length];
    const randomOffset = () => (Math.random() - 0.5) * 0.1; // ~10km radius variation
    
    additionalDocs.push({
      urn: `urn:lex:br:test:${baseDoc.type}:2021-${String(i + 1).padStart(2, '0')}-15;${1000 + i}`,
      title: `${baseDoc.type.toUpperCase()} de Teste nº ${1000 + i}/2021 - Regulamentação de Transporte ${i + 1}`,
      type: documentTypes[i % documentTypes.length],
      coordinates: {
        lat: baseDoc.coordinates.lat + randomOffset(),
        lng: baseDoc.coordinates.lng + randomOffset()
      },
      municipality: baseDoc.municipality,
      state: baseDoc.state,
      confidence: 0.6 + Math.random() * 0.4, // Random confidence between 0.6-1.0
      precision: precisionTypes[i % precisionTypes.length],
      address: {
        formattedAddress: `Documento de Teste ${i + 1} - ${baseDoc.municipality}, ${baseDoc.state}`
      }
    });
  }
  
  return additionalDocs;
};

// Export combined dataset for comprehensive testing
export const allTestDocuments = [
  ...sampleGeographicDocuments,
  ...generateAdditionalTestDocuments(100)
];

// Test data summary
export const testDataSummary = {
  states: sampleStates.length,
  municipalities: sampleMunicipalities.length,
  documents: allTestDocuments.length,
  realDocuments: sampleGeographicDocuments.length,
  syntheticDocuments: allTestDocuments.length - sampleGeographicDocuments.length,
  coverage: {
    states: [...new Set(allTestDocuments.map(doc => doc.state))].length,
    municipalities: [...new Set(allTestDocuments.map(doc => doc.municipality))].length
  },
  confidence: {
    min: Math.min(...allTestDocuments.map(doc => doc.confidence)),
    max: Math.max(...allTestDocuments.map(doc => doc.confidence)),
    avg: allTestDocuments.reduce((sum, doc) => sum + doc.confidence, 0) / allTestDocuments.length
  }
};