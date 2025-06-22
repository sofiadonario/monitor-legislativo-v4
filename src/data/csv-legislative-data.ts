import { LegislativeDocument } from '../types';

// CSV row interface
interface CSVRow {
  search_term: string;
  date_searched: string;
  url: string;
  title: string;
  urn: string;
}

// Parse URN to extract metadata
function parseURN(urn: string): {
  state?: string;
  municipality?: string;
  type: string;
  number?: string;
  date?: Date;
  chamber?: string;
} {
  // Example URN: urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491
  const parts = urn.split(':');
  
  let state: string | undefined;
  let municipality: string | undefined;
  let type = 'lei'; // default
  let number: string | undefined;
  let date: Date | undefined;
  let chamber: string | undefined;
  
  // Extract chamber and location info
  if (parts.length > 2) {
    const locationPart = parts[2];
    
    // Extract legislative chamber/authority
    if (locationPart.includes('congresso.nacional')) {
      chamber = 'Congresso Nacional';
    } else if (locationPart.includes('camara.leg.br') || locationPart.includes('camara.municipal')) {
      chamber = 'Câmara dos Deputados';
    } else if (locationPart.includes('senado.leg.br')) {
      chamber = 'Senado Federal';
    } else if (locationPart.includes('federal') || locationPart === 'br') {
      chamber = 'DOU/Planalto';
    } else if (locationPart.includes('estadual')) {
      chamber = 'Governo Estadual';
    } else if (locationPart.includes('municipal')) {
      chamber = 'Governo Municipal';
    } else if (locationPart.includes('tribunal')) {
      chamber = 'Poder Judiciário';
    }
    
    // Extract location info (state/municipality)
    if (locationPart && locationPart !== 'br') {
      const locationParts = locationPart.split(';');
      if (locationParts.length > 0) {
        const mainLocation = locationParts[0];
        if (mainLocation.includes('.')) {
          const [stateCode, municipalityCode] = mainLocation.split('.');
          state = normalizeStateName(stateCode);
          if (municipalityCode) {
            municipality = normalizeMunicipalityName(municipalityCode);
          }
        } else {
          state = normalizeStateName(mainLocation);
        }
      }
    }
  }
  
  // Extract document type
  if (parts.length > 3) {
    const typePart = parts[3];
    if (typePart.includes(':')) {
      type = typePart.split(':')[0];
    } else {
      type = typePart;
    }
    type = normalizeDocumentType(type);
  }
  
  // Extract date and number from the last part
  if (parts.length > 4) {
    const lastPart = parts[parts.length - 1];
    const datePart = parts[parts.length - 2];
    
    if (datePart && datePart.match(/\d{4}-\d{2}-\d{2}/)) {
      try {
        date = new Date(datePart);
      } catch (e) {
        // If date parsing fails, use current date
        date = new Date();
      }
    }
    
    if (lastPart && lastPart.match(/\d+/)) {
      number = lastPart.replace(/[^\d]/g, '');
    }
  }
  
  return { state, municipality, type, number, date, chamber };
}

// Normalize state names from URN codes
function normalizeStateName(stateCode: string): string {
  const stateMap: Record<string, string> = {
    'sao.paulo': 'SP',
    'rio.de.janeiro': 'RJ',
    'minas.gerais': 'MG',
    'rio.grande.sul': 'RS',
    'parana': 'PR',
    'bahia': 'BA',
    'distrito.federal': 'DF',
    'espirito.santo': 'ES',
    'goias': 'GO',
    'santa.catarina': 'SC',
    'ceara': 'CE',
    'pernambuco': 'PE',
    'para': 'PA',
    'maranhao': 'MA',
    'paraiba': 'PB',
    'alagoas': 'AL',
    'sergipe': 'SE',
    'rondonia': 'RO',
    'acre': 'AC',
    'amazonas': 'AM',
    'roraima': 'RR',
    'amapa': 'AP',
    'tocantins': 'TO',
    'mato.grosso': 'MT',
    'mato.grosso.sul': 'MS',
    'piauí': 'PI'
  };
  
  return stateMap[stateCode] || stateCode.toUpperCase();
}

// Normalize municipality names
function normalizeMunicipalityName(municipalityCode: string): string {
  return municipalityCode
    .split('.')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// Normalize document types
function normalizeDocumentType(type: string): string {
  const typeMap: Record<string, string> = {
    'lei': 'lei',
    'decreto': 'decreto',
    'decreto.lei': 'decreto_lei',
    'medida.provisoria': 'medida_provisoria',
    'portaria': 'portaria',
    'resolucao': 'resolucao',
    'acordao': 'acordao',
    'instrucao.normativa': 'instrucao_normativa',
    'emenda.constitucional': 'emenda_constitucional'
  };
  
  return typeMap[type] || type;
}

// Generate keywords from search term and title
function generateKeywords(searchTerm: string, title: string): string[] {
  const keywords = new Set<string>();
  
  // Add search term
  keywords.add(searchTerm.toLowerCase());
  
  // Extract keywords from title
  const titleWords = title.toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(word => word.length > 3);
  
  titleWords.forEach(word => keywords.add(word));
  
  // Add common transport-related terms
  const transportTerms = [
    'transporte', 'rodoviário', 'carga', 'logística', 'frete', 
    'fretamento', 'caminhão', 'veículo', 'rodovia', 'tráfego'
  ];
  
  transportTerms.forEach(term => {
    if (title.toLowerCase().includes(term)) {
      keywords.add(term);
    }
  });
  
  return Array.from(keywords).slice(0, 8); // Limit to 8 keywords
}

// A more robust CSV parser
function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"' && line[i - 1] !== '\\\\') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim().replace(/^"|"$/g, ''));
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current.trim().replace(/^"|"$/g, ''));
  return result;
}

// Generate academic citation
function generateCitation(doc: Partial<LegislativeDocument>, urn: string): string {
  const year = doc.date ? doc.date.getFullYear() : new Date().getFullYear();
  const state = doc.state || 'BRASIL';
  
  if (doc.type === 'lei' && doc.number) {
    return `${state}. Lei nº ${doc.number}, de ${doc.date?.toLocaleDateString('pt-BR') || 'data não informada'}. Disponível em: ${doc.url}. Acesso em: ${new Date().toLocaleDateString('pt-BR')}.`;
  } else if (doc.type === 'decreto' && doc.number) {
    return `${state}. Decreto nº ${doc.number}, de ${doc.date?.toLocaleDateString('pt-BR') || 'data não informada'}. Disponível em: ${doc.url}. Acesso em: ${new Date().toLocaleDateString('pt-BR')}.`;
  } else {
    return `${doc.title}. ${state}, ${year}. Disponível em: ${doc.url}. Acesso em: ${new Date().toLocaleDateString('pt-BR')}.`;
  }
}

// Parse CSV content into LegislativeDocument array
export function parseCSVData(csvContent: string): LegislativeDocument[] {
  const lines = csvContent.split('\\n').filter(line => line.trim() !== '');
  if (lines.length < 2) {
    console.warn('CSV content has no data rows.');
    return [];
  }

  const headers = parseCSVLine(lines[0]).map(h => h.trim().replace(/['"]+/g, ''));
  console.log('CSV Headers:', headers); // Debugging headers

  const documents: LegislativeDocument[] = [];
  
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    const values = parseCSVLine(line);
    
    // Basic validation
    if (values.length !== headers.length) {
      console.warn(`Skipping malformed CSV row ${i + 1}: Expected ${headers.length} fields, but found ${values.length}. Line: "${line}"`);
      continue;
    }

    const row: CSVRow = {
      search_term: values[0] || '',
      date_searched: values[1] || '',
      url: values[2] || '',
      title: values[3] || 'No Title Provided',
      urn: values[4] || ''
    };

    if (!row.urn) {
      console.warn(`Skipping row ${i + 1} due to missing URN.`);
      continue;
    }

    const { state, municipality, type, number, date, chamber } = parseURN(row.urn);
    
    // More robust date handling
    const docDate = date || new Date(); // Fallback to current date if parsing fails

    documents.push({
      id: row.urn,
      title: row.title,
      summary: `Document retrieved on ${row.date_searched} for search term "${row.search_term}".`,
      type: type || 'lei',
      date: docDate.toISOString(),
      keywords: generateKeywords(row.search_term, row.title),
      state: state || 'Federal',
      municipality: municipality,
      url: row.url,
      status: 'sancionado',
      chamber: chamber || 'Unknown',
      number: number,
      source: 'LexML',
      citation: generateCitation({ title: row.title, url: row.url, date: docDate, state, type, number }, row.urn)
    });
  }

  console.log(`Successfully parsed ${documents.length} documents from CSV.`);
  return documents;
}

// Load and parse the main CSV data file for transport legislation
export async function loadCSVLegislativeData(): Promise<LegislativeDocument[]> {
  const CSV_URL = '/lexml_transport_results_20250606_123100.csv';
  console.log(`Fetching real CSV data from: ${CSV_URL}`);

  try {
    const response = await fetch(CSV_URL);
    if (!response.ok) {
      console.warn(`CSV file not accessible (${response.status}), falling back to embedded real data`);
      // Fallback to embedded real data (NOT mock data)
      const { realLegislativeData, validateDataIntegrity } = await import('./real-legislative-data');
      
      if (!validateDataIntegrity()) {
        throw new Error('Embedded real data failed integrity validation');
      }
      
      console.log(`Using embedded real legislative data: ${realLegislativeData.length} documents from LexML`);
      return realLegislativeData;
    }
    
    const csvContent = await response.text();
    if (!csvContent) {
      throw new Error('CSV file is empty or could not be read.');
    }
    const parsedData = parseCSVData(csvContent);
    if (parsedData.length === 0) {
      throw new Error('CSV file contains no valid legislative documents.');
    }
    console.log(`Successfully loaded ${parsedData.length} documents from CSV file`);
    return parsedData;
  } catch (error) {
    console.error('Error loading CSV legislative data:', error);
    
    // Try embedded real data as final fallback
    try {
      const { realLegislativeData, validateDataIntegrity } = await import('./real-legislative-data');
      
      if (!validateDataIntegrity()) {
        throw new Error('Embedded real data failed integrity validation');
      }
      
      console.log(`Fallback: Using embedded real legislative data: ${realLegislativeData.length} documents from LexML`);
      return realLegislativeData;
    } catch (fallbackError) {
      console.error('Even embedded real data failed to load:', fallbackError);
      throw new Error(`Unable to load any real legislative data source. Please check data availability.`);
    }
  }
}

// Global variable to store loaded CSV data
let csvDataCache: LegislativeDocument[] | null = null;

// Export a synchronous version that provides immediate fallback
export const csvLegislativeData: LegislativeDocument[] = [];

// Force load real legislative data immediately when module is imported
(async () => {
  try {
    console.log('🔥 LOADING REAL LEGISLATIVE DATA...');
    csvDataCache = await loadCSVLegislativeData();
    if (csvDataCache && csvDataCache.length > 0) {
      csvLegislativeData.length = 0; // Clear array
      csvLegislativeData.push(...csvDataCache); // Add all loaded data
      console.log(`✅ SUCCESS: Loaded ${csvDataCache.length} real documents`);
    } else {
      console.error('❌ Data loading failed - no data returned');
    }
  } catch (error) {
    console.error('❌ CRITICAL: Failed to load real legislative data on module import:', error);
    console.error('🚨 Academic integrity requires real data sources only');
    console.error('📋 Action required: Check data availability or API connectivity');
    // Leave array empty to force proper error handling in UI
    csvLegislativeData.length = 0;
  }
})();