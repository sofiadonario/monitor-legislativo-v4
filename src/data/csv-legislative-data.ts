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

// Parse CSV line handling commas within quotes
function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  
  // Add the last field
  result.push(current.trim());
  
  return result.map(field => field.replace(/^["']|["']$/g, '')); // Remove surrounding quotes
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
  const lines = csvContent.split('\n');
  const headers = lines[0].split(',').map(h => h.trim().replace(/["']/g, ''));
  
  const documents: LegislativeDocument[] = [];
  
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    // Improved CSV parsing to handle commas within quotes
    const values = parseCSVLine(line);
    
    if (values.length < 5) continue; // Need at least 5 columns
    
    const row: CSVRow = {
      search_term: values[0] || '',
      date_searched: values[1] || '',
      url: values[2] || '',
      title: values[3] || '',
      urn: values[4] || ''
    };
    
    if (!row.title || !row.url || !row.urn) continue;
    
    // Parse URN for metadata
    const urnData = parseURN(row.urn);
    
    // Create document
    const doc: LegislativeDocument = {
      id: row.urn.replace(/[^\w]/g, '_'),
      title: row.title,
      summary: `Documento relacionado a ${row.search_term}. ${row.title}`,
      type: urnData.type,
      number: urnData.number,
      date: urnData.date || new Date(row.date_searched),
      keywords: generateKeywords(row.search_term, row.title),
      state: urnData.state,
      municipality: urnData.municipality,
      url: row.url,
      status: 'sancionado',
      source: 'LexML - Rede de Informação Legislativa e Jurídica',
      citation: '',
      chamber: urnData.chamber,
      urn: row.urn
    };
    
    // Generate citation
    doc.citation = generateCitation(doc, row.urn);
    
    documents.push(doc);
  }
  
  return documents;
}

// Load and parse CSV data
export async function loadCSVLegislativeData(): Promise<LegislativeDocument[]> {
  try {
    // In a real application, this would be loaded from a public URL or API
    // For now, we'll need to import the CSV content
    const response = await fetch('/lexml_transport_results_20250606_123100.csv');
    const csvContent = await response.text();
    return parseCSVData(csvContent);
  } catch (error) {
    console.warn('Failed to load CSV data:', error);
    return [];
  }
}

// Global variable to store loaded CSV data
let csvDataCache: LegislativeDocument[] | null = null;

// Export a synchronous version that provides immediate fallback
export const csvLegislativeData: LegislativeDocument[] = [];

// Load CSV data immediately when module is imported
(async () => {
  try {
    console.log('Loading full CSV dataset...');
    csvDataCache = await loadCSVLegislativeData();
    csvLegislativeData.length = 0; // Clear array
    csvLegislativeData.push(...csvDataCache); // Add all loaded data
    console.log(`Successfully loaded ${csvDataCache.length} documents from CSV`);
  } catch (error) {
    console.warn('Failed to load CSV data on module import:', error);
  }
})();

// Get CSV data synchronously (returns cached data)
export function getCSVData(): LegislativeDocument[] {
  return csvDataCache || csvLegislativeData;
}