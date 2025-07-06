import { LegislativeDocument } from '../types';
import { parseBrazilianDate } from '../utils/dateParser';
import { normalizeStateName } from '../utils/stateValidator';

// CSV row interface - Updated to match enhanced CSV with 15 columns
interface CSVRow {
  search_term: string;           // Column 1
  date_searched: string;         // Column 2
  url: string;                   // Column 3
  title: string;                 // Column 4
  urn: string;                   // Column 5
  urn_type: string;              // Column 6
  country: string;               // Column 7
  state: string;                 // Column 8 - Direct state info
  municipality: string;          // Column 9 - Direct municipality info
  justice: string;               // Column 10
  region: string;                // Column 11
  court_class: string;           // Column 12 - For chamber categorization
  document_type_full: string;    // Column 13 - Full document type
  promulgation_date: string;     // Column 14 - Actual document date
  document_description: string;  // Column 15
}

// Map document_type_full to DocumentType enum
function mapDocumentType(documentTypeFull: string): string {
  const type = documentTypeFull.toLowerCase();
  
  if (type.includes('lei')) return 'lei';
  if (type.includes('decreto')) return 'decreto';
  if (type.includes('medida provisória') || type.includes('mpv')) return 'medida_provisoria';
  if (type.includes('emenda')) return 'emenda_constitucional';
  if (type.includes('portaria')) return 'portaria';
  if (type.includes('projeto de lei') || type.includes('pl')) return 'projeto_lei';
  if (type.includes('resolução')) return 'resolucao';
  if (type.includes('instrução normativa')) return 'instrucao_normativa';
  
  // Default fallback
  return 'lei';
}

// Map court_class to chamber
function mapChamber(courtClass: string): string {
  const chamber = courtClass.toLowerCase();
  
  if (chamber.includes('federal')) return 'Federal';
  if (chamber.includes('estadual')) return 'Estadual';
  if (chamber.includes('municipal')) return 'Municipal';
  if (chamber.includes('senado')) return 'Senado';
  if (chamber.includes('câmara') || chamber.includes('camara')) return 'Câmara dos Deputados';
  
  return 'Federal'; // Default
}

// Extract document number from URN
function extractNumberFromURN(urn: string): string | undefined {
  const parts = urn.split(';');
  if (parts.length > 1) {
    const lastPart = parts[parts.length - 1];
    // Extract number from patterns like "60491" or "2014-05-26;60491"
    const numberMatch = lastPart.match(/(\d+)$/);
    return numberMatch ? numberMatch[1] : undefined;
  }
  return undefined;
}

// Parse URN to extract metadata (DEPRECATED - now using direct CSV fields)
function parseURN(urn: string): {
  state?: string;
  municipality?: string;
  type: string;
  number?: string;
  date?: Date;
  chamber?: string;
} {
  // Handle different URN formats:
  // 1. urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833
  // 2. urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491  
  // 3. urn:lex:br;minas.gerais;itabirito:municipal:lei:2008-12-05;2708
  
  const parts = urn.split(':');
  
  let state: string | undefined;
  let municipality: string | undefined;
  let type = 'lei'; // default
  let number: string | undefined;
  let date: Date | undefined;
  let chamber: string | undefined;
  
  if (parts.length < 4) {
    return { state, municipality, type, number, date, chamber };
  }
  
  // Handle federal format: urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833
  if (parts[2] === 'br' && parts[3].includes('congresso.nacional')) {
    state = 'Federal';
    chamber = 'Congresso Nacional';
    
    // Extract type from parts[4]
    if (parts.length > 4) {
      const typePart = parts[4];
      if (typePart.includes('medida.provisoria')) {
        type = 'medida_provisoria';
      } else if (typePart.includes('decreto')) {
        type = 'decreto';
      } else if (typePart.includes('lei')) {
        type = 'lei';
      }
    }
    
    // Extract number from last part
    if (parts.length > 5) {
      const lastPart = parts[parts.length - 1];
      const numberMatch = lastPart.match(/(\d+)$/);
      if (numberMatch) {
        number = numberMatch[1];
      }
    }
  }
  // Handle state/municipal format: urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491
  else if (parts[2].includes(';')) {
    const locationPart = parts[2];
    const locationSegments = locationPart.split(';');
    
    if (locationSegments.length > 1) {
      // Extract state
      const stateCode = locationSegments[1];
      state = normalizeStateName(stateCode);
      
      // Extract municipality if present
      if (locationSegments.length > 2) {
        municipality = normalizeMunicipalityName(locationSegments[2]);
      }
    }
    
    // Extract chamber from parts[3]
    if (parts.length > 3) {
      const chamberPart = parts[3];
      if (chamberPart === 'estadual') {
        chamber = 'Governo Estadual';
      } else if (chamberPart === 'municipal') {
        chamber = 'Governo Municipal';
      } else if (chamberPart === 'federal') {
        chamber = 'Governo Federal';
      }
    }
    
    // Extract type from parts[4]
    if (parts.length > 4) {
      const typePart = parts[4];
      if (typePart.includes('decreto')) {
        type = 'decreto';
      } else if (typePart.includes('lei')) {
        type = 'lei';
      } else if (typePart.includes('portaria')) {
        type = 'portaria';
      } else if (typePart.includes('resolucao')) {
        type = 'resolucao';
      }
    }
    
    // Extract date and number from last part
    if (parts.length > 5) {
      const lastPart = parts[parts.length - 1];
      const datePart = parts[parts.length - 2];
      
      // Try to parse date
      if (datePart && datePart.match(/\d{4}-\d{2}-\d{2}/)) {
        try {
          date = new Date(datePart);
        } catch (e) {
          date = new Date();
        }
      }
      
      // Extract number
      const numberMatch = lastPart.match(/(\d+)$/);
      if (numberMatch) {
        number = numberMatch[1];
      }
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
  const lines = csvContent.split(/\r?\n/).filter(line => line.trim() !== '');
  console.log(`CSV split into ${lines.length} lines`); // Debug line count
  if (lines.length < 2) {
    console.warn('CSV content has no data rows.');
    return [];
  }

  // Clean any BOM from the first line as well (belt and suspenders approach)
  if (lines[0]) {
    lines[0] = lines[0].replace(/^\uFEFF/, '');
  }
  
  const headers = parseCSVLine(lines[0]).map(h => h.trim().replace(/['"]+/g, ''));
  console.log('CSV Headers:', headers); // Debugging headers
  console.log('First line raw:', lines[0].substring(0, 50)); // Show first 50 chars of header line

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
      urn: values[4] || '',
      urn_type: values[5] || '',
      country: values[6] || '',
      state: values[7] || '',
      municipality: values[8] || '',
      justice: values[9] || '',
      region: values[10] || '',
      court_class: values[11] || '',
      document_type_full: values[12] || '',
      promulgation_date: values[13] || '',
      document_description: values[14] || ''
    };

    if (!row.urn) {
      console.warn(`Skipping row ${i + 1} due to missing URN.`);
      continue;
    }

    // Use direct CSV fields instead of URN parsing
    const documentType = mapDocumentType(row.document_type_full);
    const chamber = mapChamber(row.court_class);
    
    // Parse promulgation_date or fall back to URN parsing date
    let docDate: Date | null = null;
    
    // Try parsing promulgation_date first
    if (row.promulgation_date) {
      docDate = parseBrazilianDate(row.promulgation_date);
      if (!docDate) {
        console.warn(`Failed to parse promulgation_date for row ${i + 1}: "${row.promulgation_date}"`);
      }
    }
    
    // If no valid date from promulgation_date, try URN
    if (!docDate) {
      const { date } = parseURN(row.urn);
      docDate = date || null;
    }
    
    // If still no date, log warning but continue (don't use current date as fallback)
    if (!docDate) {
      console.warn(`No valid date found for document: ${row.title} (URN: ${row.urn})`);
      // Use a placeholder date far in the past to indicate missing data
      docDate = new Date('1900-01-01');
    }

    documents.push({
      id: row.urn,
      title: row.title,
      summary: row.document_description || `Document retrieved on ${row.date_searched} for search term "${row.search_term}".`,
      type: documentType,
      date: docDate.toISOString(),
      keywords: generateKeywords(row.search_term, row.title),
      state: normalizeStateName(row.state) || 'Federal',
      municipality: row.municipality || undefined,
      url: row.url,
      status: 'sancionado',
      chamber: chamber,
      number: extractNumberFromURN(row.urn),
      source: 'LexML',
      citation: generateCitation({ 
        title: row.title, 
        url: row.url, 
        date: docDate, 
        state: row.state, 
        type: documentType, 
        number: extractNumberFromURN(row.urn) 
      }, row.urn)
    });
  }

  console.log(`Successfully parsed ${documents.length} documents from CSV.`);
  return documents;
}

// Load and parse the main CSV data file for transport legislation
export async function loadCSVLegislativeData(): Promise<LegislativeDocument[]> {
  console.log('🔥 Loading real legislative data from backend API...');
  
  // Try to get data from backend API first
  try {
    const { getApiBaseUrl } = await import('../config/api');
    const baseUrl = getApiBaseUrl();
    const timestamp = Date.now();
    const API_URL = `${baseUrl}/api/v1/csv/documents?t=${timestamp}`;
    console.log(`🚀 Fetching real CSV data from backend API: ${API_URL}`);

    const response = await fetch(API_URL);
    if (response.ok) {
      const data = await response.json();
      if (data.status === 'success' && data.data && Array.isArray(data.data)) {
        console.log(`🎉 BACKEND API SUCCESS: Loaded ${data.count} documents from backend API (bypassing static file issues)`);
        return data.data as LegislativeDocument[];
      }
    }
    console.warn(`❌ Backend API not accessible (${response.status}), trying static CSV file`);
  } catch (apiError) {
    console.warn('❌ Backend API failed, trying static CSV file:', apiError);
  }

  // Fallback to backend-served CSV file 
  try {
    // Try backend-served CSV as static file
    const backendUrl = 'https://backend-api-production-2392.up.railway.app';
    const CSV_URL = `${backendUrl}/lexml_transport_results_20250606_123100.csv`;
    console.log(`🔄 Trying backend-served CSV file: ${CSV_URL}`);

    const response = await fetch(CSV_URL);
    if (!response.ok) {
      throw new Error(`CSV file not accessible (${response.status})`);
    }
    
    let csvContent = await response.text();
    if (!csvContent) {
      throw new Error('CSV file is empty or could not be read.');
    }
    
    // Remove UTF-8 BOM if present
    csvContent = csvContent.replace(/^\uFEFF/, '');
    
    // Debug logging
    console.log('CSV content first 100 chars:', csvContent.substring(0, 100));
    
    const parsedData = parseCSVData(csvContent);
    if (parsedData.length === 0) {
      throw new Error('CSV file contains no valid legislative documents.');
    }
    console.log(`Successfully loaded ${parsedData.length} documents from CSV file`);
    return parsedData;
  } catch (csvError) {
    console.error('Error loading CSV legislative data:', csvError);
    
    // Final fallback to embedded real data
    try {
      const { fullLegislativeData } = await import('./fullLegislativeData');
      
      // Properly transform embedded data to LegislativeDocument format
      const documents: LegislativeDocument[] = fullLegislativeData.map((doc: any) => {
        // Parse URN to extract metadata
        const { state, municipality, type, number, date, chamber } = parseURN(doc.urn);
        
        // Generate keywords from search term and title
        const keywords = generateKeywords('transporte', doc.title);
        
        // Parse date or use current date
        const docDate = date || new Date();
        
        return {
          id: doc.urn,
          title: doc.title,
          summary: `Document retrieved on ${doc.date_searched || 'unknown date'} for search term "transporte".`,
          type: type as any || 'lei',
          date: docDate.toISOString(),
          keywords: keywords,
          state: state || 'Federal',
          municipality: municipality || undefined,
          url: doc.url,
          status: 'sancionado',
          chamber: chamber || 'Federal',
          number: number,
          source: 'LexML',
          citation: generateCitation({ 
            title: doc.title, 
            url: doc.url, 
            date: docDate, 
            state: state || 'Federal', 
            type: type as any || 'lei', 
            number: number 
          }, doc.urn)
        };
      });
      
      console.log(`Fallback: Using embedded full legislative data: ${documents.length} documents from LexML`);
      return documents;
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