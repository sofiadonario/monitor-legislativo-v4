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
} {
  // Example URN: urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491
  const parts = urn.split(':');
  
  let state: string | undefined;
  let municipality: string | undefined;
  let type = 'lei'; // default
  let number: string | undefined;
  let date: Date | undefined;
  
  // Extract location info (state/municipality)
  if (parts.length > 2) {
    const locationPart = parts[2];
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
  
  return { state, municipality, type, number, date };
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
    
    // Simple CSV parsing (could be improved for more complex cases)
    const values = line.split(',').map(v => v.trim().replace(/["']/g, ''));
    
    if (values.length < headers.length) continue;
    
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

// Export a synchronous version using embedded data
export const csvLegislativeData: LegislativeDocument[] = [
  // This will be populated with a subset of the CSV data for immediate use
  {
    id: 'mpv_833_2018',
    title: 'MPV 833/2018',
    summary: 'Medida Provisória relacionada a transporte de carga',
    type: 'medida_provisoria',
    number: '833/2018',
    date: new Date('2018-05-27'),
    keywords: ['transporte', 'carga', 'medida provisória'],
    url: 'https://www.lexml.gov.br/urn/urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833',
    status: 'sancionado',
    source: 'LexML - Rede de Informação Legislativa e Jurídica',
    citation: 'BRASIL. Medida Provisória nº 833, de 27 de maio de 2018. Disponível em: https://www.lexml.gov.br/urn/urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833.',
    urn: 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833'
  },
  {
    id: 'decreto_77789_1976',
    title: 'Decreto nº 77.789, de 9 de Junho de 1976',
    summary: 'Decreto federal relacionado a transporte rodoviário de carga',
    type: 'decreto',
    number: '77.789/1976',
    date: new Date('1976-06-09'),
    keywords: ['transporte', 'rodoviário', 'carga', 'decreto'],
    url: 'https://www.lexml.gov.br/urn/urn:lex:br:federal:decreto:1976-06-09;77789',
    status: 'sancionado',
    source: 'LexML - Rede de Informação Legislativa e Jurídica',
    citation: 'BRASIL. Decreto nº 77.789, de 9 de junho de 1976. Disponível em: https://www.lexml.gov.br/urn/urn:lex:br:federal:decreto:1976-06-09;77789.',
    urn: 'urn:lex:br:federal:decreto:1976-06-09;77789'
  },
  {
    id: 'lei_2708_mg_2008',
    title: 'Lei n° 2708, de 05 de Dezembro de 2008',
    summary: 'Lei municipal de Itabirito-MG relacionada a logística de carga',
    type: 'lei',
    number: '2708/2008',
    date: new Date('2008-12-05'),
    keywords: ['logística', 'carga', 'municipal'],
    state: 'MG',
    municipality: 'Itabirito',
    url: 'https://www.lexml.gov.br/urn/urn:lex:br;minas.gerais;itabirito:municipal:lei:2008-12-05;2708',
    status: 'sancionado',
    source: 'LexML - Rede de Informação Legislativa e Jurídica',
    citation: 'MG. Lei nº 2708, de 05 de dezembro de 2008. Disponível em: https://www.lexml.gov.br/urn/urn:lex:br;minas.gerais;itabirito:municipal:lei:2008-12-05;2708.',
    urn: 'urn:lex:br;minas.gerais;itabirito:municipal:lei:2008-12-05;2708'
  },
  {
    id: 'decreto_60491_sp_2014',
    title: 'Decreto nº 60.491, de 26/05/2014',
    summary: 'Decreto estadual de São Paulo relacionado a logística de carga',
    type: 'decreto',
    number: '60.491/2014',
    date: new Date('2014-05-26'),
    keywords: ['logística', 'carga', 'estadual'],
    state: 'SP',
    url: 'https://www.lexml.gov.br/urn/urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491',
    status: 'sancionado',
    source: 'LexML - Rede de Informação Legislativa e Jurídica',
    citation: 'SP. Decreto nº 60.491, de 26 de maio de 2014. Disponível em: https://www.lexml.gov.br/urn/urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491.',
    urn: 'urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491'
  },
  {
    id: 'mpv_1050_2021',
    title: 'MPV 1050/2021',
    summary: 'Medida Provisória relacionada a caminhão e transporte',
    type: 'medida_provisoria',
    number: '1050/2021',
    date: new Date('2021-05-19'),
    keywords: ['caminhão', 'transporte', 'medida provisória'],
    url: 'https://www.lexml.gov.br/urn/urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-05-19;1050',
    status: 'sancionado',
    source: 'LexML - Rede de Informação Legislativa e Jurídica',
    citation: 'BRASIL. Medida Provisória nº 1050, de 19 de maio de 2021. Disponível em: https://www.lexml.gov.br/urn/urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-05-19;1050.',
    urn: 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-05-19;1050'
  }
];