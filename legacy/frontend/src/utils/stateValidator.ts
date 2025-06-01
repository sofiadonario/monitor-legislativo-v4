// Brazilian states validation and normalization

// All 27 Brazilian states (26 states + 1 federal district)
export const BRAZILIAN_STATES = {
  'AC': 'Acre',
  'AL': 'Alagoas',
  'AP': 'Amapá',
  'AM': 'Amazonas',
  'BA': 'Bahia',
  'CE': 'Ceará',
  'DF': 'Distrito Federal',
  'ES': 'Espírito Santo',
  'GO': 'Goiás',
  'MA': 'Maranhão',
  'MT': 'Mato Grosso',
  'MS': 'Mato Grosso do Sul',
  'MG': 'Minas Gerais',
  'PA': 'Pará',
  'PB': 'Paraíba',
  'PR': 'Paraná',
  'PE': 'Pernambuco',
  'PI': 'Piauí',
  'RJ': 'Rio de Janeiro',
  'RN': 'Rio Grande do Norte',
  'RS': 'Rio Grande do Sul',
  'RO': 'Rondônia',
  'RR': 'Roraima',
  'SC': 'Santa Catarina',
  'SP': 'São Paulo',
  'SE': 'Sergipe',
  'TO': 'Tocantins'
} as const;

// Map from various formats to state codes
const STATE_NAME_VARIATIONS: Record<string, string> = {
  // Full names (lowercase)
  'acre': 'AC',
  'alagoas': 'AL',
  'amapá': 'AP',
  'amapa': 'AP',
  'amazonas': 'AM',
  'bahia': 'BA',
  'ceará': 'CE',
  'ceara': 'CE',
  'distrito federal': 'DF',
  'espírito santo': 'ES',
  'espirito santo': 'ES',
  'goiás': 'GO',
  'goias': 'GO',
  'maranhão': 'MA',
  'maranhao': 'MA',
  'mato grosso': 'MT',
  'mato grosso do sul': 'MS',
  'minas gerais': 'MG',
  'pará': 'PA',
  'para': 'PA',
  'paraíba': 'PB',
  'paraiba': 'PB',
  'paraná': 'PR',
  'parana': 'PR',
  'pernambuco': 'PE',
  'piauí': 'PI',
  'piaui': 'PI',
  'rio de janeiro': 'RJ',
  'rio grande do norte': 'RN',
  'rio grande do sul': 'RS',
  'rondônia': 'RO',
  'rondonia': 'RO',
  'roraima': 'RR',
  'santa catarina': 'SC',
  'são paulo': 'SP',
  'sao paulo': 'SP',
  'sergipe': 'SE',
  'tocantins': 'TO',
  
  // URN format variations (with dots)
  'sao.paulo': 'SP',
  'rio.de.janeiro': 'RJ',
  'minas.gerais': 'MG',
  'rio.grande.sul': 'RS',
  'rio.grande.norte': 'RN',
  'espirito.santo': 'ES',
  'mato.grosso': 'MT',
  'mato.grosso.sul': 'MS',
  'distrito.federal': 'DF',
  'santa.catarina': 'SC',
  
  // Abbreviations (uppercase)
  'AC': 'AC',
  'AL': 'AL',
  'AP': 'AP',
  'AM': 'AM',
  'BA': 'BA',
  'CE': 'CE',
  'DF': 'DF',
  'ES': 'ES',
  'GO': 'GO',
  'MA': 'MA',
  'MT': 'MT',
  'MS': 'MS',
  'MG': 'MG',
  'PA': 'PA',
  'PB': 'PB',
  'PR': 'PR',
  'PE': 'PE',
  'PI': 'PI',
  'RJ': 'RJ',
  'RN': 'RN',
  'RS': 'RS',
  'RO': 'RO',
  'RR': 'RR',
  'SC': 'SC',
  'SP': 'SP',
  'SE': 'SE',
  'TO': 'TO'
};

// Normalize state name to code
export function normalizeStateName(state: string | null | undefined): string {
  if (!state || state.trim() === '') {
    return 'Federal'; // Default for national/federal documents
  }

  const normalizedState = state.trim().toLowerCase();
  
  // Check if it's already a valid state code
  if (normalizedState.toUpperCase() in BRAZILIAN_STATES) {
    return normalizedState.toUpperCase();
  }
  
  // Look up in variations map
  if (normalizedState in STATE_NAME_VARIATIONS) {
    return STATE_NAME_VARIATIONS[normalizedState];
  }
  
  // Special cases
  if (normalizedState === 'federal' || normalizedState === 'brasil' || normalizedState === 'brazil') {
    return 'Federal';
  }
  
  // Log unknown state for debugging
  console.warn(`Unknown state format: "${state}"`);
  return state; // Return original if can't normalize
}

// Get full state name from code
export function getStateName(stateCode: string): string {
  if (stateCode === 'Federal') {
    return 'Federal';
  }
  return BRAZILIAN_STATES[stateCode as keyof typeof BRAZILIAN_STATES] || stateCode;
}

// Validate if state code is valid
export function isValidStateCode(stateCode: string): boolean {
  return stateCode === 'Federal' || stateCode in BRAZILIAN_STATES;
}

// Get all state codes including Federal
export function getAllStateCodes(): string[] {
  return ['Federal', ...Object.keys(BRAZILIAN_STATES)];
}

// Count documents by state
export function countDocumentsByState(documents: Array<{ state?: string }>): Record<string, number> {
  const stateCounts: Record<string, number> = {
    'Federal': 0,
    ...Object.fromEntries(Object.keys(BRAZILIAN_STATES).map(code => [code, 0]))
  };
  
  documents.forEach(doc => {
    const stateCode = normalizeStateName(doc.state);
    if (stateCode in stateCounts) {
      stateCounts[stateCode]++;
    } else {
      stateCounts['Federal']++; // Count unknown states as Federal
    }
  });
  
  return stateCounts;
}

// Get missing states (states with no documents)
export function getMissingStates(documents: Array<{ state?: string }>): string[] {
  const stateCounts = countDocumentsByState(documents);
  return Object.entries(stateCounts)
    .filter(([state, count]) => state !== 'Federal' && count === 0)
    .map(([state]) => state);
}