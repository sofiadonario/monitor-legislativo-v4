/**
 * Semantic Search Service
 * Advanced semantic search engine with SKOS vocabulary expansion for Brazilian transport legislation
 */
import { LegislativeDocument, DocumentType } from '../types';

// SKOS Concept Scheme for Brazilian Transport Legislation
export interface SKOSConcept {
  id: string;
  prefLabel: string;
  altLabels: string[];
  definition: string;
  broader?: string[];
  narrower?: string[];
  related?: string[];
  inScheme: string;
  notation?: string;
  examples?: string[];
  scopeNote?: string;
}

export interface SKOSConceptScheme {
  id: string;
  title: string;
  description: string;
  concepts: Record<string, SKOSConcept>;
  hierarchy: Record<string, string[]>;
}

export interface SemanticMatch {
  concept: SKOSConcept;
  matchType: 'exact' | 'broader' | 'narrower' | 'related' | 'synonym';
  confidence: number;
  originalTerm: string;
  expandedTerms: string[];
}

export interface SemanticSearchResult {
  document: LegislativeDocument;
  relevanceScore: number;
  semanticMatches: SemanticMatch[];
  conceptCoverage: number;
  domainRelevance: number;
  snippet: string;
  highlightedSnippet: string;
}

export interface VocabularyExpansion {
  originalQuery: string;
  expandedQuery: string;
  conceptsFound: SKOSConcept[];
  expansionStrategy: 'conservative' | 'moderate' | 'aggressive';
  confidence: number;
  termMapping: Record<string, string[]>;
}

// Brazilian Transport Legislation SKOS Vocabulary
const TRANSPORT_SKOS_SCHEME: SKOSConceptScheme = {
  id: 'br-transport-legislation',
  title: 'Brazilian Transport Legislation Vocabulary',
  description: 'Controlled vocabulary for Brazilian transport and mobility legislation',
  concepts: {
    // Transport Modes
    'transport-road': {
      id: 'transport-road',
      prefLabel: 'transporte rodoviário',
      altLabels: ['transporte terrestre', 'modal rodoviário', 'estradas', 'rodovias'],
      definition: 'Transportation by road infrastructure including highways, urban roads, and vehicle circulation',
      narrower: ['transport-road-cargo', 'transport-road-passenger', 'transport-road-urban'],
      related: ['infrastructure-road', 'vehicle-road', 'regulation-road'],
      inScheme: 'br-transport-legislation',
      notation: 'TR-ROAD',
      examples: ['BR-101', 'BR-116', 'transporte intermunicipal', 'frete rodoviário']
    },
    
    'transport-road-cargo': {
      id: 'transport-road-cargo',
      prefLabel: 'transporte rodoviário de cargas',
      altLabels: ['frete rodoviário', 'transporte de mercadorias', 'logística rodoviária'],
      definition: 'Road transportation of goods and merchandise',
      broader: ['transport-road'],
      related: ['vehicle-truck', 'regulation-cargo', 'safety-cargo'],
      inScheme: 'br-transport-legislation',
      notation: 'TR-ROAD-CARGO',
      examples: ['caminhoneiros', 'transporte autônomo de cargas', 'ETC', 'TAC']
    },

    'transport-road-passenger': {
      id: 'transport-road-passenger',
      prefLabel: 'transporte rodoviário de passageiros',
      altLabels: ['transporte de pessoas', 'ônibus rodoviário', 'transporte intermunicipal'],
      definition: 'Road transportation of passengers between cities and states',
      broader: ['transport-road'],
      related: ['vehicle-bus', 'regulation-passenger', 'safety-passenger'],
      inScheme: 'br-transport-legislation',
      notation: 'TR-ROAD-PASS',
      examples: ['viação', 'ônibus interestadual', 'transporte regular']
    },

    'transport-railway': {
      id: 'transport-railway',
      prefLabel: 'transporte ferroviário',
      altLabels: ['modal ferroviário', 'ferrovia', 'sistema ferroviário'],
      definition: 'Transportation by railway infrastructure and trains',
      narrower: ['transport-railway-cargo', 'transport-railway-passenger', 'transport-metro'],
      related: ['infrastructure-railway', 'vehicle-train', 'regulation-railway'],
      inScheme: 'br-transport-legislation',
      notation: 'TR-RAIL',
      examples: ['EFVM', 'EFC', 'Rumo Logística', 'VLI']
    },

    'transport-air': {
      id: 'transport-air',
      prefLabel: 'transporte aéreo',
      altLabels: ['aviação', 'modal aéreo', 'setor aeroportuário'],
      definition: 'Air transportation including commercial and general aviation',
      narrower: ['transport-air-commercial', 'transport-air-cargo', 'transport-air-general'],
      related: ['infrastructure-airport', 'vehicle-aircraft', 'regulation-aviation'],
      inScheme: 'br-transport-legislation',
      notation: 'TR-AIR',
      examples: ['aviação civil', 'companhias aéreas', 'aeroportos']
    },

    'transport-water': {
      id: 'transport-water',
      prefLabel: 'transporte aquaviário',
      altLabels: ['transporte hidroviário', 'transporte marítimo', 'navegação'],
      definition: 'Water transportation including maritime, river, and lake navigation',
      narrower: ['transport-maritime', 'transport-river', 'transport-port'],
      related: ['infrastructure-port', 'vehicle-vessel', 'regulation-maritime'],
      inScheme: 'br-transport-legislation',
      notation: 'TR-WATER',
      examples: ['cabotagem', 'navegação interior', 'transporte fluvial']
    },

    // Urban Mobility
    'mobility-urban': {
      id: 'mobility-urban',
      prefLabel: 'mobilidade urbana',
      altLabels: ['transporte urbano', 'mobilidade metropolitana', 'transporte público'],
      definition: 'Urban transportation and mobility systems within cities and metropolitan areas',
      narrower: ['transport-public', 'transport-individual', 'mobility-active'],
      related: ['planning-urban', 'infrastructure-urban', 'sustainability-urban'],
      inScheme: 'br-transport-legislation',
      notation: 'MOB-URBAN',
      examples: ['BRT', 'metrô', 'ônibus urbano', 'ciclofaixas']
    },

    'transport-public': {
      id: 'transport-public',
      prefLabel: 'transporte público',
      altLabels: ['transporte coletivo', 'sistema público de transporte'],
      definition: 'Public transportation systems serving urban populations',
      broader: ['mobility-urban'],
      narrower: ['transport-bus-urban', 'transport-metro', 'transport-brt'],
      related: ['regulation-public', 'tariff-public', 'accessibility-public'],
      inScheme: 'br-transport-legislation',
      notation: 'TR-PUBLIC',
      examples: ['SPTrans', 'MetrôRio', 'CBTU']
    },

    // Infrastructure
    'infrastructure-road': {
      id: 'infrastructure-road',
      prefLabel: 'infraestrutura rodoviária',
      altLabels: ['malha rodoviária', 'sistema viário', 'rede rodoviária'],
      definition: 'Road infrastructure including highways, bridges, tunnels, and related facilities',
      narrower: ['highway-federal', 'highway-state', 'road-municipal'],
      related: ['construction-road', 'maintenance-road', 'concession-road'],
      inScheme: 'br-transport-legislation',
      notation: 'INF-ROAD',
      examples: ['rodovias federais', 'concessões rodoviárias', 'pedágios']
    },

    'infrastructure-railway': {
      id: 'infrastructure-railway',
      prefLabel: 'infraestrutura ferroviária',
      altLabels: ['malha ferroviária', 'sistema ferroviário', 'rede ferroviária'],
      definition: 'Railway infrastructure including tracks, stations, terminals, and related facilities',
      related: ['concession-railway', 'maintenance-railway', 'modernization-railway'],
      inScheme: 'br-transport-legislation',
      notation: 'INF-RAIL',
      examples: ['malha paulista', 'ferrovia norte-sul', 'terminais ferroviários']
    },

    // Safety and Regulation
    'safety-transport': {
      id: 'safety-transport',
      prefLabel: 'segurança no transporte',
      altLabels: ['segurança viária', 'prevenção de acidentes', 'segurança operacional'],
      definition: 'Transportation safety measures, regulations, and accident prevention',
      narrower: ['safety-road', 'safety-railway', 'safety-aviation', 'safety-maritime'],
      related: ['regulation-safety', 'inspection-safety', 'training-safety'],
      inScheme: 'br-transport-legislation',
      notation: 'SAF-TRANS',
      examples: ['CTB', 'fiscalização', 'habilitação profissional']
    },

    'regulation-transport': {
      id: 'regulation-transport',
      prefLabel: 'regulamentação de transportes',
      altLabels: ['normas de transporte', 'regulação do transporte'],
      definition: 'Legal and regulatory framework governing transportation activities',
      narrower: ['regulation-road', 'regulation-railway', 'regulation-aviation', 'regulation-maritime'],
      related: ['agency-regulation', 'licensing-transport', 'inspection-transport'],
      inScheme: 'br-transport-legislation',
      notation: 'REG-TRANS',
      examples: ['ANTT', 'ANTAQ', 'ANAC', 'habilitação', 'licenciamento']
    },

    // Environmental
    'sustainability-transport': {
      id: 'sustainability-transport',
      prefLabel: 'sustentabilidade no transporte',
      altLabels: ['transporte sustentável', 'mobilidade sustentável', 'transporte verde'],
      definition: 'Sustainable transportation practices and environmental considerations',
      narrower: ['emission-control', 'fuel-alternative', 'transport-electric'],
      related: ['environment-transport', 'energy-transport', 'climate-transport'],
      inScheme: 'br-transport-legislation',
      notation: 'SUS-TRANS',
      examples: ['veículos elétricos', 'biocombustíveis', 'emissões veiculares']
    },

    // Technology and Innovation
    'technology-transport': {
      id: 'technology-transport',
      prefLabel: 'tecnologia no transporte',
      altLabels: ['inovação em transportes', 'ITS', 'smart mobility'],
      definition: 'Transportation technology, innovation, and intelligent systems',
      narrower: ['its-systems', 'automation-transport', 'digitalization-transport'],
      related: ['innovation-transport', 'connectivity-transport', 'data-transport'],
      inScheme: 'br-transport-legislation',
      notation: 'TECH-TRANS',
      examples: ['sistemas ITS', 'veículos autônomos', 'aplicativos de transporte']
    }
  },
  hierarchy: {
    'transport': ['transport-road', 'transport-railway', 'transport-air', 'transport-water'],
    'transport-road': ['transport-road-cargo', 'transport-road-passenger', 'transport-road-urban'],
    'mobility-urban': ['transport-public', 'transport-individual', 'mobility-active'],
    'infrastructure': ['infrastructure-road', 'infrastructure-railway', 'infrastructure-airport', 'infrastructure-port'],
    'safety-transport': ['safety-road', 'safety-railway', 'safety-aviation', 'safety-maritime'],
    'regulation-transport': ['regulation-road', 'regulation-railway', 'regulation-aviation', 'regulation-maritime']
  }
};

export class SemanticSearchService {
  private static instance: SemanticSearchService;
  private skosScheme: SKOSConceptScheme;
  private conceptIndex: Map<string, string[]> = new Map();

  private constructor() {
    this.skosScheme = TRANSPORT_SKOS_SCHEME;
    this.buildConceptIndex();
  }

  public static getInstance(): SemanticSearchService {
    if (!SemanticSearchService.instance) {
      SemanticSearchService.instance = new SemanticSearchService();
    }
    return SemanticSearchService.instance;
  }

  /**
   * Expand query using SKOS vocabulary
   */
  public expandQuery(
    query: string,
    strategy: 'conservative' | 'moderate' | 'aggressive' = 'moderate'
  ): VocabularyExpansion {
    const tokens = this.tokenizeQuery(query);
    const conceptsFound: SKOSConcept[] = [];
    const termMapping: Record<string, string[]> = {};
    let expandedTerms: string[] = [...tokens];

    // Find matching concepts
    for (const token of tokens) {
      const matchedConcepts = this.findMatchingConcepts(token);
      
      for (const { concept, matchType } of matchedConcepts) {
        if (!conceptsFound.find(c => c.id === concept.id)) {
          conceptsFound.push(concept);
        }

        // Add expansion terms based on strategy
        const expansionTerms = this.getExpansionTerms(concept, matchType, strategy);
        termMapping[token] = expansionTerms;
        expandedTerms.push(...expansionTerms);
      }
    }

    // Remove duplicates and filter terms
    expandedTerms = [...new Set(expandedTerms)];
    const expandedQuery = expandedTerms.join(' ');

    // Calculate confidence based on concepts found and strategy
    const confidence = this.calculateExpansionConfidence(conceptsFound, strategy, tokens.length);

    return {
      originalQuery: query,
      expandedQuery,
      conceptsFound,
      expansionStrategy: strategy,
      confidence,
      termMapping
    };
  }

  /**
   * Find semantic matches in document corpus
   */
  public findSemanticMatches(
    documents: LegislativeDocument[],
    expansion: VocabularyExpansion
  ): SemanticSearchResult[] {
    const results: SemanticSearchResult[] = [];

    for (const document of documents) {
      const semanticMatches = this.analyzeDocumentSemantics(document, expansion);
      
      if (semanticMatches.length > 0) {
        const relevanceScore = this.calculateSemanticRelevance(document, semanticMatches, expansion);
        const conceptCoverage = this.calculateConceptCoverage(semanticMatches, expansion.conceptsFound);
        const domainRelevance = this.calculateDomainRelevance(document, semanticMatches);
        
        const snippet = this.generateSemanticSnippet(document, semanticMatches);
        const highlightedSnippet = this.highlightSemanticTerms(snippet, semanticMatches);

        results.push({
          document,
          relevanceScore,
          semanticMatches,
          conceptCoverage,
          domainRelevance,
          snippet,
          highlightedSnippet
        });
      }
    }

    // Sort by relevance score
    return results.sort((a, b) => b.relevanceScore - a.relevanceScore);
  }

  /**
   * Get concept definitions and related terms
   */
  public getConceptDetails(conceptId: string): SKOSConcept | null {
    return this.skosScheme.concepts[conceptId] || null;
  }

  /**
   * Get concept hierarchy
   */
  public getConceptHierarchy(conceptId: string): {
    broader: SKOSConcept[];
    narrower: SKOSConcept[];
    related: SKOSConcept[];
  } {
    const concept = this.skosScheme.concepts[conceptId];
    if (!concept) {
      return { broader: [], narrower: [], related: [] };
    }

    return {
      broader: (concept.broader || []).map(id => this.skosScheme.concepts[id]).filter(Boolean),
      narrower: (concept.narrower || []).map(id => this.skosScheme.concepts[id]).filter(Boolean),
      related: (concept.related || []).map(id => this.skosScheme.concepts[id]).filter(Boolean)
    };
  }

  /**
   * Search concepts by text
   */
  public searchConcepts(searchText: string, limit: number = 10): SKOSConcept[] {
    const query = searchText.toLowerCase();
    const matches: Array<{ concept: SKOSConcept; score: number }> = [];

    for (const concept of Object.values(this.skosScheme.concepts)) {
      let score = 0;

      // Exact match in preferred label
      if (concept.prefLabel.toLowerCase() === query) {
        score += 100;
      } else if (concept.prefLabel.toLowerCase().includes(query)) {
        score += 50;
      }

      // Match in alternative labels
      for (const altLabel of concept.altLabels) {
        if (altLabel.toLowerCase() === query) {
          score += 80;
        } else if (altLabel.toLowerCase().includes(query)) {
          score += 30;
        }
      }

      // Match in definition
      if (concept.definition.toLowerCase().includes(query)) {
        score += 20;
      }

      // Match in examples
      if (concept.examples) {
        for (const example of concept.examples) {
          if (example.toLowerCase().includes(query)) {
            score += 15;
          }
        }
      }

      if (score > 0) {
        matches.push({ concept, score });
      }
    }

    return matches
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(m => m.concept);
  }

  // Private helper methods

  private buildConceptIndex(): void {
    for (const concept of Object.values(this.skosScheme.concepts)) {
      const terms = [
        concept.prefLabel,
        ...concept.altLabels,
        ...(concept.examples || [])
      ];

      for (const term of terms) {
        const normalized = term.toLowerCase();
        const conceptIds = this.conceptIndex.get(normalized) || [];
        if (!conceptIds.includes(concept.id)) {
          conceptIds.push(concept.id);
          this.conceptIndex.set(normalized, conceptIds);
        }
      }
    }
  }

  private tokenizeQuery(query: string): string[] {
    return query
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(token => token.length > 2);
  }

  private findMatchingConcepts(term: string): Array<{ concept: SKOSConcept; matchType: SemanticMatch['matchType'] }> {
    const matches: Array<{ concept: SKOSConcept; matchType: SemanticMatch['matchType'] }> = [];
    const normalizedTerm = term.toLowerCase();

    for (const concept of Object.values(this.skosScheme.concepts)) {
      // Exact match in preferred label
      if (concept.prefLabel.toLowerCase() === normalizedTerm) {
        matches.push({ concept, matchType: 'exact' });
        continue;
      }

      // Match in alternative labels
      for (const altLabel of concept.altLabels) {
        if (altLabel.toLowerCase().includes(normalizedTerm)) {
          matches.push({ concept, matchType: 'synonym' });
          break;
        }
      }

      // Partial matches
      if (concept.prefLabel.toLowerCase().includes(normalizedTerm)) {
        matches.push({ concept, matchType: 'related' });
      }
    }

    return matches;
  }

  private getExpansionTerms(
    concept: SKOSConcept,
    matchType: SemanticMatch['matchType'],
    strategy: 'conservative' | 'moderate' | 'aggressive'
  ): string[] {
    const terms: string[] = [];

    // Always include preferred label
    terms.push(concept.prefLabel);

    switch (strategy) {
      case 'conservative':
        // Only close synonyms
        terms.push(...concept.altLabels.slice(0, 2));
        break;

      case 'moderate':
        // Synonyms and some related terms
        terms.push(...concept.altLabels);
        if (concept.narrower) {
          const narrowerConcepts = concept.narrower.map(id => this.skosScheme.concepts[id]).filter(Boolean);
          terms.push(...narrowerConcepts.slice(0, 2).map(c => c.prefLabel));
        }
        break;

      case 'aggressive':
        // All related terms
        terms.push(...concept.altLabels);
        if (concept.narrower) {
          const narrowerConcepts = concept.narrower.map(id => this.skosScheme.concepts[id]).filter(Boolean);
          terms.push(...narrowerConcepts.map(c => c.prefLabel));
        }
        if (concept.broader) {
          const broaderConcepts = concept.broader.map(id => this.skosScheme.concepts[id]).filter(Boolean);
          terms.push(...broaderConcepts.map(c => c.prefLabel));
        }
        if (concept.related) {
          const relatedConcepts = concept.related.map(id => this.skosScheme.concepts[id]).filter(Boolean);
          terms.push(...relatedConcepts.slice(0, 3).map(c => c.prefLabel));
        }
        break;
    }

    return [...new Set(terms)];
  }

  private calculateExpansionConfidence(
    conceptsFound: SKOSConcept[],
    strategy: 'conservative' | 'moderate' | 'aggressive',
    originalTermCount: number
  ): number {
    const baseConfidence = Math.min(conceptsFound.length / originalTermCount, 1);
    
    const strategyMultiplier = {
      conservative: 0.9,
      moderate: 0.8,
      aggressive: 0.7
    };

    return baseConfidence * strategyMultiplier[strategy];
  }

  private analyzeDocumentSemantics(
    document: LegislativeDocument,
    expansion: VocabularyExpansion
  ): SemanticMatch[] {
    const matches: SemanticMatch[] = [];
    const documentText = `${document.title} ${document.summary} ${document.keywords.join(' ')}`.toLowerCase();

    for (const concept of expansion.conceptsFound) {
      const conceptTerms = [concept.prefLabel, ...concept.altLabels];
      const matchedTerms: string[] = [];
      let bestMatchType: SemanticMatch['matchType'] = 'related';
      let confidence = 0;

      for (const term of conceptTerms) {
        if (documentText.includes(term.toLowerCase())) {
          matchedTerms.push(term);
          if (term === concept.prefLabel) {
            bestMatchType = 'exact';
            confidence = Math.max(confidence, 0.9);
          } else {
            confidence = Math.max(confidence, 0.7);
          }
        }
      }

      if (matchedTerms.length > 0) {
        matches.push({
          concept,
          matchType: bestMatchType,
          confidence,
          originalTerm: expansion.originalQuery,
          expandedTerms: matchedTerms
        });
      }
    }

    return matches;
  }

  private calculateSemanticRelevance(
    document: LegislativeDocument,
    semanticMatches: SemanticMatch[],
    expansion: VocabularyExpansion
  ): number {
    const matchCount = semanticMatches.length;
    const maxPossibleMatches = expansion.conceptsFound.length;
    const matchRatio = maxPossibleMatches > 0 ? matchCount / maxPossibleMatches : 0;

    const avgConfidence = semanticMatches.reduce((sum, match) => sum + match.confidence, 0) / matchCount;
    
    // Boost for transport-related documents
    const transportBoost = document.keywords.some(keyword => 
      ['transporte', 'mobilidade', 'rodoviário', 'ferroviário', 'aéreo', 'aquaviário'].includes(keyword.toLowerCase())
    ) ? 1.2 : 1.0;

    return (matchRatio * 0.6 + avgConfidence * 0.4) * transportBoost;
  }

  private calculateConceptCoverage(
    semanticMatches: SemanticMatch[],
    conceptsFound: SKOSConcept[]
  ): number {
    if (conceptsFound.length === 0) return 0;
    return semanticMatches.length / conceptsFound.length;
  }

  private calculateDomainRelevance(
    document: LegislativeDocument,
    semanticMatches: SemanticMatch[]
  ): number {
    const transportConcepts = semanticMatches.filter(match => 
      match.concept.id.startsWith('transport-') || 
      match.concept.id.startsWith('mobility-') ||
      match.concept.id.startsWith('infrastructure-')
    );

    return transportConcepts.length / Math.max(semanticMatches.length, 1);
  }

  private generateSemanticSnippet(
    document: LegislativeDocument,
    semanticMatches: SemanticMatch[]
  ): string {
    const allMatchedTerms = semanticMatches.flatMap(match => match.expandedTerms);
    const text = document.summary || document.title;
    
    // Find the best 200-character window that contains the most matched terms
    const windowSize = 200;
    let bestWindow = text.substring(0, windowSize);
    let maxMatches = 0;

    for (let i = 0; i <= text.length - windowSize; i += 50) {
      const window = text.substring(i, i + windowSize);
      const matchCount = allMatchedTerms.filter(term => 
        window.toLowerCase().includes(term.toLowerCase())
      ).length;

      if (matchCount > maxMatches) {
        maxMatches = matchCount;
        bestWindow = window;
      }
    }

    return bestWindow + (bestWindow.length < text.length ? '...' : '');
  }

  private highlightSemanticTerms(
    text: string,
    semanticMatches: SemanticMatch[]
  ): string {
    const allMatchedTerms = semanticMatches.flatMap(match => match.expandedTerms);
    let highlightedText = text;

    for (const term of allMatchedTerms) {
      const regex = new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
      highlightedText = highlightedText.replace(regex, '<mark>$&</mark>');
    }

    return highlightedText;
  }
}

export const semanticSearchService = SemanticSearchService.getInstance();