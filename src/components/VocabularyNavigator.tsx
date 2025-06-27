import React, { useState, useEffect } from 'react';
import GlassCard from './GlassCard';
import '../styles/glassmorphism.css';

interface SKOSConcept {
  uri: string;
  pref_label: { [lang: string]: string };
  alt_labels: { [lang: string]: string[] };
  definition: { [lang: string]: string };
  concept_scheme: string;
  broader: string[];
  narrower: string[];
  related: string[];
  notation?: string;
}

interface ConceptHierarchy {
  concept: SKOSConcept;
  path: string[];
  children: SKOSConcept[];
  parent?: SKOSConcept;
  siblings: SKOSConcept[];
  depth: number;
  is_root: boolean;
  is_leaf: boolean;
}

interface SearchResult {
  concept: SKOSConcept;
  match_type: string;
  score: number;
  matched_label: string;
  context?: string;
}

interface QueryExpansion {
  original: string[];
  narrower: string[];
  broader: string[];
  related: string[];
  synonyms: string[];
}

interface VocabularyNavigatorProps {
  onConceptSelect?: (concept: SKOSConcept) => void;
  onQueryExpansion?: (expansion: QueryExpansion) => void;
  className?: string;
  language?: string;
  initialScheme?: string;
}

const VocabularyNavigator: React.FC<VocabularyNavigatorProps> = ({
  onConceptSelect,
  onQueryExpansion,
  className = "",
  language = "pt",
  initialScheme = "transport"
}) => {
  const [selectedConcept, setSelectedConcept] = useState<SKOSConcept | null>(null);
  const [conceptHierarchy, setConceptHierarchy] = useState<ConceptHierarchy | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [currentScheme, setCurrentScheme] = useState(initialScheme);
  const [breadcrumb, setBreadcrumb] = useState<SKOSConcept[]>([]);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [showSearch, setShowSearch] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [vocabularyOverview, setVocabularyOverview] = useState<any>(null);

  // Mock vocabulary data - in production this would come from the SKOS manager service
  const mockVocabulary = {
    transport: {
      scheme: 'transport',
      total_concepts: 25,
      max_depth: 3,
      root_concepts: [
        {
          uri: 'http://vocab.lexml.gov.br/transport/modal',
          label: 'Modal de Transporte',
          children_count: 4
        }
      ],
      top_level_categories: 1
    },
    concepts: {
      'http://vocab.lexml.gov.br/transport/modal': {
        uri: 'http://vocab.lexml.gov.br/transport/modal',
        pref_label: { pt: 'Modal de Transporte', en: 'Transport Mode' },
        alt_labels: { pt: ['Modalidade', 'Modo de Transporte'] },
        definition: { pt: 'Categorias de modalidades de transporte' },
        concept_scheme: 'transport',
        broader: [],
        narrower: [
          'http://vocab.lexml.gov.br/transport/modal/rodoviario',
          'http://vocab.lexml.gov.br/transport/modal/ferroviario',
          'http://vocab.lexml.gov.br/transport/modal/aquaviario',
          'http://vocab.lexml.gov.br/transport/modal/aereo'
        ],
        related: []
      },
      'http://vocab.lexml.gov.br/transport/modal/rodoviario': {
        uri: 'http://vocab.lexml.gov.br/transport/modal/rodoviario',
        pref_label: { pt: 'Transporte Rodoviário', en: 'Road Transport' },
        alt_labels: { pt: ['Modal Rodoviário', 'Transporte por Estradas'] },
        definition: { pt: 'Transporte realizado através de rodovias e estradas' },
        concept_scheme: 'transport',
        broader: ['http://vocab.lexml.gov.br/transport/modal'],
        narrower: [
          'http://vocab.lexml.gov.br/transport/modal/rodoviario/cargas',
          'http://vocab.lexml.gov.br/transport/modal/rodoviario/passageiros'
        ],
        related: ['http://vocab.lexml.gov.br/entities/antt']
      },
      'http://vocab.lexml.gov.br/transport/modal/ferroviario': {
        uri: 'http://vocab.lexml.gov.br/transport/modal/ferroviario',
        pref_label: { pt: 'Transporte Ferroviário', en: 'Railway Transport' },
        alt_labels: { pt: ['Modal Ferroviário', 'Transporte por Trens'] },
        definition: { pt: 'Transporte realizado através de ferrovias' },
        concept_scheme: 'transport',
        broader: ['http://vocab.lexml.gov.br/transport/modal'],
        narrower: [
          'http://vocab.lexml.gov.br/transport/modal/ferroviario/cargas',
          'http://vocab.lexml.gov.br/transport/modal/ferroviario/passageiros'
        ],
        related: []
      },
      'http://vocab.lexml.gov.br/transport/modal/aquaviario': {
        uri: 'http://vocab.lexml.gov.br/transport/modal/aquaviario',
        pref_label: { pt: 'Transporte Aquaviário', en: 'Water Transport' },
        alt_labels: { pt: ['Modal Aquaviário', 'Transporte Marítimo'] },
        definition: { pt: 'Transporte realizado através de vias aquáticas' },
        concept_scheme: 'transport',
        broader: ['http://vocab.lexml.gov.br/transport/modal'],
        narrower: [
          'http://vocab.lexml.gov.br/transport/modal/aquaviario/maritimo',
          'http://vocab.lexml.gov.br/transport/modal/aquaviario/fluvial'
        ],
        related: ['http://vocab.lexml.gov.br/entities/antaq']
      },
      'http://vocab.lexml.gov.br/transport/modal/aereo': {
        uri: 'http://vocab.lexml.gov.br/transport/modal/aereo',
        pref_label: { pt: 'Transporte Aéreo', en: 'Air Transport' },
        alt_labels: { pt: ['Modal Aéreo', 'Aviação'] },
        definition: { pt: 'Transporte realizado através de aeronaves' },
        concept_scheme: 'transport',
        broader: ['http://vocab.lexml.gov.br/transport/modal'],
        narrower: [
          'http://vocab.lexml.gov.br/transport/modal/aereo/comercial',
          'http://vocab.lexml.gov.br/transport/modal/aereo/geral'
        ],
        related: ['http://vocab.lexml.gov.br/entities/anac']
      }
    }
  };

  // Load vocabulary overview
  useEffect(() => {
    setVocabularyOverview(mockVocabulary[currentScheme as keyof typeof mockVocabulary]);
  }, [currentScheme]);

  // Load concept hierarchy when concept is selected
  useEffect(() => {
    if (selectedConcept) {
      loadConceptHierarchy(selectedConcept.uri);
    }
  }, [selectedConcept]);

  // Mock API call to load concept hierarchy
  const loadConceptHierarchy = async (conceptUri: string) => {
    setIsLoading(true);
    try {
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 300));
      
      const concept = mockVocabulary.concepts[conceptUri as keyof typeof mockVocabulary.concepts];
      if (concept) {
        const hierarchy: ConceptHierarchy = {
          concept,
          path: buildConceptPath(concept),
          children: concept.narrower.map(uri => mockVocabulary.concepts[uri as keyof typeof mockVocabulary.concepts]).filter(Boolean),
          parent: concept.broader.length > 0 ? mockVocabulary.concepts[concept.broader[0] as keyof typeof mockVocabulary.concepts] : undefined,
          siblings: [],
          depth: calculateDepth(concept),
          is_root: concept.broader.length === 0,
          is_leaf: concept.narrower.length === 0
        };
        
        setConceptHierarchy(hierarchy);
        setBreadcrumb(hierarchy.path.map(uri => mockVocabulary.concepts[uri as keyof typeof mockVocabulary.concepts]).filter(Boolean));
      }
    } catch (error) {
      console.error('Error loading concept hierarchy:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Build concept path from root
  const buildConceptPath = (concept: SKOSConcept): string[] => {
    const path = [concept.uri];
    let current = concept;
    
    while (current.broader.length > 0) {
      const parentUri = current.broader[0];
      const parent = mockVocabulary.concepts[parentUri as keyof typeof mockVocabulary.concepts];
      if (parent) {
        path.unshift(parentUri);
        current = parent;
      } else {
        break;
      }
    }
    
    return path;
  };

  // Calculate concept depth
  const calculateDepth = (concept: SKOSConcept): number => {
    let depth = 0;
    let current = concept;
    
    while (current.broader.length > 0) {
      depth++;
      const parentUri = current.broader[0];
      const parent = mockVocabulary.concepts[parentUri as keyof typeof mockVocabulary.concepts];
      if (parent) {
        current = parent;
      } else {
        break;
      }
    }
    
    return depth;
  };

  // Search concepts
  const searchConcepts = async (query: string) => {
    if (!query.trim()) {
      setSearchResults([]);
      return;
    }

    setIsLoading(true);
    try {
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 200));
      
      const queryLower = query.toLowerCase();
      const results: SearchResult[] = [];
      
      Object.values(mockVocabulary.concepts).forEach(concept => {
        const prefLabel = concept.pref_label[language] || concept.pref_label.pt || '';
        const altLabels = concept.alt_labels[language] || concept.alt_labels.pt || [];
        
        // Exact match
        if (prefLabel.toLowerCase() === queryLower) {
          results.push({
            concept,
            match_type: 'exact',
            score: 1.0,
            matched_label: prefLabel
          });
        }
        // Prefix match
        else if (prefLabel.toLowerCase().startsWith(queryLower)) {
          results.push({
            concept,
            match_type: 'prefix',
            score: 0.9,
            matched_label: prefLabel
          });
        }
        // Contains match
        else if (prefLabel.toLowerCase().includes(queryLower)) {
          results.push({
            concept,
            match_type: 'contains',
            score: 0.7,
            matched_label: prefLabel
          });
        }
        // Alternative label matches
        else {
          for (const altLabel of altLabels) {
            if (altLabel.toLowerCase().includes(queryLower)) {
              results.push({
                concept,
                match_type: 'alternative',
                score: 0.6,
                matched_label: altLabel
              });
              break;
            }
          }
        }
      });
      
      // Sort by score
      results.sort((a, b) => b.score - a.score);
      setSearchResults(results.slice(0, 10));
      
    } catch (error) {
      console.error('Error searching concepts:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Handle concept selection
  const handleConceptSelect = (concept: SKOSConcept) => {
    setSelectedConcept(concept);
    setSearchQuery('');
    setSearchResults([]);
    setShowSearch(false);
    
    if (onConceptSelect) {
      onConceptSelect(concept);
    }
  };

  // Generate query expansion
  const generateQueryExpansion = (concept: SKOSConcept) => {
    const expansion: QueryExpansion = {
      original: [concept.pref_label[language] || concept.pref_label.pt || ''],
      narrower: [],
      broader: [],
      related: [],
      synonyms: concept.alt_labels[language] || concept.alt_labels.pt || []
    };

    // Add narrower terms
    concept.narrower.forEach(uri => {
      const narrowerConcept = mockVocabulary.concepts[uri as keyof typeof mockVocabulary.concepts];
      if (narrowerConcept) {
        expansion.narrower.push(narrowerConcept.pref_label[language] || narrowerConcept.pref_label.pt || '');
      }
    });

    // Add broader terms
    concept.broader.forEach(uri => {
      const broaderConcept = mockVocabulary.concepts[uri as keyof typeof mockVocabulary.concepts];
      if (broaderConcept) {
        expansion.broader.push(broaderConcept.pref_label[language] || broaderConcept.pref_label.pt || '');
      }
    });

    // Add related terms
    concept.related.forEach(uri => {
      const relatedConcept = mockVocabulary.concepts[uri as keyof typeof mockVocabulary.concepts];
      if (relatedConcept) {
        expansion.related.push(relatedConcept.pref_label[language] || relatedConcept.pref_label.pt || '');
      }
    });

    if (onQueryExpansion) {
      onQueryExpansion(expansion);
    }

    return expansion;
  };

  // Toggle node expansion
  const toggleNodeExpansion = (uri: string) => {
    const newExpanded = new Set(expandedNodes);
    if (newExpanded.has(uri)) {
      newExpanded.delete(uri);
    } else {
      newExpanded.add(uri);
    }
    setExpandedNodes(newExpanded);
  };

  // Render concept tree node
  const renderConceptNode = (concept: SKOSConcept, depth: number = 0) => {
    const hasChildren = concept.narrower.length > 0;
    const isExpanded = expandedNodes.has(concept.uri);
    const isSelected = selectedConcept?.uri === concept.uri;
    
    return (
      <div key={concept.uri} className="mb-1">
        <div
          className={`
            flex items-center gap-2 p-2 rounded cursor-pointer transition-colors
            ${isSelected ? 'bg-blue-100 text-blue-800' : 'hover:bg-gray-50'}
          `}
          style={{ paddingLeft: `${depth * 20 + 8}px` }}
          onClick={() => handleConceptSelect(concept)}
        >
          {hasChildren && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                toggleNodeExpansion(concept.uri);
              }}
              className="p-1 hover:bg-gray-200 rounded"
            >
              {isExpanded ? '🔽' : '▶️'}
            </button>
          )}
          {!hasChildren && <span className="w-6"></span>}
          
          <span className="flex-1 font-medium">
            {concept.pref_label[language] || concept.pref_label.pt}
          </span>
          
          {concept.narrower.length > 0 && (
            <span className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
              {concept.narrower.length}
            </span>
          )}
        </div>
        
        {hasChildren && isExpanded && (
          <div>
            {concept.narrower.map(childUri => {
              const childConcept = mockVocabulary.concepts[childUri as keyof typeof mockVocabulary.concepts];
              return childConcept ? renderConceptNode(childConcept, depth + 1) : null;
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={`vocabulary-navigator ${className}`}>
      {/* Header */}
      <GlassCard variant="academic" className="mb-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-xl font-bold text-gray-800">Navegador de Vocabulário SKOS</h2>
            <p className="text-gray-600">Explore hierarquias de conceitos legislativos brasileiros</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setShowSearch(!showSearch)}
              className={`glass-button-secondary px-4 py-2 ${showSearch ? 'bg-blue-50' : ''}`}
            >
              🔍 Buscar
            </button>
            <button
              onClick={() => generateQueryExpansion(selectedConcept!)}
              disabled={!selectedConcept}
              className="glass-button-primary px-4 py-2 disabled:opacity-50"
            >
              🔄 Expandir
            </button>
          </div>
        </div>
      </GlassCard>

      {/* Search Interface */}
      {showSearch && (
        <GlassCard variant="light" className="mb-4">
          <div className="relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                searchConcepts(e.target.value);
              }}
              placeholder="Buscar conceitos no vocabulário..."
              className="glass-input pr-10"
            />
            {isLoading && (
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                <div className="animate-spin w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full"></div>
              </div>
            )}
          </div>
          
          {/* Search Results */}
          {searchResults.length > 0 && (
            <div className="mt-4 max-h-60 overflow-y-auto">
              <div className="text-sm font-medium text-gray-600 mb-2">
                Resultados da busca ({searchResults.length})
              </div>
              {searchResults.map((result, index) => (
                <div
                  key={index}
                  onClick={() => handleConceptSelect(result.concept)}
                  className="flex items-center justify-between p-3 border border-gray-200 rounded mb-2 cursor-pointer hover:bg-gray-50"
                >
                  <div>
                    <div className="font-medium">{result.matched_label}</div>
                    <div className="text-sm text-gray-600">
                      {result.concept.definition[language] || result.concept.definition.pt}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`
                      px-2 py-1 rounded text-xs font-medium
                      ${result.match_type === 'exact' ? 'bg-green-100 text-green-700' :
                        result.match_type === 'prefix' ? 'bg-blue-100 text-blue-700' :
                        result.match_type === 'contains' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-gray-100 text-gray-700'
                      }
                    `}>
                      {result.match_type}
                    </span>
                    <span className="text-sm text-gray-500">
                      {Math.round(result.score * 100)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </GlassCard>
      )}

      {/* Main Content */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Vocabulary Tree */}
        <div className="lg:col-span-2">
          <GlassCard variant="research">
            <h3 className="font-bold text-lg mb-4">Hierarquia de Conceitos</h3>
            
            {/* Breadcrumb */}
            {breadcrumb.length > 0 && (
              <div className="mb-4 p-3 bg-blue-50 rounded-lg">
                <div className="text-sm font-medium text-blue-700 mb-1">Caminho:</div>
                <div className="flex items-center gap-2 text-sm">
                  {breadcrumb.map((concept, index) => (
                    <React.Fragment key={concept.uri}>
                      {index > 0 && <span className="text-gray-400">→</span>}
                      <button
                        onClick={() => handleConceptSelect(concept)}
                        className="text-blue-600 hover:text-blue-800 hover:underline"
                      >
                        {concept.pref_label[language] || concept.pref_label.pt}
                      </button>
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}

            {/* Vocabulary Overview */}
            {vocabularyOverview && (
              <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center text-sm">
                  <div>
                    <div className="font-bold text-blue-600">{vocabularyOverview.total_concepts}</div>
                    <div className="text-gray-600">Conceitos</div>
                  </div>
                  <div>
                    <div className="font-bold text-green-600">{vocabularyOverview.max_depth}</div>
                    <div className="text-gray-600">Níveis</div>
                  </div>
                  <div>
                    <div className="font-bold text-purple-600">{vocabularyOverview.top_level_categories}</div>
                    <div className="text-gray-600">Categorias</div>
                  </div>
                  <div>
                    <div className="font-bold text-orange-600">{currentScheme}</div>
                    <div className="text-gray-600">Esquema</div>
                  </div>
                </div>
              </div>
            )}

            {/* Concept Tree */}
            <div className="max-h-96 overflow-y-auto">
              {vocabularyOverview?.root_concepts.map((rootConcept: any) => {
                const concept = mockVocabulary.concepts[rootConcept.uri as keyof typeof mockVocabulary.concepts];
                return concept ? renderConceptNode(concept) : null;
              })}
            </div>
          </GlassCard>
        </div>

        {/* Concept Details */}
        <div>
          <GlassCard variant="analysis">
            <h3 className="font-bold text-lg mb-4">Detalhes do Conceito</h3>
            
            {selectedConcept ? (
              <div className="space-y-4">
                <div>
                  <h4 className="font-bold text-lg text-blue-800">
                    {selectedConcept.pref_label[language] || selectedConcept.pref_label.pt}
                  </h4>
                  {selectedConcept.notation && (
                    <div className="text-sm text-gray-600">
                      Notação: {selectedConcept.notation}
                    </div>
                  )}
                </div>

                {selectedConcept.definition[language] && (
                  <div>
                    <div className="font-medium text-gray-700 mb-1">Definição:</div>
                    <div className="text-sm text-gray-600">
                      {selectedConcept.definition[language] || selectedConcept.definition.pt}
                    </div>
                  </div>
                )}

                {selectedConcept.alt_labels[language]?.length > 0 && (
                  <div>
                    <div className="font-medium text-gray-700 mb-1">Termos alternativos:</div>
                    <div className="flex flex-wrap gap-1">
                      {selectedConcept.alt_labels[language].map(label => (
                        <span key={label} className="glass-badge text-xs">
                          {label}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {conceptHierarchy && (
                  <div className="space-y-3">
                    {conceptHierarchy.parent && (
                      <div>
                        <div className="font-medium text-gray-700 mb-1">Conceito superior:</div>
                        <button
                          onClick={() => handleConceptSelect(conceptHierarchy.parent!)}
                          className="text-sm text-blue-600 hover:text-blue-800 hover:underline"
                        >
                          {conceptHierarchy.parent.pref_label[language] || conceptHierarchy.parent.pref_label.pt}
                        </button>
                      </div>
                    )}

                    {conceptHierarchy.children.length > 0 && (
                      <div>
                        <div className="font-medium text-gray-700 mb-1">Conceitos subordinados:</div>
                        <div className="space-y-1">
                          {conceptHierarchy.children.map(child => (
                            <button
                              key={child.uri}
                              onClick={() => handleConceptSelect(child)}
                              className="block text-sm text-blue-600 hover:text-blue-800 hover:underline"
                            >
                              {child.pref_label[language] || child.pref_label.pt}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {selectedConcept.related.length > 0 && (
                      <div>
                        <div className="font-medium text-gray-700 mb-1">Conceitos relacionados:</div>
                        <div className="space-y-1">
                          {selectedConcept.related.map(relatedUri => {
                            const relatedConcept = mockVocabulary.concepts[relatedUri as keyof typeof mockVocabulary.concepts];
                            return relatedConcept ? (
                              <button
                                key={relatedUri}
                                onClick={() => handleConceptSelect(relatedConcept)}
                                className="block text-sm text-purple-600 hover:text-purple-800 hover:underline"
                              >
                                {relatedConcept.pref_label[language] || relatedConcept.pref_label.pt}
                              </button>
                            ) : null;
                          })}
                        </div>
                      </div>
                    )}

                    <div className="pt-3 border-t border-gray-200">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div className="text-center">
                          <div className="font-bold text-blue-600">{conceptHierarchy.depth}</div>
                          <div className="text-gray-600">Nível</div>
                        </div>
                        <div className="text-center">
                          <div className="font-bold text-green-600">{conceptHierarchy.children.length}</div>
                          <div className="text-gray-600">Filhos</div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <div className="pt-3 border-t border-gray-200">
                  <button
                    onClick={() => generateQueryExpansion(selectedConcept)}
                    className="glass-button-primary w-full py-2 text-sm"
                  >
                    🔄 Gerar Expansão de Consulta
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <div className="mb-2">📚</div>
                <div>Selecione um conceito para ver detalhes</div>
              </div>
            )}
          </GlassCard>
        </div>
      </div>
    </div>
  );
};

export default VocabularyNavigator;