import React, { useState, useEffect, useRef, useCallback } from 'react';
import { lexmlService } from '../services/lexmlService';
import { knowledgeGraphService } from '../services/knowledgeGraphService';
import GlassCard from './GlassCard';
import '../styles/glassmorphism.css';

interface SearchSuggestion {
  text: string;
  type: 'query' | 'entity' | 'topic' | 'location' | 'date_range';
  confidence: number;
  description?: string;
  category?: string;
}

interface QueryExpansion {
  originalQuery: string;
  expandedTerms: string[];
  relatedConcepts: string[];
  synonyms: string[];
  contextualTerms: string[];
  confidence: number;
}

interface SearchResult {
  id: string;
  title: string;
  summary: string;
  relevanceScore: number;
  source: string;
  date: string;
  documentType: string;
  url?: string;
  metadata: Record<string, any>;
}

interface AISearchInterfaceProps {
  onSearchResults?: (results: SearchResult[]) => void;
  onQueryChange?: (query: string) => void;
  placeholder?: string;
  showSuggestions?: boolean;
  showQueryExpansion?: boolean;
  enableAutoComplete?: boolean;
  maxSuggestions?: number;
  className?: string;
}

const AISearchInterface: React.FC<AISearchInterfaceProps> = ({
  onSearchResults,
  onQueryChange,
  placeholder = "Pesquise legislação brasileira com IA...",
  showSuggestions = true,
  showQueryExpansion = true,
  enableAutoComplete = true,
  maxSuggestions = 8,
  className = ""
}) => {
  const [query, setQuery] = useState('');
  const [suggestions, setSuggestions] = useState<SearchSuggestion[]>([]);
  const [queryExpansion, setQueryExpansion] = useState<QueryExpansion | null>(null);
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [isLoadingSuggestions, setIsLoadingSuggestions] = useState(false);
  const [showSuggestionList, setShowSuggestionList] = useState(false);
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);
  const [searchHistory, setSearchHistory] = useState<string[]>([]);
  const [recentQueries, setRecentQueries] = useState<string[]>([]);
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [searchFilters, setSearchFilters] = useState({
    documentType: '',
    dateRange: '',
    source: '',
    region: ''
  });

  const inputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<NodeJS.Timeout>();

  // Load search history from localStorage
  useEffect(() => {
    const savedHistory = localStorage.getItem('ai_search_history');
    if (savedHistory) {
      try {
        const history = JSON.parse(savedHistory);
        setSearchHistory(history.slice(0, 10)); // Keep last 10 searches
      } catch (error) {
        console.error('Error loading search history:', error);
      }
    }
  }, []);

  // Debounced suggestion loading
  const debouncedLoadSuggestions = useCallback((searchQuery: string) => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    debounceRef.current = setTimeout(() => {
      if (searchQuery.length >= 2 && enableAutoComplete) {
        loadSuggestions(searchQuery);
      } else {
        setSuggestions([]);
        setShowSuggestionList(false);
      }
    }, 300);
  }, [enableAutoComplete]);

  // Handle query input change
  const handleQueryChange = (value: string) => {
    setQuery(value);
    setSelectedSuggestionIndex(-1);
    
    if (onQueryChange) {
      onQueryChange(value);
    }

    if (showSuggestions) {
      debouncedLoadSuggestions(value);
    }
  };

  // Load AI-powered suggestions
  const loadSuggestions = async (searchQuery: string) => {
    if (!searchQuery.trim() || searchQuery.length < 2) {
      setSuggestions([]);
      return;
    }

    setIsLoadingSuggestions(true);
    setShowSuggestionList(true);

    try {
      // Generate suggestions based on query analysis
      const generatedSuggestions = await generateAISuggestions(searchQuery);
      
      // Add query expansion if enabled
      if (showQueryExpansion) {
        const expansion = await generateQueryExpansion(searchQuery);
        setQueryExpansion(expansion);
      }

      setSuggestions(generatedSuggestions.slice(0, maxSuggestions));
    } catch (error) {
      console.error('Error loading suggestions:', error);
      setSuggestions([]);
    } finally {
      setIsLoadingSuggestions(false);
    }
  };

  // Generate AI-powered suggestions
  const generateAISuggestions = async (searchQuery: string): Promise<SearchSuggestion[]> => {
    const suggestions: SearchSuggestion[] = [];

    try {
      // Entity-based suggestions
      const entitySuggestions = await generateEntitySuggestions(searchQuery);
      suggestions.push(...entitySuggestions);

      // Topic-based suggestions
      const topicSuggestions = generateTopicSuggestions(searchQuery);
      suggestions.push(...topicSuggestions);

      // Location-based suggestions
      const locationSuggestions = generateLocationSuggestions(searchQuery);
      suggestions.push(...locationSuggestions);

      // Date range suggestions
      const dateSuggestions = generateDateSuggestions(searchQuery);
      suggestions.push(...dateSuggestions);

      // Query refinement suggestions
      const refinementSuggestions = generateQueryRefinements(searchQuery);
      suggestions.push(...refinementSuggestions);

      // Sort by confidence and relevance
      return suggestions
        .sort((a, b) => b.confidence - a.confidence)
        .slice(0, maxSuggestions);

    } catch (error) {
      console.error('Error generating AI suggestions:', error);
      return [];
    }
  };

  // Generate entity-based suggestions
  const generateEntitySuggestions = async (query: string): Promise<SearchSuggestion[]> => {
    const suggestions: SearchSuggestion[] = [];
    
    // Check for known government entities
    const governmentEntities = [
      { name: 'ANTT', full: 'Agência Nacional de Transportes Terrestres', category: 'transport' },
      { name: 'ANTAQ', full: 'Agência Nacional de Transportes Aquaviários', category: 'transport' },
      { name: 'ANAC', full: 'Agência Nacional de Aviação Civil', category: 'transport' },
      { name: 'ANEEL', full: 'Agência Nacional de Energia Elétrica', category: 'energy' },
      { name: 'ANP', full: 'Agência Nacional do Petróleo', category: 'energy' },
      { name: 'IBAMA', full: 'Instituto Brasileiro do Meio Ambiente', category: 'environment' },
      { name: 'DNIT', full: 'Departamento Nacional de Infraestrutura', category: 'infrastructure' }
    ];

    const queryLower = query.toLowerCase();
    
    for (const entity of governmentEntities) {
      if (entity.name.toLowerCase().includes(queryLower) || 
          entity.full.toLowerCase().includes(queryLower) ||
          queryLower.includes(entity.name.toLowerCase())) {
        
        suggestions.push({
          text: `legislação ${entity.name}`,
          type: 'entity',
          confidence: 0.9,
          description: `Documentos relacionados à ${entity.full}`,
          category: entity.category
        });

        suggestions.push({
          text: `regulamentação ${entity.full}`,
          type: 'entity',
          confidence: 0.8,
          description: `Regulamentações da ${entity.full}`,
          category: entity.category
        });
      }
    }

    return suggestions;
  };

  // Generate topic-based suggestions
  const generateTopicSuggestions = (query: string): SearchSuggestion[] => {
    const suggestions: SearchSuggestion[] = [];
    const queryLower = query.toLowerCase();

    const topicMap = {
      'transporte': [
        'transporte público',
        'transporte urbano',
        'transporte de cargas',
        'transporte ferroviário',
        'transporte aquaviário',
        'transporte aéreo'
      ],
      'meio ambiente': [
        'licenciamento ambiental',
        'impacto ambiental',
        'sustentabilidade',
        'emissões',
        'preservação ambiental'
      ],
      'energia': [
        'energia elétrica',
        'energia renovável',
        'petróleo e gás',
        'eficiência energética',
        'matriz energética'
      ],
      'infraestrutura': [
        'rodovias',
        'ferrovias',
        'portos',
        'aeroportos',
        'obras públicas'
      ]
    };

    for (const [topic, subtopics] of Object.entries(topicMap)) {
      if (queryLower.includes(topic)) {
        subtopics.forEach(subtopic => {
          suggestions.push({
            text: `${subtopic} legislação`,
            type: 'topic',
            confidence: 0.7,
            description: `Legislação sobre ${subtopic}`,
            category: topic
          });
        });
      }
    }

    return suggestions;
  };

  // Generate location-based suggestions
  const generateLocationSuggestions = (query: string): SearchSuggestion[] => {
    const suggestions: SearchSuggestion[] = [];
    const queryLower = query.toLowerCase();

    const brazilianStates = [
      'São Paulo', 'Rio de Janeiro', 'Minas Gerais', 'Bahia', 'Paraná',
      'Rio Grande do Sul', 'Pernambuco', 'Ceará', 'Pará', 'Santa Catarina'
    ];

    const brazilianCities = [
      'São Paulo', 'Rio de Janeiro', 'Brasília', 'Salvador', 'Fortaleza',
      'Belo Horizonte', 'Manaus', 'Curitiba', 'Recife', 'Porto Alegre'
    ];

    [...brazilianStates, ...brazilianCities].forEach(location => {
      if (location.toLowerCase().includes(queryLower) || 
          queryLower.includes(location.toLowerCase())) {
        
        suggestions.push({
          text: `legislação ${location}`,
          type: 'location',
          confidence: 0.8,
          description: `Documentos relacionados a ${location}`,
          category: 'geographic'
        });
      }
    });

    return suggestions;
  };

  // Generate date-based suggestions
  const generateDateSuggestions = (query: string): SearchSuggestion[] => {
    const suggestions: SearchSuggestion[] = [];
    const currentYear = new Date().getFullYear();
    
    const datePatterns = [
      { pattern: /202[0-4]/, type: 'year' },
      { pattern: /\b(último|última|recent|nova|novo)\b/i, type: 'recent' },
      { pattern: /\b(antiga|antigo|anterior|passado)\b/i, type: 'historical' }
    ];

    for (const { pattern, type } of datePatterns) {
      if (pattern.test(query)) {
        switch (type) {
          case 'recent':
            suggestions.push({
              text: `${query} últimos 12 meses`,
              type: 'date_range',
              confidence: 0.7,
              description: 'Documentos dos últimos 12 meses',
              category: 'temporal'
            });
            break;
          case 'historical':
            suggestions.push({
              text: `${query} antes de ${currentYear - 2}`,
              type: 'date_range',
              confidence: 0.6,
              description: `Documentos anteriores a ${currentYear - 2}`,
              category: 'temporal'
            });
            break;
        }
      }
    }

    return suggestions;
  };

  // Generate query refinement suggestions
  const generateQueryRefinements = (query: string): SearchSuggestion[] => {
    const suggestions: SearchSuggestion[] = [];
    
    const refinementPrefixes = [
      { prefix: 'regulamentação', description: 'Foco em aspectos regulatórios' },
      { prefix: 'normas', description: 'Normas e padrões técnicos' },
      { prefix: 'fiscalização', description: 'Aspectos de fiscalização e controle' },
      { prefix: 'licenciamento', description: 'Processos de licenciamento' },
      { prefix: 'política pública', description: 'Políticas públicas relacionadas' }
    ];

    refinementPrefixes.forEach(({ prefix, description }) => {
      suggestions.push({
        text: `${prefix} ${query}`,
        type: 'query',
        confidence: 0.6,
        description,
        category: 'refinement'
      });
    });

    return suggestions;
  };

  // Generate query expansion
  const generateQueryExpansion = async (query: string): Promise<QueryExpansion> => {
    // Simplified query expansion - in production would use AI/NLP services
    const expansion: QueryExpansion = {
      originalQuery: query,
      expandedTerms: [],
      relatedConcepts: [],
      synonyms: [],
      contextualTerms: [],
      confidence: 0.7
    };

    // Basic synonym mapping
    const synonymMap: Record<string, string[]> = {
      'transporte': ['mobilidade', 'locomoção', 'tráfego', 'circulação'],
      'meio ambiente': ['ambiental', 'ecologia', 'sustentabilidade', 'preservação'],
      'energia': ['energético', 'elétrico', 'combustível', 'matriz energética'],
      'rodovia': ['estrada', 'via', 'auto-estrada', 'BR'],
      'regulamentação': ['norma', 'regra', 'disposição', 'ordenamento']
    };

    const queryLower = query.toLowerCase();
    
    Object.entries(synonymMap).forEach(([term, synonyms]) => {
      if (queryLower.includes(term)) {
        expansion.synonyms.push(...synonyms);
        expansion.expandedTerms.push(...synonyms.map(syn => query.replace(new RegExp(term, 'gi'), syn)));
      }
    });

    // Add contextual terms based on domain knowledge
    if (queryLower.includes('transporte')) {
      expansion.contextualTerms.push('ANTT', 'ANTAQ', 'ANAC', 'modal', 'infraestrutura');
    }
    
    if (queryLower.includes('ambiente')) {
      expansion.contextualTerms.push('IBAMA', 'licenciamento', 'EIA', 'RIMA', 'impacto');
    }

    return expansion;
  };

  // Handle search execution
  const handleSearch = async (searchQuery: string = query) => {
    if (!searchQuery.trim()) return;

    setIsSearching(true);
    setShowSuggestionList(false);

    try {
      // Save to search history
      const newHistory = [searchQuery, ...searchHistory.filter(h => h !== searchQuery)].slice(0, 10);
      setSearchHistory(newHistory);
      localStorage.setItem('ai_search_history', JSON.stringify(newHistory));

      // Build expanded query
      let expandedQuery = searchQuery;
      if (queryExpansion && queryExpansion.synonyms.length > 0) {
        expandedQuery = `${searchQuery} ${queryExpansion.synonyms.slice(0, 3).join(' ')}`;
      }

      // Execute search with LexML service
      const results = await lexmlService.searchDocuments({
        query: expandedQuery,
        maximumRecords: 50,
        startRecord: 1
      });

      // Transform results to our format
      const transformedResults: SearchResult[] = results.documents.map((doc, index) => ({
        id: doc.id || `result_${index}`,
        title: doc.title || 'Documento sem título',
        summary: doc.summary || '',
        relevanceScore: 1 - (index / results.documents.length), // Simple relevance scoring
        source: doc.fonte || 'LexML',
        date: doc.data_evento || doc.data_publicacao || '',
        documentType: doc.tipo_documento || 'Documento',
        url: doc.url,
        metadata: doc
      }));

      setSearchResults(transformedResults);
      
      if (onSearchResults) {
        onSearchResults(transformedResults);
      }

    } catch (error) {
      console.error('Search failed:', error);
      setSearchResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  // Handle suggestion selection
  const handleSuggestionSelect = (suggestion: SearchSuggestion) => {
    setQuery(suggestion.text);
    setShowSuggestionList(false);
    handleSearch(suggestion.text);
  };

  // Handle keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!showSuggestionList || suggestions.length === 0) {
      if (e.key === 'Enter') {
        handleSearch();
      }
      return;
    }

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedSuggestionIndex(prev => 
          prev < suggestions.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedSuggestionIndex(prev => 
          prev > 0 ? prev - 1 : suggestions.length - 1
        );
        break;
      case 'Enter':
        e.preventDefault();
        if (selectedSuggestionIndex >= 0) {
          handleSuggestionSelect(suggestions[selectedSuggestionIndex]);
        } else {
          handleSearch();
        }
        break;
      case 'Escape':
        setShowSuggestionList(false);
        setSelectedSuggestionIndex(-1);
        break;
    }
  };

  // Handle click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (suggestionsRef.current && !suggestionsRef.current.contains(event.target as Node) &&
          inputRef.current && !inputRef.current.contains(event.target as Node)) {
        setShowSuggestionList(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className={`ai-search-interface ${className}`}>
      <GlassCard variant="research" className="mb-4">
        <div className="relative">
          {/* Main Search Input */}
          <div className="relative">
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => handleQueryChange(e.target.value)}
              onKeyDown={handleKeyDown}
              onFocus={() => {
                if (suggestions.length > 0) {
                  setShowSuggestionList(true);
                }
              }}
              placeholder={placeholder}
              className="glass-input pr-24 text-lg"
              disabled={isSearching}
            />
            
            {/* Search Button */}
            <button
              onClick={() => handleSearch()}
              disabled={isSearching || !query.trim()}
              className="absolute right-2 top-1/2 transform -translate-y-1/2 glass-button-primary px-4 py-2"
            >
              {isSearching ? (
                <span className="flex items-center">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Buscando
                </span>
              ) : (
                '🔍 Buscar'
              )}
            </button>
          </div>

          {/* Loading indicator for suggestions */}
          {isLoadingSuggestions && (
            <div className="absolute right-28 top-1/2 transform -translate-y-1/2">
              <svg className="animate-spin h-4 w-4 text-blue-600" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            </div>
          )}

          {/* Suggestions Dropdown */}
          {showSuggestionList && suggestions.length > 0 && (
            <div
              ref={suggestionsRef}
              className="absolute top-full left-0 right-0 mt-2 glass-card z-50 max-h-80 overflow-y-auto"
            >
              <div className="p-2">
                <div className="text-xs font-semibold text-gray-600 mb-2 px-2">
                  Sugestões de IA
                </div>
                {suggestions.map((suggestion, index) => (
                  <div
                    key={index}
                    onClick={() => handleSuggestionSelect(suggestion)}
                    className={`
                      px-3 py-2 rounded cursor-pointer transition-colors
                      ${index === selectedSuggestionIndex 
                        ? 'bg-blue-100 text-blue-800' 
                        : 'hover:bg-gray-50'
                      }
                    `}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="font-medium text-sm">{suggestion.text}</div>
                        {suggestion.description && (
                          <div className="text-xs text-gray-600 mt-1">
                            {suggestion.description}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 ml-2">
                        {suggestion.category && (
                          <span className="glass-badge text-xs">
                            {suggestion.category}
                          </span>
                        )}
                        <span className={`
                          px-2 py-1 rounded-full text-xs font-medium
                          ${suggestion.type === 'entity' ? 'bg-blue-100 text-blue-700' :
                            suggestion.type === 'topic' ? 'bg-green-100 text-green-700' :
                            suggestion.type === 'location' ? 'bg-purple-100 text-purple-700' :
                            suggestion.type === 'date_range' ? 'bg-orange-100 text-orange-700' :
                            'bg-gray-100 text-gray-700'
                          }
                        `}>
                          {suggestion.type}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Advanced Options Toggle */}
        <div className="flex justify-between items-center mt-4">
          <button
            onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
            className="text-sm text-blue-600 hover:text-blue-800"
          >
            {showAdvancedOptions ? '🔽' : '🔼'} Opções Avançadas
          </button>

          {/* Quick Actions */}
          <div className="flex gap-2">
            {searchHistory.length > 0 && (
              <select
                onChange={(e) => {
                  if (e.target.value) {
                    setQuery(e.target.value);
                    handleSearch(e.target.value);
                  }
                }}
                value=""
                className="text-sm glass-input py-1"
              >
                <option value="">Histórico</option>
                {searchHistory.map((historyQuery, index) => (
                  <option key={index} value={historyQuery}>
                    {historyQuery.length > 30 ? historyQuery.substring(0, 30) + '...' : historyQuery}
                  </option>
                ))}
              </select>
            )}
          </div>
        </div>

        {/* Advanced Search Options */}
        {showAdvancedOptions && (
          <div className="mt-4 p-4 bg-gray-50 rounded-lg border">
            <h4 className="font-semibold mb-3">Filtros de Pesquisa</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Tipo de Documento
                </label>
                <select
                  value={searchFilters.documentType}
                  onChange={(e) => setSearchFilters(prev => ({...prev, documentType: e.target.value}))}
                  className="glass-input text-sm"
                >
                  <option value="">Todos</option>
                  <option value="lei">Lei</option>
                  <option value="decreto">Decreto</option>
                  <option value="portaria">Portaria</option>
                  <option value="resolucao">Resolução</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Período
                </label>
                <select
                  value={searchFilters.dateRange}
                  onChange={(e) => setSearchFilters(prev => ({...prev, dateRange: e.target.value}))}
                  className="glass-input text-sm"
                >
                  <option value="">Qualquer período</option>
                  <option value="last_year">Último ano</option>
                  <option value="last_5_years">Últimos 5 anos</option>
                  <option value="last_10_years">Últimos 10 anos</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Fonte
                </label>
                <select
                  value={searchFilters.source}
                  onChange={(e) => setSearchFilters(prev => ({...prev, source: e.target.value}))}
                  className="glass-input text-sm"
                >
                  <option value="">Todas as fontes</option>
                  <option value="federal">Federal</option>
                  <option value="estadual">Estadual</option>
                  <option value="municipal">Municipal</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Região
                </label>
                <select
                  value={searchFilters.region}
                  onChange={(e) => setSearchFilters(prev => ({...prev, region: e.target.value}))}
                  className="glass-input text-sm"
                >
                  <option value="">Todo o Brasil</option>
                  <option value="norte">Norte</option>
                  <option value="nordeste">Nordeste</option>
                  <option value="centro-oeste">Centro-Oeste</option>
                  <option value="sudeste">Sudeste</option>
                  <option value="sul">Sul</option>
                </select>
              </div>
            </div>
          </div>
        )}

        {/* Query Expansion Display */}
        {showQueryExpansion && queryExpansion && (
          <div className="mt-4 p-3 bg-blue-50 rounded-lg border border-blue-200">
            <h4 className="font-semibold text-blue-800 mb-2">Expansão da Consulta</h4>
            <div className="space-y-2 text-sm">
              {queryExpansion.synonyms.length > 0 && (
                <div>
                  <span className="font-medium text-blue-700">Sinônimos:</span>
                  <span className="ml-2 text-blue-600">
                    {queryExpansion.synonyms.slice(0, 5).join(', ')}
                  </span>
                </div>
              )}
              {queryExpansion.contextualTerms.length > 0 && (
                <div>
                  <span className="font-medium text-blue-700">Termos relacionados:</span>
                  <span className="ml-2 text-blue-600">
                    {queryExpansion.contextualTerms.slice(0, 5).join(', ')}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}
      </GlassCard>

      {/* Search Results Count */}
      {searchResults.length > 0 && (
        <div className="mb-4 text-sm text-gray-600">
          Encontrados {searchResults.length} resultado{searchResults.length !== 1 ? 's' : ''}
          {query && ` para "${query}"`}
        </div>
      )}
    </div>
  );
};

export default AISearchInterface;