import React, { Suspense, lazy, useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { legislativeDataService } from '../services/legislativeDataService';
import '../styles/components/Dashboard.css';
import '../styles/accessibility.css';
import { LegislativeDocument, SearchFilters } from '../types';
import { LoadingSpinner } from './LoadingSpinner';
import { useKeyboardNavigation } from '../hooks/useKeyboardNavigation';

// Lazy load heavy components
const OptimizedMap = lazy(() => import('./OptimizedMap'));
const TabbedSidebar = lazy(() => import('./TabbedSidebar'));
const ExportPanel = lazy(() => import('./ExportPanel'));
const AIResearchAssistant = lazy(() => import('./AIResearchAssistant'));
const DocumentValidationPanel = lazy(() => import('./DocumentValidationPanel'));

// Dashboard state interface
interface DashboardState {
  sidebarOpen: boolean;
  exportPanelOpen: boolean;
  aiAssistantOpen: boolean;
  validationPanelOpen: boolean;
  selectedState?: string;
  selectedMunicipality?: string;
  filters: SearchFilters;
  selectedDocuments: LegislativeDocument[];
}

// Initial state
const initialState: DashboardState = {
  sidebarOpen: true,
  exportPanelOpen: false,
  aiAssistantOpen: false,
  validationPanelOpen: false,
  selectedState: undefined,
  selectedMunicipality: undefined,
  filters: {
    searchTerm: '',
    documentTypes: [],
    states: [],
    municipalities: [],
    chambers: [],
    keywords: [],
    dateFrom: undefined,
    dateTo: undefined
  },
  selectedDocuments: []
};

// Reducer function
const dashboardReducer = (state: DashboardState, action: any): DashboardState => {
  switch (action.type) {
    case 'TOGGLE_SIDEBAR':
      return { ...state, sidebarOpen: !state.sidebarOpen };
    case 'SET_SIDEBAR_OPEN':
      return { ...state, sidebarOpen: action.payload };
    case 'TOGGLE_EXPORT_PANEL':
      return { ...state, exportPanelOpen: !state.exportPanelOpen };
    case 'TOGGLE_AI_ASSISTANT':
      return { ...state, aiAssistantOpen: !state.aiAssistantOpen };
    case 'TOGGLE_VALIDATION_PANEL':
      return { ...state, validationPanelOpen: !state.validationPanelOpen };
    case 'SELECT_STATE':
      return { ...state, selectedState: action.payload, selectedMunicipality: undefined };
    case 'SELECT_MUNICIPALITY':
      return { ...state, selectedMunicipality: action.payload };
    case 'CLEAR_SELECTION':
      return { ...state, selectedState: undefined, selectedMunicipality: undefined };
    case 'UPDATE_FILTERS':
      return { ...state, filters: action.payload };
    case 'SET_SELECTED_DOCUMENTS':
      return { ...state, selectedDocuments: action.payload };
    default:
      return state;
  }
};

const Dashboard: React.FC = () => {
  const [state, dispatch] = useReducer(dashboardReducer, initialState);
  const [documents, setDocuments] = useState<LegislativeDocument[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [usingFallbackData, setUsingFallbackData] = useState(false);
  const { sidebarOpen, exportPanelOpen, aiAssistantOpen, validationPanelOpen, selectedState, selectedMunicipality, filters, selectedDocuments } = state;

  const mainContentRef = useRef<HTMLElement>(null);
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  useKeyboardNavigation();

  useEffect(() => {
    const loadDocuments = async () => {
      // Cancel previous request if exists
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      // Clear existing debounce timer
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }

      // Set up new debounced request
      debounceTimeoutRef.current = setTimeout(async () => {
        console.log('🎯 API Request: Debounced search triggered', { searchTerm: filters.searchTerm });
        
        setIsLoading(true);
        setError(null);
        
        try {
          // Create new abort controller for this request
          abortControllerRef.current = new AbortController();
          
          const { documents: docs, usingFallback } = await legislativeDataService.fetchDocuments(filters);
          
          if (docs.length === 0 && usingFallback) {
            setError('Could not load from API or CSV. Please check data sources.');
          }
          setDocuments(docs);
          setUsingFallbackData(usingFallback);
          
          console.log('📊 Request completed', { documentsFound: docs.length, usingFallback });
        } catch (err) {
          // Don't show error if request was aborted (user typed more)
          if (err instanceof Error && err.name === 'AbortError') {
            console.log('⚡ Request cancelled - user continued typing');
            return;
          }
          
          const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred';
          setError(errorMessage);
          console.error('Error loading documents:', err);
        } finally {
          setIsLoading(false);
        }
      }, 500); // 500ms debounce delay
    };

    loadDocuments();

    // Cleanup function
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [filters]);

  const handleLocationClick = useCallback((type: 'state' | 'municipality', id: string) => {
    dispatch({ type: type === 'state' ? 'SELECT_STATE' : 'SELECT_MUNICIPALITY', payload: id });
  }, []);

  const handleClearSelection = useCallback(() => dispatch({ type: 'CLEAR_SELECTION' }), []);
  const onFiltersChange = useCallback((newFilters: SearchFilters) => dispatch({ type: 'UPDATE_FILTERS', payload: newFilters }), []);
  const toggleSidebar = useCallback(() => dispatch({ type: 'TOGGLE_SIDEBAR' }), []);
  const toggleExportPanel = useCallback(() => dispatch({ type: 'TOGGLE_EXPORT_PANEL' }), []);
  const toggleAIAssistant = useCallback(() => dispatch({ type: 'TOGGLE_AI_ASSISTANT' }), []);
  const toggleValidationPanel = useCallback(() => dispatch({ type: 'TOGGLE_VALIDATION_PANEL' }), []);

  const filteredDocuments = useMemo(() => {
    if (!documents || !Array.isArray(documents)) {
      return [];
    }
    return documents.filter(doc => {
      if (!doc) return false;
      if (selectedState && doc.state !== selectedState) return false;
      if (selectedMunicipality && doc.municipality !== selectedMunicipality) return false;
      return true;
    });
  }, [documents, selectedState, selectedMunicipality]);

  const highlightedStates = useMemo(() => {
    if (!filteredDocuments || !Array.isArray(filteredDocuments)) {
      return [];
    }
    return [...new Set(filteredDocuments
      .map(doc => doc?.state)
      .filter((state): state is string => Boolean(state))
    )];
  }, [filteredDocuments]);

  return (
    <div className="dashboard">
      <Suspense fallback={<LoadingSpinner message="Loading sidebar..." />}>
        <TabbedSidebar
          isOpen={sidebarOpen}
          onToggle={toggleSidebar}
          filters={filters}
          onFiltersChange={onFiltersChange}
          documents={documents || []}
          selectedState={selectedState}
          onClearSelection={handleClearSelection}
        />
      </Suspense>
      <main id="main-content" ref={mainContentRef} className="main-content" tabIndex={-1}>
        <header className="toolbar">
          <div className="toolbar-left">
            <h1>Brazilian Transport Legislation Monitor</h1>
            <p className="toolbar-subtitle">Academic research platform for transport legislation analysis</p>
          </div>
          <div className="toolbar-right">
            {isLoading ? <LoadingSpinner message="Loading..." /> : (
              <div className="stats" aria-live="polite">
                <span className="stat-item">📄 {filteredDocuments.length} Docs</span>
                <span className="stat-item">🗺️ {highlightedStates.length} States</span>
              </div>
            )}
            <button className="ai-btn" onClick={toggleAIAssistant} aria-controls="ai-assistant" aria-expanded={aiAssistantOpen}>
              🤖 AI Assistant
            </button>
            <button className="validation-btn" onClick={toggleValidationPanel} aria-controls="validation-panel" aria-expanded={validationPanelOpen}>
              🛡️ Validate
            </button>
            <button className="export-btn" onClick={toggleExportPanel} aria-controls="export-panel" aria-expanded={exportPanelOpen}>
              📊 Export
            </button>
          </div>
        </header>

        {usingFallbackData && (
          <div className="fallback-warning-banner" role="alert">
            <strong>Warning:</strong> Using local CSV data. API connection may have failed.
          </div>
        )}

        {error && !isLoading && (
          <div className="dashboard-error" role="alert">
            <h2>Error Loading Data</h2>
            <p>{error}</p>
            <button onClick={() => window.location.reload()}>Try Again</button>
          </div>
        )}

        <section className="map-wrapper" aria-labelledby="map-heading">
          <h2 id="map-heading" className="sr-only">Interactive map</h2>
          <Suspense fallback={<LoadingSpinner message="Loading map..." />}>
            <OptimizedMap
              selectedState={selectedState}
              selectedMunicipality={selectedMunicipality}
              documents={filteredDocuments || []}
              onLocationClick={handleLocationClick}
              highlightedLocations={highlightedStates || []}
            />
          </Suspense>
        </section>

        {(selectedState || selectedMunicipality) && (
          <aside className="info-panel" role="complementary" aria-labelledby="location-info-heading">
            <div className="info-content">
              <h3 id="location-info-heading">
                {selectedState && !selectedMunicipality && `State: ${selectedState}`}
                {selectedMunicipality && `Municipality: ${selectedMunicipality}, ${selectedState}`}
              </h3>
              <p>{filteredDocuments.length} documents found.</p>
              <button onClick={handleClearSelection} className="close-info" aria-label="Clear selection">
                ✕
              </button>
            </div>
          </aside>
        )}
      </main>
      <Suspense fallback={<LoadingSpinner message="Loading export panel..." />}>
        <ExportPanel
          id="export-panel"
          isOpen={exportPanelOpen}
          onClose={toggleExportPanel}
          documents={filteredDocuments || []}
        />
      </Suspense>
      {aiAssistantOpen && (
        <Suspense fallback={<LoadingSpinner message="Loading AI assistant..." />}>
          <AIResearchAssistant
            selectedDocuments={selectedDocuments}
            onDocumentAnalyzed={(analysis) => console.log('Document analyzed:', analysis)}
            className="ai-assistant-panel"
          />
        </Suspense>
      )}
      {validationPanelOpen && (
        <Suspense fallback={<LoadingSpinner message="Loading validation panel..." />}>
          <DocumentValidationPanel
            documents={selectedDocuments}
            onValidationComplete={(results) => console.log('Validation complete:', results)}
            className="validation-panel"
          />
        </Suspense>
      )}
    </div>
  );
};

export default Dashboard;