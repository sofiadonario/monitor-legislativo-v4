import React, { Suspense, lazy, useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { useKeyboardNavigation } from '../hooks/useKeyboardNavigation';
import { legislativeDataService } from '../services/legislativeDataService';
import '../styles/accessibility.css';
import '../styles/components/Dashboard.css';
import { LegislativeDocument, SearchFilters } from '../types';
import { LoadingSpinner } from './LoadingSpinner';

// Lazy load heavy components
const OptimizedMap = lazy(() => import('./OptimizedMap').then(module => ({ default: module.OptimizedMap })));
const TabbedSidebar = lazy(() => import('./TabbedSidebar').then(module => ({ default: module.TabbedSidebar })));
const ExportPanel = lazy(() => import('./ExportPanel').then(module => ({ default: module.ExportPanel })));
const CollectionStatus = lazy(() => import('./CollectionStatus').then(module => ({ default: module.CollectionStatus })));
const AnalyticsPage = lazy(() => import('../pages/AnalyticsPage').then(module => ({ default: module.default })));

type ViewMode = 'dashboard' | 'analytics';

// Dashboard state interface
interface DashboardState {
  sidebarOpen: boolean;
  exportPanelOpen: boolean;
  selectedState?: string;
  selectedMunicipality?: string;
  filters: SearchFilters;
  viewMode: ViewMode;
}

// Initial state
const initialState: DashboardState = {
  sidebarOpen: true,
  exportPanelOpen: false,
  selectedState: undefined,
  selectedMunicipality: undefined,
  viewMode: 'dashboard',
  filters: {
    searchTerm: '',
    documentTypes: [],
    states: [],
    municipalities: [],
    chambers: [],
    keywords: [],
    dateFrom: undefined,
    dateTo: undefined
  }
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
    case 'SELECT_STATE':
      return { ...state, selectedState: action.payload, selectedMunicipality: undefined };
    case 'SELECT_MUNICIPALITY':
      return { ...state, selectedMunicipality: action.payload };
    case 'CLEAR_SELECTION':
      return { ...state, selectedState: undefined, selectedMunicipality: undefined };
    case 'UPDATE_FILTERS':
      return { ...state, filters: action.payload };
    case 'SET_VIEW_MODE':
      return { ...state, viewMode: action.payload };
    default:
      return state;
  }
};

const DashboardV2: React.FC = () => {
  const [state, dispatch] = useReducer(dashboardReducer, initialState);
  const [documents, setDocuments] = useState<LegislativeDocument[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [usingFallbackData, setUsingFallbackData] = useState(false);
  const { sidebarOpen, exportPanelOpen, selectedState, selectedMunicipality, filters, viewMode } = state;

  const mainContentRef = useRef<HTMLElement>(null);
  useKeyboardNavigation();

  useEffect(() => {
    const loadDocuments = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const { documents: docs, usingFallback } = await legislativeDataService.fetchDocuments(filters);
        if (docs.length === 0 && usingFallback) {
          setError('Could not load from API or CSV. Please check data sources.');
        }
        setDocuments(docs);
        setUsingFallbackData(usingFallback);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred';
        setError(errorMessage);
        console.error('Error loading documents:', err);
      } finally {
        setIsLoading(false);
      }
    };
    loadDocuments();
  }, [filters]);

  const handleLocationClick = useCallback((type: 'state' | 'municipality', id: string) => {
    dispatch({ type: type === 'state' ? 'SELECT_STATE' : 'SELECT_MUNICIPALITY', payload: id });
  }, []);

  const handleClearSelection = useCallback(() => dispatch({ type: 'CLEAR_SELECTION' }), []);
  const onFiltersChange = useCallback((newFilters: SearchFilters) => dispatch({ type: 'UPDATE_FILTERS', payload: newFilters }), []);
  const toggleSidebar = useCallback(() => dispatch({ type: 'TOGGLE_SIDEBAR' }), []);
  const toggleExportPanel = useCallback(() => dispatch({ type: 'TOGGLE_EXPORT_PANEL' }), []);
  const setViewMode = useCallback((mode: ViewMode) => dispatch({ type: 'SET_VIEW_MODE', payload: mode }), []);

  const filteredDocuments = useMemo(() => {
    return documents.filter(doc => {
      if (selectedState && doc.state !== selectedState) return false;
      if (selectedMunicipality && doc.municipality !== selectedMunicipality) return false;
      return true;
    });
  }, [documents, selectedState, selectedMunicipality]);

  const highlightedStates = useMemo(() => 
    [...new Set(filteredDocuments.map(doc => doc.state).filter(Boolean as (value: string | undefined) => value is string))],
    [filteredDocuments]
  );

  return (
    <div className="dashboard">
      <Suspense fallback={<LoadingSpinner message="Loading sidebar..." />}>
        <TabbedSidebar
          isOpen={sidebarOpen}
          onToggle={toggleSidebar}
          filters={filters}
          onFiltersChange={onFiltersChange}
          documents={documents}
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
            <Suspense fallback={null}>
              <CollectionStatus compact={true} className="toolbar-collection-status" />
            </Suspense>
            <div className="view-mode-switcher">
              <button 
                className={`view-mode-btn ${viewMode === 'dashboard' ? 'active' : ''}`}
                onClick={() => setViewMode('dashboard')}
                aria-pressed={viewMode === 'dashboard'}
              >
                🗺️ Map
              </button>
              <button 
                className={`view-mode-btn ${viewMode === 'analytics' ? 'active' : ''}`}
                onClick={() => setViewMode('analytics')}
                aria-pressed={viewMode === 'analytics'}
              >
                🔬 R Analytics
              </button>
            </div>
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

        {viewMode === 'dashboard' ? (
          <section className="map-wrapper" aria-labelledby="map-heading">
            <h2 id="map-heading" className="sr-only">Interactive map</h2>
            <Suspense fallback={<LoadingSpinner message="Loading map..." />}>
              <OptimizedMap
                selectedState={selectedState}
                selectedMunicipality={selectedMunicipality}
                documents={filteredDocuments}
                onLocationClick={handleLocationClick}
                highlightedLocations={highlightedStates}
              />
            </Suspense>
          </section>
        ) : (
          <section className="analytics-wrapper" aria-labelledby="analytics-heading">
            <h2 id="analytics-heading" className="sr-only">R Shiny Analytics</h2>
            <Suspense fallback={<LoadingSpinner message="Loading R Analytics..." />}>
              <AnalyticsPage
                documents={filteredDocuments}
                filters={filters}
                selectedState={selectedState}
                selectedMunicipality={selectedMunicipality}
                onFiltersChange={onFiltersChange}
              />
            </Suspense>
          </section>
        )}

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
          documents={filteredDocuments}
        />
      </Suspense>
    </div>
  );
};

export default DashboardV2; 