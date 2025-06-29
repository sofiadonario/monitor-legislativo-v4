import React, { Suspense, lazy, useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { useKeyboardNavigation } from '../hooks/useKeyboardNavigation';
import { legislativeDataService } from '../services/legislativeDataService';
import '../styles/accessibility.css';
import '../styles/components/Dashboard.css';
import { LegislativeDocument, SearchFilters } from '../types';
import { LoadingSpinner } from './LoadingSpinner';
import { SkeletonLoader, SkeletonDocumentList, SkeletonMapLoading, SkeletonChart } from './common/SkeletonLoader';
import { Files, MapTrifold, Flask, Gear, ChartBar } from '@phosphor-icons/react';

// Lazy load heavy components
const OptimizedMap = lazy(() => import('./OptimizedMap').then(module => ({ default: module.default })));
const TabbedSidebar = lazy(() => import('./TabbedSidebar').then(module => ({ default: module.default })));
const ExportPanel = lazy(() => import('./ExportPanel').then(module => ({ default: module.default })));
const CollectionStatus = lazy(() => import('./CollectionStatus').then(module => ({ default: module.CollectionStatus })));
const AnalyticsPage = lazy(() => import('../pages/AnalyticsPage').then(module => ({ default: module.default })));
const CacheMonitor = lazy(() => import('./CacheMonitor').then(module => ({ default: module.default })));

type ViewMode = 'dashboard' | 'analytics' | 'admin';

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
            {isLoading ? (
              <div className="stats" aria-live="polite">
                <span className="stat-item"><SkeletonLoader variant="text" width="80px" /></span>
                <span className="stat-item"><SkeletonLoader variant="text" width="80px" /></span>
              </div>
            ) : (
              <div className="stats" aria-live="polite">
                <span className="stat-item"><Files size={16} weight="fill" /> {filteredDocuments.length} Docs</span>
                <span className="stat-item"><MapTrifold size={16} weight="fill" /> {highlightedStates.length} States</span>
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
                <MapTrifold size={16} weight="fill" /> Map
              </button>
              <button 
                className={`view-mode-btn ${viewMode === 'analytics' ? 'active' : ''}`}
                onClick={() => setViewMode('analytics')}
                aria-pressed={viewMode === 'analytics'}
              >
                <Flask size={16} weight="fill" /> R Analytics
              </button>
              <button 
                className={`view-mode-btn ${viewMode === 'admin' ? 'active' : ''}`}
                onClick={() => setViewMode('admin')}
                aria-pressed={viewMode === 'admin'}
              >
                <Gear size={16} weight="fill" /> Admin
              </button>
            </div>
            <button className="export-btn" onClick={toggleExportPanel} aria-controls="export-panel" aria-expanded={exportPanelOpen}>
              <ChartBar size={16} weight="fill" /> Export
            </button>
          </div>
        </header>


        {error && !isLoading && (
          <div className="dashboard-error" role="alert">
            <h2>Error Loading Data</h2>
            <p>{error}</p>
            <button onClick={() => window.location.reload()}>Try Again</button>
          </div>
        )}

        {viewMode === 'dashboard' && (
          <section className="map-wrapper" aria-labelledby="map-heading">
            <h2 id="map-heading" className="sr-only">Interactive map</h2>
            <Suspense fallback={<SkeletonMapLoading />}>
              <OptimizedMap
                selectedState={selectedState}
                selectedMunicipality={selectedMunicipality}
                documents={filteredDocuments}
                onLocationClick={handleLocationClick}
                highlightedLocations={highlightedStates}
              />
            </Suspense>
          </section>
        )}

        {viewMode === 'analytics' && (
          <section className="analytics-wrapper" aria-labelledby="analytics-heading">
            <h2 id="analytics-heading" className="sr-only">R Shiny Analytics</h2>
            <Suspense fallback={<div className="analytics-skeleton"><SkeletonChart /><SkeletonChart /><SkeletonChart /></div>}>
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

        {viewMode === 'admin' && (
          <section className="admin-wrapper" aria-labelledby="admin-heading">
            <h2 id="admin-heading" className="sr-only">Administrative Dashboard</h2>
            <div className="admin-content">
              <div className="admin-section">
                <h3>System Performance & Cache Monitoring</h3>
                <Suspense fallback={<LoadingSpinner message="Loading cache monitor..." />}>
                  <CacheMonitor showDetailedView={true} className="admin-cache-monitor" />
                </Suspense>
              </div>
              
              <div className="admin-section">
                <h3>Collection Status & Data Sources</h3>
                <Suspense fallback={<LoadingSpinner message="Loading collection status..." />}>
                  <CollectionStatus compact={false} className="admin-collection-status" />
                </Suspense>
              </div>
              
              <div className="admin-section">
                <h3>System Information</h3>
                <div className="system-info">
                  <div className="info-card">
                    <h4>Data Summary</h4>
                    <p><strong>Total Documents:</strong> {documents.length}</p>
                    <p><strong>Filtered Documents:</strong> {filteredDocuments.length}</p>
                    <p><strong>Using Fallback:</strong> {usingFallbackData ? 'Yes' : 'No'}</p>
                    <p><strong>Active States:</strong> {highlightedStates.length}</p>
                  </div>
                  
                  <div className="info-card">
                    <h4>Search Filters</h4>
                    <p><strong>Search Term:</strong> {filters.searchTerm || 'None'}</p>
                    <p><strong>Document Types:</strong> {filters.documentTypes.length || 'All'}</p>
                    <p><strong>Selected States:</strong> {filters.states.length || 'All'}</p>
                    <p><strong>Date Range:</strong> {filters.dateFrom || filters.dateTo ? 'Active' : 'None'}</p>
                  </div>
                  
                  <div className="info-card">
                    <h4>Performance</h4>
                    <p><strong>Loading:</strong> {isLoading ? 'Yes' : 'No'}</p>
                    <p><strong>Error State:</strong> {error ? 'Yes' : 'No'}</p>
                    <p><strong>Sidebar Open:</strong> {sidebarOpen ? 'Yes' : 'No'}</p>
                    <p><strong>Export Panel:</strong> {exportPanelOpen ? 'Open' : 'Closed'}</p>
                  </div>
                </div>
              </div>
            </div>
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