import React, { Suspense, lazy, useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { useKeyboardNavigation } from '../hooks/useKeyboardNavigation';
import { legislativeDataService } from '../services/legislativeDataService';
import '../styles/accessibility.css';
import '../styles/components/Dashboard.css';
import { ExportOptions, LegislativeDocument, SearchFilters } from '../types';
import { LoadingSpinner } from './LoadingSpinner';

// Lazy load heavy components
const OptimizedMap = lazy(() => import('./OptimizedMap').then(module => ({ default: module.OptimizedMap })));
const TabbedSidebar = lazy(() => import('./TabbedSidebar').then(module => ({ default: module.TabbedSidebar })));
const ExportPanel = lazy(() => import('./ExportPanel').then(module => ({ default: module.ExportPanel })));
const BudgetRealtimeStatus = lazy(() => import('./BudgetRealtimeStatus').then(module => ({ default: module.BudgetRealtimeStatus })));

// Dashboard state interface
interface DashboardState {
  sidebarOpen: boolean;
  exportPanelOpen: boolean;
  selectedState?: string;
  selectedMunicipality?: string;
  filters: SearchFilters;
}

// Dashboard actions
type DashboardAction =
  | { type: 'TOGGLE_SIDEBAR' }
  | { type: 'TOGGLE_EXPORT_PANEL' }
  | { type: 'SET_SIDEBAR_OPEN'; payload: boolean }
  | { type: 'SELECT_STATE'; payload: string }
  | { type: 'SELECT_MUNICIPALITY'; payload: string }
  | { type: 'CLEAR_SELECTION' }
  | { type: 'UPDATE_FILTERS'; payload: SearchFilters }
  | { type: 'CLOSE_EXPORT_PANEL' };

// Initial state
const initialState: DashboardState = {
  sidebarOpen: true,
  exportPanelOpen: false,
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
  }
};

// Reducer function
const dashboardReducer = (state: DashboardState, action: DashboardAction): DashboardState => {
  switch (action.type) {
    case 'TOGGLE_SIDEBAR':
      return { ...state, sidebarOpen: !state.sidebarOpen };
    case 'TOGGLE_EXPORT_PANEL':
      return { ...state, exportPanelOpen: !state.exportPanelOpen };
    case 'SET_SIDEBAR_OPEN':
      return { ...state, sidebarOpen: action.payload };
    case 'SELECT_STATE':
      return { 
        ...state, 
        selectedState: action.payload, 
        selectedMunicipality: undefined 
      };
    case 'SELECT_MUNICIPALITY':
      return { ...state, selectedMunicipality: action.payload };
    case 'CLEAR_SELECTION':
      return { 
        ...state, 
        selectedState: undefined, 
        selectedMunicipality: undefined 
      };
    case 'UPDATE_FILTERS':
      return { ...state, filters: action.payload };
    case 'CLOSE_EXPORT_PANEL':
      return { ...state, exportPanelOpen: false };
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
  
  const { sidebarOpen, exportPanelOpen, selectedState, selectedMunicipality, filters } = state;
  
  // Accessibility refs
  const mainContentRef = useRef<HTMLElement>(null);
  const skipLinkRef = useRef<HTMLAnchorElement>(null);
  
  // Keyboard navigation
  useKeyboardNavigation();
  
  // Load documents on mount and when filters change
  useEffect(() => {
    const loadDocuments = async () => {
      setIsLoading(true);
      setError(null);
      
      try {
        const { documents: docs, usingFallback } = await legislativeDataService.fetchDocuments(filters);
        setDocuments(docs);
        setUsingFallbackData(usingFallback);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load documents');
        console.error('Error loading documents:', err);
      } finally {
        setIsLoading(false);
      }
    };
    
    loadDocuments();
  }, [filters]);

  // Handle responsive behavior
  useEffect(() => {
    const handleResize = () => {
      const shouldOpenSidebar = window.innerWidth >= 768;
      dispatch({ type: 'SET_SIDEBAR_OPEN', payload: shouldOpenSidebar });
    };

    handleResize(); // Check initial size
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const handleLocationClick = useCallback((type: 'state' | 'municipality', id: string) => {
    if (type === 'state') {
      dispatch({ type: 'SELECT_STATE', payload: id });
    } else {
      dispatch({ type: 'SELECT_MUNICIPALITY', payload: id });
    }
    
    // On mobile, close sidebar when selecting location
    if (window.innerWidth < 768) {
      dispatch({ type: 'SET_SIDEBAR_OPEN', payload: false });
    }
  }, []);

  const handleClearSelection = useCallback(() => {
    dispatch({ type: 'CLEAR_SELECTION' });
  }, []);

  const handleExport = useCallback((options: ExportOptions) => {
    // Export functionality will be implemented in ExportPanel
    console.log('Exporting with options:', options);
    dispatch({ type: 'CLOSE_EXPORT_PANEL' });
  }, []);

  const toggleSidebar = useCallback(() => {
    dispatch({ type: 'TOGGLE_SIDEBAR' });
    // Announce state change to screen readers
    const announcement = sidebarOpen ? 'Sidebar closed' : 'Sidebar opened';
    announceToScreenReader(announcement);
  }, [sidebarOpen]);

  const toggleExportPanel = useCallback(() => {
    dispatch({ type: 'TOGGLE_EXPORT_PANEL' });
    // Announce state change to screen readers
    const announcement = exportPanelOpen ? 'Export panel closed' : 'Export panel opened';
    announceToScreenReader(announcement);
  }, [exportPanelOpen]);
  
  // Helper function to announce changes to screen readers
  const announceToScreenReader = useCallback((message: string) => {
    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', 'polite');
    announcement.setAttribute('aria-atomic', 'true');
    announcement.className = 'sr-only';
    announcement.textContent = message;
    document.body.appendChild(announcement);
    setTimeout(() => document.body.removeChild(announcement), 1000);
  }, []);
  
  // Skip to main content handler
  const skipToMainContent = useCallback((event: React.KeyboardEvent) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      mainContentRef.current?.focus();
    }
  }, []);

  // Memoize filtered documents for performance
  const filteredDocuments = useMemo(() => {
    return documents.filter(doc => {
      if (filters.searchTerm && 
          !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) &&
          !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase()) &&
          !doc.keywords.some(keyword => keyword.toLowerCase().includes(filters.searchTerm.toLowerCase()))) {
        return false;
      }
      
      if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
        return false;
      }
      
      if (filters.chambers.length > 0 && doc.chamber && !filters.chambers.includes(doc.chamber)) {
        return false;
      }
      
      if (filters.dateFrom) {
        const docDate = typeof doc.date === 'string' ? new Date(doc.date) : doc.date;
        if (docDate < filters.dateFrom) return false;
      }
      
      if (filters.dateTo) {
        const docDate = typeof doc.date === 'string' ? new Date(doc.date) : doc.date;
        if (docDate > filters.dateTo) return false;
      }
      
      if (selectedState && doc.state !== selectedState) {
        return false;
      }
      
      if (selectedMunicipality && doc.municipality !== selectedMunicipality) {
        return false;
      }
      
      return true;
    });
  }, [documents, filters, selectedState, selectedMunicipality]);

  // Memoize highlighted locations for map
  const highlightedStates = useMemo(() => 
    [...new Set(filteredDocuments.map(doc => doc.state).filter(Boolean))],
    [filteredDocuments]
  );

  if (error) {
    return (
      <div className="dashboard-error" role="alert">
        <h2>Error Loading Data</h2>
        <p>{error}</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }
  
  const isDemoMode = import.meta.env.VITE_USE_MOCK_DATA === 'true';
  
  return (
    <div className="dashboard demo-mode">
      {usingFallbackData && (
        <div className="fallback-warning-banner" role="alert">
          <strong>Warning:</strong> Could not load the complete dataset. Displaying limited mock data. Please verify the CSV data file.
        </div>
      )}
      {/* Demo Mode Banner - Always present for layout stability */}
      <div className={`demo-banner ${isDemoMode ? 'show' : 'hide'}`} role="alert" aria-live="polite">
        <span className="demo-icon" aria-hidden="true">⚠️</span>
        <strong>RESEARCH MODE</strong> - Brazilian Transport Legislation Database
      </div>
      
      {/* Skip to main content link for keyboard navigation */}
      <a 
        ref={skipLinkRef}
        href="#main-content"
        className="skip-link sr-only"
        onKeyDown={skipToMainContent}
        onClick={(e) => {
          e.preventDefault();
          mainContentRef.current?.focus();
        }}
      >
        Skip to main content
      </a>
      
      {/* Live region for announcements */}
      <div aria-live="polite" aria-atomic="true" className="sr-only" id="announcements" />
      
      {/* Sidebar backdrop */}
      <div 
        className={`sidebar-backdrop ${sidebarOpen ? 'show' : ''}`}
        onClick={() => dispatch({ type: 'SET_SIDEBAR_OPEN', payload: false })}
        aria-hidden="true"
      />
      
      <Suspense fallback={<LoadingSpinner message="Loading sidebar..." />}>
        <TabbedSidebar
          isOpen={sidebarOpen}
          onToggle={toggleSidebar}
          filters={filters}
          onFiltersChange={(newFilters) => dispatch({ type: 'UPDATE_FILTERS', payload: newFilters })}
          documents={documents}
          selectedState={selectedState}
          onClearSelection={handleClearSelection}
        />
      </Suspense>
      
      <main 
        id="main-content"
        ref={mainContentRef}
        className="main-content"
        tabIndex={-1}
        role="main"
        aria-label="Main content area"
      >
        {/* Top toolbar */}
        <header className="toolbar" role="banner" style={{ gridArea: 'toolbar' }}>
          <div className="toolbar-left">
            <h1 id="page-title">Brazilian Transport Legislation Monitor</h1>
            <p className="subtitle" id="page-description">
              Academic research platform for transport legislation analysis
            </p>
          </div>
          
          {/* Real-time status */}
          <div className="toolbar-status">
            <Suspense fallback={null}>
              <BudgetRealtimeStatus />
            </Suspense>
          </div>
          
          {/* Export and stats */}
          <div className="toolbar-export">
            <div className="stats" role="status" aria-live="polite">
              {isLoading ? (
                <span className="stat-item">Loading...</span>
              ) : (
                <>
                  <span className="stat-item" aria-label={`${filteredDocuments.length} documents found`}>
                    <span aria-hidden="true">📄</span>
                    <span>{filteredDocuments.length} docs</span>
                  </span>
                  <span className="stat-item" aria-label={`${highlightedStates.length} states with documents`}>
                    <span aria-hidden="true">🗺️</span>
                    <span>{highlightedStates.length} estados</span>
                  </span>
                </>
              )}
            </div>
            
            <button 
              className="export-btn"
              onClick={toggleExportPanel}
              aria-label={`Export data ${exportPanelOpen ? '(panel currently open)' : ''}`}
              aria-expanded={exportPanelOpen}
              aria-controls="export-panel"
              type="button"
            >
              <span aria-hidden="true">📊</span>
              <span>Export</span>
            </button>
          </div>
        </header>
        
        {/* Map container */}
        <section 
          className="map-wrapper" 
          aria-labelledby="map-heading"
          role="region"
          style={{ gridArea: 'content' }}
        >
          <h2 id="map-heading" className="sr-only">
            Interactive map of Brazilian states with legislative documents
          </h2>
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
        
        {/* Info panel for selected location */}
        {(selectedState || selectedMunicipality) && (
          <aside 
            className="info-panel"
            role="complementary"
            aria-labelledby="location-info-heading"
            aria-live="polite"
            style={{ gridArea: 'info' }}
          >
            <div className="info-content">
              <h3 id="location-info-heading">
                {selectedState && !selectedMunicipality && `Estado: ${selectedState}`}
                {selectedMunicipality && `Município: ${selectedMunicipality}, ${selectedState}`}
              </h3>
              <p>
                {filteredDocuments.length} documentos encontrados nesta localização
              </p>
              <button 
                onClick={handleClearSelection} 
                className="close-info"
                aria-label="Clear location selection"
                type="button"
              >
                <span aria-hidden="true">✕</span>
                <span className="sr-only">Fechar</span>
              </button>
            </div>
          </aside>
        )}
      </main>
      
      {/* Export Panel */}
      {exportPanelOpen && (
        <Suspense fallback={<LoadingSpinner message="Loading export panel..." />}>
          <ExportPanel
            id="export-panel"
            isOpen={exportPanelOpen}
            onClose={toggleExportPanel}
            documents={filteredDocuments}
          />
        </Suspense>
      )}
    </div>
  );
};

export default Dashboard;