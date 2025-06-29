import React, { useState } from 'react';
import { SearchFilters, LegislativeDocument } from '../types';
import { DataVisualization } from './DataVisualization';
import { EnhancedSearch } from './EnhancedSearch';
import { MagnifyingGlass, ChartBar, FlaskConical, CaretLeft, CaretRight } from '@phosphor-icons/react';
import '../styles/components/TabbedSidebar.css';

interface TabbedSidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  documents: LegislativeDocument[];
  selectedState?: string;
  onClearSelection: () => void;
}

type TabType = 'search' | 'analytics' | 'rshiny';

export const TabbedSidebar: React.FC<TabbedSidebarProps> = ({
  isOpen,
  onToggle,
  filters,
  onFiltersChange,
  documents,
  selectedState,
  onClearSelection
}) => {
  const [activeTab, setActiveTab] = useState<TabType>('search');


  const filteredDocuments = documents.filter(doc => {
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
    
    return true;
  });

  return (
    <aside 
      className={`tabbed-sidebar ${isOpen ? 'open' : 'closed'}`}
      role="complementary"
      aria-labelledby="sidebar-title"
    >
      <div className="sidebar-header">
        <h2 id="sidebar-title">Monitor Legislativo</h2>
        <button
          className="sidebar-toggle"
          onClick={onToggle}
          aria-label={isOpen ? 'Fechar painel lateral' : 'Abrir painel lateral'}
          aria-expanded={isOpen}
        >
          {isOpen ? <CaretLeft size={16} weight="bold" /> : <CaretRight size={16} weight="bold" />}
        </button>
      </div>

      {isOpen && (
        <>
          <div className="sidebar-tabs">
            <button
              className={`tab-button ${activeTab === 'search' ? 'active' : ''}`}
              onClick={() => setActiveTab('search')}
              aria-selected={activeTab === 'search'}
            >
              <MagnifyingGlass size={16} weight="fill" /> Search & Filters
            </button>
            <button
              className={`tab-button ${activeTab === 'analytics' ? 'active' : ''}`}
              onClick={() => setActiveTab('analytics')}
              aria-selected={activeTab === 'analytics'}
            >
              <ChartBar size={16} weight="fill" /> Analytics
            </button>
            <button
              className={`tab-button ${activeTab === 'rshiny' ? 'active' : ''}`}
              onClick={() => setActiveTab('rshiny')}
              aria-selected={activeTab === 'rshiny'}
            >
              <FlaskConical size={16} weight="fill" /> R Analytics
            </button>
          </div>

          <div className="sidebar-content">
            {activeTab === 'search' && (
              <div className="search-tab">
                <EnhancedSearch
                  filters={filters}
                  onFiltersChange={onFiltersChange}
                  documents={documents}
                  selectedState={selectedState}
                  onClearSelection={onClearSelection}
                />
                
                {/* Results Summary */}
                <div className="results-summary">
                  <h3>Resultados</h3>
                  <p>{filteredDocuments.length} documentos encontrados</p>
                </div>

                {/* Document List - Show ALL matching documents */}
                <div className="document-list">
                  {filteredDocuments.map(doc => (
                    <div key={doc.id} className="document-item">
                      <h4>{doc.title}</h4>
                      <p className="document-type">{doc.type}</p>
                      {doc.chamber && (
                        <p className="document-chamber">Origem: {doc.chamber}</p>
                      )}
                      <p className="document-date">
                        {typeof doc.date === 'string' ? new Date(doc.date).toLocaleDateString() : doc.date.toLocaleDateString()}
                      </p>
                      {doc.state && (
                        <p className="document-location">Estado: {doc.state}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'analytics' && (
              <div className="analytics-tab">
                <DataVisualization documents={filteredDocuments} />
              </div>
            )}

            {activeTab === 'rshiny' && (
              <div className="rshiny-tab">
                <div className="rshiny-info">
                  <h3>🔬 R Analytics Dashboard</h3>
                  <p>Advanced statistical analysis and visualizations powered by R Shiny.</p>
                  
                  <div className="rshiny-stats">
                    <div className="stat-item">
                      <span className="stat-value">{filteredDocuments.length}</span>
                      <span className="stat-label">Documents</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-value">{new Set(filteredDocuments.map(d => d.state)).size}</span>
                      <span className="stat-label">States</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-value">{new Set(filteredDocuments.map(d => d.type)).size}</span>
                      <span className="stat-label">Types</span>
                    </div>
                  </div>

                  <div className="rshiny-features">
                    <h4>Available Analyses:</h4>
                    <ul>
                      <li>📈 Statistical distributions</li>
                      <li>🗺️ Interactive geographic analysis</li>
                      <li>📊 Time series analysis</li>
                      <li>🔗 Network analysis</li>
                      <li>📋 Custom report generation</li>
                    </ul>
                  </div>

                  <div className="rshiny-note">
                    <p><strong>Note:</strong> The R Shiny application runs independently and provides advanced analytics capabilities beyond the standard dashboard visualizations.</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </aside>
  );
};

export default TabbedSidebar;