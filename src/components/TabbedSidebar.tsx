import React, { useState } from 'react';
import { SearchFilters, LegislativeDocument } from '../types';
import { DataVisualization } from './DataVisualization';
import { EnhancedSearch } from './EnhancedSearch';
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

type TabType = 'search' | 'analytics';

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
        !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase())) {
      return false;
    }
    
    if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
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
          {isOpen ? '◀' : '▶'}
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
              🔍 Search & Filters
            </button>
            <button
              className={`tab-button ${activeTab === 'analytics' ? 'active' : ''}`}
              onClick={() => setActiveTab('analytics')}
              aria-selected={activeTab === 'analytics'}
            >
              📊 Analytics
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

                {/* Document List */}
                <div className="document-list">
                  {filteredDocuments.slice(0, 10).map(doc => (
                    <div key={doc.id} className="document-item">
                      <h4>{doc.title}</h4>
                      <p className="document-type">{doc.type}</p>
                      <p className="document-date">
                        {typeof doc.date === 'string' ? new Date(doc.date).toLocaleDateString() : doc.date.toLocaleDateString()}
                      </p>
                      {doc.state && (
                        <p className="document-location">Estado: {doc.state}</p>
                      )}
                    </div>
                  ))}
                  {filteredDocuments.length > 10 && (
                    <p className="more-results">
                      +{filteredDocuments.length - 10} documentos adicionais
                    </p>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'analytics' && (
              <div className="analytics-tab">
                <DataVisualization documents={filteredDocuments} />
              </div>
            )}
          </div>
        </>
      )}
    </aside>
  );
};