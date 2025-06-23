import React from 'react';
import { documentTypes } from '../data/document-types';
import { LegislativeDocument, SearchFilters } from '../types';
import '../styles/components/Sidebar.css';

interface SidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  documents: LegislativeDocument[];
  selectedState?: string;
  onClearSelection: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({
  isOpen,
  onToggle,
  filters,
  onFiltersChange,
  documents,
  selectedState,
  onClearSelection
}) => {
  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFiltersChange({
      ...filters,
      searchTerm: e.target.value
    });
  };

  const handleDateFromChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFiltersChange({
      ...filters,
      dateFrom: e.target.value
    });
  };

  const handleDateToChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFiltersChange({
      ...filters,
      dateTo: e.target.value
    });
  };

  const handleDocumentTypeChange = (type: string, checked: boolean) => {
    const newTypes = checked 
      ? [...filters.documentTypes, type]
      : filters.documentTypes.filter(t => t !== type);
    
    onFiltersChange({
      ...filters,
      documentTypes: newTypes
    });
  };

  const filteredDocuments = documents.filter(doc => {
    if (filters.searchTerm && !doc.title.toLowerCase().includes(filters.searchTerm.toLowerCase()) &&
        !doc.summary.toLowerCase().includes(filters.searchTerm.toLowerCase())) {
      return false;
    }
    
    if (filters.documentTypes.length > 0 && !filters.documentTypes.includes(doc.type)) {
      return false;
    }
    
    if (filters.dateFrom && doc.date < filters.dateFrom) {
      return false;
    }
    
    if (filters.dateTo && doc.date > filters.dateTo) {
      return false;
    }
    
    if (selectedState && doc.state !== selectedState) {
      return false;
    }
    
    return true;
  });

  return (
    <>
      <div className={`sidebar ${isOpen ? 'open' : 'closed'}`}>
        <div className="sidebar-header">
          <h2>Mapa Legislativo Acadêmico</h2>
          <button className="toggle-btn" onClick={onToggle} aria-label="Toggle sidebar">
            {isOpen ? '←' : '→'}
          </button>
        </div>
        
        {isOpen && (
          <div className="sidebar-content">
            {/* Search Section */}
            <div className="search-section">
              <h3>Busca</h3>
              <div className="search-container">
                <input
                  type="text"
                  placeholder="Buscar por título ou resumo..."
                  value={filters.searchTerm}
                  onChange={handleSearchChange}
                  className="search-input"
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      onFiltersChange({ ...filters });
                    }
                  }}
                />
                <button 
                  className="search-button"
                  onClick={() => onFiltersChange({ ...filters })}
                  aria-label="Buscar"
                >
                  🔍
                </button>
              </div>
            </div>
            
            {/* Date Filters */}
            <div className="filter-section">
              <h3>Período</h3>
              <div className="date-inputs">
                <input
                  type="date"
                  value={filters.dateFrom || ''}
                  onChange={handleDateFromChange}
                  className="date-input"
                  aria-label="Data de início"
                />
                <span>até</span>
                <input
                  type="date"
                  value={filters.dateTo || ''}
                  onChange={handleDateToChange}
                  className="date-input"
                  aria-label="Data de fim"
                />
              </div>
            </div>
            
            {/* Document Type Filters */}
            <div className="filter-section">
              <h3>Tipo de Documento</h3>
              {documentTypes.map(type => (
                <label key={type.id} className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={filters.documentTypes.includes(type.id)}
                    onChange={(e) => handleDocumentTypeChange(type.id, e.target.checked)}
                  />
                  {type.label}
                </label>
              ))}
            </div>
            
            {/* Selected State Info */}
            {selectedState && (
              <div className="selected-state">
                <h3>Estado Selecionado</h3>
                <p>{selectedState}</p>
                <button onClick={onClearSelection} className="clear-btn">
                  Limpar Seleção
                </button>
              </div>
            )}
            
            {/* Results Summary */}
            <div className="results-summary">
              <h3>Resultados</h3>
              <p>{filteredDocuments.length} documentos encontrados</p>
            </div>
            
            {/* Document List */}
            <div className="document-list">
              <h3>Documentos</h3>
              <div className="document-items">
                {filteredDocuments.slice(0, 10).map(doc => (
                  <div key={doc.id} className="document-item">
                    <h4>{doc.title}</h4>
                    <p className="doc-meta">
                      {doc.type} • {doc.number} • {new Date(doc.date).toLocaleDateString('pt-BR')}
                    </p>
                    {doc.state && <p className="doc-location">Estado: {doc.state}</p>}
                    <p className="doc-summary">{doc.summary.slice(0, 100)}...</p>
                    {doc.url && (
                      <a href={doc.url} target="_blank" rel="noopener noreferrer" className="doc-link">
                        Ver documento
                      </a>
                    )}
                  </div>
                ))}
                {filteredDocuments.length > 10 && (
                  <p className="more-results">
                    E mais {filteredDocuments.length - 10} documentos...
                  </p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
      
      {/* Overlay for mobile */}
      {isOpen && <div className="sidebar-overlay" onClick={onToggle}></div>}
    </>
  );
};

export default Sidebar;