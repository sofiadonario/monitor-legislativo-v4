/**
 * FieldSpecificFilters Component
 * Detailed filtering interface for legislative documents
 */
import React, { useState, useEffect } from 'react';
import { SearchFilters, DocumentType } from '../../types';
import { brazilianStates } from '../../data/brazil-states';

interface FieldSpecificFiltersProps {
  filters: SearchFilters;
  onFiltersChange: (filters: Partial<SearchFilters>) => void;
  showAdvanced?: boolean;
}

const DOCUMENT_TYPES: Array<{value: DocumentType; label: string}> = [
  { value: 'lei', label: 'Lei' },
  { value: 'decreto', label: 'Decreto' },
  { value: 'portaria', label: 'Portaria' },
  { value: 'resolucao', label: 'Resolução' },
  { value: 'instrucao_normativa', label: 'Instrução Normativa' },
  { value: 'projeto_lei', label: 'Projeto de Lei' },
  { value: 'medida_provisoria', label: 'Medida Provisória' }
];

const CHAMBERS = [
  'Câmara dos Deputados',
  'Senado Federal',
  'Assembleia Legislativa',
  'Câmara Municipal',
  'Tribunal de Contas',
  'Supremo Tribunal Federal',
  'Superior Tribunal de Justiça'
];

const TRANSPORT_KEYWORDS = [
  'transporte', 'mobilidade', 'trânsito', 'ônibus', 'metro', 'trem',
  'ferrovia', 'rodovia', 'aeroporto', 'porto', 'navegação', 'aviação',
  'bicicleta', 'pedestre', 'táxi', 'uber', 'motocicleta', 'caminhão',
  'logística', 'infraestrutura', 'concessão', 'pedágio', 'combustível'
];

export const FieldSpecificFilters: React.FC<FieldSpecificFiltersProps> = ({
  filters,
  onFiltersChange,
  showAdvanced = false
}) => {
  const [municipalitySearch, setMunicipalitySearch] = useState('');
  const [keywordSearch, setKeywordSearch] = useState('');
  const [availableMunicipalities, setAvailableMunicipalities] = useState<string[]>([]);

  // Load municipalities for selected states
  useEffect(() => {
    if (filters.states.length > 0) {
      const municipalities = filters.states.flatMap(stateAbbr => {
        const state = brazilianStates.find(s => s.abbreviation === stateAbbr);
        return state?.municipalities || [];
      });
      setAvailableMunicipalities(municipalities);
    } else {
      setAvailableMunicipalities([]);
    }
  }, [filters.states]);

  const handleDocumentTypesChange = (type: DocumentType, checked: boolean) => {
    const newTypes = checked 
      ? [...filters.documentTypes, type]
      : filters.documentTypes.filter(t => t !== type);
    onFiltersChange({ documentTypes: newTypes });
  };

  const handleStatesChange = (stateAbbr: string, checked: boolean) => {
    const newStates = checked 
      ? [...filters.states, stateAbbr]
      : filters.states.filter(s => s !== stateAbbr);
    onFiltersChange({ states: newStates });
    
    // Clear municipalities if state is deselected
    if (!checked) {
      const remainingMunicipalities = filters.municipalities.filter(muni => {
        const remainingStates = newStates;
        return remainingStates.some(stateAbbr => {
          const state = brazilianStates.find(s => s.abbreviation === stateAbbr);
          return state?.municipalities.includes(muni);
        });
      });
      onFiltersChange({ municipalities: remainingMunicipalities });
    }
  };

  const handleMunicipalityAdd = (municipality: string) => {
    if (!filters.municipalities.includes(municipality)) {
      onFiltersChange({ 
        municipalities: [...filters.municipalities, municipality] 
      });
    }
    setMunicipalitySearch('');
  };

  const handleMunicipalityRemove = (municipality: string) => {
    onFiltersChange({ 
      municipalities: filters.municipalities.filter(m => m !== municipality) 
    });
  };

  const handleChambersChange = (chamber: string, checked: boolean) => {
    const newChambers = checked 
      ? [...filters.chambers, chamber]
      : filters.chambers.filter(c => c !== chamber);
    onFiltersChange({ chambers: newChambers });
  };

  const handleKeywordAdd = (keyword: string) => {
    if (!filters.keywords.includes(keyword)) {
      onFiltersChange({ 
        keywords: [...filters.keywords, keyword] 
      });
    }
    setKeywordSearch('');
  };

  const handleKeywordRemove = (keyword: string) => {
    onFiltersChange({ 
      keywords: filters.keywords.filter(k => k !== keyword) 
    });
  };

  const filteredMunicipalities = availableMunicipalities.filter(muni =>
    muni.toLowerCase().includes(municipalitySearch.toLowerCase()) &&
    !filters.municipalities.includes(muni)
  );

  const filteredKeywords = TRANSPORT_KEYWORDS.filter(keyword =>
    keyword.toLowerCase().includes(keywordSearch.toLowerCase()) &&
    !filters.keywords.includes(keyword)
  );

  return (
    <div className="field-specific-filters">
      {/* Document Types */}
      <div className="field-specific-filters__section">
        <h3>Document Types</h3>
        <div className="field-specific-filters__checkbox-grid">
          {DOCUMENT_TYPES.map(type => (
            <label key={type.value} className="field-specific-filters__checkbox">
              <input
                type="checkbox"
                checked={filters.documentTypes.includes(type.value)}
                onChange={(e) => handleDocumentTypesChange(type.value, e.target.checked)}
              />
              {type.label}
            </label>
          ))}
        </div>
      </div>

      {/* Geographic Filters */}
      <div className="field-specific-filters__section">
        <h3>Geographic Filters</h3>
        
        {/* States */}
        <div className="field-specific-filters__subsection">
          <h4>States</h4>
          <div className="field-specific-filters__checkbox-grid states">
            {brazilianStates.map(state => (
              <label key={state.abbreviation} className="field-specific-filters__checkbox">
                <input
                  type="checkbox"
                  checked={filters.states.includes(state.abbreviation)}
                  onChange={(e) => handleStatesChange(state.abbreviation, e.target.checked)}
                />
                {state.name} ({state.abbreviation})
              </label>
            ))}
          </div>
        </div>

        {/* Municipalities */}
        {filters.states.length > 0 && (
          <div className="field-specific-filters__subsection">
            <h4>Municipalities</h4>
            <div className="field-specific-filters__municipality-selector">
              <input
                type="text"
                value={municipalitySearch}
                onChange={(e) => setMunicipalitySearch(e.target.value)}
                placeholder="Search municipalities..."
                className="field-specific-filters__search-input"
              />
              {municipalitySearch && filteredMunicipalities.length > 0 && (
                <div className="field-specific-filters__dropdown">
                  {filteredMunicipalities.slice(0, 10).map(municipality => (
                    <button
                      key={municipality}
                      onClick={() => handleMunicipalityAdd(municipality)}
                      className="field-specific-filters__dropdown-item"
                    >
                      {municipality}
                    </button>
                  ))}
                </div>
              )}
            </div>
            
            {filters.municipalities.length > 0 && (
              <div className="field-specific-filters__selected-items">
                {filters.municipalities.map(municipality => (
                  <span key={municipality} className="field-specific-filters__tag">
                    {municipality}
                    <button 
                      onClick={() => handleMunicipalityRemove(municipality)}
                      className="field-specific-filters__tag-remove"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Date Range */}
      <div className="field-specific-filters__section">
        <h3>Date Range</h3>
        <div className="field-specific-filters__date-range">
          <div className="field-specific-filters__date-input">
            <label htmlFor="date-from">From:</label>
            <input
              id="date-from"
              type="date"
              value={filters.dateFrom ? new Date(filters.dateFrom).toISOString().split('T')[0] : ''}
              onChange={(e) => onFiltersChange({ 
                dateFrom: e.target.value ? new Date(e.target.value) : undefined 
              })}
              className="field-specific-filters__date"
            />
          </div>
          <div className="field-specific-filters__date-input">
            <label htmlFor="date-to">To:</label>
            <input
              id="date-to"
              type="date"
              value={filters.dateTo ? new Date(filters.dateTo).toISOString().split('T')[0] : ''}
              onChange={(e) => onFiltersChange({ 
                dateTo: e.target.value ? new Date(e.target.value) : undefined 
              })}
              className="field-specific-filters__date"
            />
          </div>
        </div>
      </div>

      {/* Keywords */}
      <div className="field-specific-filters__section">
        <h3>Keywords</h3>
        <div className="field-specific-filters__keyword-selector">
          <input
            type="text"
            value={keywordSearch}
            onChange={(e) => setKeywordSearch(e.target.value)}
            placeholder="Search or add keywords..."
            className="field-specific-filters__search-input"
            onKeyPress={(e) => {
              if (e.key === 'Enter' && keywordSearch.trim()) {
                handleKeywordAdd(keywordSearch.trim());
              }
            }}
          />
          {keywordSearch && filteredKeywords.length > 0 && (
            <div className="field-specific-filters__dropdown">
              {filteredKeywords.slice(0, 8).map(keyword => (
                <button
                  key={keyword}
                  onClick={() => handleKeywordAdd(keyword)}
                  className="field-specific-filters__dropdown-item"
                >
                  {keyword}
                </button>
              ))}
            </div>
          )}
          {keywordSearch.trim() && !TRANSPORT_KEYWORDS.includes(keywordSearch.trim()) && (
            <div className="field-specific-filters__add-custom">
              <button
                onClick={() => handleKeywordAdd(keywordSearch.trim())}
                className="field-specific-filters__add-btn"
              >
                Add "{keywordSearch.trim()}"
              </button>
            </div>
          )}
        </div>
        
        {filters.keywords.length > 0 && (
          <div className="field-specific-filters__selected-items">
            {filters.keywords.map(keyword => (
              <span key={keyword} className="field-specific-filters__tag">
                {keyword}
                <button 
                  onClick={() => handleKeywordRemove(keyword)}
                  className="field-specific-filters__tag-remove"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Advanced Filters (only shown in advanced mode) */}
      {showAdvanced && (
        <>
          {/* Chambers */}
          <div className="field-specific-filters__section">
            <h3>Issuing Chambers</h3>
            <div className="field-specific-filters__checkbox-grid">
              {CHAMBERS.map(chamber => (
                <label key={chamber} className="field-specific-filters__checkbox">
                  <input
                    type="checkbox"
                    checked={filters.chambers.includes(chamber)}
                    onChange={(e) => handleChambersChange(chamber, e.target.checked)}
                  />
                  {chamber}
                </label>
              ))}
            </div>
          </div>

          {/* Additional Advanced Options */}
          <div className="field-specific-filters__section">
            <h3>Advanced Options</h3>
            <div className="field-specific-filters__advanced-options">
              <label className="field-specific-filters__checkbox">
                <input
                  type="checkbox"
                  // Add advanced options as needed
                />
                Include revoked documents
              </label>
              <label className="field-specific-filters__checkbox">
                <input
                  type="checkbox"
                  // Add advanced options as needed
                />
                Only current versions
              </label>
              <label className="field-specific-filters__checkbox">
                <input
                  type="checkbox"
                  // Add advanced options as needed
                />
                Include draft documents
              </label>
            </div>
          </div>
        </>
      )}
    </div>
  );
};