/**
 * AdvancedSearch Component
 * Comprehensive search interface with CQL query building and field-specific filters
 */
import React, { useState, useEffect } from 'react';
import { SearchFilters } from '../../types';
import { CQLQueryBuilder } from './CQLQueryBuilder';
import { FieldSpecificFilters } from './FieldSpecificFilters';
import { SearchTemplates } from './SearchTemplates';
import { SavedSearches } from './SavedSearches';
import './AdvancedSearch.css';

interface AdvancedSearchProps {
  onSearch: (filters: SearchFilters) => void;
  onCQLSearch?: (cqlQuery: string) => void;
  initialFilters?: Partial<SearchFilters>;
  className?: string;
}

type TabType = 'basic' | 'advanced' | 'cql' | 'templates' | 'saved';

export const AdvancedSearch: React.FC<AdvancedSearchProps> = ({
  onSearch,
  onCQLSearch,
  initialFilters = {},
  className = ''
}) => {
  const [activeTab, setActiveTab] = useState<TabType>('basic');
  const [filters, setFilters] = useState<SearchFilters>({
    searchTerm: '',
    documentTypes: [],
    states: [],
    municipalities: [],
    chambers: [],
    keywords: [],
    dateFrom: undefined,
    dateTo: undefined,
    ...initialFilters
  });
  const [cqlQuery, setCqlQuery] = useState('');
  const [isFormValid, setIsFormValid] = useState(false);

  // Validate form whenever filters change
  useEffect(() => {
    const hasSearchTerm = filters.searchTerm.trim().length > 0;
    const hasFilters = filters.documentTypes.length > 0 || 
                      filters.states.length > 0 || 
                      filters.municipalities.length > 0 ||
                      filters.chambers.length > 0 ||
                      filters.keywords.length > 0 ||
                      !!filters.dateFrom || 
                      !!filters.dateTo;
    
    setIsFormValid(hasSearchTerm || hasFilters);
  }, [filters]);

  const handleFiltersChange = (newFilters: Partial<SearchFilters>) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
  };

  const handleSearch = () => {
    if (isFormValid) {
      onSearch(filters);
    }
  };

  const handleCQLSearch = () => {
    if (cqlQuery.trim() && onCQLSearch) {
      onCQLSearch(cqlQuery);
    }
  };

  const handleTemplateApply = (templateFilters: SearchFilters) => {
    setFilters(templateFilters);
    setActiveTab('basic');
  };

  const handleSavedSearchApply = (savedFilters: SearchFilters) => {
    setFilters(savedFilters);
    setActiveTab('basic');
  };

  const clearFilters = () => {
    setFilters({
      searchTerm: '',
      documentTypes: [],
      states: [],
      municipalities: [],
      chambers: [],
      keywords: [],
      dateFrom: undefined,
      dateTo: undefined
    });
    setCqlQuery('');
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'basic':
        return (
          <div className="advanced-search__basic-tab">
            <div className="advanced-search__search-term">
              <label htmlFor="search-term">Search Term</label>
              <input
                id="search-term"
                type="text"
                value={filters.searchTerm}
                onChange={(e) => handleFiltersChange({ searchTerm: e.target.value })}
                placeholder="Enter search terms..."
                className="advanced-search__input"
              />
              <small className="advanced-search__help">
                Use quotes for exact phrases, AND/OR for boolean logic
              </small>
            </div>

            <FieldSpecificFilters
              filters={filters}
              onFiltersChange={handleFiltersChange}
            />
          </div>
        );

      case 'advanced':
        return (
          <div className="advanced-search__advanced-tab">
            <FieldSpecificFilters
              filters={filters}
              onFiltersChange={handleFiltersChange}
              showAdvanced={true}
            />
          </div>
        );

      case 'cql':
        return (
          <div className="advanced-search__cql-tab">
            <CQLQueryBuilder
              query={cqlQuery}
              onQueryChange={setCqlQuery}
              filters={filters}
              onFiltersToQuery={(newQuery) => setCqlQuery(newQuery)}
            />
          </div>
        );

      case 'templates':
        return (
          <div className="advanced-search__templates-tab">
            <SearchTemplates
              onTemplateApply={handleTemplateApply}
            />
          </div>
        );

      case 'saved':
        return (
          <div className="advanced-search__saved-tab">
            <SavedSearches
              currentFilters={filters}
              onSavedSearchApply={handleSavedSearchApply}
            />
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className={`advanced-search ${className}`}>
      <div className="advanced-search__header">
        <h2>Advanced Search</h2>
        <p>Build sophisticated queries for legislative document research</p>
      </div>

      <div className="advanced-search__tabs">
        <button
          className={`advanced-search__tab ${activeTab === 'basic' ? 'active' : ''}`}
          onClick={() => setActiveTab('basic')}
        >
          Basic Search
        </button>
        <button
          className={`advanced-search__tab ${activeTab === 'advanced' ? 'active' : ''}`}
          onClick={() => setActiveTab('advanced')}
        >
          Advanced Filters
        </button>
        <button
          className={`advanced-search__tab ${activeTab === 'cql' ? 'active' : ''}`}
          onClick={() => setActiveTab('cql')}
        >
          CQL Query
        </button>
        <button
          className={`advanced-search__tab ${activeTab === 'templates' ? 'active' : ''}`}
          onClick={() => setActiveTab('templates')}
        >
          Templates
        </button>
        <button
          className={`advanced-search__tab ${activeTab === 'saved' ? 'active' : ''}`}
          onClick={() => setActiveTab('saved')}
        >
          Saved Searches
        </button>
      </div>

      <div className="advanced-search__content">
        {renderTabContent()}
      </div>

      <div className="advanced-search__actions">
        <div className="advanced-search__left-actions">
          <button
            onClick={clearFilters}
            className="advanced-search__clear-btn"
          >
            Clear All
          </button>
          {activeTab === 'cql' && (
            <span className="advanced-search__cql-status">
              {cqlQuery.trim() ? 'CQL Query Ready' : 'Enter CQL Query'}
            </span>
          )}
        </div>

        <div className="advanced-search__right-actions">
          {activeTab === 'cql' ? (
            <button
              onClick={handleCQLSearch}
              disabled={!cqlQuery.trim()}
              className="advanced-search__search-btn"
            >
              Search with CQL
            </button>
          ) : (
            <button
              onClick={handleSearch}
              disabled={!isFormValid}
              className="advanced-search__search-btn"
            >
              Search Documents
            </button>
          )}
        </div>
      </div>

      {/* Search Summary */}
      {(isFormValid || cqlQuery.trim()) && (
        <div className="advanced-search__summary">
          <h4>Search Summary</h4>
          {activeTab === 'cql' ? (
            <div className="advanced-search__cql-summary">
              <code>{cqlQuery}</code>
            </div>
          ) : (
            <div className="advanced-search__filters-summary">
              {filters.searchTerm && (
                <span className="advanced-search__summary-item">
                  Term: "{filters.searchTerm}"
                </span>
              )}
              {filters.documentTypes.length > 0 && (
                <span className="advanced-search__summary-item">
                  Types: {filters.documentTypes.join(', ')}
                </span>
              )}
              {filters.states.length > 0 && (
                <span className="advanced-search__summary-item">
                  States: {filters.states.join(', ')}
                </span>
              )}
              {filters.municipalities.length > 0 && (
                <span className="advanced-search__summary-item">
                  Cities: {filters.municipalities.length} selected
                </span>
              )}
              {filters.chambers.length > 0 && (
                <span className="advanced-search__summary-item">
                  Chambers: {filters.chambers.join(', ')}
                </span>
              )}
              {filters.keywords.length > 0 && (
                <span className="advanced-search__summary-item">
                  Keywords: {filters.keywords.join(', ')}
                </span>
              )}
              {(filters.dateFrom || filters.dateTo) && (
                <span className="advanced-search__summary-item">
                  Date Range: {filters.dateFrom ? new Date(filters.dateFrom).toLocaleDateString() : '∞'} - {filters.dateTo ? new Date(filters.dateTo).toLocaleDateString() : '∞'}
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};