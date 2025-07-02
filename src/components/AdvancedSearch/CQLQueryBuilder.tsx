/**
 * CQLQueryBuilder Component
 * Visual interface for building Contextual Query Language (CQL) queries
 */
import React, { useState, useEffect } from 'react';
import { SearchFilters } from '../../types';

interface CQLQueryBuilderProps {
  query: string;
  onQueryChange: (query: string) => void;
  filters?: SearchFilters;
  onFiltersToQuery?: (query: string) => void;
}

interface CQLClause {
  id: string;
  field: string;
  operator: string;
  value: string;
  connector: 'AND' | 'OR' | '';
}

const CQL_FIELDS = [
  { value: 'dc.title', label: 'Title' },
  { value: 'dc.description', label: 'Description' },
  { value: 'dc.subject', label: 'Subject/Keywords' },
  { value: 'dc.creator', label: 'Author/Creator' },
  { value: 'dc.publisher', label: 'Publisher' },
  { value: 'dc.date', label: 'Date' },
  { value: 'dc.type', label: 'Document Type' },
  { value: 'dc.identifier', label: 'Identifier' },
  { value: 'dc.language', label: 'Language' },
  { value: 'dc.coverage', label: 'Geographic Coverage' },
  { value: 'cql.allRecords', label: 'All Fields' }
];

const CQL_OPERATORS = [
  { value: '=', label: 'equals' },
  { value: 'exact', label: 'exact match' },
  { value: 'all', label: 'contains all words' },
  { value: 'any', label: 'contains any word' },
  { value: 'adj', label: 'words adjacent' },
  { value: 'within', label: 'within N words' },
  { value: '>', label: 'greater than' },
  { value: '<', label: 'less than' },
  { value: '>=', label: 'greater or equal' },
  { value: '<=', label: 'less or equal' }
];

export const CQLQueryBuilder: React.FC<CQLQueryBuilderProps> = ({
  query,
  onQueryChange,
  filters,
  onFiltersToQuery
}) => {
  const [clauses, setClauses] = useState<CQLClause[]>([]);
  const [manualQuery, setManualQuery] = useState(query);
  const [buildMode, setBuildMode] = useState<'visual' | 'manual'>('visual');
  const [validationError, setValidationError] = useState<string>('');

  // Initialize with default clause
  useEffect(() => {
    if (clauses.length === 0) {
      addClause();
    }
  }, []);

  // Update query when clauses change
  useEffect(() => {
    if (buildMode === 'visual') {
      const newQuery = buildCQLFromClauses(clauses);
      onQueryChange(newQuery);
    }
  }, [clauses, buildMode]);

  // Update manual query when external query changes
  useEffect(() => {
    if (buildMode === 'manual') {
      setManualQuery(query);
    }
  }, [query, buildMode]);

  const addClause = () => {
    const newClause: CQLClause = {
      id: Date.now().toString(),
      field: 'cql.allRecords',
      operator: '=',
      value: '',
      connector: clauses.length > 0 ? 'AND' : ''
    };
    setClauses([...clauses, newClause]);
  };

  const removeClause = (id: string) => {
    const newClauses = clauses.filter(clause => clause.id !== id);
    // Remove connector from first clause if it exists
    if (newClauses.length > 0) {
      newClauses[0].connector = '';
    }
    setClauses(newClauses);
  };

  const updateClause = (id: string, updates: Partial<CQLClause>) => {
    setClauses(clauses.map(clause => 
      clause.id === id ? { ...clause, ...updates } : clause
    ));
  };

  const buildCQLFromClauses = (clauseList: CQLClause[]): string => {
    const validClauses = clauseList.filter(clause => clause.value.trim());
    
    if (validClauses.length === 0) return '';

    return validClauses.map((clause, index) => {
      let cqlClause = '';
      
      // Add connector for subsequent clauses
      if (index > 0 && clause.connector) {
        cqlClause += `${clause.connector} `;
      }
      
      // Build the field operator value part
      const value = clause.value.includes(' ') && !clause.value.startsWith('"') 
        ? `"${clause.value}"` 
        : clause.value;
      
      cqlClause += `${clause.field} ${clause.operator} ${value}`;
      
      return cqlClause;
    }).join(' ');
  };

  const convertFiltersToQuery = () => {
    if (!filters || !onFiltersToQuery) return;

    const newClauses: CQLClause[] = [];

    // Search term
    if (filters.searchTerm) {
      newClauses.push({
        id: Date.now().toString(),
        field: 'cql.allRecords',
        operator: 'all',
        value: filters.searchTerm,
        connector: ''
      });
    }

    // Document types
    if (filters.documentTypes.length > 0) {
      const typeQuery = filters.documentTypes.map(type => `"${type}"`).join(' OR ');
      newClauses.push({
        id: (Date.now() + 1).toString(),
        field: 'dc.type',
        operator: '=',
        value: `(${typeQuery})`,
        connector: newClauses.length > 0 ? 'AND' : ''
      });
    }

    // States/Geographic coverage
    if (filters.states.length > 0) {
      const stateQuery = filters.states.map(state => `"${state}"`).join(' OR ');
      newClauses.push({
        id: (Date.now() + 2).toString(),
        field: 'dc.coverage',
        operator: '=',
        value: `(${stateQuery})`,
        connector: newClauses.length > 0 ? 'AND' : ''
      });
    }

    // Keywords
    if (filters.keywords.length > 0) {
      const keywordQuery = filters.keywords.map(keyword => `"${keyword}"`).join(' OR ');
      newClauses.push({
        id: (Date.now() + 3).toString(),
        field: 'dc.subject',
        operator: '=',
        value: `(${keywordQuery})`,
        connector: newClauses.length > 0 ? 'AND' : ''
      });
    }

    // Date range
    if (filters.dateFrom || filters.dateTo) {
      let dateValue = '';
      if (filters.dateFrom && filters.dateTo) {
        dateValue = `>= "${filters.dateFrom}" AND dc.date <= "${filters.dateTo}"`;
        newClauses.push({
          id: (Date.now() + 4).toString(),
          field: 'dc.date',
          operator: '',
          value: dateValue,
          connector: newClauses.length > 0 ? 'AND' : ''
        });
      } else if (filters.dateFrom) {
        newClauses.push({
          id: (Date.now() + 4).toString(),
          field: 'dc.date',
          operator: '>=',
          value: `"${filters.dateFrom}"`,
          connector: newClauses.length > 0 ? 'AND' : ''
        });
      } else if (filters.dateTo) {
        newClauses.push({
          id: (Date.now() + 4).toString(),
          field: 'dc.date',
          operator: '<=',
          value: `"${filters.dateTo}"`,
          connector: newClauses.length > 0 ? 'AND' : ''
        });
      }
    }

    if (newClauses.length > 0) {
      setClauses(newClauses);
      const generatedQuery = buildCQLFromClauses(newClauses);
      onFiltersToQuery(generatedQuery);
    }
  };

  const validateCQLQuery = (queryToValidate: string): string => {
    if (!queryToValidate.trim()) return '';

    // Basic CQL validation
    const openParens = (queryToValidate.match(/\(/g) || []).length;
    const closeParens = (queryToValidate.match(/\)/g) || []).length;
    
    if (openParens !== closeParens) {
      return 'Mismatched parentheses in query';
    }

    // Check for common CQL field names
    const hasValidField = CQL_FIELDS.some(field => 
      queryToValidate.includes(field.value)
    );
    
    if (!hasValidField && !queryToValidate.includes('cql.allRecords')) {
      return 'Query should include valid CQL fields (e.g., dc.title, dc.subject)';
    }

    return '';
  };

  const handleManualQueryChange = (newQuery: string) => {
    setManualQuery(newQuery);
    onQueryChange(newQuery);
    
    const error = validateCQLQuery(newQuery);
    setValidationError(error);
  };

  return (
    <div className="cql-query-builder">
      <div className="cql-query-builder__header">
        <h3>CQL Query Builder</h3>
        <div className="cql-query-builder__mode-toggle">
          <button
            className={`cql-query-builder__mode-btn ${buildMode === 'visual' ? 'active' : ''}`}
            onClick={() => setBuildMode('visual')}
          >
            Visual Builder
          </button>
          <button
            className={`cql-query-builder__mode-btn ${buildMode === 'manual' ? 'active' : ''}`}
            onClick={() => setBuildMode('manual')}
          >
            Manual Entry
          </button>
        </div>
      </div>

      {buildMode === 'visual' ? (
        <div className="cql-query-builder__visual">
          <div className="cql-query-builder__actions">
            <button onClick={addClause} className="cql-query-builder__add-btn">
              Add Clause
            </button>
            {filters && (
              <button 
                onClick={convertFiltersToQuery}
                className="cql-query-builder__convert-btn"
              >
                Convert Filters to CQL
              </button>
            )}
          </div>

          <div className="cql-query-builder__clauses">
            {clauses.map((clause, index) => (
              <div key={clause.id} className="cql-query-builder__clause">
                {index > 0 && (
                  <select
                    value={clause.connector}
                    onChange={(e) => updateClause(clause.id, { connector: e.target.value as 'AND' | 'OR' })}
                    className="cql-query-builder__connector"
                  >
                    <option value="AND">AND</option>
                    <option value="OR">OR</option>
                  </select>
                )}

                <select
                  value={clause.field}
                  onChange={(e) => updateClause(clause.id, { field: e.target.value })}
                  className="cql-query-builder__field"
                >
                  {CQL_FIELDS.map(field => (
                    <option key={field.value} value={field.value}>
                      {field.label}
                    </option>
                  ))}
                </select>

                <select
                  value={clause.operator}
                  onChange={(e) => updateClause(clause.id, { operator: e.target.value })}
                  className="cql-query-builder__operator"
                >
                  {CQL_OPERATORS.map(op => (
                    <option key={op.value} value={op.value}>
                      {op.label}
                    </option>
                  ))}
                </select>

                <input
                  type="text"
                  value={clause.value}
                  onChange={(e) => updateClause(clause.id, { value: e.target.value })}
                  placeholder="Enter value..."
                  className="cql-query-builder__value"
                />

                {clauses.length > 1 && (
                  <button
                    onClick={() => removeClause(clause.id)}
                    className="cql-query-builder__remove-btn"
                    title="Remove clause"
                  >
                    ×
                  </button>
                )}
              </div>
            ))}
          </div>

          <div className="cql-query-builder__preview">
            <h4>Generated CQL Query:</h4>
            <code className="cql-query-builder__preview-code">
              {buildCQLFromClauses(clauses) || 'No valid clauses'}
            </code>
          </div>
        </div>
      ) : (
        <div className="cql-query-builder__manual">
          <div className="cql-query-builder__manual-input">
            <label htmlFor="manual-cql">CQL Query:</label>
            <textarea
              id="manual-cql"
              value={manualQuery}
              onChange={(e) => handleManualQueryChange(e.target.value)}
              placeholder="Enter CQL query manually..."
              className="cql-query-builder__textarea"
              rows={6}
            />
            {validationError && (
              <div className="cql-query-builder__error">
                {validationError}
              </div>
            )}
          </div>

          <div className="cql-query-builder__help">
            <h4>CQL Query Examples:</h4>
            <ul>
              <li><code>dc.title = "transport"</code> - Title contains "transport"</li>
              <li><code>dc.subject any "bus metro train"</code> - Subject contains any of these words</li>
              <li><code>dc.date {'>'}= "2020-01-01"</code> - Documents from 2020 onwards</li>
              <li><code>dc.title = "transport" AND dc.type = "lei"</code> - Title contains "transport" and type is "lei"</li>
              <li><code>(dc.title = "bus" OR dc.title = "metro") AND dc.coverage = "São Paulo"</code> - Complex query with grouping</li>
            </ul>
          </div>
        </div>
      )}

      <div className="cql-query-builder__reference">
        <details>
          <summary>CQL Reference</summary>
          <div className="cql-query-builder__reference-content">
            <h4>Available Fields:</h4>
            <ul>
              {CQL_FIELDS.map(field => (
                <li key={field.value}>
                  <code>{field.value}</code> - {field.label}
                </li>
              ))}
            </ul>
            
            <h4>Operators:</h4>
            <ul>
              {CQL_OPERATORS.map(op => (
                <li key={op.value}>
                  <code>{op.value}</code> - {op.label}
                </li>
              ))}
            </ul>
            
            <h4>Connectors:</h4>
            <ul>
              <li><code>AND</code> - Both conditions must be true</li>
              <li><code>OR</code> - Either condition can be true</li>
              <li><code>NOT</code> - Exclude results matching condition</li>
            </ul>
          </div>
        </details>
      </div>
    </div>
  );
};