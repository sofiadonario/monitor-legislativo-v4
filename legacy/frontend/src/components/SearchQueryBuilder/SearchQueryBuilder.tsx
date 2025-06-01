/**
 * SearchQueryBuilder Component
 * Natural language processing and visual query construction interface
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { DocumentType } from '../../types';
import { advancedSearchService } from '../../services/advancedSearchService';
import { semanticSearchService } from '../../services/semanticSearchService';

interface QueryCondition {
  id: string;
  field: 'title' | 'content' | 'author' | 'type' | 'date' | 'state' | 'keywords';
  operator: 'contains' | 'equals' | 'starts_with' | 'ends_with' | 'before' | 'after' | 'between' | 'in' | 'not_in';
  value: string | string[] | Date | { start: Date; end: Date };
  logicalOperator?: 'AND' | 'OR' | 'NOT';
}

interface NaturalLanguageQuery {
  originalText: string;
  parsedConditions: QueryCondition[];
  confidence: number;
  suggestions: string[];
  entities: Array<{
    text: string;
    type: 'date' | 'location' | 'organization' | 'document_type' | 'keyword';
    startPos: number;
    endPos: number;
    confidence: number;
  }>;
}

interface SearchQueryBuilderProps {
  onQueryChange?: (query: string, conditions: QueryCondition[]) => void;
  onExecuteSearch?: (query: string, conditions: QueryCondition[]) => void;
  initialQuery?: string;
  showNaturalLanguage?: boolean;
  showVisualBuilder?: boolean;
  allowAdvancedSyntax?: boolean;
}

export const SearchQueryBuilder: React.FC<SearchQueryBuilderProps> = ({
  onQueryChange,
  onExecuteSearch,
  initialQuery = '',
  showNaturalLanguage = true,
  showVisualBuilder = true,
  allowAdvancedSyntax = true
}) => {
  // State management
  const [activeTab, setActiveTab] = useState<'natural' | 'visual' | 'advanced'>('natural');
  const [naturalQuery, setNaturalQuery] = useState(initialQuery);
  const [visualConditions, setVisualConditions] = useState<QueryCondition[]>([]);
  const [advancedQuery, setAdvancedQuery] = useState('');
  const [parsedNLQuery, setParsedNLQuery] = useState<NaturalLanguageQuery | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // Available field options
  const fieldOptions = [
    { value: 'title', label: 'Title', description: 'Document title' },
    { value: 'content', label: 'Content', description: 'Document content and summary' },
    { value: 'author', label: 'Author', description: 'Document author or issuing authority' },
    { value: 'type', label: 'Type', description: 'Document type (lei, decreto, etc.)' },
    { value: 'date', label: 'Date', description: 'Publication or effective date' },
    { value: 'state', label: 'State', description: 'Brazilian state' },
    { value: 'keywords', label: 'Keywords', description: 'Document keywords and tags' }
  ];

  const operatorOptions = {
    text: [
      { value: 'contains', label: 'contains', description: 'Field contains the text' },
      { value: 'equals', label: 'equals', description: 'Field equals exactly' },
      { value: 'starts_with', label: 'starts with', description: 'Field starts with text' },
      { value: 'ends_with', label: 'ends with', description: 'Field ends with text' }
    ],
    date: [
      { value: 'before', label: 'before', description: 'Date is before' },
      { value: 'after', label: 'after', description: 'Date is after' },
      { value: 'between', label: 'between', description: 'Date is between two dates' }
    ],
    list: [
      { value: 'in', label: 'is one of', description: 'Field matches any of the values' },
      { value: 'not_in', label: 'is not one of', description: 'Field does not match any value' }
    ]
  };

  // Natural language processing
  const processNaturalLanguage = useCallback(async (text: string) => {
    if (!text.trim()) {
      setParsedNLQuery(null);
      return;
    }

    setIsProcessing(true);
    
    try {
      // Simple NLP parsing (in production, this would use more sophisticated NLP)
      const entities = extractEntities(text);
      const conditions = await parseToConditions(text, entities);
      const confidence = calculateParsingConfidence(text, entities, conditions);
      const suggestions = generateSuggestions(text, entities);

      const parsed: NaturalLanguageQuery = {
        originalText: text,
        parsedConditions: conditions,
        confidence,
        suggestions,
        entities
      };

      setParsedNLQuery(parsed);
      
      if (onQueryChange) {
        onQueryChange(text, conditions);
      }

    } catch (error) {
      console.error('Natural language processing failed:', error);
    } finally {
      setIsProcessing(false);
    }
  }, [onQueryChange]);

  // Handle natural language input changes
  useEffect(() => {
    const timer = setTimeout(() => {
      processNaturalLanguage(naturalQuery);
    }, 500);

    return () => clearTimeout(timer);
  }, [naturalQuery, processNaturalLanguage]);

  // Generate final query string
  const generateQueryString = useCallback((conditions: QueryCondition[]): string => {
    if (conditions.length === 0) return '';

    return conditions.map((condition, index) => {
      let query = '';
      
      // Add logical operator for subsequent conditions
      if (index > 0 && condition.logicalOperator) {
        query += ` ${condition.logicalOperator} `;
      }

      // Build condition string based on field and operator
      switch (condition.operator) {
        case 'contains':
          query += `${condition.field}:"${condition.value}"`;
          break;
        case 'equals':
          query += `${condition.field}:=${condition.value}`;
          break;
        case 'starts_with':
          query += `${condition.field}:${condition.value}*`;
          break;
        case 'ends_with':
          query += `${condition.field}:*${condition.value}`;
          break;
        case 'before':
          query += `${condition.field}:<${formatDate(condition.value as Date)}`;
          break;
        case 'after':
          query += `${condition.field}:>${formatDate(condition.value as Date)}`;
          break;
        case 'between':
          const range = condition.value as { start: Date; end: Date };
          query += `${condition.field}:[${formatDate(range.start)} TO ${formatDate(range.end)}]`;
          break;
        case 'in':
          const values = condition.value as string[];
          query += `${condition.field}:(${values.map(v => `"${v}"`).join(' OR ')})`;
          break;
        case 'not_in':
          const notValues = condition.value as string[];
          query += `NOT ${condition.field}:(${notValues.map(v => `"${v}"`).join(' OR ')})`;
          break;
      }

      return query;
    }).join('');
  }, []);

  // Handle visual condition changes
  const handleVisualConditionChange = useCallback((conditions: QueryCondition[]) => {
    setVisualConditions(conditions);
    const queryString = generateQueryString(conditions);
    
    if (onQueryChange) {
      onQueryChange(queryString, conditions);
    }
  }, [generateQueryString, onQueryChange]);

  // Add new visual condition
  const addVisualCondition = () => {
    const newCondition: QueryCondition = {
      id: `condition_${Date.now()}`,
      field: 'title',
      operator: 'contains',
      value: '',
      logicalOperator: visualConditions.length > 0 ? 'AND' : undefined
    };

    const newConditions = [...visualConditions, newCondition];
    handleVisualConditionChange(newConditions);
  };

  // Remove visual condition
  const removeVisualCondition = (id: string) => {
    const newConditions = visualConditions.filter(condition => condition.id !== id);
    handleVisualConditionChange(newConditions);
  };

  // Update visual condition
  const updateVisualCondition = (id: string, updates: Partial<QueryCondition>) => {
    const newConditions = visualConditions.map(condition =>
      condition.id === id ? { ...condition, ...updates } : condition
    );
    handleVisualConditionChange(newConditions);
  };

  // Execute search
  const handleExecuteSearch = () => {
    let query = '';
    let conditions: QueryCondition[] = [];

    switch (activeTab) {
      case 'natural':
        query = naturalQuery;
        conditions = parsedNLQuery?.parsedConditions || [];
        break;
      case 'visual':
        query = generateQueryString(visualConditions);
        conditions = visualConditions;
        break;
      case 'advanced':
        query = advancedQuery;
        conditions = []; // Advanced query is free-form
        break;
    }

    if (onExecuteSearch && query.trim()) {
      onExecuteSearch(query, conditions);
    }
  };

  // Get appropriate operators for field type
  const getOperatorsForField = (field: string) => {
    if (field === 'date') return operatorOptions.date;
    if (field === 'type' || field === 'state') return [...operatorOptions.text, ...operatorOptions.list];
    return operatorOptions.text;
  };

  return (
    <div className="search-query-builder">
      <div className="query-builder-header">
        <h3>Query Builder</h3>
        <div className="query-tabs">
          {showNaturalLanguage && (
            <button
              className={`tab ${activeTab === 'natural' ? 'active' : ''}`}
              onClick={() => setActiveTab('natural')}
            >
              🗣️ Natural Language
            </button>
          )}
          {showVisualBuilder && (
            <button
              className={`tab ${activeTab === 'visual' ? 'active' : ''}`}
              onClick={() => setActiveTab('visual')}
            >
              🔧 Visual Builder
            </button>
          )}
          {allowAdvancedSyntax && (
            <button
              className={`tab ${activeTab === 'advanced' ? 'active' : ''}`}
              onClick={() => setActiveTab('advanced')}
            >
              💻 Advanced Syntax
            </button>
          )}
        </div>
      </div>

      <div className="query-builder-content">
        {/* Natural Language Tab */}
        {activeTab === 'natural' && (
          <div className="natural-language-panel">
            <div className="nl-input-section">
              <label htmlFor="natural-query">Describe your search in natural language:</label>
              <textarea
                id="natural-query"
                value={naturalQuery}
                onChange={(e) => setNaturalQuery(e.target.value)}
                placeholder="e.g., Find laws about road transport published after 2020 in São Paulo or Rio de Janeiro"
                className="nl-textarea"
                rows={3}
              />
              
              {isProcessing && (
                <div className="processing-indicator">
                  <span className="spinner">⏳</span> Processing natural language...
                </div>
              )}
            </div>

            {parsedNLQuery && (
              <div className="nl-analysis">
                <div className="analysis-header">
                  <h4>Query Analysis</h4>
                  <div className={`confidence-score ${getConfidenceClass(parsedNLQuery.confidence)}`}>
                    {Math.round(parsedNLQuery.confidence * 100)}% confidence
                  </div>
                </div>

                {/* Extracted Entities */}
                {parsedNLQuery.entities.length > 0 && (
                  <div className="extracted-entities">
                    <h5>Extracted Information:</h5>
                    <div className="entities-list">
                      {parsedNLQuery.entities.map((entity, index) => (
                        <span key={index} className={`entity entity-${entity.type}`}>
                          {entity.text} ({entity.type})
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Parsed Conditions */}
                {parsedNLQuery.parsedConditions.length > 0 && (
                  <div className="parsed-conditions">
                    <h5>Parsed Search Conditions:</h5>
                    <div className="conditions-preview">
                      {parsedNLQuery.parsedConditions.map((condition, index) => (
                        <div key={condition.id} className="condition-preview">
                          {index > 0 && condition.logicalOperator && (
                            <span className="logical-op">{condition.logicalOperator}</span>
                          )}
                          <span className="field">{condition.field}</span>
                          <span className="operator">{condition.operator}</span>
                          <span className="value">{String(condition.value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Suggestions */}
                {parsedNLQuery.suggestions.length > 0 && (
                  <div className="nl-suggestions">
                    <h5>💡 Suggestions to improve your query:</h5>
                    <ul>
                      {parsedNLQuery.suggestions.map((suggestion, index) => (
                        <li key={index}>{suggestion}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Visual Builder Tab */}
        {activeTab === 'visual' && (
          <div className="visual-builder-panel">
            <div className="conditions-list">
              {visualConditions.map((condition, index) => (
                <div key={condition.id} className="visual-condition">
                  {index > 0 && (
                    <select
                      value={condition.logicalOperator || 'AND'}
                      onChange={(e) => updateVisualCondition(condition.id, { 
                        logicalOperator: e.target.value as 'AND' | 'OR' | 'NOT' 
                      })}
                      className="logical-operator-select"
                    >
                      <option value="AND">AND</option>
                      <option value="OR">OR</option>
                      <option value="NOT">NOT</option>
                    </select>
                  )}

                  <select
                    value={condition.field}
                    onChange={(e) => updateVisualCondition(condition.id, { 
                      field: e.target.value as QueryCondition['field']
                    })}
                    className="field-select"
                  >
                    {fieldOptions.map(option => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>

                  <select
                    value={condition.operator}
                    onChange={(e) => updateVisualCondition(condition.id, { 
                      operator: e.target.value as QueryCondition['operator']
                    })}
                    className="operator-select"
                  >
                    {getOperatorsForField(condition.field).map(option => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>

                  <ConditionValueInput
                    condition={condition}
                    onChange={(value) => updateVisualCondition(condition.id, { value })}
                  />

                  <button
                    onClick={() => removeVisualCondition(condition.id)}
                    className="remove-condition-btn"
                    title="Remove condition"
                  >
                    ❌
                  </button>
                </div>
              ))}

              <button onClick={addVisualCondition} className="add-condition-btn">
                ➕ Add Condition
              </button>
            </div>

            {visualConditions.length > 0 && (
              <div className="query-preview">
                <h5>Generated Query:</h5>
                <pre className="query-code">{generateQueryString(visualConditions)}</pre>
              </div>
            )}
          </div>
        )}

        {/* Advanced Syntax Tab */}
        {activeTab === 'advanced' && (
          <div className="advanced-syntax-panel">
            <div className="syntax-help">
              <h5>Advanced Search Syntax:</h5>
              <div className="syntax-examples">
                <div className="syntax-example">
                  <code>title:"transport law"</code> - Exact phrase in title
                </div>
                <div className="syntax-example">
                  <code>author:ANTT AND type:resolucao</code> - Combine conditions
                </div>
                <div className="syntax-example">
                  <code>date:[2020 TO 2023]</code> - Date range
                </div>
                <div className="syntax-example">
                  <code>state:(SP OR RJ) NOT keywords:revoked</code> - Complex logic
                </div>
              </div>
            </div>

            <textarea
              value={advancedQuery}
              onChange={(e) => setAdvancedQuery(e.target.value)}
              placeholder="Enter your advanced search query using the syntax above..."
              className="advanced-textarea"
              rows={5}
            />
          </div>
        )}
      </div>

      <div className="query-builder-actions">
        <button
          onClick={handleExecuteSearch}
          disabled={!hasValidQuery()}
          className="execute-search-btn"
        >
          🔍 Execute Search
        </button>
        
        <button
          onClick={() => {
            setNaturalQuery('');
            setVisualConditions([]);
            setAdvancedQuery('');
            setParsedNLQuery(null);
          }}
          className="clear-query-btn"
        >
          🗑️ Clear All
        </button>
      </div>
    </div>
  );

  // Helper function to check if we have a valid query
  function hasValidQuery(): boolean {
    switch (activeTab) {
      case 'natural':
        return naturalQuery.trim().length > 0;
      case 'visual':
        return visualConditions.length > 0 && visualConditions.every(c => 
          c.value && String(c.value).trim().length > 0
        );
      case 'advanced':
        return advancedQuery.trim().length > 0;
      default:
        return false;
    }
  }
};

// Helper component for condition value input
const ConditionValueInput: React.FC<{
  condition: QueryCondition;
  onChange: (value: any) => void;
}> = ({ condition, onChange }) => {
  if (condition.field === 'date') {
    if (condition.operator === 'between') {
      const range = condition.value as { start: Date; end: Date } || { start: new Date(), end: new Date() };
      return (
        <div className="date-range-input">
          <input
            type="date"
            value={formatDateForInput(range.start)}
            onChange={(e) => onChange({ ...range, start: new Date(e.target.value) })}
          />
          <span>to</span>
          <input
            type="date"
            value={formatDateForInput(range.end)}
            onChange={(e) => onChange({ ...range, end: new Date(e.target.value) })}
          />
        </div>
      );
    } else {
      return (
        <input
          type="date"
          value={formatDateForInput(condition.value as Date)}
          onChange={(e) => onChange(new Date(e.target.value))}
          className="condition-input"
        />
      );
    }
  }

  if (condition.field === 'type') {
    const documentTypes: DocumentType[] = ['lei', 'decreto', 'portaria', 'resolucao', 'instrucao_normativa', 'projeto_lei', 'medida_provisoria'];
    
    if (condition.operator === 'in' || condition.operator === 'not_in') {
      return (
        <select
          multiple
          value={condition.value as string[]}
          onChange={(e) => {
            const values = Array.from(e.target.selectedOptions, option => option.value);
            onChange(values);
          }}
          className="condition-select-multiple"
        >
          {documentTypes.map(type => (
            <option key={type} value={type}>{type.toUpperCase()}</option>
          ))}
        </select>
      );
    } else {
      return (
        <select
          value={condition.value as string}
          onChange={(e) => onChange(e.target.value)}
          className="condition-select"
        >
          <option value="">Select type...</option>
          {documentTypes.map(type => (
            <option key={type} value={type}>{type.toUpperCase()}</option>
          ))}
        </select>
      );
    }
  }

  return (
    <input
      type="text"
      value={condition.value as string}
      onChange={(e) => onChange(e.target.value)}
      className="condition-input"
      placeholder="Enter value..."
    />
  );
};

// Helper functions
function extractEntities(text: string) {
  const entities = [];
  
  // Extract dates
  const dateRegex = /\b(20\d{2}|19\d{2})\b|\b(janeiro|fevereiro|março|abril|maio|junho|julho|agosto|setembro|outubro|novembro|dezembro)\b|\b(antes|depois|após)\s+(de\s+)?20\d{2}\b/gi;
  let match;
  while ((match = dateRegex.exec(text)) !== null) {
    entities.push({
      text: match[0],
      type: 'date' as const,
      startPos: match.index,
      endPos: match.index + match[0].length,
      confidence: 0.8
    });
  }

  // Extract Brazilian states
  const stateRegex = /\b(SP|RJ|MG|RS|PR|SC|BA|GO|DF|ES|MT|MS|PA|AM|RO|AC|RR|AP|TO|MA|PI|CE|RN|PB|PE|AL|SE)\b|\b(São Paulo|Rio de Janeiro|Minas Gerais|Rio Grande do Sul)\b/gi;
  while ((match = stateRegex.exec(text)) !== null) {
    entities.push({
      text: match[0],
      type: 'location' as const,
      startPos: match.index,
      endPos: match.index + match[0].length,
      confidence: 0.9
    });
  }

  // Extract document types
  const typeRegex = /\b(lei|decreto|portaria|resolução|instrução normativa|projeto de lei|medida provisória)\b/gi;
  while ((match = typeRegex.exec(text)) !== null) {
    entities.push({
      text: match[0],
      type: 'document_type' as const,
      startPos: match.index,
      endPos: match.index + match[0].length,
      confidence: 0.95
    });
  }

  return entities;
}

async function parseToConditions(text: string, entities: any[]): Promise<QueryCondition[]> {
  const conditions: QueryCondition[] = [];
  
  // Simple parsing logic - in production, this would be more sophisticated
  entities.forEach((entity, index) => {
    const condition: QueryCondition = {
      id: `parsed_${index}`,
      field: mapEntityTypeToField(entity.type),
      operator: 'contains',
      value: entity.text,
      logicalOperator: index > 0 ? 'AND' : undefined
    };
    
    conditions.push(condition);
  });

  return conditions;
}

function mapEntityTypeToField(entityType: string): QueryCondition['field'] {
  switch (entityType) {
    case 'date': return 'date';
    case 'location': return 'state';
    case 'document_type': return 'type';
    case 'organization': return 'author';
    default: return 'content';
  }
}

function calculateParsingConfidence(text: string, entities: any[], conditions: QueryCondition[]): number {
  const entityCoverage = entities.length / Math.max(text.split(' ').length, 1);
  const conditionQuality = conditions.length > 0 ? 0.8 : 0.3;
  return Math.min(entityCoverage + conditionQuality, 1);
}

function generateSuggestions(text: string, entities: any[]): string[] {
  const suggestions = [];
  
  if (entities.length === 0) {
    suggestions.push('Try adding specific terms like document types (lei, decreto) or dates');
  }
  
  if (!entities.some(e => e.type === 'date')) {
    suggestions.push('Consider adding a time period to narrow your search');
  }
  
  if (!entities.some(e => e.type === 'location')) {
    suggestions.push('Specify a Brazilian state to limit geographical scope');
  }

  return suggestions;
}

function getConfidenceClass(confidence: number): string {
  if (confidence >= 0.8) return 'high';
  if (confidence >= 0.6) return 'medium';
  return 'low';
}

function formatDate(date: Date): string {
  return date.toISOString().split('T')[0];
}

function formatDateForInput(date: Date | string): string {
  if (!date) return '';
  return new Date(date).toISOString().split('T')[0];
}

// CSS styles (to be injected)
const queryBuilderStyles = `
.search-query-builder {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.query-builder-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
  border-bottom: 1px solid #e2e8f0;
  padding-bottom: 1rem;
}

.query-builder-header h3 {
  color: #2d3748;
  font-size: 1.25rem;
  margin: 0;
}

.query-tabs {
  display: flex;
  gap: 0.5rem;
}

.tab {
  padding: 0.5rem 1rem;
  border: 1px solid #e2e8f0;
  background: #f7fafc;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.tab:hover {
  background: #edf2f7;
}

.tab.active {
  background: #4299e1;
  color: #ffffff;
  border-color: #4299e1;
}

.query-builder-content {
  min-height: 300px;
}

/* Natural Language Panel */
.natural-language-panel {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.nl-input-section label {
  display: block;
  font-weight: 500;
  color: #4a5568;
  margin-bottom: 0.5rem;
}

.nl-textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
  resize: vertical;
}

.processing-indicator {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: #4a5568;
  font-size: 0.875rem;
  margin-top: 0.5rem;
}

.spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.nl-analysis {
  background: #f7fafc;
  border-radius: 6px;
  padding: 1rem;
}

.analysis-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.analysis-header h4 {
  color: #2d3748;
  font-size: 1rem;
  margin: 0;
}

.confidence-score {
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 600;
}

.confidence-score.high {
  background: #c6f6d5;
  color: #22543d;
}

.confidence-score.medium {
  background: #fef5e7;
  color: #744210;
}

.confidence-score.low {
  background: #fed7d7;
  color: #742a2a;
}

.extracted-entities h5,
.parsed-conditions h5,
.nl-suggestions h5 {
  color: #2d3748;
  font-size: 0.875rem;
  margin: 0 0 0.75rem 0;
  font-weight: 600;
}

.entities-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.entity {
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 500;
}

.entity-date {
  background: #dbeafe;
  color: #1e40af;
}

.entity-location {
  background: #d1fae5;
  color: #065f46;
}

.entity-document_type {
  background: #fef3c7;
  color: #92400e;
}

.entity-organization {
  background: #e0e7ff;
  color: #3730a3;
}

.conditions-preview {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.condition-preview {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
}

.logical-op {
  background: #4299e1;
  color: #ffffff;
  padding: 0.125rem 0.25rem;
  border-radius: 2px;
  font-size: 0.75rem;
  font-weight: 600;
}

.field, .operator, .value {
  padding: 0.125rem 0.25rem;
  border-radius: 2px;
  font-family: monospace;
}

.field {
  background: #e2e8f0;
  color: #2d3748;
}

.operator {
  background: #fed7d7;
  color: #742a2a;
}

.value {
  background: #c6f6d5;
  color: #22543d;
}

.nl-suggestions ul {
  margin: 0;
  padding-left: 1.5rem;
}

.nl-suggestions li {
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
  color: #4a5568;
}

/* Visual Builder Panel */
.visual-builder-panel {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.conditions-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.visual-condition {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  background: #f7fafc;
  border-radius: 6px;
  border: 1px solid #e2e8f0;
}

.logical-operator-select,
.field-select,
.operator-select,
.condition-select {
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
  background: #ffffff;
}

.condition-input {
  flex: 1;
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
}

.condition-select-multiple {
  min-width: 150px;
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
  background: #ffffff;
}

.date-range-input {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.date-range-input span {
  font-size: 0.875rem;
  color: #4a5568;
}

.remove-condition-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 1rem;
  padding: 0.25rem;
  border-radius: 3px;
  transition: background-color 0.2s;
}

.remove-condition-btn:hover {
  background: #fed7d7;
}

.add-condition-btn {
  background: #48bb78;
  color: #ffffff;
  border: none;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  font-size: 0.875rem;
  cursor: pointer;
  transition: background-color 0.2s;
}

.add-condition-btn:hover {
  background: #38a169;
}

.query-preview {
  background: #1a202c;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: 6px;
}

.query-preview h5 {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0 0 0.5rem 0;
}

.query-code {
  margin: 0;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  white-space: pre-wrap;
  word-break: break-all;
}

/* Advanced Syntax Panel */
.advanced-syntax-panel {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.syntax-help h5 {
  color: #2d3748;
  font-size: 1rem;
  margin: 0 0 1rem 0;
}

.syntax-examples {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.syntax-example {
  background: #f7fafc;
  padding: 0.5rem;
  border-radius: 4px;
  border-left: 3px solid #4299e1;
}

.syntax-example code {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  color: #2d3748;
}

.advanced-textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  resize: vertical;
}

/* Actions */
.query-builder-actions {
  display: flex;
  justify-content: space-between;
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid #e2e8f0;
}

.execute-search-btn,
.clear-query-btn {
  padding: 0.75rem 1.5rem;
  border: none;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.execute-search-btn {
  background: #4299e1;
  color: #ffffff;
}

.execute-search-btn:hover:not(:disabled) {
  background: #3182ce;
}

.execute-search-btn:disabled {
  background: #a0aec0;
  cursor: not-allowed;
}

.clear-query-btn {
  background: #f7fafc;
  color: #4a5568;
  border: 1px solid #e2e8f0;
}

.clear-query-btn:hover {
  background: #edf2f7;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = queryBuilderStyles;
  document.head.appendChild(styleElement);
}