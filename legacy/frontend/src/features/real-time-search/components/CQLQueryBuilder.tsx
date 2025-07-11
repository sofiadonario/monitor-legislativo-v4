/**
 * Visual CQL Query Builder Component
 * Drag-and-drop interface for building complex CQL queries
 */

import React, { useState, useCallback } from 'react';
import { DocumentType, Autoridade } from '../types/lexml-api.types';

interface CQLCondition {
  id: string;
  field: string;
  operator: 'exact' | 'any' | 'all' | 'within';
  value: string;
  connector?: 'AND' | 'OR' | 'NOT';
}

interface CQLGroup {
  id: string;
  conditions: CQLCondition[];
  connector?: 'AND' | 'OR';
}

interface CQLQueryBuilderProps {
  onQueryChange: (cqlQuery: string) => void;
  onValidationChange?: (isValid: boolean, error?: string) => void;
  initialQuery?: string;
  className?: string;
}

const FIELD_OPTIONS = [
  { value: 'title', label: 'Title', description: 'Document title' },
  { value: 'description', label: 'Description', description: 'Document description/summary' },
  { value: 'tipoDocumento', label: 'Document Type', description: 'Type of legal document' },
  { value: 'autoridade', label: 'Authority', description: 'Issuing authority level' },
  { value: 'localidade', label: 'Location', description: 'Geographic jurisdiction' },
  { value: 'subject', label: 'Subject', description: 'Document subject/topic' },
  { value: 'date', label: 'Date', description: 'Publication date' },
  { value: 'urn', label: 'URN', description: 'Unique identifier' }
];

const OPERATOR_OPTIONS = [
  { value: 'exact', label: 'Exact Match', description: 'Exact value match' },
  { value: 'any', label: 'Contains Any', description: 'Contains any of the words' },
  { value: 'all', label: 'Contains All', description: 'Contains all words' },
  { value: 'within', label: 'Within Range', description: 'Within date/number range' }
];

const CONNECTOR_OPTIONS = [
  { value: 'AND', label: 'AND', description: 'Both conditions must be true' },
  { value: 'OR', label: 'OR', description: 'Either condition can be true' },
  { value: 'NOT', label: 'NOT', description: 'Condition must not be true' }
];

const DOCUMENT_TYPES: DocumentType[] = [
  'Lei', 'Decreto', 'Decreto-Lei', 'Medida Provisória', 'Portaria', 
  'Resolução', 'Instrução Normativa', 'Emenda Constitucional', 'Acórdão', 'Parecer'
];

const AUTHORITIES: Autoridade[] = ['federal', 'estadual', 'municipal', 'distrital'];

const COMMON_LOCATIONS = [
  'br', 'sao.paulo', 'rio.de.janeiro', 'minas.gerais', 'rio.grande.sul',
  'parana', 'bahia', 'distrito.federal', 'espirito.santo', 'goias'
];

export const CQLQueryBuilder: React.FC<CQLQueryBuilderProps> = ({
  onQueryChange,
  onValidationChange,
  initialQuery,
  className = ''
}) => {
  const [groups, setGroups] = useState<CQLGroup[]>([
    {
      id: 'group-1',
      conditions: [
        {
          id: 'condition-1',
          field: 'title',
          operator: 'any',
          value: ''
        }
      ]
    }
  ]);

  const [previewMode, setPreviewMode] = useState<'visual' | 'query'>('visual');

  // Generate CQL query from visual builder
  const generateCQLQuery = useCallback((groupsData: CQLGroup[]): string => {
    const groupQueries = groupsData.map(group => {
      if (group.conditions.length === 0) return '';
      
      const conditionQueries = group.conditions.map(condition => {
        if (!condition.value.trim()) return '';
        
        let query = '';
        const escapedValue = condition.value.replace(/"/g, '\\"');
        
        // Handle special fields
        if (condition.field === 'date' && condition.operator === 'within') {
          // Date range format: date within "2020 2024"
          query = `date within "${escapedValue}"`;
        } else {
          query = `${condition.field} ${condition.operator} "${escapedValue}"`;
        }
        
        return query;
      }).filter(q => q.length > 0);
      
      if (conditionQueries.length === 0) return '';
      
      // Connect conditions within group
      let groupQuery = conditionQueries[0];
      for (let i = 1; i < conditionQueries.length; i++) {
        const connector = group.conditions[i].connector || 'AND';
        groupQuery += ` ${connector} ${conditionQueries[i]}`;
      }
      
      return conditionQueries.length > 1 ? `(${groupQuery})` : groupQuery;
    }).filter(q => q.length > 0);
    
    if (groupQueries.length === 0) return '*';
    if (groupQueries.length === 1) return groupQueries[0];
    
    // Connect groups with AND by default
    return groupQueries.join(' AND ');
  }, []);

  // Update CQL query when groups change
  React.useEffect(() => {
    const query = generateCQLQuery(groups);
    onQueryChange(query);
    
    // Validate query
    const isValid = query === '*' || groups.some(group => 
      group.conditions.some(condition => condition.value.trim().length > 0)
    );
    onValidationChange?.(isValid, isValid ? undefined : 'Query cannot be empty');
  }, [groups, generateCQLQuery, onQueryChange, onValidationChange]);

  // Add new condition to group
  const addCondition = (groupId: string) => {
    setGroups(prev => prev.map(group => {
      if (group.id === groupId) {
        const newCondition: CQLCondition = {
          id: `condition-${Date.now()}`,
          field: 'title',
          operator: 'any',
          value: '',
          connector: 'AND'
        };
        return {
          ...group,
          conditions: [...group.conditions, newCondition]
        };
      }
      return group;
    }));
  };

  // Remove condition
  const removeCondition = (groupId: string, conditionId: string) => {
    setGroups(prev => prev.map(group => {
      if (group.id === groupId) {
        return {
          ...group,
          conditions: group.conditions.filter(c => c.id !== conditionId)
        };
      }
      return group;
    }));
  };

  // Update condition
  const updateCondition = (groupId: string, conditionId: string, updates: Partial<CQLCondition>) => {
    setGroups(prev => prev.map(group => {
      if (group.id === groupId) {
        return {
          ...group,
          conditions: group.conditions.map(condition => {
            if (condition.id === conditionId) {
              return { ...condition, ...updates };
            }
            return condition;
          })
        };
      }
      return group;
    }));
  };

  // Add new group
  const addGroup = () => {
    const newGroup: CQLGroup = {
      id: `group-${Date.now()}`,
      conditions: [
        {
          id: `condition-${Date.now()}`,
          field: 'title',
          operator: 'any',
          value: ''
        }
      ],
      connector: 'AND'
    };
    setGroups(prev => [...prev, newGroup]);
  };

  // Remove group
  const removeGroup = (groupId: string) => {
    if (groups.length > 1) {
      setGroups(prev => prev.filter(g => g.id !== groupId));
    }
  };

  // Get value suggestions based on field
  const getValueSuggestions = (field: string): string[] => {
    switch (field) {
      case 'tipoDocumento':
        return DOCUMENT_TYPES;
      case 'autoridade':
        return AUTHORITIES;
      case 'localidade':
        return COMMON_LOCATIONS;
      case 'subject':
        return ['transporte', 'transporte urbano', 'mobilidade', 'infraestrutura', 'logística'];
      default:
        return [];
    }
  };

  // Generate query string for preview
  const currentQuery = generateCQLQuery(groups);

  return (
    <div className={`bg-white border border-gray-200 rounded-lg ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900">CQL Query Builder</h3>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-gray-300">
            <button
              onClick={() => setPreviewMode('visual')}
              className={`px-3 py-1 text-sm rounded-l-lg ${
                previewMode === 'visual' 
                  ? 'bg-blue-500 text-white' 
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              Visual
            </button>
            <button
              onClick={() => setPreviewMode('query')}
              className={`px-3 py-1 text-sm rounded-r-lg ${
                previewMode === 'query' 
                  ? 'bg-blue-500 text-white' 
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              Query
            </button>
          </div>
        </div>
      </div>

      <div className="p-4">
        {previewMode === 'visual' ? (
          /* Visual Builder */
          <div className="space-y-4">
            {groups.map((group, groupIndex) => (
              <div key={group.id} className="border border-gray-200 rounded-lg p-4">
                {/* Group Header */}
                <div className="flex items-center justify-between mb-4">
                  <span className="text-sm font-medium text-gray-700">
                    Group {groupIndex + 1}
                  </span>
                  <div className="flex items-center gap-2">
                    {groupIndex > 0 && (
                      <select
                        value={group.connector || 'AND'}
                        onChange={(e) => {
                          setGroups(prev => prev.map(g => 
                            g.id === group.id 
                              ? { ...g, connector: e.target.value as 'AND' | 'OR' }
                              : g
                          ));
                        }}
                        className="text-xs border border-gray-300 rounded px-2 py-1"
                      >
                        {CONNECTOR_OPTIONS.map(conn => (
                          <option key={conn.value} value={conn.value}>
                            {conn.label}
                          </option>
                        ))}
                      </select>
                    )}
                    {groups.length > 1 && (
                      <button
                        onClick={() => removeGroup(group.id)}
                        className="text-red-600 hover:text-red-800 text-sm"
                      >
                        Remove Group
                      </button>
                    )}
                  </div>
                </div>

                {/* Conditions */}
                <div className="space-y-3">
                  {group.conditions.map((condition, conditionIndex) => (
                    <div key={condition.id} className="flex items-center gap-2 p-2 bg-gray-50 rounded">
                      {/* Connector */}
                      {conditionIndex > 0 && (
                        <select
                          value={condition.connector || 'AND'}
                          onChange={(e) => updateCondition(group.id, condition.id, { 
                            connector: e.target.value as 'AND' | 'OR' | 'NOT' 
                          })}
                          className="text-xs border border-gray-300 rounded px-2 py-1 w-16"
                        >
                          {CONNECTOR_OPTIONS.map(conn => (
                            <option key={conn.value} value={conn.value}>
                              {conn.label}
                            </option>
                          ))}
                        </select>
                      )}

                      {/* Field */}
                      <select
                        value={condition.field}
                        onChange={(e) => updateCondition(group.id, condition.id, { field: e.target.value })}
                        className="text-sm border border-gray-300 rounded px-2 py-1 min-w-32"
                      >
                        {FIELD_OPTIONS.map(field => (
                          <option key={field.value} value={field.value} title={field.description}>
                            {field.label}
                          </option>
                        ))}
                      </select>

                      {/* Operator */}
                      <select
                        value={condition.operator}
                        onChange={(e) => updateCondition(group.id, condition.id, { 
                          operator: e.target.value as 'exact' | 'any' | 'all' | 'within' 
                        })}
                        className="text-sm border border-gray-300 rounded px-2 py-1 min-w-24"
                      >
                        {OPERATOR_OPTIONS.map(op => (
                          <option key={op.value} value={op.value} title={op.description}>
                            {op.label}
                          </option>
                        ))}
                      </select>

                      {/* Value */}
                      <div className="flex-1 relative">
                        <input
                          type="text"
                          value={condition.value}
                          onChange={(e) => updateCondition(group.id, condition.id, { value: e.target.value })}
                          placeholder={`Enter ${condition.field} value...`}
                          className="w-full text-sm border border-gray-300 rounded px-2 py-1"
                          list={`suggestions-${condition.id}`}
                        />
                        
                        {/* Value suggestions */}
                        <datalist id={`suggestions-${condition.id}`}>
                          {getValueSuggestions(condition.field).map(suggestion => (
                            <option key={suggestion} value={suggestion} />
                          ))}
                        </datalist>
                      </div>

                      {/* Remove condition */}
                      {group.conditions.length > 1 && (
                        <button
                          onClick={() => removeCondition(group.id, condition.id)}
                          className="text-red-600 hover:text-red-800 p-1"
                          title="Remove condition"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  ))}
                </div>

                {/* Add condition */}
                <button
                  onClick={() => addCondition(group.id)}
                  className="mt-2 text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1"
                >
                  + Add Condition
                </button>
              </div>
            ))}

            {/* Add group */}
            <button
              onClick={addGroup}
              className="w-full py-2 border-2 border-dashed border-gray-300 rounded-lg text-gray-600 hover:border-gray-400 hover:text-gray-800 transition-colors"
            >
              + Add Group
            </button>
          </div>
        ) : (
          /* Query Preview */
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Generated CQL Query:
              </label>
              <div className="bg-gray-100 border border-gray-300 rounded-lg p-4">
                <code className="text-sm text-gray-800 break-all">
                  {currentQuery}
                </code>
              </div>
            </div>
            
            <div>
              <h4 className="text-sm font-medium text-gray-700 mb-2">Query Explanation:</h4>
              <div className="text-sm text-gray-600 space-y-1">
                {groups.map((group, index) => (
                  <div key={group.id}>
                    <strong>Group {index + 1}:</strong> {
                      group.conditions
                        .filter(c => c.value.trim())
                        .map(c => `${c.field} ${c.operator} "${c.value}"`)
                        .join(` ${group.conditions[1]?.connector || 'AND'} `)
                    }
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Query Examples */}
        <div className="mt-6 p-3 bg-blue-50 rounded-lg">
          <h4 className="text-sm font-medium text-blue-900 mb-2">Common Query Patterns:</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
            <button 
              onClick={() => onQueryChange('tipoDocumento exact "Lei" AND title any "transporte"')}
              className="text-left p-2 bg-blue-100 rounded hover:bg-blue-200"
            >
              <strong>Transport Laws:</strong><br />
              <code>tipoDocumento exact "Lei" AND title any "transporte"</code>
            </button>
            <button 
              onClick={() => onQueryChange('autoridade exact "federal" AND date within "2020 2024"')}
              className="text-left p-2 bg-blue-100 rounded hover:bg-blue-200"
            >
              <strong>Recent Federal Acts:</strong><br />
              <code>autoridade exact "federal" AND date within "2020 2024"</code>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CQLQueryBuilder;