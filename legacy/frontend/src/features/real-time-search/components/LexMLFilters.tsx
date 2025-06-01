/**
 * LexML Advanced Filters Component
 * Provides filtering options based on LexML taxonomy
 */

import React, { useState } from 'react';
import { SearchFilters, DocumentType, Autoridade } from '../types/lexml-api.types';

interface LexMLFiltersProps {
  filters: SearchFilters;
  onFiltersChange: (filters: Partial<SearchFilters>) => void;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  className?: string;
}

const documentTypes: { value: DocumentType; label: string; description: string }[] = [
  { value: 'Lei', label: 'Lei', description: 'Federal, state, or municipal laws' },
  { value: 'Decreto', label: 'Decreto', description: 'Executive decrees and regulations' },
  { value: 'Decreto-Lei', label: 'Decreto-Lei', description: 'Decree-laws (historical)' },
  { value: 'Medida Provisória', label: 'Medida Provisória', description: 'Provisional measures' },
  { value: 'Portaria', label: 'Portaria', description: 'Administrative ordinances' },
  { value: 'Resolução', label: 'Resolução', description: 'Resolutions and decisions' },
  { value: 'Instrução Normativa', label: 'Instrução Normativa', description: 'Normative instructions' },
  { value: 'Emenda Constitucional', label: 'Emenda Constitucional', description: 'Constitutional amendments' },
  { value: 'Acórdão', label: 'Acórdão', description: 'Court decisions and rulings' },
  { value: 'Parecer', label: 'Parecer', description: 'Legal opinions and reports' }
];

const autoridades: { value: Autoridade; label: string; description: string }[] = [
  { value: 'federal', label: 'Federal', description: 'Federal government authorities' },
  { value: 'estadual', label: 'Estadual', description: 'State government authorities' },
  { value: 'municipal', label: 'Municipal', description: 'Municipal government authorities' },
  { value: 'distrital', label: 'Distrital', description: 'Federal District authorities' }
];

const brazilianStates = [
  { code: 'br', name: 'Federal (Brasil)', description: 'Federal legislation' },
  { code: 'sao.paulo', name: 'São Paulo', description: 'SP state legislation' },
  { code: 'rio.de.janeiro', name: 'Rio de Janeiro', description: 'RJ state legislation' },
  { code: 'minas.gerais', name: 'Minas Gerais', description: 'MG state legislation' },
  { code: 'rio.grande.sul', name: 'Rio Grande do Sul', description: 'RS state legislation' },
  { code: 'parana', name: 'Paraná', description: 'PR state legislation' },
  { code: 'bahia', name: 'Bahia', description: 'BA state legislation' },
  { code: 'distrito.federal', name: 'Distrito Federal', description: 'DF legislation' },
  { code: 'espirito.santo', name: 'Espírito Santo', description: 'ES state legislation' },
  { code: 'goias', name: 'Goiás', description: 'GO state legislation' },
  { code: 'santa.catarina', name: 'Santa Catarina', description: 'SC state legislation' },
  { code: 'ceara', name: 'Ceará', description: 'CE state legislation' }
];

const transportSubjects = [
  'transporte',
  'transporte urbano',
  'transporte público',
  'transporte de carga',
  'transporte rodoviário',
  'transporte ferroviário',
  'transporte aquaviário',
  'transporte aéreo',
  'logística',
  'infraestrutura',
  'mobilidade urbana',
  'trânsito',
  'pedágio',
  'combustível',
  'frete',
  'carga',
  'veículo'
];

export const LexMLFilters: React.FC<LexMLFiltersProps> = ({
  filters,
  onFiltersChange,
  isCollapsed = false,
  onToggleCollapse,
  className = ''
}) => {
  const [dateFrom, setDateFrom] = useState(filters.date_from || '');
  const [dateTo, setDateTo] = useState(filters.date_to || '');

  const handleDocumentTypeChange = (type: DocumentType, checked: boolean) => {
    const newTypes = checked
      ? [...filters.tipoDocumento, type]
      : filters.tipoDocumento.filter(t => t !== type);
    
    onFiltersChange({ tipoDocumento: newTypes });
  };

  const handleAutoridadeChange = (auth: Autoridade, checked: boolean) => {
    const newAuth = checked
      ? [...filters.autoridade, auth]
      : filters.autoridade.filter(a => a !== auth);
    
    onFiltersChange({ autoridade: newAuth });
  };

  const handleLocalidadeChange = (loc: string, checked: boolean) => {
    const newLoc = checked
      ? [...filters.localidade, loc]
      : filters.localidade.filter(l => l !== loc);
    
    onFiltersChange({ localidade: newLoc });
  };

  const handleSubjectChange = (subject: string, checked: boolean) => {
    const newSubjects = checked
      ? [...filters.subject, subject]
      : filters.subject.filter(s => s !== subject);
    
    onFiltersChange({ subject: newSubjects });
  };

  const handleDateFromChange = (date: string) => {
    setDateFrom(date);
    onFiltersChange({ date_from: date || undefined });
  };

  const handleDateToChange = (date: string) => {
    setDateTo(date);
    onFiltersChange({ date_to: date || undefined });
  };

  const clearAllFilters = () => {
    setDateFrom('');
    setDateTo('');
    onFiltersChange({
      tipoDocumento: [],
      autoridade: [],
      localidade: [],
      subject: [],
      date_from: undefined,
      date_to: undefined
    });
  };

  const activeFilterCount = 
    filters.tipoDocumento.length + 
    filters.autoridade.length + 
    filters.localidade.length + 
    filters.subject.length + 
    (filters.date_from ? 1 : 0) + 
    (filters.date_to ? 1 : 0);

  if (isCollapsed) {
    return (
      <div className={`bg-white border border-gray-200 rounded-lg p-4 ${className}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-700">Filters</span>
            {activeFilterCount > 0 && (
              <span className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full">
                {activeFilterCount} active
              </span>
            )}
          </div>
          <button
            onClick={onToggleCollapse}
            className="text-sm text-blue-600 hover:text-blue-800"
          >
            Show filters
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white border border-gray-200 rounded-lg ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <div className="flex items-center gap-2">
          <span className="text-lg font-semibold text-gray-800">Advanced Filters</span>
          {activeFilterCount > 0 && (
            <span className="bg-blue-100 text-blue-800 text-sm px-2 py-1 rounded-full">
              {activeFilterCount} active
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {activeFilterCount > 0 && (
            <button
              onClick={clearAllFilters}
              className="text-sm text-red-600 hover:text-red-800"
            >
              Clear all
            </button>
          )}
          {onToggleCollapse && (
            <button
              onClick={onToggleCollapse}
              className="text-sm text-gray-600 hover:text-gray-800"
            >
              Hide filters
            </button>
          )}
        </div>
      </div>

      <div className="p-4 space-y-6">
        {/* Document Type Filter */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Document Type</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {documentTypes.map(type => (
              <label key={type.value} className="flex items-center space-x-2 text-sm">
                <input
                  type="checkbox"
                  checked={filters.tipoDocumento.includes(type.value)}
                  onChange={(e) => handleDocumentTypeChange(type.value, e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">{type.label}</span>
                <span className="text-gray-400 text-xs">({type.description})</span>
              </label>
            ))}
          </div>
        </div>

        {/* Authority Level Filter */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Authority Level</h3>
          <div className="grid grid-cols-2 gap-2">
            {autoridades.map(auth => (
              <label key={auth.value} className="flex items-center space-x-2 text-sm">
                <input
                  type="checkbox"
                  checked={filters.autoridade.includes(auth.value)}
                  onChange={(e) => handleAutoridadeChange(auth.value, e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">{auth.label}</span>
                <span className="text-gray-400 text-xs">({auth.description})</span>
              </label>
            ))}
          </div>
        </div>

        {/* Geographic Filter */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Geographic Scope</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto">
            {brazilianStates.map(state => (
              <label key={state.code} className="flex items-center space-x-2 text-sm">
                <input
                  type="checkbox"
                  checked={filters.localidade.includes(state.code)}
                  onChange={(e) => handleLocalidadeChange(state.code, e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">{state.name}</span>
                <span className="text-gray-400 text-xs">({state.description})</span>
              </label>
            ))}
          </div>
        </div>

        {/* Date Range Filter */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Date Range</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-600 mb-1">From</label>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => handleDateFromChange(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-600 mb-1">To</label>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => handleDateToChange(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
        </div>

        {/* Subject/Topic Filter */}
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-3">Transport Topics</h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-h-32 overflow-y-auto">
            {transportSubjects.map(subject => (
              <label key={subject} className="flex items-center space-x-2 text-sm">
                <input
                  type="checkbox"
                  checked={filters.subject.includes(subject)}
                  onChange={(e) => handleSubjectChange(subject, e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700 capitalize">{subject}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Active Filters Summary */}
        {activeFilterCount > 0 && (
          <div className="mt-6 p-3 bg-blue-50 rounded-lg">
            <h4 className="text-sm font-medium text-blue-800 mb-2">Active Filters:</h4>
            <div className="flex flex-wrap gap-2">
              {filters.tipoDocumento.map(type => (
                <span key={type} className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full">
                  Type: {type}
                </span>
              ))}
              {filters.autoridade.map(auth => (
                <span key={auth} className="bg-purple-100 text-purple-800 text-xs px-2 py-1 rounded-full">
                  Authority: {auth}
                </span>
              ))}
              {filters.localidade.map(loc => (
                <span key={loc} className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">
                  Location: {brazilianStates.find(s => s.code === loc)?.name || loc}
                </span>
              ))}
              {filters.subject.map(subj => (
                <span key={subj} className="bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded-full">
                  Topic: {subj}
                </span>
              ))}
              {filters.date_from && (
                <span className="bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded-full">
                  From: {filters.date_from}
                </span>
              )}
              {filters.date_to && (
                <span className="bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded-full">
                  To: {filters.date_to}
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default LexMLFilters;