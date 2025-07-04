import React from 'react';
import { LegislativeDocument } from '../types';

interface AccessibleMapProps {
  documents: LegislativeDocument[];
  onStateSelect: (stateId: string) => void;
  selectedState: string | undefined;
}

export const AccessibleMap: React.FC<AccessibleMapProps> = ({ documents, onStateSelect, selectedState }) => {
  
  const stateDocumentCounts = documents.reduce((acc, doc) => {
    if (doc.state) {
      acc[doc.state] = (acc[doc.state] || 0) + 1;
    }
    return acc;
  }, {} as Record<string, number>);

  const handleStateSelection = (stateId: string) => {
    onStateSelect(stateId);
  };

  return (
    <div className="accessible-map" role="application" aria-label="Interactive map of Brazilian states with legislation data">
      <h2 id="map-heading">Brazilian States Legislative Data</h2>
      
      {/* Screen reader alternative */}
      <div className="sr-only" aria-live="polite" id="map-status">
        {selectedState ? `Selected state: ${selectedState}` : 'No state selected'}
      </div>
      
      {/* Keyboard navigable state list */}
      <div role="group" aria-labelledby="map-heading">
        {Object.entries(stateDocumentCounts).map(([stateId, count]) => (
          <button
            key={stateId}
            className={`state-button ${selectedState === stateId ? 'selected' : ''}`}
            onClick={() => handleStateSelection(stateId)}
            aria-pressed={Boolean(selectedState === stateId)}
            aria-describedby={`${stateId}-info`}
          >
            <span className="state-name">{stateId}</span>
            <span className="state-count" id={`${stateId}-info`}>
              {count} {count === 1 ? 'document' : 'documents'}
            </span>
          </button>
        ))}
      </div>
      
      {/* Alternative text-based interface */}
      <div className="text-interface">
        <label htmlFor="state-select">Select state:</label>
        <select
          id="state-select"
          value={selectedState || ''}
          onChange={(e) => handleStateSelection(e.target.value)}
          aria-describedby="state-select-help"
        >
          <option value="">All states</option>
          {Object.keys(stateDocumentCounts).map(stateId => (
            <option key={stateId} value={stateId}>
              {stateId} ({stateDocumentCounts[stateId]} documents)
            </option>
          ))}
        </select>
        <div id="state-select-help" className="help-text">
          Choose a Brazilian state to filter legislation documents
        </div>
      </div>
    </div>
  );
};