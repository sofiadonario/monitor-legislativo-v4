import React, { useMemo } from 'react';
import { LegislativeDocument } from '../types';
import { countDocumentsByState, getMissingStates, BRAZILIAN_STATES } from '../utils/stateValidator';
import { getYearFromDate } from '../utils/dateParser';
import '../styles/components/DataDiagnostics.css';

interface DataDiagnosticsProps {
  documents: LegislativeDocument[];
}

export const DataDiagnostics: React.FC<DataDiagnosticsProps> = ({ documents }) => {
  const diagnostics = useMemo(() => {
    // State coverage analysis
    const stateCounts = countDocumentsByState(documents);
    const missingStates = getMissingStates(documents);
    const statesWithData = Object.entries(stateCounts)
      .filter(([_, count]) => count > 0)
      .length - 1; // Subtract 1 for Federal
    
    // Date analysis
    let validDates = 0;
    let invalidDates = 0;
    let missingDates = 0;
    const yearDistribution: Record<number, number> = {};
    
    documents.forEach(doc => {
      const year = getYearFromDate(doc.date);
      if (year === null) {
        missingDates++;
      } else if (year === 1900) {
        invalidDates++;
      } else {
        validDates++;
        yearDistribution[year] = (yearDistribution[year] || 0) + 1;
      }
    });
    
    // Sort years
    const sortedYears = Object.entries(yearDistribution)
      .sort(([a], [b]) => parseInt(a) - parseInt(b));
    
    return {
      totalDocuments: documents.length,
      stateCounts,
      missingStates,
      statesWithData,
      totalStates: Object.keys(BRAZILIAN_STATES).length,
      validDates,
      invalidDates,
      missingDates,
      yearDistribution: sortedYears,
      dateIssuePercentage: ((invalidDates + missingDates) / documents.length * 100).toFixed(1)
    };
  }, [documents]);

  return (
    <div className="data-diagnostics">
      <h3>Data Quality Diagnostics</h3>
      
      <div className="diagnostic-section">
        <h4>State Coverage</h4>
        <p className="diagnostic-summary">
          <strong>{diagnostics.statesWithData}</strong> of <strong>{diagnostics.totalStates}</strong> Brazilian states have data
          {diagnostics.missingStates.length > 0 && (
            <span className="warning"> ({diagnostics.missingStates.length} states missing)</span>
          )}
        </p>
        
        {diagnostics.missingStates.length > 0 && (
          <div className="missing-states">
            <p>Missing states:</p>
            <ul>
              {diagnostics.missingStates.map(stateCode => (
                <li key={stateCode}>
                  {stateCode} - {BRAZILIAN_STATES[stateCode as keyof typeof BRAZILIAN_STATES]}
                </li>
              ))}
            </ul>
          </div>
        )}
        
        <div className="state-distribution">
          <p>Documents by state:</p>
          <div className="state-bars">
            {Object.entries(diagnostics.stateCounts)
              .filter(([_, count]) => count > 0)
              .sort(([_, a], [__, b]) => b - a)
              .map(([state, count]) => (
                <div key={state} className="state-bar">
                  <span className="state-name">{state}:</span>
                  <span className="state-count">{count}</span>
                  <div className="bar" style={{ 
                    width: `${(count / diagnostics.totalDocuments * 100).toFixed(1)}%`,
                    minWidth: '2px'
                  }} />
                </div>
              ))}
          </div>
        </div>
      </div>
      
      <div className="diagnostic-section">
        <h4>Date Quality</h4>
        <p className="diagnostic-summary">
          <strong>{diagnostics.dateIssuePercentage}%</strong> of documents have date issues
        </p>
        <ul className="date-stats">
          <li>Valid dates: <strong>{diagnostics.validDates}</strong></li>
          <li>Invalid dates: <strong>{diagnostics.invalidDates}</strong></li>
          <li>Missing dates: <strong>{diagnostics.missingDates}</strong></li>
        </ul>
        
        {diagnostics.yearDistribution.length > 0 && (
          <div className="year-distribution">
            <p>Year distribution (valid dates only):</p>
            <div className="year-bars">
              {diagnostics.yearDistribution.slice(0, 10).map(([year, count]) => (
                <div key={year} className="year-bar">
                  <span className="year">{year}:</span>
                  <span className="count">{count}</span>
                </div>
              ))}
              {diagnostics.yearDistribution.length > 10 && (
                <p className="more-years">...and {diagnostics.yearDistribution.length - 10} more years</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};