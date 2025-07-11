/**
 * RegionalStatistics Component
 * Displays comprehensive regional analysis and statistics for Brazilian states
 */
import React, { useState, useMemo } from 'react';
import { RegionalStatistics as RegionalStats, spatialAnalysisService } from '../../services/spatialAnalysisService';
import { DocumentLocation, StateData, Municipality } from '../../types';

interface RegionalStatisticsProps {
  documents: DocumentLocation[];
  states: StateData[];
  municipalities: Municipality[];
  onStateSelect?: (stateId: string) => void;
  selectedState?: string;
}

export const RegionalStatistics: React.FC<RegionalStatisticsProps> = ({
  documents,
  states,
  municipalities,
  onStateSelect,
  selectedState
}) => {
  const [sortBy, setSortBy] = useState<keyof RegionalStats>('totalDocuments');
  const [showOnlyWithData, setShowOnlyWithData] = useState(true);

  // Calculate regional statistics
  const regionalStats = useMemo(() => {
    return spatialAnalysisService.calculateRegionalStatistics(documents, states, municipalities);
  }, [documents, states, municipalities]);

  // Filter and sort statistics
  const filteredStats = useMemo(() => {
    let filtered = regionalStats;
    
    if (showOnlyWithData) {
      filtered = filtered.filter(stat => stat.totalDocuments > 0);
    }

    return filtered.sort((a, b) => {
      const aValue = a[sortBy];
      const bValue = b[sortBy];
      
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return bValue - aValue;
      }
      return String(bValue).localeCompare(String(aValue));
    });
  }, [regionalStats, sortBy, showOnlyWithData]);

  // Calculate national totals
  const nationalStats = useMemo(() => {
    const total = regionalStats.reduce((acc, stat) => ({
      totalDocuments: acc.totalDocuments + stat.totalDocuments,
      totalMunicipalities: acc.totalMunicipalities + stat.municipalityCount,
      totalStates: acc.totalStates + 1,
      avgConfidence: acc.avgConfidence + (stat.averageConfidence * stat.totalDocuments),
      totalArea: acc.totalArea + (states.find(s => s.id === stat.stateId)?.area || 0)
    }), {
      totalDocuments: 0,
      totalMunicipalities: 0,
      totalStates: 0,
      avgConfidence: 0,
      totalArea: 0
    });

    total.avgConfidence = total.totalDocuments > 0 ? total.avgConfidence / total.totalDocuments : 0;

    return total;
  }, [regionalStats, states]);

  const handleStateClick = (stateId: string) => {
    if (onStateSelect) {
      onStateSelect(stateId);
    }
  };

  const getDocumentTypeColor = (type: string): string => {
    const colors: Record<string, string> = {
      lei: '#4299e1',
      decreto: '#48bb78',
      portaria: '#ed8936',
      resolucao: '#9f7aea',
      instrucao_normativa: '#38b2ac',
      projeto_lei: '#f56565',
      medida_provisoria: '#d69e2e'
    };
    return colors[type] || '#718096';
  };

  const formatPercentage = (value: number): string => {
    return `${(value * 100).toFixed(1)}%`;
  };

  return (
    <div className="regional-statistics">
      <div className="regional-statistics__header">
        <h3>Regional Statistics Analysis</h3>
        <p>Comprehensive breakdown of legislative documents by Brazilian states and regions</p>
      </div>

      {/* National Overview */}
      <div className="national-overview">
        <h4>National Overview</h4>
        <div className="national-stats">
          <div className="national-stat">
            <div className="stat-value">{nationalStats.totalDocuments.toLocaleString()}</div>
            <div className="stat-label">Total Documents</div>
          </div>
          <div className="national-stat">
            <div className="stat-value">{nationalStats.totalStates}</div>
            <div className="stat-label">States with Data</div>
          </div>
          <div className="national-stat">
            <div className="stat-value">{nationalStats.totalMunicipalities.toLocaleString()}</div>
            <div className="stat-label">Municipalities</div>
          </div>
          <div className="national-stat">
            <div className="stat-value">{formatPercentage(nationalStats.avgConfidence)}</div>
            <div className="stat-label">Avg Confidence</div>
          </div>
          <div className="national-stat">
            <div className="stat-value">{(nationalStats.totalArea / 1000000).toFixed(1)}M</div>
            <div className="stat-label">Total Area (km²)</div>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="regional-controls">
        <div className="control-group">
          <label htmlFor="sort-by">Sort by:</label>
          <select 
            id="sort-by"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as keyof RegionalStats)}
          >
            <option value="totalDocuments">Total Documents</option>
            <option value="documentDensity">Document Density</option>
            <option value="coverage">Coverage Rate</option>
            <option value="averageConfidence">Average Confidence</option>
            <option value="municipalityCount">Municipality Count</option>
          </select>
        </div>

        <div className="control-group">
          <label>
            <input
              type="checkbox"
              checked={showOnlyWithData}
              onChange={(e) => setShowOnlyWithData(e.target.checked)}
            />
            Show only states with documents
          </label>
        </div>
      </div>

      {/* Regional Statistics List */}
      <div className="regional-list">
        <h4>State-by-State Analysis ({filteredStats.length} states)</h4>
        
        <div className="regional-list__container">
          {filteredStats.map((stat) => {
            const state = states.find(s => s.id === stat.stateId);
            const isSelected = selectedState === stat.stateId;
            
            return (
              <div 
                key={stat.stateId}
                className={`regional-item ${isSelected ? 'selected' : ''}`}
                onClick={() => handleStateClick(stat.stateId)}
              >
                <div className="regional-item__header">
                  <div className="regional-item__title">
                    <h5>{stat.stateName}</h5>
                    <div className="regional-item__region">{state?.region}</div>
                  </div>
                  <div className="regional-item__key-stats">
                    <div className="key-stat">
                      <span className="key-stat__value">{stat.totalDocuments}</span>
                      <span className="key-stat__label">docs</span>
                    </div>
                    <div className="key-stat">
                      <span className="key-stat__value">{formatPercentage(stat.coverage)}</span>
                      <span className="key-stat__label">coverage</span>
                    </div>
                  </div>
                </div>

                <div className="regional-item__stats">
                  <div className="stat-row">
                    <span className="stat-label">Municipalities with documents:</span>
                    <span className="stat-value">
                      {stat.topMunicipalities.reduce((sum, m) => sum + m.documentCount, 0)} / {stat.municipalityCount}
                    </span>
                  </div>
                  <div className="stat-row">
                    <span className="stat-label">Document density:</span>
                    <span className="stat-value">{stat.documentDensity.toFixed(4)} docs/km²</span>
                  </div>
                  <div className="stat-row">
                    <span className="stat-label">Average confidence:</span>
                    <span className="stat-value">{formatPercentage(stat.averageConfidence)}</span>
                  </div>
                </div>

                {/* Document Types Distribution */}
                <div className="document-types">
                  <h6>Document Types</h6>
                  <div className="type-distribution">
                    {Object.entries(stat.documentsByType).map(([type, count]) => {
                      const percentage = (count / stat.totalDocuments) * 100;
                      return (
                        <div key={type} className="type-item">
                          <div className="type-info">
                            <span className="type-name">{type.toUpperCase()}</span>
                            <span className="type-count">{count}</span>
                          </div>
                          <div className="type-bar">
                            <div 
                              className="type-bar__fill"
                              style={{ 
                                width: `${percentage}%`,
                                backgroundColor: getDocumentTypeColor(type)
                              }}
                            />
                          </div>
                          <span className="type-percentage">{percentage.toFixed(1)}%</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Top Municipalities */}
                <div className="top-municipalities">
                  <h6>Top Municipalities</h6>
                  <div className="municipality-list">
                    {stat.topMunicipalities.slice(0, 3).map((muni) => (
                      <div key={muni.id} className="municipality-item">
                        <span className="municipality-name">{muni.name}</span>
                        <span className="municipality-count">{muni.documentCount} docs</span>
                      </div>
                    ))}
                    {stat.topMunicipalities.length > 3 && (
                      <div className="more-municipalities">
                        +{stat.topMunicipalities.length - 3} more municipalities
                      </div>
                    )}
                  </div>
                </div>

                {/* Precision Distribution */}
                <div className="precision-distribution">
                  <h6>Location Precision</h6>
                  <div className="precision-bars">
                    {Object.entries(stat.precisionDistribution).map(([precision, count]) => {
                      const percentage = (count / stat.totalDocuments) * 100;
                      return (
                        <div key={precision} className="precision-item">
                          <span className="precision-label">{precision}</span>
                          <div className="precision-bar">
                            <div 
                              className="precision-bar__fill"
                              style={{ width: `${percentage}%` }}
                            />
                          </div>
                          <span className="precision-count">{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

// CSS styles (to be injected)
const regionalStyles = `
.regional-statistics {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.regional-statistics__header h3 {
  color: #2d3748;
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 0.5rem 0;
}

.regional-statistics__header p {
  color: #718096;
  font-size: 0.875rem;
  margin: 0 0 1.5rem 0;
}

.national-overview {
  background: #f7fafc;
  border-radius: 6px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}

.national-overview h4 {
  color: #2d3748;
  font-size: 1.125rem;
  margin: 0 0 1rem 0;
}

.national-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 1rem;
}

.national-stat {
  background: #ffffff;
  border-radius: 6px;
  padding: 1rem;
  text-align: center;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.national-stat .stat-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: #2d3748;
  line-height: 1;
}

.national-stat .stat-label {
  font-size: 0.875rem;
  color: #718096;
  margin-top: 0.5rem;
}

.regional-controls {
  display: flex;
  gap: 2rem;
  margin-bottom: 1.5rem;
  align-items: end;
  flex-wrap: wrap;
}

.control-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.control-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #4a5568;
}

.control-group select {
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
  background: #ffffff;
}

.control-group input[type="checkbox"] {
  margin-right: 0.5rem;
}

.regional-list h4 {
  color: #2d3748;
  font-size: 1.125rem;
  margin-bottom: 1rem;
}

.regional-list__container {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-height: 800px;
  overflow-y: auto;
}

.regional-item {
  background: #f7fafc;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.regional-item:hover {
  border-color: #cbd5e0;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.regional-item.selected {
  border-color: #4299e1;
  box-shadow: 0 0 0 2px rgba(66, 153, 225, 0.2);
}

.regional-item__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.regional-item__title h5 {
  color: #2d3748;
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0;
}

.regional-item__region {
  color: #718096;
  font-size: 0.875rem;
  margin-top: 0.25rem;
}

.regional-item__key-stats {
  display: flex;
  gap: 1rem;
}

.key-stat {
  text-align: center;
}

.key-stat__value {
  display: block;
  font-size: 1.25rem;
  font-weight: 700;
  color: #2d3748;
}

.key-stat__label {
  font-size: 0.75rem;
  color: #718096;
  text-transform: uppercase;
}

.regional-item__stats {
  margin-bottom: 1.5rem;
}

.stat-row {
  display: flex;
  justify-content: space-between;
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
}

.stat-label {
  color: #4a5568;
}

.stat-value {
  font-weight: 500;
  color: #2d3748;
}

.document-types,
.top-municipalities,
.precision-distribution {
  margin-bottom: 1.5rem;
}

.document-types h6,
.top-municipalities h6,
.precision-distribution h6 {
  color: #2d3748;
  font-size: 0.875rem;
  font-weight: 600;
  margin: 0 0 0.75rem 0;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.type-distribution {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.type-item {
  display: grid;
  grid-template-columns: 120px 1fr 60px;
  gap: 0.75rem;
  align-items: center;
  font-size: 0.875rem;
}

.type-info {
  display: flex;
  justify-content: space-between;
}

.type-name {
  font-weight: 500;
  color: #4a5568;
}

.type-count {
  color: #718096;
}

.type-bar {
  height: 6px;
  background-color: #e2e8f0;
  border-radius: 3px;
  overflow: hidden;
}

.type-bar__fill {
  height: 100%;
  transition: width 0.3s ease;
}

.type-percentage {
  font-size: 0.75rem;
  color: #718096;
  text-align: right;
}

.municipality-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.municipality-item {
  display: flex;
  justify-content: space-between;
  font-size: 0.875rem;
  padding: 0.25rem 0;
}

.municipality-name {
  color: #4a5568;
}

.municipality-count {
  color: #718096;
  font-weight: 500;
}

.more-municipalities {
  font-size: 0.75rem;
  color: #718096;
  font-style: italic;
  text-align: center;
  padding: 0.25rem 0;
}

.precision-bars {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.precision-item {
  display: grid;
  grid-template-columns: 80px 1fr 40px;
  gap: 0.75rem;
  align-items: center;
  font-size: 0.875rem;
}

.precision-label {
  font-weight: 500;
  color: #4a5568;
  text-transform: capitalize;
}

.precision-bar {
  height: 4px;
  background-color: #e2e8f0;
  border-radius: 2px;
  overflow: hidden;
}

.precision-bar__fill {
  height: 100%;
  background-color: #4299e1;
  transition: width 0.3s ease;
}

.precision-count {
  font-size: 0.75rem;
  color: #718096;
  text-align: right;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = regionalStyles;
  document.head.appendChild(styleElement);
}