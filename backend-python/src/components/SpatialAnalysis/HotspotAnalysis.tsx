/**
 * HotspotAnalysis Component
 * Displays spatial hotspots with Getis-Ord Gi* statistics
 */
import React, { useState, useMemo } from 'react';
import { SpatialHotspot, spatialAnalysisService } from '../../services/spatialAnalysisService';
import { DocumentLocation } from '../../types';

interface HotspotAnalysisProps {
  documents: DocumentLocation[];
  searchRadius?: number;
  onHotspotSelect?: (hotspot: SpatialHotspot) => void;
  selectedHotspot?: string;
}

export const HotspotAnalysis: React.FC<HotspotAnalysisProps> = ({
  documents,
  searchRadius = 100,
  onHotspotSelect,
  selectedHotspot
}) => {
  const [filterType, setFilterType] = useState<'all' | 'hot' | 'cold'>('all');
  const [minSignificance, setMinSignificance] = useState(1.96);

  // Calculate hotspots
  const allHotspots = useMemo(() => {
    return spatialAnalysisService.identifyHotspots(documents, searchRadius);
  }, [documents, searchRadius]);

  // Filter hotspots
  const filteredHotspots = useMemo(() => {
    return allHotspots.filter(hotspot => {
      if (hotspot.significance < minSignificance) return false;
      if (filterType === 'hot') return hotspot.type === 'hot';
      if (filterType === 'cold') return hotspot.type === 'cold';
      return true;
    });
  }, [allHotspots, filterType, minSignificance]);

  // Calculate statistics
  const statistics = useMemo(() => {
    const hotSpots = allHotspots.filter(h => h.type === 'hot');
    const coldSpots = allHotspots.filter(h => h.type === 'cold');
    
    const avgHotSignificance = hotSpots.length > 0 
      ? hotSpots.reduce((sum, h) => sum + h.significance, 0) / hotSpots.length 
      : 0;
    
    const avgColdSignificance = coldSpots.length > 0 
      ? coldSpots.reduce((sum, h) => sum + h.significance, 0) / coldSpots.length 
      : 0;

    const totalDocs = allHotspots.reduce((sum, h) => sum + h.documentCount, 0);
    const avgDocsPerHotspot = allHotspots.length > 0 ? totalDocs / allHotspots.length : 0;

    return {
      totalHotspots: allHotspots.length,
      hotSpots: hotSpots.length,
      coldSpots: coldSpots.length,
      avgHotSignificance,
      avgColdSignificance,
      avgDocsPerHotspot,
      significanceRange: {
        min: Math.min(...allHotspots.map(h => h.significance)),
        max: Math.max(...allHotspots.map(h => h.significance))
      }
    };
  }, [allHotspots]);

  const handleHotspotClick = (hotspot: SpatialHotspot) => {
    if (onHotspotSelect) {
      onHotspotSelect(hotspot);
    }
  };

  const getSignificanceLevel = (significance: number): string => {
    if (significance >= 2.58) return 'Highly Significant (99%)';
    if (significance >= 1.96) return 'Significant (95%)';
    if (significance >= 1.65) return 'Marginally Significant (90%)';
    return 'Not Significant';
  };

  const getSignificanceColor = (significance: number): string => {
    if (significance >= 2.58) return '#dc2626';
    if (significance >= 1.96) return '#ea580c';
    if (significance >= 1.65) return '#f59e0b';
    return '#94a3b8';
  };

  return (
    <div className="hotspot-analysis">
      <div className="hotspot-analysis__header">
        <h3>Spatial Hotspot Analysis</h3>
        <div className="hotspot-analysis__info">
          <p>Getis-Ord Gi* statistic identifies areas with significantly high or low document concentrations</p>
        </div>
      </div>

      <div className="hotspot-controls">
        <div className="control-group">
          <label htmlFor="hotspot-filter">Filter Type:</label>
          <select 
            id="hotspot-filter"
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as 'all' | 'hot' | 'cold')}
          >
            <option value="all">All Hotspots</option>
            <option value="hot">Hot Spots Only</option>
            <option value="cold">Cold Spots Only</option>
          </select>
        </div>

        <div className="control-group">
          <label htmlFor="min-significance">Minimum Significance:</label>
          <select 
            id="min-significance"
            value={minSignificance}
            onChange={(e) => setMinSignificance(parseFloat(e.target.value))}
          >
            <option value={1.65}>90% Confidence (1.65)</option>
            <option value={1.96}>95% Confidence (1.96)</option>
            <option value={2.58}>99% Confidence (2.58)</option>
          </select>
        </div>
      </div>

      <div className="hotspot-stats">
        <div className="hotspot-stats__grid">
          <div className="stat-card hotspot-stat">
            <div className="stat-card__value">{statistics.totalHotspots}</div>
            <div className="stat-card__label">Total Hotspots</div>
          </div>
          <div className="stat-card hot-stat">
            <div className="stat-card__value">{statistics.hotSpots}</div>
            <div className="stat-card__label">Hot Spots</div>
          </div>
          <div className="stat-card cold-stat">
            <div className="stat-card__value">{statistics.coldSpots}</div>
            <div className="stat-card__label">Cold Spots</div>
          </div>
          <div className="stat-card avg-stat">
            <div className="stat-card__value">{statistics.avgDocsPerHotspot.toFixed(1)}</div>
            <div className="stat-card__label">Avg Docs/Hotspot</div>
          </div>
        </div>

        <div className="significance-metrics">
          <div className="metric">
            <strong>Average Hot Spot Significance:</strong> {statistics.avgHotSignificance.toFixed(2)}
          </div>
          <div className="metric">
            <strong>Average Cold Spot Significance:</strong> {statistics.avgColdSignificance.toFixed(2)}
          </div>
          <div className="metric">
            <strong>Significance Range:</strong> {statistics.significanceRange.min.toFixed(2)} - {statistics.significanceRange.max.toFixed(2)}
          </div>
        </div>
      </div>

      <div className="hotspot-list">
        <h4>
          {filterType === 'all' ? 'All Hotspots' : 
           filterType === 'hot' ? 'Hot Spots' : 'Cold Spots'} 
          ({filteredHotspots.length})
        </h4>
        
        <div className="hotspot-list__container">
          {filteredHotspots.length === 0 ? (
            <div className="no-hotspots">
              <p>No hotspots found with current parameters.</p>
              <p>Try reducing the significance threshold or changing the search radius.</p>
            </div>
          ) : (
            filteredHotspots.map((hotspot, index) => (
              <div 
                key={hotspot.id}
                className={`hotspot-item ${hotspot.type} ${selectedHotspot === hotspot.id ? 'selected' : ''}`}
                onClick={() => handleHotspotClick(hotspot)}
              >
                <div className="hotspot-item__header">
                  <div className="hotspot-item__title">
                    {hotspot.type === 'hot' ? '🔥' : '❄️'} {hotspot.type.toUpperCase()} SPOT {index + 1}
                  </div>
                  <div 
                    className="hotspot-item__significance"
                    style={{ backgroundColor: getSignificanceColor(hotspot.significance) }}
                  >
                    Z = {hotspot.zScore.toFixed(2)}
                  </div>
                </div>

                <div className="hotspot-item__stats">
                  <div className="hotspot-stat">
                    <span className="stat-label">Documents:</span>
                    <span className="stat-value">{hotspot.documentCount}</span>
                  </div>
                  <div className="hotspot-stat">
                    <span className="stat-label">Radius:</span>
                    <span className="stat-value">{hotspot.radius} km</span>
                  </div>
                  <div className="hotspot-stat">
                    <span className="stat-label">Significance:</span>
                    <span className="stat-value">{hotspot.significance.toFixed(2)}</span>
                  </div>
                  <div className="hotspot-stat">
                    <span className="stat-label">P-Value:</span>
                    <span className="stat-value">{hotspot.pValue.toFixed(4)}</span>
                  </div>
                </div>

                <div className="hotspot-item__location">
                  📍 {hotspot.center.lat.toFixed(4)}, {hotspot.center.lng.toFixed(4)}
                </div>

                <div className="hotspot-item__interpretation">
                  <div className="interpretation-level" style={{ color: getSignificanceColor(hotspot.significance) }}>
                    {getSignificanceLevel(hotspot.significance)}
                  </div>
                  <div className="interpretation-text">
                    {hotspot.type === 'hot' 
                      ? 'This area has significantly higher document concentration than expected by chance'
                      : 'This area has significantly lower document concentration than expected by chance'
                    }
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="hotspot-methodology">
        <details>
          <summary>Methodology</summary>
          <div className="methodology-content">
            <p>
              <strong>Getis-Ord Gi* Statistic:</strong> A spatial statistics measure that identifies 
              areas where high or low values cluster together more than would be expected by random chance.
            </p>
            <ul>
              <li><strong>Hot Spots (Positive Z-score):</strong> Areas with high document concentration surrounded by areas with high values</li>
              <li><strong>Cold Spots (Negative Z-score):</strong> Areas with low document concentration surrounded by areas with low values</li>
              <li><strong>Significance Levels:</strong> 90% (Z ≥ 1.65), 95% (Z ≥ 1.96), 99% (Z ≥ 2.58)</li>
              <li><strong>Search Radius:</strong> {searchRadius} km - defines the neighborhood for each analysis point</li>
            </ul>
          </div>
        </details>
      </div>
    </div>
  );
};

// CSS styles (to be injected)
const hotspotStyles = `
.hotspot-analysis {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.hotspot-analysis__header h3 {
  color: #2d3748;
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 0.5rem 0;
}

.hotspot-analysis__info p {
  color: #718096;
  font-size: 0.875rem;
  margin: 0 0 1.5rem 0;
  line-height: 1.4;
}

.hotspot-controls {
  display: flex;
  gap: 1.5rem;
  margin-bottom: 1.5rem;
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

.hotspot-stats {
  background: #f7fafc;
  border-radius: 6px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}

.hotspot-stats__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.stat-card {
  background: #ffffff;
  border-radius: 6px;
  padding: 1rem;
  text-align: center;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.stat-card.hotspot-stat {
  border-left: 4px solid #4299e1;
}

.stat-card.hot-stat {
  border-left: 4px solid #dc2626;
}

.stat-card.cold-stat {
  border-left: 4px solid #2563eb;
}

.stat-card.avg-stat {
  border-left: 4px solid #059669;
}

.stat-card__value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #2d3748;
  line-height: 1;
}

.stat-card__label {
  font-size: 0.875rem;
  color: #718096;
  margin-top: 0.5rem;
}

.significance-metrics {
  margin-bottom: 1rem;
}

.metric {
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
  color: #4a5568;
}

.hotspot-list h4 {
  color: #2d3748;
  font-size: 1.125rem;
  margin-bottom: 1rem;
}

.hotspot-list__container {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-height: 600px;
  overflow-y: auto;
}

.no-hotspots {
  text-align: center;
  padding: 2rem;
  color: #718096;
}

.hotspot-item {
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 1rem;
  cursor: pointer;
  transition: all 0.2s;
}

.hotspot-item.hot {
  background: linear-gradient(135deg, #fed7d7 0%, #ffffff 100%);
  border-left: 4px solid #dc2626;
}

.hotspot-item.cold {
  background: linear-gradient(135deg, #dbeafe 0%, #ffffff 100%);
  border-left: 4px solid #2563eb;
}

.hotspot-item:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  transform: translateY(-1px);
}

.hotspot-item.selected {
  box-shadow: 0 0 0 2px rgba(66, 153, 225, 0.3);
}

.hotspot-item__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.hotspot-item__title {
  font-weight: 600;
  color: #2d3748;
  font-size: 1rem;
}

.hotspot-item__significance {
  color: #ffffff;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: 600;
  font-family: monospace;
}

.hotspot-item__stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.hotspot-stat {
  display: flex;
  justify-content: space-between;
  font-size: 0.875rem;
}

.stat-label {
  color: #718096;
}

.stat-value {
  font-weight: 500;
  color: #2d3748;
}

.hotspot-item__location {
  font-family: monospace;
  font-size: 0.875rem;
  color: #4a5568;
  margin-bottom: 1rem;
}

.hotspot-item__interpretation {
  background: rgba(255, 255, 255, 0.7);
  border-radius: 4px;
  padding: 0.75rem;
}

.interpretation-level {
  font-weight: 600;
  font-size: 0.875rem;
  margin-bottom: 0.5rem;
}

.interpretation-text {
  font-size: 0.875rem;
  color: #4a5568;
  line-height: 1.4;
}

.hotspot-methodology {
  margin-top: 1.5rem;
  border-top: 1px solid #e2e8f0;
  padding-top: 1.5rem;
}

.hotspot-methodology summary {
  font-weight: 600;
  color: #4a5568;
  cursor: pointer;
  margin-bottom: 1rem;
}

.methodology-content {
  font-size: 0.875rem;
  line-height: 1.5;
  color: #4a5568;
}

.methodology-content p {
  margin-bottom: 1rem;
}

.methodology-content ul {
  margin: 0;
  padding-left: 1.5rem;
}

.methodology-content li {
  margin-bottom: 0.5rem;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = hotspotStyles;
  document.head.appendChild(styleElement);
}