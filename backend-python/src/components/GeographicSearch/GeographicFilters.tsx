/**
 * GeographicFilters Component
 * State and region filters for Brazilian geographic search
 */
import React, { useMemo } from 'react';
import { StateData } from '../../types';

interface GeographicFiltersProps {
  states: StateData[];
  selectedStates: string[];
  selectedRegions: string[];
  onStateToggle: (stateId: string) => void;
  onRegionToggle: (region: string) => void;
  showRegions?: boolean;
}

const BRAZIL_REGIONS = [
  { id: 'Norte', name: 'Norte', color: '#10b981' },
  { id: 'Nordeste', name: 'Nordeste', color: '#f59e0b' },
  { id: 'Centro-Oeste', name: 'Centro-Oeste', color: '#8b5cf6' },
  { id: 'Sudeste', name: 'Sudeste', color: '#3b82f6' },
  { id: 'Sul', name: 'Sul', color: '#ef4444' }
];

export const GeographicFilters: React.FC<GeographicFiltersProps> = ({
  states,
  selectedStates,
  selectedRegions,
  onStateToggle,
  onRegionToggle,
  showRegions = true
}) => {
  // Group states by region
  const statesByRegion = useMemo(() => {
    const grouped: Record<string, StateData[]> = {};
    
    states.forEach(state => {
      if (!grouped[state.region]) {
        grouped[state.region] = [];
      }
      grouped[state.region].push(state);
    });

    // Sort states within each region
    Object.keys(grouped).forEach(region => {
      grouped[region].sort((a, b) => a.name.localeCompare(b.name));
    });

    return grouped;
  }, [states]);

  const handleRegionClick = (region: string) => {
    const regionStates = statesByRegion[region] || [];
    const allSelected = regionStates.every(state => 
      selectedStates.includes(state.id)
    );

    if (allSelected) {
      // Deselect all states in region
      regionStates.forEach(state => {
        if (selectedStates.includes(state.id)) {
          onStateToggle(state.id);
        }
      });
    } else {
      // Select all states in region
      regionStates.forEach(state => {
        if (!selectedStates.includes(state.id)) {
          onStateToggle(state.id);
        }
      });
    }

    onRegionToggle(region);
  };

  const getRegionSelectionStatus = (region: string) => {
    const regionStates = statesByRegion[region] || [];
    const selectedCount = regionStates.filter(state => 
      selectedStates.includes(state.id)
    ).length;

    if (selectedCount === 0) return 'none';
    if (selectedCount === regionStates.length) return 'all';
    return 'partial';
  };

  const getSelectedStats = () => {
    const selectedStateData = states.filter(s => selectedStates.includes(s.id));
    const totalPopulation = selectedStateData.reduce((sum, s) => sum + (s.population || 0), 0);
    const totalArea = selectedStateData.reduce((sum, s) => sum + (s.area || 0), 0);
    
    return {
      states: selectedStates.length,
      regions: selectedRegions.length,
      population: totalPopulation,
      area: totalArea
    };
  };

  const stats = getSelectedStats();

  return (
    <div className="geographic-filters">
      <div className="geographic-filters__header">
        <h4>Geographic Filters</h4>
        {stats.states > 0 && (
          <span className="geographic-filters__stats">
            {stats.states} state{stats.states !== 1 ? 's' : ''} selected
            {stats.population > 0 && (
              <> • {(stats.population / 1000000).toFixed(1)}M people</>
            )}
          </span>
        )}
      </div>

      {showRegions && (
        <div className="geographic-filters__regions">
          <h5>Regions</h5>
          <div className="geographic-filters__region-grid">
            {BRAZIL_REGIONS.map(region => {
              const status = getRegionSelectionStatus(region.id);
              const stateCount = statesByRegion[region.id]?.length || 0;
              
              return (
                <button
                  key={region.id}
                  onClick={() => handleRegionClick(region.id)}
                  className={`geographic-filters__region-btn ${status}`}
                  style={{ borderColor: region.color }}
                >
                  <span 
                    className="geographic-filters__region-indicator"
                    style={{ backgroundColor: region.color }}
                  />
                  <span className="geographic-filters__region-name">
                    {region.name}
                  </span>
                  <span className="geographic-filters__region-count">
                    ({stateCount})
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <div className="geographic-filters__states">
        <h5>States</h5>
        {BRAZIL_REGIONS.map(region => {
          const regionStates = statesByRegion[region.id] || [];
          if (regionStates.length === 0) return null;

          return (
            <div key={region.id} className="geographic-filters__state-group">
              <h6 
                className="geographic-filters__state-group-title"
                style={{ color: BRAZIL_REGIONS.find(r => r.id === region.id)?.color }}
              >
                {region.id}
              </h6>
              <div className="geographic-filters__state-grid">
                {regionStates.map(state => (
                  <label
                    key={state.id}
                    className={`geographic-filters__state-item ${
                      selectedStates.includes(state.id) ? 'selected' : ''
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={selectedStates.includes(state.id)}
                      onChange={() => onStateToggle(state.id)}
                    />
                    <span className="geographic-filters__state-abbr">
                      {state.abbreviation}
                    </span>
                    <span className="geographic-filters__state-name">
                      {state.name}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <div className="geographic-filters__actions">
        <button
          onClick={() => {
            states.forEach(state => {
              if (selectedStates.includes(state.id)) {
                onStateToggle(state.id);
              }
            });
            selectedRegions.forEach(region => {
              onRegionToggle(region);
            });
          }}
          className="geographic-filters__clear-btn"
          disabled={selectedStates.length === 0 && selectedRegions.length === 0}
        >
          Clear Selection
        </button>
        <button
          onClick={() => {
            states.forEach(state => {
              if (!selectedStates.includes(state.id)) {
                onStateToggle(state.id);
              }
            });
          }}
          className="geographic-filters__select-all-btn"
          disabled={selectedStates.length === states.length}
        >
          Select All States
        </button>
      </div>
    </div>
  );
};