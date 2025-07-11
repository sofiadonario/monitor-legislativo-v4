/**
 * GeographicSearch Component
 * Location-based search interface with Brazilian municipality filters
 */
import React, { useState, useEffect, useCallback } from 'react';
import { 
  Coordinates, 
  Municipality, 
  StateData, 
  GeographicSearchParams,
  LegislativeDocument 
} from '../../types';
import { geographicService } from '../../services/geographicService';
import { LocationSearchInput } from './LocationSearchInput';
import { RadiusSelector } from './RadiusSelector';
import { MunicipalityPicker } from './MunicipalityPicker';
import { GeographicFilters } from './GeographicFilters';
import './GeographicSearch.css';

interface GeographicSearchProps {
  onSearchResults: (documents: LegislativeDocument[]) => void;
  onLocationChange?: (location: Coordinates | null) => void;
  defaultLocation?: Coordinates;
  defaultRadius?: number;
}

export const GeographicSearch: React.FC<GeographicSearchProps> = ({
  onSearchResults,
  onLocationChange,
  defaultLocation,
  defaultRadius = 50
}) => {
  const [searchLocation, setSearchLocation] = useState<Coordinates | null>(defaultLocation || null);
  const [searchRadius, setSearchRadius] = useState<number>(defaultRadius);
  const [selectedStates, setSelectedStates] = useState<string[]>([]);
  const [selectedMunicipalities, setSelectedMunicipalities] = useState<string[]>([]);
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);
  const [includeNearby, setIncludeNearby] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [states, setStates] = useState<StateData[]>([]);
  const [municipalities, setMunicipalities] = useState<Municipality[]>([]);
  const [searchMode, setSearchMode] = useState<'radius' | 'boundary'>('radius');
  const [documentCount, setDocumentCount] = useState<number | null>(null);

  // Load states on component mount
  useEffect(() => {
    loadStates();
  }, []);

  // Load municipalities when states change
  useEffect(() => {
    if (selectedStates.length > 0) {
      loadMunicipalities();
    } else {
      setMunicipalities([]);
      setSelectedMunicipalities([]);
    }
  }, [selectedStates]);

  // Notify parent of location changes
  useEffect(() => {
    if (onLocationChange) {
      onLocationChange(searchLocation);
    }
  }, [searchLocation, onLocationChange]);

  const loadStates = async () => {
    try {
      const stateData = await geographicService.getStates();
      setStates(stateData);
    } catch (error) {
      console.error('Failed to load states:', error);
      setError('Failed to load Brazilian states');
    }
  };

  const loadMunicipalities = async () => {
    try {
      const muniPromises = selectedStates.map(state => 
        geographicService.getMunicipalities(state)
      );
      const results = await Promise.all(muniPromises);
      const allMunicipalities = results.flat();
      setMunicipalities(allMunicipalities);
    } catch (error) {
      console.error('Failed to load municipalities:', error);
    }
  };

  const handleLocationSelect = useCallback((location: Coordinates | null) => {
    setSearchLocation(location);
    setError(null);
  }, []);

  const handleRadiusChange = useCallback((radius: number) => {
    setSearchRadius(radius);
  }, []);

  const handleStateToggle = (stateId: string) => {
    setSelectedStates(prev => 
      prev.includes(stateId)
        ? prev.filter(id => id !== stateId)
        : [...prev, stateId]
    );
  };

  const handleMunicipalityToggle = (municipalityId: string) => {
    setSelectedMunicipalities(prev =>
      prev.includes(municipalityId)
        ? prev.filter(id => id !== municipalityId)
        : [...prev, municipalityId]
    );
  };

  const handleRegionToggle = (region: string) => {
    setSelectedRegions(prev =>
      prev.includes(region)
        ? prev.filter(r => r !== region)
        : [...prev, region]
    );
  };

  const performSearch = async () => {
    if (searchMode === 'radius' && !searchLocation) {
      setError('Please select a location for radius-based search');
      return;
    }

    if (searchMode === 'boundary' && selectedStates.length === 0 && selectedMunicipalities.length === 0) {
      setError('Please select at least one state or municipality');
      return;
    }

    setLoading(true);
    setError(null);
    setDocumentCount(null);

    try {
      const searchParams: GeographicSearchParams = {
        states: selectedStates.length > 0 ? selectedStates : undefined,
        municipalities: selectedMunicipalities.length > 0 ? selectedMunicipalities : undefined,
        regions: selectedRegions.length > 0 ? selectedRegions : undefined,
        includeNearby
      };

      let results: LegislativeDocument[] = [];

      if (searchMode === 'radius' && searchLocation) {
        results = await geographicService.searchByLocation(
          searchLocation,
          searchRadius,
          searchParams
        );
      } else {
        // For boundary mode, use the first state or municipality as center
        if (selectedStates.length > 0) {
          const state = states.find(s => s.id === selectedStates[0]);
          if (state) {
            results = await geographicService.searchByLocation(
              { lat: state.coordinates[0], lng: state.coordinates[1] },
              1000, // Large radius to cover whole state
              searchParams
            );
          }
        } else if (selectedMunicipalities.length > 0) {
          const municipality = municipalities.find(m => m.id === selectedMunicipalities[0]);
          if (municipality) {
            results = await geographicService.searchByLocation(
              municipality.coordinates,
              100, // Reasonable radius for municipality
              searchParams
            );
          }
        }
      }

      setDocumentCount(results.length);
      onSearchResults(results);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Search failed');
      onSearchResults([]);
    } finally {
      setLoading(false);
    }
  };

  const clearFilters = () => {
    setSearchLocation(null);
    setSelectedStates([]);
    setSelectedMunicipalities([]);
    setSelectedRegions([]);
    setSearchRadius(defaultRadius);
    setIncludeNearby(true);
    setError(null);
    setDocumentCount(null);
  };

  const getSelectedLocationName = () => {
    if (!searchLocation) return null;
    
    // Try to find matching municipality or state
    const matchingMuni = municipalities.find(m => 
      Math.abs(m.coordinates.lat - searchLocation.lat) < 0.01 &&
      Math.abs(m.coordinates.lng - searchLocation.lng) < 0.01
    );
    
    if (matchingMuni) {
      return `${matchingMuni.name}, ${matchingMuni.stateAbbreviation}`;
    }

    const matchingState = states.find(s =>
      Math.abs(s.coordinates[0] - searchLocation.lat) < 0.01 &&
      Math.abs(s.coordinates[1] - searchLocation.lng) < 0.01
    );

    if (matchingState) {
      return matchingState.name;
    }

    return `${searchLocation.lat.toFixed(4)}, ${searchLocation.lng.toFixed(4)}`;
  };

  return (
    <div className="geographic-search">
      <div className="geographic-search__header">
        <h3>Geographic Search</h3>
        <p>Search legislative documents by location</p>
      </div>

      <div className="geographic-search__mode-selector">
        <button
          onClick={() => setSearchMode('radius')}
          className={`geographic-search__mode-btn ${searchMode === 'radius' ? 'active' : ''}`}
        >
          📍 Radius Search
        </button>
        <button
          onClick={() => setSearchMode('boundary')}
          className={`geographic-search__mode-btn ${searchMode === 'boundary' ? 'active' : ''}`}
        >
          🗺️ Boundary Search
        </button>
      </div>

      {searchMode === 'radius' && (
        <div className="geographic-search__radius-controls">
          <LocationSearchInput
            onLocationSelect={handleLocationSelect}
            placeholder="Search for a city, state, or address..."
            defaultLocation={searchLocation}
          />
          
          {searchLocation && (
            <div className="geographic-search__location-info">
              <span className="geographic-search__location-label">
                📍 {getSelectedLocationName()}
              </span>
              <button
                onClick={() => handleLocationSelect(null)}
                className="geographic-search__clear-location"
              >
                ✕
              </button>
            </div>
          )}

          <RadiusSelector
            radius={searchRadius}
            onRadiusChange={handleRadiusChange}
            disabled={!searchLocation}
          />
        </div>
      )}

      <GeographicFilters
        states={states}
        selectedStates={selectedStates}
        selectedRegions={selectedRegions}
        onStateToggle={handleStateToggle}
        onRegionToggle={handleRegionToggle}
        showRegions={true}
      />

      {selectedStates.length > 0 && municipalities.length > 0 && (
        <MunicipalityPicker
          municipalities={municipalities}
          selectedMunicipalities={selectedMunicipalities}
          onMunicipalityToggle={handleMunicipalityToggle}
        />
      )}

      <div className="geographic-search__options">
        <label className="geographic-search__checkbox">
          <input
            type="checkbox"
            checked={includeNearby}
            onChange={(e) => setIncludeNearby(e.target.checked)}
          />
          Include nearby documents outside selected areas
        </label>
      </div>

      {error && (
        <div className="geographic-search__error">
          <span>⚠️ {error}</span>
        </div>
      )}

      <div className="geographic-search__actions">
        <button
          onClick={clearFilters}
          className="geographic-search__clear-btn"
          disabled={loading}
        >
          Clear Filters
        </button>
        <button
          onClick={performSearch}
          className="geographic-search__search-btn"
          disabled={loading || (searchMode === 'radius' && !searchLocation)}
        >
          {loading ? (
            <>
              <span className="geographic-search__spinner"></span>
              Searching...
            </>
          ) : (
            <>
              🔍 Search Documents
            </>
          )}
        </button>
      </div>

      {documentCount !== null && (
        <div className="geographic-search__results-count">
          <p>
            Found <strong>{documentCount}</strong> document{documentCount !== 1 ? 's' : ''} 
            {searchMode === 'radius' && searchLocation && (
              <> within {searchRadius}km of {getSelectedLocationName()}</>
            )}
            {searchMode === 'boundary' && (
              <> in selected areas</>
            )}
          </p>
        </div>
      )}
    </div>
  );
};