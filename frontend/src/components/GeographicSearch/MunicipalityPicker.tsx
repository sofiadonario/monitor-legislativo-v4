/**
 * MunicipalityPicker Component
 * Brazilian municipality selection with search and filtering
 */
import React, { useState, useMemo } from 'react';
import { Municipality } from '../../types';

interface MunicipalityPickerProps {
  municipalities: Municipality[];
  selectedMunicipalities: string[];
  onMunicipalityToggle: (municipalityId: string) => void;
  maxSelections?: number;
}

export const MunicipalityPicker: React.FC<MunicipalityPickerProps> = ({
  municipalities,
  selectedMunicipalities,
  onMunicipalityToggle,
  maxSelections
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [showAll, setShowAll] = useState(false);
  const [sortBy, setSortBy] = useState<'name' | 'population'>('name');

  const filteredAndSortedMunicipalities = useMemo(() => {
    let filtered = municipalities;

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = municipalities.filter(muni =>
        muni.name.toLowerCase().includes(query) ||
        muni.stateAbbreviation.toLowerCase().includes(query)
      );
    }

    // Sort municipalities
    return [...filtered].sort((a, b) => {
      if (sortBy === 'name') {
        return a.name.localeCompare(b.name);
      } else {
        return (b.population || 0) - (a.population || 0);
      }
    });
  }, [municipalities, searchQuery, sortBy]);

  const displayedMunicipalities = showAll 
    ? filteredAndSortedMunicipalities 
    : filteredAndSortedMunicipalities.slice(0, 20);

  const handleToggleAll = () => {
    if (selectedMunicipalities.length === municipalities.length) {
      // Clear all
      municipalities.forEach(muni => {
        if (selectedMunicipalities.includes(muni.id)) {
          onMunicipalityToggle(muni.id);
        }
      });
    } else {
      // Select all (up to max)
      const toSelect = maxSelections 
        ? municipalities.slice(0, maxSelections - selectedMunicipalities.length)
        : municipalities;
      
      toSelect.forEach(muni => {
        if (!selectedMunicipalities.includes(muni.id)) {
          onMunicipalityToggle(muni.id);
        }
      });
    }
  };

  const isMaxReached = maxSelections ? selectedMunicipalities.length >= maxSelections : false;

  const getMunicipalityStats = () => {
    const selected = municipalities.filter(m => selectedMunicipalities.includes(m.id));
    const totalPopulation = selected.reduce((sum, m) => sum + (m.population || 0), 0);
    const totalArea = selected.reduce((sum, m) => sum + (m.area || 0), 0);
    
    return {
      count: selected.length,
      population: totalPopulation,
      area: totalArea
    };
  };

  const stats = getMunicipalityStats();

  return (
    <div className="municipality-picker">
      <div className="municipality-picker__header">
        <h4>Municipalities</h4>
        <div className="municipality-picker__controls">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search municipalities..."
            className="municipality-picker__search"
          />
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'name' | 'population')}
            className="municipality-picker__sort"
          >
            <option value="name">Sort by Name</option>
            <option value="population">Sort by Population</option>
          </select>
        </div>
      </div>

      {municipalities.length > 0 && (
        <div className="municipality-picker__stats">
          <span>
            {stats.count} of {municipalities.length} selected
            {stats.population > 0 && (
              <> • Population: {stats.population.toLocaleString('pt-BR')}</>
            )}
          </span>
          <button
            onClick={handleToggleAll}
            className="municipality-picker__toggle-all"
            disabled={isMaxReached && selectedMunicipalities.length < municipalities.length}
          >
            {selectedMunicipalities.length === municipalities.length ? 'Clear All' : 'Select All'}
          </button>
        </div>
      )}

      <div className="municipality-picker__list">
        {displayedMunicipalities.map(municipality => (
          <label
            key={municipality.id}
            className={`municipality-picker__item ${
              selectedMunicipalities.includes(municipality.id) ? 'selected' : ''
            }`}
          >
            <input
              type="checkbox"
              checked={selectedMunicipalities.includes(municipality.id)}
              onChange={() => onMunicipalityToggle(municipality.id)}
              disabled={isMaxReached && !selectedMunicipalities.includes(municipality.id)}
            />
            <div className="municipality-picker__item-content">
              <span className="municipality-picker__item-name">
                {municipality.name}
              </span>
              <span className="municipality-picker__item-info">
                {municipality.stateAbbreviation}
                {municipality.population && (
                  <> • Pop: {municipality.population.toLocaleString('pt-BR')}</>
                )}
              </span>
            </div>
          </label>
        ))}
      </div>

      {filteredAndSortedMunicipalities.length > 20 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="municipality-picker__show-more"
        >
          {showAll 
            ? 'Show Less' 
            : `Show All (${filteredAndSortedMunicipalities.length - 20} more)`
          }
        </button>
      )}

      {searchQuery && filteredAndSortedMunicipalities.length === 0 && (
        <div className="municipality-picker__no-results">
          <p>No municipalities found matching "{searchQuery}"</p>
        </div>
      )}

      {maxSelections && isMaxReached && (
        <div className="municipality-picker__max-warning">
          <p>⚠️ Maximum of {maxSelections} municipalities can be selected</p>
        </div>
      )}
    </div>
  );
};