/**
 * GeographicBounds Component
 * Displays Brazilian state and municipality boundaries with interactive selection
 */
import React, { useEffect, useMemo } from 'react';
import { GeoJSON } from 'react-leaflet';
import L from 'leaflet';
import { StateData, Municipality } from '../../types';

interface GeographicBoundsProps {
  states?: StateData[];
  municipalities?: Municipality[];
  selectedStates?: string[];
  selectedMunicipalities?: string[];
  onStateClick?: (stateId: string) => void;
  onMunicipalityClick?: (municipalityId: string) => void;
  showStateLabels?: boolean;
  showMunicipalityLabels?: boolean;
  highlightSelected?: boolean;
}

const BRAZIL_REGION_COLORS = {
  'Norte': '#10b981',
  'Nordeste': '#f59e0b', 
  'Centro-Oeste': '#8b5cf6',
  'Sudeste': '#3b82f6',
  'Sul': '#ef4444'
};

export const GeographicBounds: React.FC<GeographicBoundsProps> = ({
  states = [],
  municipalities = [],
  selectedStates = [],
  selectedMunicipalities = [],
  onStateClick,
  onMunicipalityClick,
  showStateLabels = true,
  showMunicipalityLabels = false,
  highlightSelected = true
}) => {
  
  // Create state features from StateData
  const stateFeatures = useMemo(() => {
    return {
      type: 'FeatureCollection',
      features: states
        .filter(state => state.boundaries)
        .map(state => ({
          type: 'Feature',
          properties: {
            id: state.id,
            name: state.name,
            abbreviation: state.abbreviation,
            region: state.region,
            population: state.population,
            area: state.area,
            isSelected: selectedStates.includes(state.id)
          },
          geometry: state.boundaries
        }))
    };
  }, [states, selectedStates]);

  // Create municipality features from Municipality data
  const municipalityFeatures = useMemo(() => {
    return {
      type: 'FeatureCollection',
      features: municipalities
        .filter(muni => muni.boundaries)
        .map(muni => ({
          type: 'Feature',
          properties: {
            id: muni.id,
            name: muni.name,
            stateId: muni.stateId,
            stateAbbreviation: muni.stateAbbreviation,
            population: muni.population,
            area: muni.area,
            ibgeCode: muni.ibgeCode,
            isSelected: selectedMunicipalities.includes(muni.id)
          },
          geometry: muni.boundaries
        }))
    };
  }, [municipalities, selectedMunicipalities]);

  // Style function for states
  const getStateStyle = (feature: any) => {
    const isSelected = feature.properties.isSelected;
    const region = feature.properties.region;
    const regionColor = BRAZIL_REGION_COLORS[region as keyof typeof BRAZIL_REGION_COLORS] || '#718096';

    return {
      fillColor: isSelected && highlightSelected ? regionColor : 'transparent',
      weight: isSelected ? 3 : 1,
      opacity: 1,
      color: isSelected ? regionColor : '#94a3b8',
      dashArray: isSelected ? '' : '5, 5',
      fillOpacity: isSelected && highlightSelected ? 0.3 : 0.1
    };
  };

  // Style function for municipalities  
  const getMunicipalityStyle = (feature: any) => {
    const isSelected = feature.properties.isSelected;

    return {
      fillColor: isSelected && highlightSelected ? '#4299e1' : 'transparent',
      weight: isSelected ? 2 : 1,
      opacity: 0.8,
      color: isSelected ? '#2b6cb0' : '#94a3b8',
      dashArray: isSelected ? '' : '3, 3',
      fillOpacity: isSelected && highlightSelected ? 0.4 : 0.05
    };
  };

  // Handle state feature events
  const onStateFeature = (feature: any, layer: L.Layer) => {
    const properties = feature.properties;
    
    // Create popup content
    const popupContent = `
      <div class="boundary-popup">
        <h3 class="boundary-popup__title">${properties.name}</h3>
        <div class="boundary-popup__info">
          <div class="boundary-popup__item">
            <strong>Região:</strong> ${properties.region}
          </div>
          <div class="boundary-popup__item">
            <strong>UF:</strong> ${properties.abbreviation}
          </div>
          ${properties.population ? `
            <div class="boundary-popup__item">
              <strong>População:</strong> ${properties.population.toLocaleString('pt-BR')}
            </div>
          ` : ''}
          ${properties.area ? `
            <div class="boundary-popup__item">
              <strong>Área:</strong> ${properties.area.toLocaleString('pt-BR')} km²
            </div>
          ` : ''}
        </div>
        ${onStateClick ? `
          <button class="boundary-popup__select-btn" onclick="window.selectState?.('${properties.id}')">
            ${properties.isSelected ? 'Desselecionar' : 'Selecionar'} Estado
          </button>
        ` : ''}
      </div>
    `;

    layer.bindPopup(popupContent, {
      maxWidth: 250,
      className: 'boundary-popup-container'
    });

    // Add hover effects
    layer.on({
      mouseover: (e) => {
        const target = e.target;
        target.setStyle({
          weight: 3,
          color: '#2563eb',
          fillOpacity: 0.4
        });
        target.bringToFront();
      },
      mouseout: (e) => {
        const target = e.target;
        target.setStyle(getStateStyle(feature));
      },
      click: () => {
        if (onStateClick) {
          onStateClick(properties.id);
        }
      }
    });

    // Add label if enabled
    if (showStateLabels) {
      const bounds = (layer as L.Polygon).getBounds();
      const center = bounds.getCenter();
      
      const label = L.divIcon({
        html: `<div class="state-label">${properties.abbreviation}</div>`,
        className: 'state-label-container',
        iconSize: [30, 20],
        iconAnchor: [15, 10]
      });

      L.marker(center, { icon: label }).addTo((layer as any)._map);
    }
  };

  // Handle municipality feature events
  const onMunicipalityFeature = (feature: any, layer: L.Layer) => {
    const properties = feature.properties;
    
    const popupContent = `
      <div class="boundary-popup">
        <h3 class="boundary-popup__title">${properties.name}</h3>
        <div class="boundary-popup__info">
          <div class="boundary-popup__item">
            <strong>Estado:</strong> ${properties.stateAbbreviation}
          </div>
          <div class="boundary-popup__item">
            <strong>Código IBGE:</strong> ${properties.ibgeCode}
          </div>
          ${properties.population ? `
            <div class="boundary-popup__item">
              <strong>População:</strong> ${properties.population.toLocaleString('pt-BR')}
            </div>
          ` : ''}
          ${properties.area ? `
            <div class="boundary-popup__item">
              <strong>Área:</strong> ${properties.area.toLocaleString('pt-BR')} km²
            </div>
          ` : ''}
        </div>
        ${onMunicipalityClick ? `
          <button class="boundary-popup__select-btn" onclick="window.selectMunicipality?.('${properties.id}')">
            ${properties.isSelected ? 'Desselecionar' : 'Selecionar'} Município
          </button>
        ` : ''}
      </div>
    `;

    layer.bindPopup(popupContent, {
      maxWidth: 250,
      className: 'boundary-popup-container'
    });

    layer.on({
      mouseover: (e) => {
        const target = e.target;
        target.setStyle({
          weight: 2,
          color: '#1d4ed8',
          fillOpacity: 0.5
        });
        target.bringToFront();
      },
      mouseout: (e) => {
        const target = e.target;
        target.setStyle(getMunicipalityStyle(feature));
      },
      click: () => {
        if (onMunicipalityClick) {
          onMunicipalityClick(properties.id);
        }
      }
    });

    // Add label if enabled
    if (showMunicipalityLabels) {
      const bounds = (layer as L.Polygon).getBounds();
      const center = bounds.getCenter();
      
      const label = L.divIcon({
        html: `<div class="municipality-label">${properties.name}</div>`,
        className: 'municipality-label-container',
        iconSize: [60, 15],
        iconAnchor: [30, 7]
      });

      L.marker(center, { icon: label }).addTo((layer as any)._map);
    }
  };

  // Set up global selection functions
  useEffect(() => {
    (window as any).selectState = onStateClick;
    (window as any).selectMunicipality = onMunicipalityClick;

    return () => {
      delete (window as any).selectState;
      delete (window as any).selectMunicipality;
    };
  }, [onStateClick, onMunicipalityClick]);

  return (
    <>
      {/* State boundaries */}
      {stateFeatures.features.length > 0 && (
        <GeoJSON
          key={`states-${selectedStates.join('-')}`}
          data={stateFeatures as any}
          style={getStateStyle}
          onEachFeature={onStateFeature}
        />
      )}
      
      {/* Municipality boundaries */}
      {municipalityFeatures.features.length > 0 && (
        <GeoJSON
          key={`municipalities-${selectedMunicipalities.join('-')}`}
          data={municipalityFeatures as any}
          style={getMunicipalityStyle}
          onEachFeature={onMunicipalityFeature}
        />
      )}
    </>
  );
};

// CSS styles (to be injected)
const boundaryStyles = `
.boundary-popup-container .leaflet-popup-content-wrapper {
  border-radius: 8px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.boundary-popup {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-width: 200px;
}

.boundary-popup__title {
  color: #2d3748;
  font-size: 1rem;
  font-weight: 600;
  margin: 0 0 0.75rem 0;
  line-height: 1.3;
}

.boundary-popup__info {
  margin-bottom: 1rem;
}

.boundary-popup__item {
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  line-height: 1.3;
}

.boundary-popup__item strong {
  color: #4a5568;
  font-weight: 600;
}

.boundary-popup__select-btn {
  background-color: #4299e1;
  color: #ffffff;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  width: 100%;
  transition: background-color 0.2s;
}

.boundary-popup__select-btn:hover {
  background-color: #3182ce;
}

.state-label-container,
.municipality-label-container {
  background: none !important;
  border: none !important;
}

.state-label {
  background-color: rgba(255, 255, 255, 0.9);
  color: #2d3748;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-align: center;
  border: 1px solid #e2e8f0;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  pointer-events: none;
}

.municipality-label {
  background-color: rgba(255, 255, 255, 0.8);
  color: #4a5568;
  padding: 0.125rem 0.25rem;
  border-radius: 3px;
  font-size: 0.6rem;
  font-weight: 500;
  text-align: center;
  border: 1px solid #e2e8f0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  pointer-events: none;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = boundaryStyles;
  document.head.appendChild(styleElement);
}