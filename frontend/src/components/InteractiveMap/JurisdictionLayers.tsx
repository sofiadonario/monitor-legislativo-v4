/**
 * JurisdictionLayers Component
 * Displays administrative and regulatory jurisdiction boundaries
 */
import React, { useEffect, useMemo } from 'react';
import { GeoJSON, useMap } from 'react-leaflet';
import L from 'leaflet';
import { JurisdictionType, JurisdictionArea } from '../../types';

interface JurisdictionLayersProps {
  jurisdictions?: JurisdictionArea[];
  visible?: boolean;
  showLabels?: boolean;
  filterByType?: JurisdictionType[];
  selectedJurisdictions?: string[];
  onJurisdictionClick?: (jurisdiction: JurisdictionArea) => void;
}

// Jurisdiction type colors and patterns
const JURISDICTION_STYLES = {
  federal: {
    color: '#dc2626',
    fillColor: 'rgba(220, 38, 38, 0.1)',
    weight: 3,
    dashArray: ''
  },
  state: {
    color: '#2563eb',
    fillColor: 'rgba(37, 99, 235, 0.1)',
    weight: 2,
    dashArray: '5, 5'
  },
  municipal: {
    color: '#16a34a',
    fillColor: 'rgba(22, 163, 74, 0.1)',
    weight: 1,
    dashArray: '3, 3'
  },
  regulatory: {
    color: '#9333ea',
    fillColor: 'rgba(147, 51, 234, 0.1)',
    weight: 2,
    dashArray: '10, 2'
  },
  environmental: {
    color: '#059669',
    fillColor: 'rgba(5, 150, 105, 0.1)',
    weight: 2,
    dashArray: '8, 4'
  },
  transport: {
    color: '#ea580c',
    fillColor: 'rgba(234, 88, 12, 0.1)',
    weight: 2,
    dashArray: '6, 3'
  }
};

// Sample Brazilian jurisdiction areas
const SAMPLE_JURISDICTIONS: JurisdictionArea[] = [
  {
    id: 'antt-national',
    name: 'ANTT - Jurisdição Nacional',
    type: 'regulatory',
    agency: 'ANTT',
    description: 'Agência Nacional de Transportes Terrestres',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-73.9856, 5.2718],
        [-28.8503, 5.2718],
        [-28.8503, -33.7506],
        [-73.9856, -33.7506],
        [-73.9856, 5.2718]
      ]]
    }
  },
  {
    id: 'antaq-waterways',
    name: 'ANTAQ - Hidrovias',
    type: 'transport',
    agency: 'ANTAQ',
    description: 'Agência Nacional de Transportes Aquaviários',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-60.0000, -5.0000],
        [-45.0000, -5.0000],
        [-45.0000, -25.0000],
        [-60.0000, -25.0000],
        [-60.0000, -5.0000]
      ]]
    }
  },
  {
    id: 'ibama-amazonia',
    name: 'IBAMA - Região Amazônica',
    type: 'environmental',
    agency: 'IBAMA',
    description: 'Instituto Brasileiro do Meio Ambiente',
    boundaries: {
      type: 'Polygon',
      coordinates: [[
        [-73.9856, 5.2718],
        [-49.0000, 5.2718],
        [-49.0000, -16.0000],
        [-73.9856, -16.0000],
        [-73.9856, 5.2718]
      ]]
    }
  }
];

export const JurisdictionLayers: React.FC<JurisdictionLayersProps> = ({
  jurisdictions = SAMPLE_JURISDICTIONS,
  visible = true,
  showLabels = true,
  filterByType,
  selectedJurisdictions = [],
  onJurisdictionClick
}) => {
  const map = useMap();

  // Filter jurisdictions by type if specified
  const filteredJurisdictions = useMemo(() => {
    if (!filterByType || filterByType.length === 0) {
      return jurisdictions;
    }
    return jurisdictions.filter(jurisdiction => filterByType.includes(jurisdiction.type));
  }, [jurisdictions, filterByType]);

  // Create GeoJSON features from jurisdictions
  const jurisdictionFeatures = useMemo(() => {
    return {
      type: 'FeatureCollection',
      features: filteredJurisdictions.map(jurisdiction => ({
        type: 'Feature',
        properties: {
          id: jurisdiction.id,
          name: jurisdiction.name,
          type: jurisdiction.type,
          agency: jurisdiction.agency,
          description: jurisdiction.description,
          isSelected: selectedJurisdictions.includes(jurisdiction.id)
        },
        geometry: jurisdiction.boundaries
      }))
    };
  }, [filteredJurisdictions, selectedJurisdictions]);

  // Style function for jurisdictions
  const getJurisdictionStyle = (feature: any) => {
    const jurisdictionType = feature.properties.type;
    const isSelected = feature.properties.isSelected;
    const baseStyle = JURISDICTION_STYLES[jurisdictionType as keyof typeof JURISDICTION_STYLES] || JURISDICTION_STYLES.federal;
    
    return {
      ...baseStyle,
      weight: isSelected ? baseStyle.weight + 1 : baseStyle.weight,
      opacity: isSelected ? 1 : 0.7,
      fillOpacity: isSelected ? 0.3 : 0.1
    };
  };

  // Handle jurisdiction feature events
  const onEachJurisdiction = (feature: any, layer: L.Layer) => {
    const properties = feature.properties;
    
    const popupContent = `
      <div class="jurisdiction-popup">
        <h3 class="jurisdiction-popup__title">${properties.name}</h3>
        <div class="jurisdiction-popup__info">
          <div class="jurisdiction-popup__type">
            <strong>Tipo:</strong> ${properties.type.toUpperCase()}
          </div>
          ${properties.agency ? `
            <div class="jurisdiction-popup__agency">
              <strong>Órgão:</strong> ${properties.agency}
            </div>
          ` : ''}
          ${properties.description ? `
            <div class="jurisdiction-popup__description">
              ${properties.description}
            </div>
          ` : ''}
        </div>
        ${onJurisdictionClick ? `
          <button class="jurisdiction-popup__select-btn" onclick="window.selectJurisdiction?.('${properties.id}')">
            ${properties.isSelected ? 'Desselecionar' : 'Selecionar'} Jurisdição
          </button>
        ` : ''}
      </div>
    `;

    layer.bindPopup(popupContent, {
      maxWidth: 300,
      className: 'jurisdiction-popup-container'
    });

    layer.on({
      mouseover: (e) => {
        const target = e.target;
        target.setStyle({
          weight: 4,
          opacity: 1,
          fillOpacity: 0.4
        });
        target.bringToFront();
      },
      mouseout: (e) => {
        const target = e.target;
        target.setStyle(getJurisdictionStyle(feature));
      },
      click: () => {
        if (onJurisdictionClick) {
          const jurisdiction = filteredJurisdictions.find(j => j.id === properties.id);
          if (jurisdiction) {
            onJurisdictionClick(jurisdiction);
          }
        }
      }
    });
  };

  useEffect(() => {
    if (!map || !visible) return;

    const jurisdictionLabels: L.Marker[] = [];

    // Add jurisdiction labels if enabled
    if (showLabels) {
      filteredJurisdictions.forEach(jurisdiction => {
        if (jurisdiction.boundaries && jurisdiction.boundaries.type === 'Polygon') {
          // Calculate centroid for label placement
          const coords = jurisdiction.boundaries.coordinates[0];
          const centroid = coords.reduce(
            (acc, coord) => ({
              lat: acc.lat + coord[1],
              lng: acc.lng + coord[0]
            }),
            { lat: 0, lng: 0 }
          );
          centroid.lat /= coords.length;
          centroid.lng /= coords.length;

          const style = JURISDICTION_STYLES[jurisdiction.type] || JURISDICTION_STYLES.federal;
          
          const label = L.divIcon({
            html: `<div class="jurisdiction-label" style="color: ${style.color}">${jurisdiction.agency || jurisdiction.name}</div>`,
            className: 'jurisdiction-label-container',
            iconSize: [80, 20],
            iconAnchor: [40, 10]
          });

          const marker = L.marker([centroid.lat, centroid.lng], { icon: label });
          map.addLayer(marker);
          jurisdictionLabels.push(marker);
        }
      });
    }

    // Set up global selection function
    (window as any).selectJurisdiction = (jurisdictionId: string) => {
      if (onJurisdictionClick) {
        const jurisdiction = filteredJurisdictions.find(j => j.id === jurisdictionId);
        if (jurisdiction) {
          onJurisdictionClick(jurisdiction);
        }
      }
    };

    // Cleanup function
    return () => {
      jurisdictionLabels.forEach(marker => map.removeLayer(marker));
      delete (window as any).selectJurisdiction;
    };
  }, [map, filteredJurisdictions, visible, showLabels, onJurisdictionClick]);

  if (!visible || jurisdictionFeatures.features.length === 0) return null;

  return (
    <GeoJSON
      key={`jurisdictions-${selectedJurisdictions.join('-')}`}
      data={jurisdictionFeatures as any}
      style={getJurisdictionStyle}
      onEachFeature={onEachJurisdiction}
    />
  );
};

// CSS styles (to be injected)
const jurisdictionStyles = `
.jurisdiction-popup-container .leaflet-popup-content-wrapper {
  border-radius: 8px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.jurisdiction-popup {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-width: 250px;
}

.jurisdiction-popup__title {
  color: #2d3748;
  font-size: 1rem;
  font-weight: 600;
  margin: 0 0 0.75rem 0;
  line-height: 1.3;
}

.jurisdiction-popup__info {
  margin-bottom: 1rem;
}

.jurisdiction-popup__type,
.jurisdiction-popup__agency {
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  line-height: 1.3;
}

.jurisdiction-popup__type strong,
.jurisdiction-popup__agency strong {
  color: #4a5568;
  font-weight: 600;
}

.jurisdiction-popup__description {
  color: #718096;
  font-size: 0.85rem;
  line-height: 1.4;
  margin-bottom: 0.75rem;
  font-style: italic;
}

.jurisdiction-popup__select-btn {
  background-color: #9333ea;
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

.jurisdiction-popup__select-btn:hover {
  background-color: #7c3aed;
}

.jurisdiction-label-container {
  background: none !important;
  border: none !important;
}

.jurisdiction-label {
  background-color: rgba(255, 255, 255, 0.9);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 600;
  text-align: center;
  border: 1px solid #e2e8f0;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  pointer-events: none;
  white-space: nowrap;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = jurisdictionStyles;
  document.head.appendChild(styleElement);
}