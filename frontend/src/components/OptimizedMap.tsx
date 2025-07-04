import L from 'leaflet';
import React, { memo, useCallback, useMemo } from 'react';
import { GeoJSON, MapContainer, TileLayer, useMap } from 'react-leaflet';
import { brazilStatesData } from '../data/brazil-states';
import { LegislativeDocument } from '../types';
import { GeoJSONFeature, GeoJSONFeatureCollection } from '../types/geo';
import { AccessibleMap } from './AccessibleMap';
import '../styles/components/OptimizedMap.css';

interface MapProps {
  selectedState?: string;
  selectedMunicipality?: string;
  documents: LegislativeDocument[];
  onLocationClick: (type: 'state' | 'municipality', id: string) => void;
  highlightedLocations?: string[];
}

const MapController: React.FC<{ center: [number, number]; zoom: number }> = memo(({ center, zoom }) => {
  const map = useMap();
  
  React.useEffect(() => {
    map.setView(center, zoom);
  }, [center, zoom, map]);
  
  return null;
});

MapController.displayName = 'MapController';

export const OptimizedMap = memo<MapProps>(({ 
  selectedState,
  selectedMunicipality,
  documents, 
  onLocationClick, 
  highlightedLocations = []
}) => {
  // Memoize filtered documents to avoid unnecessary re-processing
  const memoizedDocuments = useMemo(() => 
    documents.filter(doc => doc.state), 
    [documents]
  );
  
  // Memoize state document counts for performance
  const stateDocumentCounts = useMemo(() => 
    memoizedDocuments.reduce((acc, doc) => {
      if (doc.state) acc[doc.state] = (acc[doc.state] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
    [memoizedDocuments]
  );

  // Memoize map center and zoom
  const [mapCenter, mapZoom] = useMemo(() => {
    if (selectedState) {
      const stateData = (brazilStatesData as GeoJSONFeatureCollection).features.find(
        (feature: GeoJSONFeature) => feature.properties.id === selectedState
      );
      if (stateData?.properties?.coordinates) {
        return [stateData.properties.coordinates, 6] as const;
      }
    }
    return [[-15.7801, -47.9292] as [number, number], 4] as const;
  }, [selectedState]);

  // Memoize style function
  const getStateStyle = useCallback((feature: GeoJSONFeature | undefined) => {
    if (!feature) {
      return {};
    }
    const stateId = feature.properties.id;
    const isSelected = selectedState === stateId;
    const isHighlighted = highlightedLocations.includes(stateId);
    
    return {
      fillColor: isSelected ? '#2196F3' : isHighlighted ? '#FFC107' : '#4CAF50',
      weight: isSelected ? 3 : 2,
      opacity: 1,
      color: 'white',
      dashArray: isSelected ? '' : '3',
      fillOpacity: isSelected ? 0.9 : isHighlighted ? 0.7 : 0.5
    };
  }, [selectedState, highlightedLocations]);

  // Memoize location click handler
  const handleLocationClick = useCallback((type: string, id: string) => {
    onLocationClick(type as 'state' | 'municipality', id);
  }, [onLocationClick]);

  // Memoize onEachFeature function for better performance
  const onEachState = useCallback((feature: GeoJSONFeature, layer: L.Layer) => {
    if (feature.properties && feature.properties.name) {
      const stateData = feature.properties;
      const stateDocuments = memoizedDocuments.filter(doc => doc.state === stateData.abbreviation);
      
      layer.bindPopup(`
        <div style="min-width: 200px;">
          <h3>${stateData.name} (${stateData.abbreviation})</h3>
          <p><strong>Capital:</strong> ${stateData.capital}</p>
          <p><strong>Região:</strong> ${stateData.region}</p>
          <p><strong>Documentos:</strong> ${stateDocuments.length}</p>
        </div>
      `);
      
      (layer as any).on({
        mouseover: (e: L.LeafletMouseEvent) => {
          const targetLayer = e.target;
          targetLayer.setStyle({
            weight: 5,
            color: '#666',
            dashArray: '',
            fillOpacity: 0.7
          });
          targetLayer.bringToFront();
        },
        mouseout: (e: L.LeafletMouseEvent) => {
          const targetLayer = e.target;
          targetLayer.setStyle(getStateStyle(feature));
        },
        click: () => {
          handleLocationClick('state', stateData.id);
        }
      });
    }
  }, [memoizedDocuments, getStateStyle, handleLocationClick]);

  return (
    <div className="map-wrapper">
      {/* Visual map for sighted users */}
      <div 
        className="visual-map" 
        role="img" 
        aria-label="Interactive map of Brazil showing legislative data by state"
        aria-describedby="map-description"
      >
        <div id="map-description" className="sr-only">
          This map shows Brazilian states with different colors indicating legislative document availability. 
          Use the accessible interface below for keyboard navigation.
        </div>
        
        <div className="map-container map-controls" style={{ height: '100%', width: '100%' }}>
          <MapContainer 
            center={mapCenter} 
            zoom={mapZoom} 
            style={{ height: '100%', width: '100%' }}
            zoomControl={true}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            
            <MapController center={mapCenter} zoom={mapZoom} />
            
            <GeoJSON 
              data={brazilStatesData as GeoJSONFeatureCollection}
              style={getStateStyle}
              onEachFeature={onEachState}
            />
          </MapContainer>
          
          {/* Map legend for exports */}
          <div className="map-legend" style={{
            position: 'absolute',
            bottom: '20px',
            right: '20px',
            background: 'rgba(255, 255, 255, 0.95)',
            padding: '12px',
            borderRadius: '8px',
            boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
            fontSize: '12px',
            lineHeight: '1.4',
            zIndex: 1000
          }}>
            <div style={{ fontWeight: 'bold', marginBottom: '8px' }}>Legenda</div>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
              <div style={{ 
                width: '16px', 
                height: '16px', 
                backgroundColor: '#2196F3', 
                marginRight: '8px',
                border: '1px solid #fff'
              }}></div>
              Estado selecionado
            </div>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
              <div style={{ 
                width: '16px', 
                height: '16px', 
                backgroundColor: '#FFC107', 
                marginRight: '8px',
                border: '1px solid #fff'
              }}></div>
              Estados destacados
            </div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{ 
                width: '16px', 
                height: '16px', 
                backgroundColor: '#4CAF50', 
                marginRight: '8px',
                border: '1px solid #fff'
              }}></div>
              Estados com documentos
            </div>
          </div>
        </div>
      </div>
      
      {/* Accessible alternative */}
      <AccessibleMap 
        documents={memoizedDocuments} 
        onStateSelect={(stateId) => handleLocationClick('state', stateId)} 
        selectedState={selectedState}
      />
    </div>
  );
});

OptimizedMap.displayName = 'OptimizedMap';

export default OptimizedMap;