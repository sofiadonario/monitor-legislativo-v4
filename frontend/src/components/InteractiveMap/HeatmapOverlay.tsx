/**
 * HeatmapOverlay Component
 * Displays document density heatmap using Leaflet.heat plugin
 */
import React, { useEffect, useMemo } from 'react';
import L from 'leaflet';
import { useMap } from 'react-leaflet';
import { DocumentLocation, DocumentType } from '../../types';

// Import heatmap functionality
let HeatLayer: any;
try {
  require('leaflet.heat');
  HeatLayer = (L as any).heatLayer;
} catch (error) {
  console.warn('Leaflet.heat not available, heatmap disabled');
}

interface HeatmapOverlayProps {
  documents: DocumentLocation[];
  visible?: boolean;
  radius?: number;
  blur?: number;
  maxZoom?: number;
  gradient?: Record<number, string>;
  filterByType?: DocumentType[];
  intensityMultiplier?: number;
}

const DEFAULT_GRADIENT = {
  0.4: '#0066cc',
  0.6: '#00cc66',
  0.7: '#ffcc00',
  0.8: '#ff6600',
  1.0: '#ff0000'
};

export const HeatmapOverlay: React.FC<HeatmapOverlayProps> = ({
  documents,
  visible = true,
  radius = 25,
  blur = 15,
  maxZoom = 18,
  gradient = DEFAULT_GRADIENT,
  filterByType,
  intensityMultiplier = 1
}) => {
  const map = useMap();

  // Filter and process documents for heatmap
  const heatmapData = useMemo(() => {
    let filteredDocs = documents;

    // Filter by document type if specified
    if (filterByType && filterByType.length > 0) {
      filteredDocs = documents.filter(doc => filterByType.includes(doc.type));
    }

    // Convert to heatmap format: [lat, lng, intensity]
    return filteredDocs.map(doc => {
      // Calculate intensity based on confidence and document type
      let intensity = doc.confidence * intensityMultiplier;
      
      // Boost intensity for certain document types
      const typeMultipliers = {
        lei: 1.5,
        decreto: 1.3,
        medida_provisoria: 1.4,
        portaria: 1.0,
        resolucao: 1.1,
        instrucao_normativa: 1.0,
        projeto_lei: 0.8
      };
      
      intensity *= typeMultipliers[doc.type] || 1.0;
      
      // Boost intensity for exact locations
      if (doc.precision === 'exact') {
        intensity *= 1.2;
      } else if (doc.precision === 'approximate') {
        intensity *= 0.8;
      }

      return [doc.coordinates.lat, doc.coordinates.lng, Math.min(intensity, 1.0)];
    });
  }, [documents, filterByType, intensityMultiplier]);

  useEffect(() => {
    if (!map || !HeatLayer || !visible || heatmapData.length === 0) return;

    // Create heatmap layer
    const heatmapLayer = HeatLayer(heatmapData, {
      radius,
      blur,
      maxZoom,
      gradient
    });

    // Add to map
    map.addLayer(heatmapLayer);

    // Cleanup function
    return () => {
      map.removeLayer(heatmapLayer);
    };
  }, [map, heatmapData, visible, radius, blur, maxZoom, gradient]);

  return null; // This component doesn't render anything directly
};

// Alternative implementation using CircleMarkers for browsers without heatmap support
export const FallbackHeatmapOverlay: React.FC<HeatmapOverlayProps> = ({
  documents,
  visible = true,
  filterByType,
  intensityMultiplier = 1
}) => {
  const map = useMap();

  useEffect(() => {
    if (!map || !visible) return;

    const markers: L.CircleMarker[] = [];

    let filteredDocs = documents;
    if (filterByType && filterByType.length > 0) {
      filteredDocs = documents.filter(doc => filterByType.includes(doc.type));
    }

    filteredDocs.forEach(doc => {
      const intensity = Math.min(doc.confidence * intensityMultiplier, 1.0);
      const opacity = Math.max(0.1, intensity * 0.6);
      const radius = Math.max(5, intensity * 15);

      const circle = L.circleMarker(
        [doc.coordinates.lat, doc.coordinates.lng],
        {
          radius,
          fillOpacity: opacity,
          color: '#ff0000',
          fillColor: '#ff0000',
          weight: 0
        }
      );

      map.addLayer(circle);
      markers.push(circle);
    });

    // Cleanup function
    return () => {
      markers.forEach(marker => map.removeLayer(marker));
    };
  }, [map, documents, visible, filterByType, intensityMultiplier]);

  return null;
};

// Wrapper component that uses heatmap if available, fallback otherwise
export const AdaptiveHeatmapOverlay: React.FC<HeatmapOverlayProps> = (props) => {
  if (HeatLayer) {
    return <HeatmapOverlay {...props} />;
  } else {
    return <FallbackHeatmapOverlay {...props} />;
  }
};