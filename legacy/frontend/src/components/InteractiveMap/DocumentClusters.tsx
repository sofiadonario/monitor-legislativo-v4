/**
 * DocumentClusters Component
 * Displays clustered document markers on the map with Leaflet MarkerCluster
 */
import React, { useEffect, useMemo } from 'react';
import L from 'leaflet';
import { useMap } from 'react-leaflet';
import { DocumentLocation, DocumentType } from '../../types';
import 'leaflet.markercluster/dist/MarkerCluster.css';
import 'leaflet.markercluster/dist/MarkerCluster.Default.css';

// Import marker cluster functionality
let MarkerClusterGroup: any;
try {
  MarkerClusterGroup = require('leaflet.markercluster');
} catch (error) {
  // Fallback if markercluster not available
  console.warn('Leaflet MarkerCluster not available, using standard markers');
}

interface DocumentClustersProps {
  documents: DocumentLocation[];
  onDocumentClick?: (document: DocumentLocation) => void;
  maxClusterRadius?: number;
  showCoverageOnHover?: boolean;
  zoomToBoundsOnClick?: boolean;
  spiderfyOnMaxZoom?: boolean;
}

// Document type colors
const DOCUMENT_TYPE_COLORS = {
  lei: '#4299e1',
  decreto: '#48bb78',
  portaria: '#ed8936',
  resolucao: '#9f7aea',
  instrucao_normativa: '#38b2ac',
  projeto_lei: '#f56565',
  medida_provisoria: '#d69e2e'
};

// Create custom icon based on document type
const createDocumentIcon = (type: DocumentType, count?: number): L.DivIcon => {
  const color = DOCUMENT_TYPE_COLORS[type] || '#718096';
  const isCluster = count && count > 1;
  
  return L.divIcon({
    html: `
      <div class="document-marker ${isCluster ? 'cluster' : 'single'}" style="background-color: ${color}">
        <div class="document-marker__content">
          ${isCluster ? count : getDocumentTypeIcon(type)}
        </div>
      </div>
    `,
    className: 'document-marker-container',
    iconSize: isCluster ? [40, 40] : [30, 30],
    iconAnchor: isCluster ? [20, 40] : [15, 30]
  });
};

const getDocumentTypeIcon = (type: DocumentType): string => {
  const icons = {
    lei: '📜',
    decreto: '📋',
    portaria: '📄',
    resolucao: '📃',
    instrucao_normativa: '📑',
    projeto_lei: '📝',
    medida_provisoria: '⚡'
  };
  return icons[type] || '📄';
};

export const DocumentClusters: React.FC<DocumentClustersProps> = ({
  documents,
  onDocumentClick,
  maxClusterRadius = 80,
  showCoverageOnHover = true,
  zoomToBoundsOnClick = true,
  spiderfyOnMaxZoom = true
}) => {
  const map = useMap();

  // Group documents by type for better clustering
  const documentsByType = useMemo(() => {
    return documents.reduce((acc, doc) => {
      if (!acc[doc.type]) {
        acc[doc.type] = [];
      }
      acc[doc.type].push(doc);
      return acc;
    }, {} as Record<DocumentType, DocumentLocation[]>);
  }, [documents]);

  useEffect(() => {
    if (!map || documents.length === 0) return;

    const markerClusterGroups: L.MarkerClusterGroup[] = [];

    // Create cluster group for each document type
    Object.entries(documentsByType).forEach(([type, docsOfType]) => {
      const clusterGroup = MarkerClusterGroup ? new L.MarkerClusterGroup({
        maxClusterRadius,
        showCoverageOnHover,
        zoomToBoundsOnClick,
        spiderfyOnMaxZoom,
        iconCreateFunction: (cluster: any) => {
          const count = cluster.getChildCount();
          return createDocumentIcon(type as DocumentType, count);
        }
      }) : new L.LayerGroup();

      docsOfType.forEach(doc => {
        const marker = L.marker(
          [doc.coordinates.lat, doc.coordinates.lng],
          { icon: createDocumentIcon(doc.type) }
        );

        // Create popup content
        const popupContent = `
          <div class="document-popup">
            <div class="document-popup__header">
              <span class="document-popup__type">${getDocumentTypeIcon(doc.type)} ${doc.type.toUpperCase()}</span>
              <span class="document-popup__precision ${doc.precision}">${doc.precision}</span>
            </div>
            <h3 class="document-popup__title">${doc.title}</h3>
            <div class="document-popup__location">
              📍 ${doc.municipality}, ${doc.state}
            </div>
            ${doc.address ? `
              <div class="document-popup__address">
                ${doc.address.formattedAddress}
              </div>
            ` : ''}
            <div class="document-popup__confidence">
              Confidence: ${Math.round(doc.confidence * 100)}%
            </div>
            <div class="document-popup__actions">
              <button class="document-popup__view-btn" onclick="window.viewDocument?.('${doc.urn}')">
                View Document
              </button>
            </div>
          </div>
        `;

        marker.bindPopup(popupContent, {
          maxWidth: 300,
          className: 'document-popup-container'
        });

        // Handle marker click
        marker.on('click', () => {
          if (onDocumentClick) {
            onDocumentClick(doc);
          }
        });

        // Add marker to cluster group
        if (MarkerClusterGroup && clusterGroup.addLayer) {
          clusterGroup.addLayer(marker);
        } else {
          (clusterGroup as L.LayerGroup).addLayer(marker);
        }
      });

      map.addLayer(clusterGroup);
      markerClusterGroups.push(clusterGroup);
    });

    // Add global view document function
    (window as any).viewDocument = (urn: string) => {
      const doc = documents.find(d => d.urn === urn);
      if (doc && onDocumentClick) {
        onDocumentClick(doc);
      }
    };

    // Fit map to show all markers if there are any
    if (documents.length > 0) {
      const group = new L.FeatureGroup();
      documents.forEach(doc => {
        group.addLayer(L.marker([doc.coordinates.lat, doc.coordinates.lng]));
      });
      
      try {
        map.fitBounds(group.getBounds(), { padding: [20, 20] });
      } catch (error) {
        // Fallback to center of Brazil if bounds calculation fails
        map.setView([-15.7942, -47.8822], 4);
      }
    }

    // Cleanup function
    return () => {
      markerClusterGroups.forEach(group => {
        map.removeLayer(group);
      });
      delete (window as any).viewDocument;
    };
  }, [map, documents, documentsByType, onDocumentClick, maxClusterRadius, showCoverageOnHover, zoomToBoundsOnClick, spiderfyOnMaxZoom]);

  return null; // This component doesn't render anything directly
};

// CSS for document markers (to be injected)
const markerStyles = `
.document-marker-container {
  background: none !important;
  border: none !important;
}

.document-marker {
  border-radius: 50%;
  border: 2px solid #ffffff;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #ffffff;
  font-weight: 600;
  transition: transform 0.2s ease;
}

.document-marker:hover {
  transform: scale(1.1);
}

.document-marker.single {
  font-size: 16px;
}

.document-marker.cluster {
  font-size: 14px;
}

.document-marker__content {
  display: flex;
  align-items: center;
  justify-content: center;
}

.document-popup {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-width: 280px;
}

.document-popup__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.document-popup__type {
  background-color: #f7fafc;
  color: #4a5568;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 600;
}

.document-popup__precision {
  padding: 0.125rem 0.375rem;
  border-radius: 3px;
  font-size: 0.7rem;
  font-weight: 500;
  text-transform: uppercase;
}

.document-popup__precision.exact {
  background-color: #c6f6d5;
  color: #22543d;
}

.document-popup__precision.municipality {
  background-color: #fef5e7;
  color: #744210;
}

.document-popup__precision.state {
  background-color: #fed7d7;
  color: #742a2a;
}

.document-popup__precision.approximate {
  background-color: #e6fffa;
  color: #234e52;
}

.document-popup__title {
  color: #2d3748;
  font-size: 1rem;
  font-weight: 600;
  line-height: 1.3;
  margin: 0 0 0.75rem 0;
}

.document-popup__location {
  color: #4a5568;
  font-size: 0.9rem;
  margin-bottom: 0.5rem;
}

.document-popup__address {
  color: #718096;
  font-size: 0.85rem;
  margin-bottom: 0.5rem;
  line-height: 1.3;
}

.document-popup__confidence {
  color: #718096;
  font-size: 0.8rem;
  margin-bottom: 1rem;
}

.document-popup__actions {
  display: flex;
  gap: 0.5rem;
}

.document-popup__view-btn {
  background-color: #4299e1;
  color: #ffffff;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s;
}

.document-popup__view-btn:hover {
  background-color: #3182ce;
}

/* Cluster marker overrides */
.marker-cluster-small {
  background-color: rgba(66, 153, 225, 0.8) !important;
}

.marker-cluster-medium {
  background-color: rgba(66, 153, 225, 0.9) !important;
}

.marker-cluster-large {
  background-color: rgba(66, 153, 225, 1) !important;
}

.marker-cluster {
  border: 2px solid #ffffff !important;
  border-radius: 50% !important;
  color: #ffffff !important;
  font-weight: 600 !important;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = markerStyles;
  document.head.appendChild(styleElement);
}