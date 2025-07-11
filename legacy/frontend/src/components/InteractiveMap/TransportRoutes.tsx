/**
 * TransportRoutes Component
 * Displays Brazilian transport corridors and routes on the map
 */
import React, { useEffect, useMemo } from 'react';
import { Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import { Coordinates, TransportRoute, TransportType } from '../../types';

interface TransportRoutesProps {
  routes?: TransportRoute[];
  visible?: boolean;
  showLabels?: boolean;
  filterByType?: TransportType[];
  onRouteClick?: (route: TransportRoute) => void;
}

// Transport type colors
const TRANSPORT_TYPE_COLORS = {
  highway: '#3b82f6',
  railway: '#ef4444',
  waterway: '#06b6d4',
  airway: '#8b5cf6',
  pipeline: '#f59e0b'
};

// Major Brazilian transport corridors (sample data)
const MAJOR_CORRIDORS: TransportRoute[] = [
  {
    id: 'br-101',
    name: 'BR-101 (Rio-Bahia Highway)',
    type: 'highway',
    coordinates: [
      { lat: -22.9068, lng: -43.1729 }, // Rio de Janeiro
      { lat: -20.3155, lng: -40.3128 }, // Vitória
      { lat: -16.6869, lng: -39.2091 }, // Porto Seguro
      { lat: -12.9714, lng: -38.5014 }  // Salvador
    ],
    description: 'Major coastal highway connecting Rio de Janeiro to Bahia'
  },
  {
    id: 'br-116',
    name: 'BR-116 (Dutra Highway)',
    type: 'highway',
    coordinates: [
      { lat: -23.5505, lng: -46.6333 }, // São Paulo
      { lat: -22.9068, lng: -43.1729 }  // Rio de Janeiro
    ],
    description: 'Main highway connecting São Paulo and Rio de Janeiro'
  },
  {
    id: 'tietê-paraná',
    name: 'Tietê-Paraná Waterway',
    type: 'waterway',
    coordinates: [
      { lat: -23.5505, lng: -46.6333 }, // São Paulo
      { lat: -22.7295, lng: -47.6307 }, // Piracicaba
      { lat: -20.4697, lng: -54.6201 }  // Campo Grande
    ],
    description: 'Strategic waterway for grain transport'
  },
  {
    id: 'vale-railway',
    name: 'Estrada de Ferro Vitória-Minas',
    type: 'railway',
    coordinates: [
      { lat: -20.3155, lng: -40.3128 }, // Vitória
      { lat: -19.9191, lng: -43.9386 }  // Belo Horizonte
    ],
    description: 'Iron ore railway from Minas Gerais to port of Vitória'
  }
];

export const TransportRoutes: React.FC<TransportRoutesProps> = ({
  routes = MAJOR_CORRIDORS,
  visible = true,
  showLabels = true,
  filterByType,
  onRouteClick
}) => {
  const map = useMap();

  // Filter routes by type if specified
  const filteredRoutes = useMemo(() => {
    if (!filterByType || filterByType.length === 0) {
      return routes;
    }
    return routes.filter(route => filterByType.includes(route.type));
  }, [routes, filterByType]);

  useEffect(() => {
    if (!map || !visible) return;

    const routeMarkers: L.Marker[] = [];

    // Add route labels if enabled
    if (showLabels) {
      filteredRoutes.forEach(route => {
        if (route.coordinates.length > 0) {
          // Place label at midpoint of route
          const midIndex = Math.floor(route.coordinates.length / 2);
          const midPoint = route.coordinates[midIndex];
          
          const color = TRANSPORT_TYPE_COLORS[route.type] || '#718096';
          
          const label = L.divIcon({
            html: `<div class="route-label" style="background-color: ${color}">${route.name}</div>`,
            className: 'route-label-container',
            iconSize: [120, 20],
            iconAnchor: [60, 10]
          });

          const marker = L.marker([midPoint.lat, midPoint.lng], { icon: label });
          map.addLayer(marker);
          routeMarkers.push(marker);
        }
      });
    }

    // Cleanup function
    return () => {
      routeMarkers.forEach(marker => map.removeLayer(marker));
    };
  }, [map, filteredRoutes, visible, showLabels]);

  if (!visible) return null;

  return (
    <>
      {filteredRoutes.map(route => {
        const color = TRANSPORT_TYPE_COLORS[route.type] || '#718096';
        const positions = route.coordinates.map(coord => [coord.lat, coord.lng] as [number, number]);
        
        // Determine line style based on transport type
        const getLineOptions = (type: TransportType) => {
          const baseOptions = {
            color,
            weight: 4,
            opacity: 0.8
          };

          switch (type) {
            case 'highway':
              return { ...baseOptions, weight: 5 };
            case 'railway':
              return { ...baseOptions, weight: 3, dashArray: '10, 5' };
            case 'waterway':
              return { ...baseOptions, weight: 6, opacity: 0.6 };
            case 'airway':
              return { ...baseOptions, weight: 2, dashArray: '5, 10' };
            case 'pipeline':
              return { ...baseOptions, weight: 3, dashArray: '15, 5' };
            default:
              return baseOptions;
          }
        };

        return (
          <Polyline
            key={route.id}
            positions={positions}
            pathOptions={getLineOptions(route.type)}
            eventHandlers={{
              click: () => {
                if (onRouteClick) {
                  onRouteClick(route);
                }
              },
              mouseover: (e) => {
                e.target.setStyle({ weight: 6, opacity: 1 });
              },
              mouseout: (e) => {
                e.target.setStyle(getLineOptions(route.type));
              }
            }}
          >
            {/* Popup for route information */}
            <div className="route-popup">
              <h3 className="route-popup__title">{route.name}</h3>
              <div className="route-popup__info">
                <div className="route-popup__type">
                  <strong>Type:</strong> {route.type.toUpperCase()}
                </div>
                {route.description && (
                  <div className="route-popup__description">
                    {route.description}
                  </div>
                )}
                {route.length && (
                  <div className="route-popup__length">
                    <strong>Length:</strong> {route.length.toLocaleString('pt-BR')} km
                  </div>
                )}
                {route.operator && (
                  <div className="route-popup__operator">
                    <strong>Operator:</strong> {route.operator}
                  </div>
                )}
              </div>
            </div>
          </Polyline>
        );
      })}
    </>
  );
};

// CSS styles (to be injected)
const routeStyles = `
.route-label-container {
  background: none !important;
  border: none !important;
}

.route-label {
  color: #ffffff;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 600;
  text-align: center;
  white-space: nowrap;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  pointer-events: none;
}

.route-popup {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-width: 250px;
}

.route-popup__title {
  color: #2d3748;
  font-size: 1rem;
  font-weight: 600;
  margin: 0 0 0.75rem 0;
  line-height: 1.3;
}

.route-popup__info {
  margin-bottom: 0.5rem;
}

.route-popup__type,
.route-popup__length,
.route-popup__operator {
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  line-height: 1.3;
}

.route-popup__type strong,
.route-popup__length strong,
.route-popup__operator strong {
  color: #4a5568;
  font-weight: 600;
}

.route-popup__description {
  color: #718096;
  font-size: 0.85rem;
  line-height: 1.4;
  margin-bottom: 0.75rem;
  font-style: italic;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = routeStyles;
  document.head.appendChild(styleElement);
}