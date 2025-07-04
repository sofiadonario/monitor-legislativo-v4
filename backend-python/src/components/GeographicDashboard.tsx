/**
 * GeographicDashboard Component
 * Comprehensive geographic analysis dashboard combining all spatial features
 */
import React, { useState, useMemo } from 'react';
import { MapContainer, TileLayer } from 'react-leaflet';
import { DocumentLocation, StateData, Municipality } from '../types';
import { geographicService } from '../services/geographicService';
import { ClusterVisualization, HotspotAnalysis, RegionalStatistics } from './SpatialAnalysis';
import { 
  DocumentClusters, 
  HeatmapOverlay, 
  GeographicBounds, 
  TransportRoutes, 
  JurisdictionLayers 
} from './InteractiveMap';

interface GeographicDashboardProps {
  documents: DocumentLocation[];
  onDocumentSelect?: (document: DocumentLocation) => void;
}

type AnalysisTab = 'clusters' | 'hotspots' | 'regional' | 'transport' | 'jurisdiction';
type MapLayer = 'heatmap' | 'clusters' | 'boundaries' | 'routes' | 'jurisdictions';

export const GeographicDashboard: React.FC<GeographicDashboardProps> = ({
  documents,
  onDocumentSelect
}) => {
  // State management
  const [activeTab, setActiveTab] = useState<AnalysisTab>('clusters');
  const [activeLayers, setActiveLayers] = useState<Set<MapLayer>>(new Set(['clusters']));
  const [selectedState, setSelectedState] = useState<string>();
  const [selectedCluster, setSelectedCluster] = useState<string>();
  const [selectedHotspot, setSelectedHotspot] = useState<string>();

  // Sample data (in real implementation, these would come from props or services)
  const states = useMemo<StateData[]>(() => [
    {
      id: 'sp',
      name: 'São Paulo',
      abbreviation: 'SP',
      region: 'Sudeste',
      capital: 'São Paulo',
      population: 44420459,
      area: 248219,
      coordinates: [-23.5505, -46.6333],
      boundaries: {
        type: 'Polygon',
        coordinates: [[
          [-50.0, -20.0], [-44.0, -20.0], [-44.0, -25.0], [-50.0, -25.0], [-50.0, -20.0]
        ]]
      }
    },
    {
      id: 'rj',
      name: 'Rio de Janeiro',
      abbreviation: 'RJ',
      region: 'Sudeste',
      capital: 'Rio de Janeiro',
      population: 16054524,
      area: 43777,
      coordinates: [-22.9068, -43.1729],
      boundaries: {
        type: 'Polygon',
        coordinates: [[
          [-45.0, -20.0], [-40.0, -20.0], [-40.0, -24.0], [-45.0, -24.0], [-45.0, -20.0]
        ]]
      }
    }
  ], []);

  const municipalities = useMemo<Municipality[]>(() => [
    {
      id: 'sp-capital',
      name: 'São Paulo',
      stateId: 'sp',
      stateAbbreviation: 'SP',
      population: 12252023,
      area: 1521,
      coordinates: { lat: -23.5505, lng: -46.6333 },
      ibgeCode: '3550308',
      boundaries: {
        type: 'Polygon',
        coordinates: [[
          [-46.8, -23.3], [-46.4, -23.3], [-46.4, -23.8], [-46.8, -23.8], [-46.8, -23.3]
        ]]
      }
    },
    {
      id: 'rj-capital',
      name: 'Rio de Janeiro',
      stateId: 'rj',
      stateAbbreviation: 'RJ',
      population: 6748000,
      area: 1200,
      coordinates: { lat: -22.9068, lng: -43.1729 },
      ibgeCode: '3304557',
      boundaries: {
        type: 'Polygon',
        coordinates: [[
          [-43.8, -22.7], [-43.1, -22.7], [-43.1, -23.1], [-43.8, -23.1], [-43.8, -22.7]
        ]]
      }
    }
  ], []);

  // Filter documents by selected state
  const filteredDocuments = useMemo(() => {
    if (!selectedState) return documents;
    const state = states.find(s => s.id === selectedState);
    if (!state) return documents;
    return documents.filter(doc => doc.state === state.abbreviation);
  }, [documents, selectedState, states]);

  // Map configuration
  const mapCenter: [number, number] = [-15.7801, -47.9292]; // Center of Brazil
  const mapZoom = 4;

  // Layer toggle handlers
  const toggleLayer = (layer: MapLayer) => {
    const newLayers = new Set(activeLayers);
    if (newLayers.has(layer)) {
      newLayers.delete(layer);
    } else {
      newLayers.add(layer);
    }
    setActiveLayers(newLayers);
  };

  // Event handlers
  const handleDocumentClick = (document: DocumentLocation) => {
    if (onDocumentSelect) {
      onDocumentSelect(document);
    }
  };

  const handleStateSelect = (stateId: string) => {
    setSelectedState(stateId === selectedState ? undefined : stateId);
  };

  const handleClusterSelect = (cluster: any) => {
    setSelectedCluster(cluster.id);
  };

  const handleHotspotSelect = (hotspot: any) => {
    setSelectedHotspot(hotspot.id);
  };

  // Summary statistics
  const summaryStats = useMemo(() => {
    const totalDocs = filteredDocuments.length;
    const uniqueStates = new Set(filteredDocuments.map(doc => doc.state)).size;
    const uniqueMunicipalities = new Set(filteredDocuments.map(doc => doc.municipality)).size;
    const avgConfidence = totalDocs > 0 
      ? filteredDocuments.reduce((sum, doc) => sum + doc.confidence, 0) / totalDocs 
      : 0;
    
    return {
      totalDocs,
      uniqueStates,
      uniqueMunicipalities,
      avgConfidence
    };
  }, [filteredDocuments]);

  return (
    <div className="geographic-dashboard">
      <div className="dashboard-header">
        <h2>Geographic Analysis Dashboard</h2>
        <p>Comprehensive spatial analysis of Brazilian legislative documents</p>
        
        {/* Summary Statistics */}
        <div className="summary-stats">
          <div className="summary-stat">
            <span className="stat-value">{summaryStats.totalDocs.toLocaleString()}</span>
            <span className="stat-label">Documents</span>
          </div>
          <div className="summary-stat">
            <span className="stat-value">{summaryStats.uniqueStates}</span>
            <span className="stat-label">States</span>
          </div>
          <div className="summary-stat">
            <span className="stat-value">{summaryStats.uniqueMunicipalities}</span>
            <span className="stat-label">Municipalities</span>
          </div>
          <div className="summary-stat">
            <span className="stat-value">{Math.round(summaryStats.avgConfidence * 100)}%</span>
            <span className="stat-label">Avg Confidence</span>
          </div>
        </div>
      </div>

      <div className="dashboard-content">
        {/* Map Section */}
        <div className="map-section">
          <div className="map-controls">
            <h3>Interactive Map</h3>
            <div className="layer-controls">
              <span className="controls-label">Layers:</span>
              {[
                { key: 'clusters' as MapLayer, label: 'Document Clusters' },
                { key: 'heatmap' as MapLayer, label: 'Density Heatmap' },
                { key: 'boundaries' as MapLayer, label: 'Geographic Boundaries' },
                { key: 'routes' as MapLayer, label: 'Transport Routes' },
                { key: 'jurisdictions' as MapLayer, label: 'Jurisdiction Areas' }
              ].map(({ key, label }) => (
                <label key={key} className="layer-toggle">
                  <input
                    type="checkbox"
                    checked={activeLayers.has(key)}
                    onChange={() => toggleLayer(key)}
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>

          <div className="map-container">
            <MapContainer
              center={mapCenter}
              zoom={mapZoom}
              style={{ height: '500px', width: '100%' }}
            >
              <TileLayer
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              />
              
              {activeLayers.has('clusters') && (
                <DocumentClusters
                  documents={filteredDocuments}
                  onDocumentClick={handleDocumentClick}
                />
              )}
              
              {activeLayers.has('heatmap') && (
                <HeatmapOverlay
                  documents={filteredDocuments}
                  visible={true}
                />
              )}
              
              {activeLayers.has('boundaries') && (
                <GeographicBounds
                  states={states}
                  municipalities={municipalities}
                  selectedStates={selectedState ? [selectedState] : []}
                  onStateClick={handleStateSelect}
                />
              )}
              
              {activeLayers.has('routes') && (
                <TransportRoutes visible={true} />
              )}
              
              {activeLayers.has('jurisdictions') && (
                <JurisdictionLayers visible={true} />
              )}
            </MapContainer>
          </div>
        </div>

        {/* Analysis Section */}
        <div className="analysis-section">
          <div className="analysis-tabs">
            {[
              { key: 'clusters' as AnalysisTab, label: 'Cluster Analysis', icon: '🔗' },
              { key: 'hotspots' as AnalysisTab, label: 'Hotspot Detection', icon: '🔥' },
              { key: 'regional' as AnalysisTab, label: 'Regional Statistics', icon: '📊' },
              { key: 'transport' as AnalysisTab, label: 'Transport Analysis', icon: '🚛' },
              { key: 'jurisdiction' as AnalysisTab, label: 'Jurisdiction Map', icon: '⚖️' }
            ].map(({ key, label, icon }) => (
              <button
                key={key}
                className={`analysis-tab ${activeTab === key ? 'active' : ''}`}
                onClick={() => setActiveTab(key)}
              >
                <span className="tab-icon">{icon}</span>
                <span className="tab-label">{label}</span>
              </button>
            ))}
          </div>

          <div className="analysis-content">
            {activeTab === 'clusters' && (
              <ClusterVisualization
                documents={filteredDocuments}
                onClusterSelect={handleClusterSelect}
                selectedCluster={selectedCluster}
              />
            )}
            
            {activeTab === 'hotspots' && (
              <HotspotAnalysis
                documents={filteredDocuments}
                onHotspotSelect={handleHotspotSelect}
                selectedHotspot={selectedHotspot}
              />
            )}
            
            {activeTab === 'regional' && (
              <RegionalStatistics
                documents={filteredDocuments}
                states={states}
                municipalities={municipalities}
                onStateSelect={handleStateSelect}
                selectedState={selectedState}
              />
            )}
            
            {activeTab === 'transport' && (
              <div className="transport-analysis">
                <h3>Transport Corridor Analysis</h3>
                <p>Analysis of legislative documents in relation to major Brazilian transport corridors.</p>
                <div className="feature-coming-soon">
                  <p>🚧 Advanced transport analysis features coming soon</p>
                  <ul>
                    <li>Document proximity to major highways and railways</li>
                    <li>Regulatory impact on transport corridors</li>
                    <li>Inter-modal transport regulation analysis</li>
                  </ul>
                </div>
              </div>
            )}
            
            {activeTab === 'jurisdiction' && (
              <div className="jurisdiction-analysis">
                <h3>Regulatory Jurisdiction Analysis</h3>
                <p>Analysis of documents by regulatory agency jurisdiction and administrative boundaries.</p>
                <div className="feature-coming-soon">
                  <p>🚧 Jurisdiction analysis features coming soon</p>
                  <ul>
                    <li>ANTT, ANTAQ, ANAC jurisdiction mapping</li>
                    <li>Overlapping regulatory authority analysis</li>
                    <li>Administrative boundary conflicts</li>
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// CSS styles (to be injected)
const dashboardStyles = `
.geographic-dashboard {
  background: #f8fafc;
  min-height: 100vh;
  padding: 1.5rem;
}

.dashboard-header {
  background: #ffffff;
  border-radius: 8px;
  padding: 2rem;
  margin-bottom: 1.5rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.dashboard-header h2 {
  color: #2d3748;
  font-size: 1.875rem;
  font-weight: 700;
  margin: 0 0 0.5rem 0;
}

.dashboard-header p {
  color: #718096;
  font-size: 1rem;
  margin: 0 0 1.5rem 0;
}

.summary-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1.5rem;
}

.summary-stat {
  text-align: center;
  padding: 1rem;
  background: #f7fafc;
  border-radius: 6px;
}

.stat-value {
  display: block;
  font-size: 2rem;
  font-weight: 700;
  color: #2d3748;
  line-height: 1;
}

.stat-label {
  font-size: 0.875rem;
  color: #718096;
  margin-top: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.dashboard-content {
  display: grid;
  grid-template-columns: 1fr 400px;
  gap: 1.5rem;
  min-height: 800px;
}

@media (max-width: 1200px) {
  .dashboard-content {
    grid-template-columns: 1fr;
  }
}

.map-section {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

.map-controls {
  padding: 1.5rem;
  border-bottom: 1px solid #e2e8f0;
}

.map-controls h3 {
  color: #2d3748;
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 1rem 0;
}

.layer-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  align-items: center;
}

.controls-label {
  font-weight: 500;
  color: #4a5568;
  margin-right: 0.5rem;
}

.layer-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  color: #4a5568;
  cursor: pointer;
}

.layer-toggle input[type="checkbox"] {
  margin: 0;
}

.map-container {
  height: 500px;
}

.analysis-section {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.analysis-tabs {
  display: flex;
  flex-direction: column;
  border-bottom: 1px solid #e2e8f0;
}

.analysis-tab {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem 1.5rem;
  border: none;
  background: #f7fafc;
  border-bottom: 1px solid #e2e8f0;
  cursor: pointer;
  transition: all 0.2s;
  text-align: left;
}

.analysis-tab:hover {
  background: #edf2f7;
}

.analysis-tab.active {
  background: #ffffff;
  border-left: 4px solid #4299e1;
  border-bottom-color: transparent;
}

.analysis-tab:last-child {
  border-bottom: none;
}

.tab-icon {
  font-size: 1.125rem;
}

.tab-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #4a5568;
}

.analysis-tab.active .tab-label {
  color: #2d3748;
  font-weight: 600;
}

.analysis-content {
  flex: 1;
  overflow-y: auto;
}

.transport-analysis,
.jurisdiction-analysis {
  padding: 1.5rem;
}

.transport-analysis h3,
.jurisdiction-analysis h3 {
  color: #2d3748;
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 0.75rem 0;
}

.transport-analysis p,
.jurisdiction-analysis p {
  color: #718096;
  margin: 0 0 1.5rem 0;
  line-height: 1.5;
}

.feature-coming-soon {
  background: #f7fafc;
  border-left: 4px solid #4299e1;
  border-radius: 4px;
  padding: 1.5rem;
}

.feature-coming-soon p {
  color: #4a5568;
  font-weight: 500;
  margin: 0 0 1rem 0;
}

.feature-coming-soon ul {
  margin: 0;
  padding-left: 1.5rem;
}

.feature-coming-soon li {
  color: #718096;
  margin-bottom: 0.5rem;
  line-height: 1.4;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = dashboardStyles;
  document.head.appendChild(styleElement);
}