import React, { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker, Tooltip } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { brazilianGeographyService, LegislativeHeatmapData, BrazilianMunicipality, BrazilianState } from '../services/brazilianGeographyService';
import GlassCard from './GlassCard';
import { SkeletonMapLoading } from './common/SkeletonLoader';
import '../styles/glassmorphism.css';

// Fix for default markers in React Leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

interface BrazilianMapViewerProps {
  query?: string;
  showMunicipalities?: boolean;
  showHeatmap?: boolean;
  height?: number;
  interactive?: boolean;
}

const BrazilianMapViewer: React.FC<BrazilianMapViewerProps> = ({
  query = '',
  showMunicipalities = true,
  showHeatmap = true,
  height = 600,
  interactive = true
}) => {
  const [heatmapData, setHeatmapData] = useState<LegislativeHeatmapData[]>([]);
  const [municipalities, setMunicipalities] = useState<BrazilianMunicipality[]>([]);
  const [states, setStates] = useState<BrazilianState[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedState, setSelectedState] = useState<BrazilianState | null>(null);
  const [selectedMunicipality, setSelectedMunicipality] = useState<BrazilianMunicipality | null>(null);
  const [viewMode, setViewMode] = useState<'states' | 'municipalities' | 'heatmap'>('heatmap');
  const [filterRegion, setFilterRegion] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');
  
  const mapRef = useRef<L.Map | null>(null);

  // Brazilian regions
  const regions = ['Norte', 'Nordeste', 'Centro-Oeste', 'Sudeste', 'Sul'];

  // Activity level colors
  const activityColors = {
    low: '#22c55e',      // Green
    medium: '#eab308',   // Yellow
    high: '#f97316',     // Orange
    very_high: '#ef4444' // Red
  };

  useEffect(() => {
    loadMapData();
  }, [query]);

  const loadMapData = async () => {
    setLoading(true);
    try {
      const [heatmapResult, municipalitiesResult, statesResult] = await Promise.all([
        brazilianGeographyService.getLegislativeHeatmapData(),
        brazilianGeographyService.loadBrazilianMunicipalities(),
        brazilianGeographyService.loadBrazilianStates()
      ]);

      setHeatmapData(heatmapResult);
      setMunicipalities(municipalitiesResult);
      setStates(statesResult);
    } catch (error) {
      console.error('Error loading map data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getFilteredData = () => {
    let filteredHeatmap = heatmapData;
    let filteredMunicipalities = municipalities;
    let filteredStates = states;

    // Filter by region
    if (filterRegion) {
      filteredStates = states.filter(state => state.region === filterRegion);
      filteredHeatmap = heatmapData.filter(data => {
        const state = states.find(s => s.code === data.state_code);
        return state?.region === filterRegion;
      });
      filteredMunicipalities = municipalities.filter(municipality => {
        const state = states.find(s => s.code === municipality.state_code);
        return state?.region === filterRegion;
      });
    }

    // Filter by search term
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      filteredMunicipalities = filteredMunicipalities.filter(municipality =>
        municipality.name.toLowerCase().includes(searchLower) ||
        municipality.state_name.toLowerCase().includes(searchLower)
      );
      filteredStates = filteredStates.filter(state =>
        state.name.toLowerCase().includes(searchLower) ||
        state.capital.toLowerCase().includes(searchLower)
      );
    }

    return { filteredHeatmap, filteredMunicipalities, filteredStates };
  };

  const { filteredHeatmap, filteredMunicipalities, filteredStates } = getFilteredData();

  const renderHeatmapMarkers = () => {
    return filteredHeatmap.map((data) => {
      const color = activityColors[data.activity_level];
      const radius = Math.min(Math.max(data.document_count / 2, 5), 25);

      return (
        <CircleMarker
          key={data.state_code}
          center={[data.coordinates[0], data.coordinates[1]]}
          radius={radius}
          pathOptions={{
            fillColor: color,
            color: color,
            weight: 2,
            opacity: 0.8,
            fillOpacity: 0.6
          }}
          eventHandlers={{
            click: () => {
              const state = states.find(s => s.code === data.state_code);
              if (state) setSelectedState(state);
            }
          }}
        >
          <Tooltip>
            <div className="text-sm">
              <strong>{data.state_name}</strong><br />
              <span>Documentos: {data.document_count}</span><br />
              <span>Atividade: {data.activity_level.replace('_', ' ').toUpperCase()}</span>
            </div>
          </Tooltip>
        </CircleMarker>
      );
    });
  };

  const renderMunicipalityMarkers = () => {
    return filteredMunicipalities.slice(0, 50).map((municipality) => { // Limit to 50 for performance
      return (
        <Marker
          key={municipality.ibge_code}
          position={[municipality.latitude, municipality.longitude]}
          eventHandlers={{
            click: () => setSelectedMunicipality(municipality)
          }}
        >
          <Popup>
            <div className="text-sm">
              <strong>{municipality.name}</strong><br />
              <span>{municipality.state_name} ({municipality.state_code})</span><br />
              <span>Região: {municipality.region}</span><br />
              {municipality.population && (
                <span>População: {municipality.population.toLocaleString()}</span>
              )}
            </div>
          </Popup>
        </Marker>
      );
    });
  };

  const renderStateMarkers = () => {
    return filteredStates.map((state) => {
      const stateHeatmap = heatmapData.find(h => h.state_code === state.code);
      const documentCount = stateHeatmap?.document_count || 0;
      
      return (
        <CircleMarker
          key={state.code}
          center={[state.latitude, state.longitude]}
          radius={Math.min(Math.max(documentCount / 3, 8), 20)}
          pathOptions={{
            fillColor: '#3b82f6',
            color: '#1e40af',
            weight: 2,
            opacity: 0.8,
            fillOpacity: 0.5
          }}
          eventHandlers={{
            click: () => setSelectedState(state)
          }}
        >
          <Tooltip>
            <div className="text-sm">
              <strong>{state.name}</strong><br />
              <span>Capital: {state.capital}</span><br />
              <span>Região: {state.region}</span><br />
              <span>Municípios: {state.municipalities.length}</span><br />
              <span>Documentos: {documentCount}</span>
            </div>
          </Tooltip>
        </CircleMarker>
      );
    });
  };

  const getBrazilBounds = () => {
    const bounds = brazilianGeographyService.getBrazilBounds();
    return [
      [bounds.south, bounds.west],
      [bounds.north, bounds.east]
    ] as [[number, number], [number, number]];
  };

  const centerMapOnBrazil = () => {
    if (mapRef.current) {
      mapRef.current.fitBounds(getBrazilBounds());
    }
  };

  const getStatistics = () => {
    const totalDocuments = heatmapData.reduce((sum, data) => sum + data.document_count, 0);
    const avgDocuments = totalDocuments / heatmapData.length || 0;
    const maxDocuments = Math.max(...heatmapData.map(d => d.document_count));
    const mostActiveState = heatmapData.find(d => d.document_count === maxDocuments);

    return {
      totalDocuments,
      avgDocuments: avgDocuments.toFixed(1),
      totalStates: heatmapData.length,
      totalMunicipalities: municipalities.length,
      mostActiveState: mostActiveState?.state_name || 'N/A'
    };
  };

  const statistics = getStatistics();

  return (
    <div className="brazilian-map-viewer">
      <GlassCard variant="research" className="mb-4">
        <div className="flex flex-col lg:flex-row gap-4 mb-4">
          <div className="flex-1">
            <h2 className="text-xl font-semibold mb-2 text-gray-800">
              Mapa Legislativo do Brasil
            </h2>
            <p className="text-sm text-gray-600">
              Visualização geográfica da atividade legislativa por estado e município
            </p>
          </div>
          
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              placeholder="Buscar estado ou município..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="glass-input flex-1"
            />
            <select
              value={filterRegion}
              onChange={(e) => setFilterRegion(e.target.value)}
              className="glass-input"
            >
              <option value="">Todas as Regiões</option>
              {regions.map(region => (
                <option key={region} value={region}>{region}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex flex-wrap gap-2 mb-4">
          <button
            onClick={() => setViewMode('heatmap')}
            className={`glass-button ${viewMode === 'heatmap' ? 'glass-button-primary' : ''}`}
          >
            Mapa de Calor
          </button>
          <button
            onClick={() => setViewMode('states')}
            className={`glass-button ${viewMode === 'states' ? 'glass-button-primary' : ''}`}
          >
            Estados
          </button>
          <button
            onClick={() => setViewMode('municipalities')}
            className={`glass-button ${viewMode === 'municipalities' ? 'glass-button-primary' : ''}`}
          >
            Municípios
          </button>
          <button
            onClick={centerMapOnBrazil}
            className="glass-button"
          >
            Centralizar no Brasil
          </button>
          <button
            onClick={loadMapData}
            className="glass-button"
            disabled={loading}
          >
            {loading ? 'Carregando...' : 'Atualizar'}
          </button>
        </div>
      </GlassCard>

      <div className="flex flex-col lg:flex-row gap-4">
        <div className="flex-1">
          <GlassCard variant="light" className="p-0 overflow-hidden">
            {loading ? (
              <div style={{ height: `${height}px` }}>
                <SkeletonMapLoading />
              </div>
            ) : (
              <MapContainer
                ref={mapRef}
                bounds={getBrazilBounds()}
                style={{ height: `${height}px`, width: '100%' }}
                scrollWheelZoom={interactive}
                className="z-0"
              >
                <TileLayer
                  attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                  url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                />
                
                {viewMode === 'heatmap' && showHeatmap && renderHeatmapMarkers()}
                {viewMode === 'municipalities' && showMunicipalities && renderMunicipalityMarkers()}
                {viewMode === 'states' && renderStateMarkers()}
              </MapContainer>
            )}
          </GlassCard>
        </div>

        <div className="lg:w-80">
          <div className="space-y-4">
            {/* Statistics */}
            <GlassCard variant="academic" size="compact">
              <h3 className="font-semibold mb-3 text-gray-800">Estatísticas</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>Total de Documentos:</span>
                  <span className="font-semibold">{statistics.totalDocuments}</span>
                </div>
                <div className="flex justify-between">
                  <span>Média por Estado:</span>
                  <span className="font-semibold">{statistics.avgDocuments}</span>
                </div>
                <div className="flex justify-between">
                  <span>Estados:</span>
                  <span className="font-semibold">{statistics.totalStates}</span>
                </div>
                <div className="flex justify-between">
                  <span>Municípios:</span>
                  <span className="font-semibold">{statistics.totalMunicipalities}</span>
                </div>
                <div className="flex justify-between">
                  <span>Mais Ativo:</span>
                  <span className="font-semibold text-blue-600">{statistics.mostActiveState}</span>
                </div>
              </div>
            </GlassCard>

            {/* Legend */}
            {viewMode === 'heatmap' && (
              <GlassCard variant="light" size="compact">
                <h3 className="font-semibold mb-3 text-gray-800">Legenda - Atividade</h3>
                <div className="space-y-2">
                  {Object.entries(activityColors).map(([level, color]) => (
                    <div key={level} className="flex items-center gap-2">
                      <div
                        className="w-4 h-4 rounded-full"
                        style={{ backgroundColor: color }}
                      />
                      <span className="text-sm capitalize">
                        {level.replace('_', ' ')}
                      </span>
                    </div>
                  ))}
                </div>
              </GlassCard>
            )}

            {/* Selected State Info */}
            {selectedState && (
              <GlassCard variant="blue" size="compact">
                <h3 className="font-semibold mb-3 text-gray-800">Estado Selecionado</h3>
                <div className="space-y-2 text-sm">
                  <div><strong>Nome:</strong> {selectedState.name}</div>
                  <div><strong>Código:</strong> {selectedState.code}</div>
                  <div><strong>Capital:</strong> {selectedState.capital}</div>
                  <div><strong>Região:</strong> {selectedState.region}</div>
                  <div><strong>Municípios:</strong> {selectedState.municipalities.length}</div>
                  {(() => {
                    const stateData = heatmapData.find(h => h.state_code === selectedState.code);
                    return stateData ? (
                      <>
                        <div><strong>Documentos:</strong> {stateData.document_count}</div>
                        <div><strong>Atividade:</strong> {stateData.activity_level.replace('_', ' ')}</div>
                      </>
                    ) : null;
                  })()}
                </div>
                <button
                  onClick={() => setSelectedState(null)}
                  className="glass-button mt-3 w-full"
                >
                  Fechar
                </button>
              </GlassCard>
            )}

            {/* Selected Municipality Info */}
            {selectedMunicipality && (
              <GlassCard variant="green" size="compact">
                <h3 className="font-semibold mb-3 text-gray-800">Município Selecionado</h3>
                <div className="space-y-2 text-sm">
                  <div><strong>Nome:</strong> {selectedMunicipality.name}</div>
                  <div><strong>Estado:</strong> {selectedMunicipality.state_name} ({selectedMunicipality.state_code})</div>
                  <div><strong>Região:</strong> {selectedMunicipality.region}</div>
                  <div><strong>IBGE:</strong> {selectedMunicipality.ibge_code}</div>
                  {selectedMunicipality.population && (
                    <div><strong>População:</strong> {selectedMunicipality.population.toLocaleString()}</div>
                  )}
                  <div><strong>Coordenadas:</strong> {selectedMunicipality.latitude.toFixed(4)}, {selectedMunicipality.longitude.toFixed(4)}</div>
                </div>
                <button
                  onClick={() => setSelectedMunicipality(null)}
                  className="glass-button mt-3 w-full"
                >
                  Fechar
                </button>
              </GlassCard>
            )}

            {/* Filtered Results */}
            {(searchTerm || filterRegion) && (
              <GlassCard variant="purple" size="compact">
                <h3 className="font-semibold mb-3 text-gray-800">Resultados do Filtro</h3>
                <div className="space-y-2 text-sm">
                  <div>Estados encontrados: {filteredStates.length}</div>
                  <div>Municípios encontrados: {filteredMunicipalities.length}</div>
                  {searchTerm && <div>Busca: "{searchTerm}"</div>}
                  {filterRegion && <div>Região: {filterRegion}</div>}
                </div>
                <button
                  onClick={() => {
                    setSearchTerm('');
                    setFilterRegion('');
                  }}
                  className="glass-button mt-3 w-full"
                >
                  Limpar Filtros
                </button>
              </GlassCard>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default BrazilianMapViewer;