# Quick Implementation Guide
## Dashboard Enhancement Implementation Steps

### Step 1: Install Enhanced Libraries

```bash
# Navigate to project directory
cd /path/to/monitor_legislativo_v4

# Install enhanced visualization libraries
npm install recharts @nivo/core @nivo/line @nivo/bar @nivo/heatmap @nivo/network
npm install deck.gl @deck.gl/core @deck.gl/layers @deck.gl/react
npm install mapbox-gl @types/mapbox-gl
npm install three @types/three
npm install socket.io-client

# Install additional utilities
npm install date-fns lodash
npm install @types/lodash
```

### Step 2: Database Optimization

```sql
-- Connect to your PostgreSQL database
-- Add performance indexes
CREATE INDEX CONCURRENTLY idx_documents_date_state 
ON documents(date, state);

CREATE INDEX CONCURRENTLY idx_documents_type_date 
ON documents(type, date);

CREATE INDEX CONCURRENTLY idx_documents_author_date 
ON documents(author, date);

-- Create materialized views for analytics
CREATE MATERIALIZED VIEW mv_document_stats AS
SELECT 
  state,
  type,
  DATE_TRUNC('month', date) as month,
  COUNT(*) as count,
  MIN(date) as earliest_date,
  MAX(date) as latest_date
FROM documents 
GROUP BY state, type, DATE_TRUNC('month', date);

-- Create index on materialized view
CREATE INDEX idx_mv_document_stats_state_type 
ON mv_document_stats(state, type);

-- Refresh materialized view (run periodically)
REFRESH MATERIALIZED VIEW mv_document_stats;
```

### Step 3: Enhanced Map Component

Create `src/components/EnhancedMapViewer.tsx`:

```typescript
import React, { useEffect, useRef, useState } from 'react';
import { Deck } from '@deck.gl/core';
import { GeoJsonLayer, HeatmapLayer } from '@deck.gl/layers';
import mapboxgl from 'mapbox-gl';
import 'mapbox-gl/dist/mapbox-gl.css';
import { LegislativeDocument } from '../types';

interface EnhancedMapViewerProps {
  documents: LegislativeDocument[];
  selectedState?: string;
  selectedMunicipality?: string;
  onLocationClick: (type: 'state' | 'municipality', id: string) => void;
  highlightedLocations: string[];
}

export const EnhancedMapViewer: React.FC<EnhancedMapViewerProps> = ({
  documents,
  selectedState,
  selectedMunicipality,
  onLocationClick,
  highlightedLocations
}) => {
  const mapContainer = useRef<HTMLDivElement>(null);
  const map = useRef<mapboxgl.Map | null>(null);
  const [deck, setDeck] = useState<Deck | null>(null);

  useEffect(() => {
    if (!mapContainer.current) return;

    // Initialize Mapbox
    mapboxgl.accessToken = process.env.REACT_APP_MAPBOX_TOKEN || '';
    
    map.current = new mapboxgl.Map({
      container: mapContainer.current,
      style: 'mapbox://styles/mapbox/light-v11',
      center: [-47.9292, -15.7801], // Brazil center
      zoom: 4,
      maxZoom: 18
    });

    // Initialize Deck.gl
    const deckInstance = new Deck({
      canvas: 'deck-canvas',
      initialViewState: {
        longitude: -47.9292,
        latitude: -15.7801,
        zoom: 4,
        pitch: 0,
        bearing: 0
      },
      controller: true,
      layers: []
    });

    setDeck(deckInstance);

    return () => {
      if (map.current) {
        map.current.remove();
      }
      if (deckInstance) {
        deckInstance.finalize();
      }
    };
  }, []);

  // Update layers when documents change
  useEffect(() => {
    if (!deck || !documents.length) return;

    // Create heatmap layer
    const heatmapLayer = new HeatmapLayer({
      id: 'documents-heatmap',
      data: documents.map(doc => ({
        position: [doc.longitude || 0, doc.latitude || 0],
        weight: 1
      })),
      getPosition: d => d.position,
      getWeight: d => d.weight,
      radiusPixels: 30,
      intensity: 1,
      threshold: 0.03
    });

    // Create state boundaries layer
    const stateLayer = new GeoJsonLayer({
      id: 'state-boundaries',
      data: '/data/brazil-states.geojson',
      stroked: true,
      filled: true,
      lineWidthMinPixels: 1,
      getLineColor: [255, 255, 255],
      getFillColor: [200, 200, 200],
      pickable: true,
      onClick: (info) => {
        if (info.object) {
          onLocationClick('state', info.object.properties.state_code);
        }
      }
    });

    deck.setProps({
      layers: [heatmapLayer, stateLayer]
    });
  }, [documents, deck, onLocationClick]);

  return (
    <div className="enhanced-map-container">
      <div ref={mapContainer} className="mapbox-container" />
      <canvas id="deck-canvas" className="deck-canvas" />
      
      {/* Map controls */}
      <div className="map-controls">
        <button onClick={() => map.current?.flyTo({ center: [-47.9292, -15.7801], zoom: 4 })}>
          🏠 Reset View
        </button>
        <button onClick={() => {
          // Toggle layer visibility
        }}>
          🗺️ Toggle Layers
        </button>
      </div>
    </div>
  );
};
```

### Step 4: Advanced Analytics Dashboard

Create `src/components/AdvancedAnalytics.tsx`:

```typescript
import React, { useMemo } from 'react';
import { ResponsiveLine, ResponsiveBar, ResponsiveHeatMap } from '@nivo/core';
import { ResponsivePie } from '@nivo/pie';
import { LegislativeDocument } from '../types';

interface AdvancedAnalyticsProps {
  documents: LegislativeDocument[];
  selectedState?: string;
  selectedMunicipality?: string;
}

export const AdvancedAnalytics: React.FC<AdvancedAnalyticsProps> = ({
  documents,
  selectedState,
  selectedMunicipality
}) => {
  // Process data for visualizations
  const chartData = useMemo(() => {
    // Temporal analysis
    const temporalData = documents.reduce((acc, doc) => {
      const year = new Date(doc.date).getFullYear();
      acc[year] = (acc[year] || 0) + 1;
      return acc;
    }, {} as Record<number, number>);

    const temporalChartData = Object.entries(temporalData).map(([year, count]) => ({
      x: year,
      y: count
    }));

    // Document type distribution
    const typeData = documents.reduce((acc, doc) => {
      acc[doc.type] = (acc[doc.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const pieData = Object.entries(typeData).map(([type, count]) => ({
      id: type,
      label: type,
      value: count
    }));

    // State distribution
    const stateData = documents.reduce((acc, doc) => {
      if (doc.state) {
        acc[doc.state] = (acc[doc.state] || 0) + 1;
      }
      return acc;
    }, {} as Record<string, number>);

    const barData = Object.entries(stateData)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([state, count]) => ({
        state,
        count
      }));

    return {
      temporal: temporalChartData,
      types: pieData,
      states: barData
    };
  }, [documents]);

  return (
    <div className="advanced-analytics">
      <h2>Advanced Analytics Dashboard</h2>
      
      <div className="analytics-grid">
        {/* Temporal Analysis */}
        <div className="chart-container">
          <h3>Document Trends Over Time</h3>
          <div className="chart-wrapper">
            <ResponsiveLine
              data={[
                {
                  id: 'documents',
                  data: chartData.temporal
                }
              ]}
              margin={{ top: 20, right: 20, bottom: 50, left: 60 }}
              xScale={{ type: 'point' }}
              yScale={{ type: 'linear', min: 'auto', max: 'auto' }}
              axisTop={null}
              axisRight={null}
              axisBottom={{
                tickSize: 5,
                tickPadding: 5,
                tickRotation: 0,
                legend: 'Year',
                legendOffset: 36,
                legendPosition: 'middle'
              }}
              axisLeft={{
                tickSize: 5,
                tickPadding: 5,
                tickRotation: 0,
                legend: 'Number of Documents',
                legendOffset: -40,
                legendPosition: 'middle'
              }}
              pointSize={10}
              pointColor={{ theme: 'background' }}
              pointBorderWidth={2}
              pointBorderColor={{ from: 'serieColor' }}
              pointLabelYOffset={-12}
              useMesh={true}
              legends={[
                {
                  anchor: 'bottom',
                  direction: 'row',
                  justify: false,
                  translateX: 0,
                  translateY: 50,
                  itemsSpacing: 0,
                  itemDirection: 'left-to-right',
                  itemWidth: 80,
                  itemHeight: 20,
                  itemOpacity: 0.75,
                  symbolSize: 12,
                  symbolShape: 'circle',
                  symbolBorderColor: 'rgba(0, 0, 0, .5)',
                  effects: [
                    {
                      on: 'hover',
                      style: {
                        itemBackground: 'rgba(0, 0, 0, .03)',
                        itemOpacity: 1
                      }
                    }
                  ]
                }
              ]}
            />
          </div>
        </div>

        {/* Document Type Distribution */}
        <div className="chart-container">
          <h3>Document Type Distribution</h3>
          <div className="chart-wrapper">
            <ResponsivePie
              data={chartData.types}
              margin={{ top: 40, right: 80, bottom: 80, left: 80 }}
              innerRadius={0.5}
              padAngle={0.7}
              cornerRadius={3}
              activeOuterRadiusOffset={8}
              borderWidth={1}
              borderColor={{ from: 'color', modifiers: [['darker', 0.2]] }}
              arcLinkLabelsSkipAngle={10}
              arcLinkLabelsTextColor="#333333"
              arcLinkLabelsThickness={2}
              arcLinkLabelsColor={{ from: 'color' }}
              arcLabelsSkipAngle={10}
              arcLabelsTextColor={{ from: 'color', modifiers: [['darker', 2]] }}
              legends={[
                {
                  anchor: 'bottom',
                  direction: 'row',
                  justify: false,
                  translateX: 0,
                  translateY: 56,
                  itemsSpacing: 0,
                  itemWidth: 100,
                  itemHeight: 18,
                  itemTextColor: '#999',
                  itemDirection: 'left-to-right',
                  itemOpacity: 1,
                  symbolSize: 18,
                  symbolShape: 'circle',
                  effects: [
                    {
                      on: 'hover',
                      style: {
                        itemTextColor: '#000'
                      }
                    }
                  ]
                }
              ]}
            />
          </div>
        </div>

        {/* State Distribution */}
        <div className="chart-container">
          <h3>Top States by Document Count</h3>
          <div className="chart-wrapper">
            <ResponsiveBar
              data={chartData.states}
              keys={['count']}
              indexBy="state"
              margin={{ top: 50, right: 130, bottom: 50, left: 60 }}
              padding={0.3}
              valueScale={{ type: 'linear' }}
              indexScale={{ type: 'band', round: true }}
              colors={{ scheme: 'nivo' }}
              borderColor={{ from: 'color', modifiers: [['darker', 1.6]] }}
              axisTop={null}
              axisRight={null}
              axisBottom={{
                tickSize: 5,
                tickPadding: 5,
                tickRotation: 0,
                legend: 'State',
                legendPosition: 'middle',
                legendOffset: 32
              }}
              axisLeft={{
                tickSize: 5,
                tickPadding: 5,
                tickRotation: 0,
                legend: 'Number of Documents',
                legendPosition: 'middle',
                legendOffset: -40
              }}
              labelSkipWidth={12}
              labelSkipHeight={12}
              labelTextColor={{ from: 'color', modifiers: [['darker', 1.6]] }}
              legends={[
                {
                  dataFrom: 'keys',
                  anchor: 'bottom-right',
                  direction: 'column',
                  justify: false,
                  translateX: 120,
                  translateY: 0,
                  itemsSpacing: 2,
                  itemWidth: 100,
                  itemHeight: 20,
                  itemDirection: 'left-to-right',
                  itemOpacity: 0.85,
                  symbolSize: 20,
                  effects: [
                    {
                      on: 'hover',
                      style: {
                        itemOpacity: 1
                      }
                    }
                  ]
                }
              ]}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
```

### Step 5: Real-time Updates

Create `src/services/realTimeService.ts`:

```typescript
import { io, Socket } from 'socket.io-client';

export class RealTimeService {
  private socket: Socket | null = null;
  private listeners: Map<string, Function[]> = new Map();

  connect() {
    this.socket = io(process.env.REACT_APP_WEBSOCKET_URL || 'ws://localhost:8000');
    
    this.socket.on('connect', () => {
      console.log('Connected to real-time service');
    });

    this.socket.on('disconnect', () => {
      console.log('Disconnected from real-time service');
    });

    this.socket.on('data_update', (data) => {
      this.notifyListeners('data_update', data);
    });

    this.socket.on('performance_metrics', (metrics) => {
      this.notifyListeners('performance_metrics', metrics);
    });
  }

  subscribe(event: string, callback: Function) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  unsubscribe(event: string, callback: Function) {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  private notifyListeners(event: string, data: any) {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }
}

export const realTimeService = new RealTimeService();
```

### Step 6: CSS Styling

Add to `src/styles/components/EnhancedMapViewer.css`:

```css
.enhanced-map-container {
  position: relative;
  width: 100%;
  height: 600px;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.mapbox-container {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 1;
}

.deck-canvas {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 2;
  pointer-events: none;
}

.map-controls {
  position: absolute;
  top: 10px;
  right: 10px;
  z-index: 3;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.map-controls button {
  padding: 8px 12px;
  background: white;
  border: 1px solid #ddd;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  transition: all 0.2s;
}

.map-controls button:hover {
  background: #f5f5f5;
  border-color: #2196F3;
}
```

Add to `src/styles/components/AdvancedAnalytics.css`:

```css
.advanced-analytics {
  padding: 2rem;
  background: #f8f9fa;
  min-height: 100vh;
}

.advanced-analytics h2 {
  margin: 0 0 2rem 0;
  color: #333;
  font-size: 1.75rem;
}

.analytics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
  gap: 2rem;
  margin-bottom: 2rem;
}

.chart-container {
  background: white;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.chart-container h3 {
  margin: 0 0 1rem 0;
  color: #495057;
  font-size: 1.25rem;
}

.chart-wrapper {
  height: 400px;
  width: 100%;
}

@media (max-width: 768px) {
  .analytics-grid {
    grid-template-columns: 1fr;
  }
  
  .chart-wrapper {
    height: 300px;
  }
}
```

### Step 7: Integration

Update `src/components/Dashboard.tsx`:

```typescript
// Add imports
import { EnhancedMapViewer } from './EnhancedMapViewer';
import { AdvancedAnalytics } from './AdvancedAnalytics';
import { realTimeService } from '../services/realTimeService';

// In the Dashboard component, replace the existing map with:
{viewMode === 'dashboard' && (
  <section className="map-wrapper" aria-labelledby="map-heading">
    <h2 id="map-heading" className="sr-only">Interactive map</h2>
    <Suspense fallback={<LoadingSpinner message="Loading enhanced map..." />}>
      <EnhancedMapViewer
        selectedState={selectedState}
        selectedMunicipality={selectedMunicipality}
        documents={filteredDocuments}
        onLocationClick={handleLocationClick}
        highlightedLocations={highlightedStates}
      />
    </Suspense>
  </section>
)}

// Add new analytics view mode
{viewMode === 'advanced-analytics' && (
  <section className="analytics-wrapper" aria-labelledby="analytics-heading">
    <h2 id="analytics-heading" className="sr-only">Advanced Analytics</h2>
    <Suspense fallback={<LoadingSpinner message="Loading advanced analytics..." />}>
      <AdvancedAnalytics
        documents={filteredDocuments}
        selectedState={selectedState}
        selectedMunicipality={selectedMunicipality}
      />
    </Suspense>
  </section>
)}
```

### Step 8: Environment Variables

Add to `.env`:

```env
REACT_APP_MAPBOX_TOKEN=your_mapbox_token_here
REACT_APP_WEBSOCKET_URL=ws://localhost:8000
```

### Step 9: Test the Implementation

```bash
# Start the development server
npm run dev

# Test the enhanced map
# Test the advanced analytics
# Test real-time updates
```

### Next Steps

1. **Performance Testing:** Monitor load times and optimize
2. **User Testing:** Gather feedback on new features
3. **R Integration:** Enhance R Shiny integration
4. **Mobile Optimization:** Improve mobile experience
5. **Export Enhancement:** Add more export formats

---

**Implementation Time:** 2-3 days for basic setup  
**Testing Time:** 1-2 days  
**Total:** 1 week for initial implementation 