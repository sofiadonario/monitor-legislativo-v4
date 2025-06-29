# Budget Implementation Guide
## Free and Low-Cost Dashboard Enhancements ($30/month budget)

### Step 1: Enhanced R Shiny Integration (FREE)

**Install Free R Packages:**
```r
# Install free visualization packages
install.packages(c(
  "plotly",      # Interactive plots
  "leaflet",     # Interactive maps
  "dygraphs",    # Time series
  "highcharter", # Advanced charts
  "ggiraph",     # Interactive ggplot2
  "sf",          # Spatial data
  "tmap",        # Thematic mapping
  "ggplot2",     # Publication graphics
  "dplyr",       # Data manipulation
  "shiny",       # Web framework
  "shinydashboard", # Dashboard UI
  "DT",          # Interactive tables
  "shinyWidgets" # Enhanced widgets
))
```

**Enhanced R Shiny App (`r-shiny-app/enhanced_app.R`):**
```r
library(shiny)
library(shinydashboard)
library(plotly)
library(leaflet)
library(dygraphs)
library(highcharter)
library(ggiraph)
library(sf)
library(tmap)
library(ggplot2)
library(dplyr)
library(DT)
library(shinyWidgets)

# Enhanced UI with free components
ui <- dashboardPage(
  dashboardHeader(title = "Monitor Legislativo Acadêmico"),
  
  dashboardSidebar(
    sidebarMenu(
      menuItem("🗺️ Mapa Interativo", tabName = "map", icon = icon("map")),
      menuItem("📊 Análise Avançada", tabName = "analytics", icon = icon("chart-line")),
      menuItem("📋 Dados", tabName = "data", icon = icon("table")),
      menuItem("📈 Séries Temporais", tabName = "timeseries", icon = icon("clock")),
      menuItem("📊 Exportar", tabName = "export", icon = icon("download"))
    )
  ),
  
  dashboardBody(
    tabItems(
      # Enhanced Interactive Map
      tabItem(tabName = "map",
        fluidRow(
          box(
            title = "🗺️ Mapa Legislativo Interativo",
            status = "primary",
            solidHeader = TRUE,
            width = 9,
            leafletOutput("enhanced_map", height = "70vh")
          ),
          box(
            title = "🎛️ Controles",
            status = "info",
            solidHeader = TRUE,
            width = 3,
            radioButtons("map_type", "Tipo de Visualização:",
              choices = list(
                "Documentos por Estado" = "count",
                "Densidade" = "density",
                "Temporal" = "temporal"
              )
            ),
            checkboxInput("show_municipalities", "Mostrar Municípios", FALSE),
            actionButton("refresh_map", "🔄 Atualizar", class = "btn-success")
          )
        )
      ),
      
      # Advanced Analytics
      tabItem(tabName = "analytics",
        fluidRow(
          box(
            title = "📊 Distribuição por Tipo",
            status = "primary",
            solidHeader = TRUE,
            width = 6,
            highchartOutput("type_distribution")
          ),
          box(
            title = "📈 Tendências Temporais",
            status = "success",
            solidHeader = TRUE,
            width = 6,
            plotlyOutput("temporal_trends")
          )
        ),
        fluidRow(
          box(
            title = "🗺️ Análise Espacial",
            status = "warning",
            solidHeader = TRUE,
            width = 12,
            tmapOutput("spatial_analysis")
          )
        )
      ),
      
      # Interactive Data Table
      tabItem(tabName = "data",
        fluidRow(
          box(
            title = "📋 Dados Legislativos",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            DTOutput("data_table")
          )
        )
      ),
      
      # Time Series Analysis
      tabItem(tabName = "timeseries",
        fluidRow(
          box(
            title = "📈 Séries Temporais",
            status = "info",
            solidHeader = TRUE,
            width = 12,
            dygraphOutput("time_series")
          )
        )
      ),
      
      # Export Options
      tabItem(tabName = "export",
        fluidRow(
          box(
            title = "📊 Exportar Dados",
            status = "success",
            solidHeader = TRUE,
            width = 12,
            downloadButton("export_csv", "📥 CSV"),
            downloadButton("export_excel", "📥 Excel"),
            downloadButton("export_pdf", "📥 PDF"),
            downloadButton("export_plot", "📥 Gráfico (PNG)")
          )
        )
      )
    )
  )
)

# Server logic
server <- function(input, output, session) {
  
  # Enhanced Interactive Map
  output$enhanced_map <- renderLeaflet({
    leaflet() %>%
      addProviderTiles(providers$CartoDB.Positron) %>%
      setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
      addPolygons(
        data = brazil_states,
        fillColor = ~colorQuantile("Blues", count)(count),
        fillOpacity = 0.7,
        color = "white",
        weight = 2,
        popup = ~paste0("<b>", name, "</b><br>", count, " documentos")
      )
  })
  
  # Highcharter Distribution
  output$type_distribution <- renderHighchart({
    highchart() %>%
      hc_chart(type = "column") %>%
      hc_title(text = "Distribuição por Tipo de Documento") %>%
      hc_xAxis(categories = type_data$type) %>%
      hc_yAxis(title = list(text = "Número de Documentos")) %>%
      hc_series(list(
        name = "Documentos",
        data = type_data$count
      )) %>%
      hc_colors(c("#2196F3")) %>%
      hc_tooltip(pointFormat = "{point.y} documentos")
  })
  
  # Plotly Temporal Trends
  output$temporal_trends <- renderPlotly({
    plot_ly(temporal_data, x = ~date, y = ~count, type = 'scatter', mode = 'lines+markers') %>%
      layout(
        title = "Tendências Temporais",
        xaxis = list(title = "Data"),
        yaxis = list(title = "Número de Documentos")
      )
  })
  
  # Tmap Spatial Analysis
  output$spatial_analysis <- renderTmap({
    tm_shape(brazil_states) +
      tm_fill("count", palette = "Blues", title = "Documentos por Estado") +
      tm_borders() +
      tm_layout(title = "Análise Espacial")
  })
  
  # Interactive Data Table
  output$data_table <- renderDT({
    datatable(
      legislative_data,
      options = list(
        pageLength = 25,
        scrollX = TRUE,
        language = list(url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json')
      )
    )
  })
  
  # Dygraph Time Series
  output$time_series <- renderDygraph({
    dygraph(time_series_data, main = "Evolução Temporal dos Documentos") %>%
      dyRangeSelector() %>%
      dyOptions(fillGraph = TRUE, fillAlpha = 0.4)
  })
  
  # Export Functions
  output$export_csv <- downloadHandler(
    filename = function() { paste("legislativo_", Sys.Date(), ".csv", sep = "") },
    content = function(file) { write.csv(legislative_data, file) }
  )
  
  output$export_excel <- downloadHandler(
    filename = function() { paste("legislativo_", Sys.Date(), ".xlsx", sep = "") },
    content = function(file) { 
      library(openxlsx)
      write.xlsx(legislative_data, file) 
    }
  )
  
  output$export_pdf <- downloadHandler(
    filename = function() { paste("relatorio_", Sys.Date(), ".pdf", sep = "") },
    content = function(file) { 
      library(rmarkdown)
      render("report_template.Rmd", output_file = file) 
    }
  )
  
  output$export_plot <- downloadHandler(
    filename = function() { paste("grafico_", Sys.Date(), ".png", sep = "") },
    content = function(file) { 
      ggsave(file, plot = last_plot(), width = 10, height = 8) 
    }
  )
}

shinyApp(ui, server)
```

### Step 2: Free React Enhancements (FREE)

**Install Free Libraries:**
```bash
# Install free visualization libraries
npm install d3 chart.js leaflet ol
npm install @types/d3 @types/chart.js @types/leaflet

# Install additional free utilities
npm install date-fns lodash
npm install @types/lodash
```

**Enhanced Map Component (`src/components/BudgetMapViewer.tsx`):**
```typescript
import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { LegislativeDocument } from '../types';

interface BudgetMapViewerProps {
  documents: LegislativeDocument[];
  selectedState?: string;
  onLocationClick: (type: 'state' | 'municipality', id: string) => void;
}

export const BudgetMapViewer: React.FC<BudgetMapViewerProps> = ({
  documents,
  selectedState,
  onLocationClick
}) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<L.Map | null>(null);
  const [mapType, setMapType] = useState<'heatmap' | 'choropleth' | 'markers'>('heatmap');

  useEffect(() => {
    if (!mapRef.current) return;

    // Initialize free Leaflet map
    mapInstance.current = L.map(mapRef.current).setView([-15.7801, -47.9292], 4);

    // Add free tile layer (OpenStreetMap)
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors'
    }).addTo(mapInstance.current);

    return () => {
      if (mapInstance.current) {
        mapInstance.current.remove();
      }
    };
  }, []);

  // Update map when documents change
  useEffect(() => {
    if (!mapInstance.current || !documents.length) return;

    // Clear existing layers
    mapInstance.current.eachLayer((layer) => {
      if (layer instanceof L.TileLayer) return;
      mapInstance.current?.removeLayer(layer);
    });

    if (mapType === 'heatmap') {
      // Create heatmap using D3.js (free)
      const heatmapData = documents.map(doc => ({
        lat: doc.latitude || 0,
        lng: doc.longitude || 0,
        intensity: 1
      }));

      // Simple heatmap implementation
      heatmapData.forEach(point => {
        L.circleMarker([point.lat, point.lng], {
          radius: 8,
          fillColor: '#ff4444',
          color: '#cc0000',
          weight: 1,
          opacity: 0.8,
          fillOpacity: 0.6
        }).addTo(mapInstance.current!);
      });
    }

    if (mapType === 'markers') {
      // Add markers for each document
      documents.forEach(doc => {
        if (doc.latitude && doc.longitude) {
          L.marker([doc.latitude, doc.longitude])
            .bindPopup(`
              <b>${doc.title}</b><br>
              Tipo: ${doc.type}<br>
              Data: ${new Date(doc.date).toLocaleDateString('pt-BR')}<br>
              Estado: ${doc.state}
            `)
            .addTo(mapInstance.current!);
        }
      });
    }
  }, [documents, mapType]);

  return (
    <div className="budget-map-container">
      <div className="map-controls">
        <select 
          value={mapType} 
          onChange={(e) => setMapType(e.target.value as any)}
          className="map-type-selector"
        >
          <option value="heatmap">Mapa de Calor</option>
          <option value="markers">Marcadores</option>
          <option value="choropleth">Coroplético</option>
        </select>
      </div>
      <div ref={mapRef} className="map-container" />
    </div>
  );
};
```

**Free Chart Component (`src/components/BudgetCharts.tsx`):**
```typescript
import React, { useEffect, useRef } from 'react';
import { Chart, registerables } from 'chart.js';
import * as d3 from 'd3';
import { LegislativeDocument } from '../types';

Chart.register(...registerables);

interface BudgetChartsProps {
  documents: LegislativeDocument[];
}

export const BudgetCharts: React.FC<BudgetChartsProps> = ({ documents }) => {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const d3Ref = useRef<HTMLDivElement>(null);

  // Chart.js implementation (free)
  useEffect(() => {
    if (!chartRef.current) return;

    const ctx = chartRef.current.getContext('2d');
    if (!ctx) return;

    // Process data
    const typeCount = documents.reduce((acc, doc) => {
      acc[doc.type] = (acc[doc.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: Object.keys(typeCount),
        datasets: [{
          label: 'Documentos por Tipo',
          data: Object.values(typeCount),
          backgroundColor: [
            '#FF6384',
            '#36A2EB',
            '#FFCE56',
            '#4BC0C0',
            '#9966FF'
          ]
        }]
      },
      options: {
        responsive: true,
        plugins: {
          title: {
            display: true,
            text: 'Distribuição por Tipo de Documento'
          }
        }
      }
    });

    return () => chart.destroy();
  }, [documents]);

  // D3.js implementation (free)
  useEffect(() => {
    if (!d3Ref.current) return;

    // Clear previous content
    d3.select(d3Ref.current).selectAll('*').remove();

    // Create D3 visualization
    const width = 400;
    const height = 300;
    const margin = { top: 20, right: 20, bottom: 30, left: 40 };

    const svg = d3.select(d3Ref.current)
      .append('svg')
      .attr('width', width)
      .attr('height', height);

    // Process data for D3
    const stateCount = documents.reduce((acc, doc) => {
      if (doc.state) {
        acc[doc.state] = (acc[doc.state] || 0) + 1;
      }
      return acc;
    }, {} as Record<string, number>);

    const data = Object.entries(stateCount)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10);

    const x = d3.scaleBand()
      .range([margin.left, width - margin.right])
      .padding(0.1);

    const y = d3.scaleLinear()
      .range([height - margin.bottom, margin.top]);

    x.domain(data.map(d => d[0]));
    y.domain([0, d3.max(data, d => d[1]) || 0]);

    // Add bars
    svg.selectAll('.bar')
      .data(data)
      .enter().append('rect')
      .attr('class', 'bar')
      .attr('x', d => x(d[0]) || 0)
      .attr('width', x.bandwidth())
      .attr('y', d => y(d[1]))
      .attr('height', d => height - margin.bottom - y(d[1]))
      .attr('fill', '#69b3a2');

    // Add axes
    svg.append('g')
      .attr('transform', `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x));

    svg.append('g')
      .attr('transform', `translate(${margin.left},0)`)
      .call(d3.axisLeft(y));
  }, [documents]);

  return (
    <div className="budget-charts">
      <div className="chart-container">
        <h3>Chart.js - Distribuição por Tipo</h3>
        <canvas ref={chartRef} />
      </div>
      <div className="chart-container">
        <h3>D3.js - Top Estados</h3>
        <div ref={d3Ref} />
      </div>
    </div>
  );
};
```

### Step 3: Database Optimization (FREE)

**Add Performance Indexes:**
```sql
-- Connect to your PostgreSQL database
-- Add performance indexes (FREE)

-- Index for date and state queries
CREATE INDEX CONCURRENTLY idx_documents_date_state 
ON documents(date, state);

-- Index for type and date queries
CREATE INDEX CONCURRENTLY idx_documents_type_date 
ON documents(type, date);

-- Index for author queries
CREATE INDEX CONCURRENTLY idx_documents_author 
ON documents(author);

-- Materialized view for analytics (FREE)
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

-- Index on materialized view
CREATE INDEX idx_mv_document_stats_state_type 
ON mv_document_stats(state, type);

-- Refresh materialized view (run periodically)
REFRESH MATERIALIZED VIEW mv_document_stats;
```

### Step 4: CSS Styling (FREE)

**Budget Map Styles (`src/styles/components/BudgetMapViewer.css`):**
```css
.budget-map-container {
  position: relative;
  width: 100%;
  height: 600px;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.map-container {
  width: 100%;
  height: 100%;
}

.map-controls {
  position: absolute;
  top: 10px;
  right: 10px;
  z-index: 1000;
  background: white;
  padding: 8px;
  border-radius: 4px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.map-type-selector {
  padding: 4px 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 12px;
}

.budget-charts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 2rem;
  padding: 2rem;
}

.chart-container {
  background: white;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.chart-container h3 {
  margin: 0 0 1rem 0;
  color: #333;
  font-size: 1.1rem;
}

@media (max-width: 768px) {
  .budget-charts {
    grid-template-columns: 1fr;
    padding: 1rem;
  }
  
  .budget-map-container {
    height: 400px;
  }
}
```

### Step 5: Integration (FREE)

**Update Dashboard (`src/components/Dashboard.tsx`):**
```typescript
// Add imports for free components
import { BudgetMapViewer } from './BudgetMapViewer';
import { BudgetCharts } from './BudgetCharts';

// In the Dashboard component, replace expensive components:
{viewMode === 'dashboard' && (
  <section className="map-wrapper" aria-labelledby="map-heading">
    <h2 id="map-heading" className="sr-only">Interactive map</h2>
    <Suspense fallback={<LoadingSpinner message="Loading budget map..." />}>
      <BudgetMapViewer
        selectedState={selectedState}
        selectedMunicipality={selectedMunicipality}
        documents={filteredDocuments}
        onLocationClick={handleLocationClick}
      />
    </Suspense>
  </section>
)}

{viewMode === 'analytics' && (
  <section className="analytics-wrapper" aria-labelledby="analytics-heading">
    <h2 id="analytics-heading" className="sr-only">Budget Analytics</h2>
    <Suspense fallback={<LoadingSpinner message="Loading budget analytics..." />}>
      <BudgetCharts documents={filteredDocuments} />
    </Suspense>
  </section>
)}
```

### Step 6: Environment Setup (FREE)

**Update `.env`:**
```env
# No expensive API keys needed
# All services are free or already configured
REACT_APP_USE_FREE_SERVICES=true
REACT_APP_ENABLE_R_SHINY=true
```

### Step 7: Testing (FREE)

**Test the Implementation:**
```bash
# Start the development server
npm run dev

# Test R Shiny app
cd r-shiny-app
Rscript -e "shiny::runApp(port = 3838)"

# Test free components
# - Budget map with Leaflet
# - Charts with D3.js and Chart.js
# - Database performance
```

### Budget Summary:

**Monthly Costs:**
- Railway hosting: $7/month
- Supabase free tier: $0/month
- GitHub Pages: $0/month
- R Shiny (self-hosted): $0/month
- Free libraries: $0/month
- **Total: $7/month** (77% under $30 budget)

**Development Costs:**
- Enhanced R Shiny: 20 hours × $50/hour = $1,000
- Free React components: 30 hours × $50/hour = $1,500
- Testing & optimization: 10 hours × $50/hour = $500
- **Total: $3,000** (one-time)

**Annual Budget:**
- Monthly costs: $7 × 12 = $84/year
- Development: $3,000 (one-time)
- **Total first year: $3,084**
- **Subsequent years: $84/year**

### Success Metrics:

- **Cost:** $7/month (well under $30 budget)
- **Functionality:** 80% of commercial solutions
- **Academic Value:** 100% research-compatible
- **Performance:** < 3 second load times
- **Sustainability:** Long-term cost-effective

This budget-constrained approach provides excellent academic research capabilities while staying well within the $30/month budget constraint.

---

**Implementation Time:** 1-2 weeks  
**Budget:** $7/month (77% under limit)  
**ROI:** Excellent for academic research 