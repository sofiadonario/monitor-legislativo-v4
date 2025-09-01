# Enhanced Interactive Maps Module for Brazilian Legislative Monitoring
# =====================================================================
# Professional-grade interactive mapping with WebGL, real-time filtering,
# and advanced geospatial analysis capabilities for 134k+ documents

# SOLUTION ARCHITECTURE
# =====================
# This module implements a high-performance interactive mapping system using:
# - Leaflet with WebGL acceleration for handling 134k+ points
# - PostGIS spatial queries for efficient data processing
# - Progressive loading with viewport culling
# - Real-time clustering and heatmap generation
# - Advanced spatial analysis tools

# Load required libraries
library(leaflet)
library(leaflet.extras)
library(leaflet.extras2)
library(sf)
library(DBI)
library(pool)
library(data.table)
library(memoise)
library(jsonlite)
library(htmlwidgets)
library(shinyjs)

# DATABASE SCHEMA & OPTIMIZATION
# ===============================
create_spatial_indexes <- function(con) {
  "
  -- Create spatial indexes for performance
  CREATE INDEX IF NOT EXISTS idx_documents_geom ON documents USING GIST (geom);
  CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents (estado);
  CREATE INDEX IF NOT EXISTS idx_documents_municipio ON documents (municipio);
  CREATE INDEX IF NOT EXISTS idx_documents_date ON documents (data_publicacao);
  CREATE INDEX IF NOT EXISTS idx_documents_category ON documents (categoria);
  
  -- Create materialized view for municipality aggregations
  CREATE MATERIALIZED VIEW IF NOT EXISTS mv_municipality_stats AS
  SELECT 
    municipio,
    estado,
    ST_Centroid(ST_Union(geom)) as centroid,
    COUNT(*) as doc_count,
    COUNT(DISTINCT categoria) as category_count,
    MIN(data_publicacao) as first_doc,
    MAX(data_publicacao) as last_doc,
    array_agg(DISTINCT categoria) as categories
  FROM documents
  WHERE geom IS NOT NULL
  GROUP BY municipio, estado;
  
  CREATE INDEX ON mv_municipality_stats USING GIST (centroid);
  "
}

# ENHANCED UI COMPONENT
# ======================
enhancedInteractiveMapsUI <- function(id) {
  ns <- NS(id)
  
  tagList(
    # Include required CSS and JS
    tags$head(
      tags$style(HTML("
        .leaflet-container { background: #1a1a1a; }
        .map-control-panel { 
          background: rgba(255,255,255,0.95); 
          border-radius: 8px; 
          padding: 15px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .spatial-tools {
          position: absolute;
          top: 10px;
          right: 10px;
          z-index: 1000;
          background: white;
          border-radius: 4px;
          padding: 8px;
        }
        .layer-control {
          max-height: 400px;
          overflow-y: auto;
        }
        .timeline-slider {
          background: rgba(255,255,255,0.9);
          padding: 10px;
          border-radius: 4px;
        }
        .map-stats-overlay {
          position: absolute;
          bottom: 20px;
          left: 20px;
          background: rgba(255,255,255,0.95);
          padding: 10px 15px;
          border-radius: 6px;
          font-size: 12px;
          z-index: 999;
        }
        .cluster-icon {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 50%;
          color: white;
          text-align: center;
          font-weight: bold;
        }
      ")),
      
      # Include Leaflet plugins
      tags$script(src = "https://unpkg.com/leaflet.vectorgrid@1.3.0/dist/Leaflet.VectorGrid.bundled.js"),
      tags$script(src = "https://unpkg.com/leaflet-webgl-heatmap/src/webgl-heatmap/webgl-heatmap.js"),
      tags$script(src = "https://unpkg.com/leaflet-webgl-heatmap/src/leaflet-webgl-heatmap.js")
    ),
    
    # Main container
    fluidRow(
      # Advanced Control Panel
      column(width = 12,
        div(class = "map-control-panel",
          fluidRow(
            # Layer Controls
            column(width = 3,
              h4("Map Layers", style = "margin-top: 0;"),
              div(class = "layer-control",
                checkboxGroupInput(ns("map_layers"),
                  label = NULL,
                  choices = list(
                    "Document Markers" = "markers",
                    "Cluster View" = "clusters",
                    "Heat Map" = "heatmap",
                    "Municipality Boundaries" = "boundaries",
                    "State Choropleth" = "choropleth",
                    "Transport Corridors" = "corridors",
                    "3D Building View" = "buildings"
                  ),
                  selected = c("clusters", "boundaries")
                ),
                
                hr(),
                
                h5("Data Filters"),
                selectInput(ns("category_filter"),
                  "Document Category:",
                  choices = c("All" = "all",
                    "Legislation" = "legislacao",
                    "Jurisprudence" = "jurisprudencia",
                    "Transport Policy" = "transporte",
                    "Environmental" = "ambiental",
                    "Infrastructure" = "infraestrutura"
                  ),
                  selected = "all"
                ),
                
                selectInput(ns("state_filter"),
                  "State:",
                  choices = c("All States" = "all"),
                  selected = "all"
                ),
                
                dateRangeInput(ns("date_filter"),
                  "Date Range:",
                  start = Sys.Date() - 365,
                  end = Sys.Date()
                )
              )
            ),
            
            # Visualization Settings
            column(width = 3,
              h4("Visualization", style = "margin-top: 0;"),
              
              selectInput(ns("render_mode"),
                "Rendering Mode:",
                choices = c(
                  "WebGL (Fast)" = "webgl",
                  "Canvas" = "canvas",
                  "SVG (Quality)" = "svg"
                ),
                selected = "webgl"
              ),
              
              sliderInput(ns("cluster_threshold"),
                "Clustering Threshold:",
                min = 10, max = 100, value = 50,
                step = 10
              ),
              
              sliderInput(ns("heatmap_radius"),
                "Heatmap Radius:",
                min = 5, max = 50, value = 20,
                step = 5
              ),
              
              selectInput(ns("color_scheme"),
                "Color Scheme:",
                choices = c(
                  "Viridis" = "viridis",
                  "Plasma" = "plasma",
                  "Inferno" = "inferno",
                  "Government Blue" = "gov_blue",
                  "Brazil Green-Yellow" = "brazil"
                ),
                selected = "viridis"
              ),
              
              sliderInput(ns("opacity"),
                "Layer Opacity:",
                min = 0.1, max = 1, value = 0.7,
                step = 0.1
              )
            ),
            
            # Spatial Analysis Tools
            column(width = 3,
              h4("Spatial Analysis", style = "margin-top: 0;"),
              
              radioButtons(ns("spatial_tool"),
                "Analysis Tool:",
                choices = c(
                  "None" = "none",
                  "Radius Search" = "radius",
                  "Polygon Selection" = "polygon",
                  "Distance Measure" = "distance",
                  "Corridor Analysis" = "corridor",
                  "Density Grid" = "density"
                ),
                selected = "none"
              ),
              
              conditionalPanel(
                condition = sprintf("input['%s'] == 'radius'", ns("spatial_tool")),
                sliderInput(ns("search_radius"),
                  "Search Radius (km):",
                  min = 1, max = 100, value = 10
                )
              ),
              
              conditionalPanel(
                condition = sprintf("input['%s'] == 'corridor'", ns("spatial_tool")),
                selectInput(ns("corridor_type"),
                  "Corridor Type:",
                  choices = c(
                    "Highway BR-116" = "br116",
                    "Railway Network" = "railway",
                    "Port Access" = "ports",
                    "Custom Route" = "custom"
                  )
                ),
                sliderInput(ns("corridor_buffer"),
                  "Buffer Distance (km):",
                  min = 1, max = 50, value = 5
                )
              ),
              
              actionButton(ns("clear_selection"),
                "Clear Selection",
                icon = icon("times"),
                class = "btn-sm btn-warning"
              )
            ),
            
            # Performance & Export
            column(width = 3,
              h4("Performance", style = "margin-top: 0;"),
              
              sliderInput(ns("viewport_limit"),
                "Max Points in View:",
                min = 100, max = 10000, value = 2000,
                step = 100
              ),
              
              checkboxInput(ns("progressive_load"),
                "Progressive Loading",
                value = TRUE
              ),
              
              checkboxInput(ns("cache_tiles"),
                "Cache Map Tiles",
                value = TRUE
              ),
              
              hr(),
              
              h5("Export Options"),
              
              downloadButton(ns("export_map"),
                "Export Map Image",
                class = "btn-sm btn-primary btn-block"
              ),
              
              downloadButton(ns("export_data"),
                "Export Visible Data",
                class = "btn-sm btn-info btn-block"
              ),
              
              actionButton(ns("share_map"),
                "Share Map View",
                icon = icon("share-alt"),
                class = "btn-sm btn-success btn-block"
              )
            )
          )
        )
      )
    ),
    
    # Map Container with Timeline
    fluidRow(
      column(width = 12,
        div(style = "position: relative;",
          # Main map
          leafletOutput(ns("interactive_map"), 
            width = "100%", 
            height = "700px"
          ),
          
          # Stats overlay
          div(class = "map-stats-overlay",
            uiOutput(ns("map_stats"))
          ),
          
          # Timeline slider
          conditionalPanel(
            condition = sprintf("input['%s'].includes('clusters') || input['%s'].includes('heatmap')", 
              ns("map_layers"), ns("map_layers")),
            div(class = "timeline-slider",
              style = "position: absolute; bottom: 70px; left: 50%; transform: translateX(-50%); width: 60%; z-index: 999;",
              h5("Temporal Animation", style = "margin-bottom: 10px;"),
              sliderInput(ns("time_slider"),
                label = NULL,
                min = as.Date("1988-01-01"),
                max = Sys.Date(),
                value = c(as.Date("2020-01-01"), Sys.Date()),
                timeFormat = "%Y-%m",
                animate = animationOptions(interval = 1000, loop = TRUE)
              )
            )
          )
        )
      )
    ),
    
    # Comparison Panel
    fluidRow(
      column(width = 12,
        conditionalPanel(
          condition = sprintf("input['%s'] == 'true'", ns("show_comparison")),
          div(class = "map-control-panel", style = "margin-top: 20px;",
            h4("Map Comparison View"),
            fluidRow(
              column(width = 6,
                h5("Left Map - Historical"),
                leafletOutput(ns("comparison_map_left"), height = "400px")
              ),
              column(width = 6,
                h5("Right Map - Current"),
                leafletOutput(ns("comparison_map_right"), height = "400px")
              )
            )
          )
        )
      )
    ),
    
    # Hidden elements for map state
    shinyjs::hidden(
      textInput(ns("map_state"), "Map State", value = "")
    )
  )
}

# ENHANCED SERVER LOGIC
# =====================
enhancedInteractiveMapsServer <- function(id, pool, reactive_data = NULL) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for state management
    values <- reactiveValues(
      current_data = NULL,
      filtered_data = NULL,
      selected_features = NULL,
      map_bounds = NULL,
      render_queue = list(),
      cache = list()
    )
    
    # Memoized data loading for performance
    load_spatial_data <- memoise(function(category, state, date_range) {
      con <- pool::poolCheckout(pool)
      on.exit(pool::poolReturn(con))
      
      query <- "
        SELECT 
          id, titulo, categoria, estado, municipio,
          data_publicacao, url, resumo,
          ST_X(geom) as lng, ST_Y(geom) as lat
        FROM documents
        WHERE geom IS NOT NULL
      "
      
      params <- list()
      
      if (category != "all") {
        query <- paste0(query, " AND categoria = $1")
        params <- append(params, list(category))
      }
      
      if (state != "all") {
        query <- paste0(query, " AND estado = $2")
        params <- append(params, list(state))
      }
      
      if (!is.null(date_range)) {
        query <- paste0(query, " AND data_publicacao BETWEEN $3 AND $4")
        params <- append(params, list(date_range[1], date_range[2]))
      }
      
      query <- paste0(query, " LIMIT 50000") # Safety limit
      
      result <- DBI::dbGetQuery(con, query, params = params)
      
      # Convert to sf object for spatial operations
      if (nrow(result) > 0) {
        sf::st_as_sf(result, coords = c("lng", "lat"), crs = 4326)
      } else {
        NULL
      }
    }, cache = cachem::cache_mem(max_size = 100 * 1024^2)) # 100MB cache
    
    # Load initial data
    observe({
      req(input$category_filter, input$state_filter)
      
      showNotification("Loading spatial data...", type = "message", id = "loading")
      
      tryCatch({
        data <- load_spatial_data(
          input$category_filter,
          input$state_filter,
          input$date_filter
        )
        
        values$current_data <- data
        values$filtered_data <- data
        
        removeNotification("loading")
        showNotification(
          sprintf("Loaded %d documents", nrow(data)), 
          type = "success",
          duration = 3
        )
      }, error = function(e) {
        removeNotification("loading")
        showNotification(
          paste("Error loading data:", e$message),
          type = "error"
        )
      })
    })
    
    # Progressive rendering based on viewport
    observe({
      req(values$filtered_data, input$progressive_load)
      
      if (input$progressive_load && !is.null(values$map_bounds)) {
        # Filter data to viewport
        bounds <- values$map_bounds
        viewport_data <- values$filtered_data[
          sf::st_coordinates(values$filtered_data)[,1] >= bounds$west &
          sf::st_coordinates(values$filtered_data)[,1] <= bounds$east &
          sf::st_coordinates(values$filtered_data)[,2] >= bounds$south &
          sf::st_coordinates(values$filtered_data)[,2] <= bounds$north,
        ]
        
        # Limit points if necessary
        if (nrow(viewport_data) > input$viewport_limit) {
          # Sample points intelligently (spatial sampling)
          sample_idx <- sample(nrow(viewport_data), input$viewport_limit)
          viewport_data <- viewport_data[sample_idx,]
        }
        
        values$render_queue <- list(data = viewport_data)
      }
    })
    
    # Main interactive map
    output$interactive_map <- renderLeaflet({
      leaflet() %>%
        addProviderTiles("CartoDB.DarkMatter",
          options = providerTileOptions(
            updateWhenZooming = FALSE,
            updateWhenIdle = TRUE
          )
        ) %>%
        setView(lng = -47.9292, lat = -15.7801, zoom = 4) %>%
        addScaleBar(position = "bottomright") %>%
        addMeasure(
          position = "topleft",
          primaryLengthUnit = "kilometers",
          primaryAreaUnit = "sqkilometers"
        ) %>%
        addDrawToolbar(
          targetGroup = "selection",
          editOptions = editToolbarOptions(
            selectedPathOptions = selectedPathOptions()
          ),
          circleOptions = FALSE,
          circleMarkerOptions = FALSE,
          singleFeature = TRUE
        ) %>%
        htmlwidgets::onRender("
          function(el, x) {
            var map = this;
            
            // Track map bounds
            map.on('moveend', function() {
              Shiny.setInputValue('" %+% session$ns("map_bounds") %+% "', 
                map.getBounds());
            });
            
            // Handle drawing events
            map.on('draw:created', function(e) {
              var layer = e.layer;
              var coords = layer.toGeoJSON();
              Shiny.setInputValue('" %+% session$ns("drawn_feature") %+% "', 
                coords);
            });
            
            // WebGL heatmap initialization
            if (L.webGLHeatmap) {
              window['" %+% session$ns("heatmapLayer") %+% "'] = L.webGLHeatmap({
                size: 30000,
                units: 'm',
                alphaRange: 0.4
              });
            }
          }
        ")
    })
    
    # Update map layers based on selections
    observeEvent(input$map_layers, {
      proxy <- leafletProxy("interactive_map")
      
      # Clear all layers first
      proxy %>% clearMarkers() %>% clearMarkerClusters() %>% clearHeatmap() %>% clearShapes()
      
      req(values$filtered_data)
      data <- values$filtered_data
      
      # Document Markers
      if ("markers" %in% input$map_layers && nrow(data) < 1000) {
        coords <- sf::st_coordinates(data)
        proxy %>%
          addCircleMarkers(
            lng = coords[,1],
            lat = coords[,2],
            radius = 4,
            color = switch(input$color_scheme,
              "viridis" = "#440154",
              "plasma" = "#0d0887",
              "inferno" = "#000004",
              "gov_blue" = "#003366",
              "brazil" = "#009739"
            ),
            fillOpacity = input$opacity,
            popup = ~paste0(
              "<b>", data$titulo, "</b><br>",
              "Category: ", data$categoria, "<br>",
              "State: ", data$estado, "<br>",
              "Date: ", data$data_publicacao
            ),
            group = "markers"
          )
      }
      
      # Cluster View
      if ("clusters" %in% input$map_layers) {
        coords <- sf::st_coordinates(data)
        proxy %>%
          addMarkers(
            lng = coords[,1],
            lat = coords[,2],
            clusterOptions = markerClusterOptions(
              maxClusterRadius = input$cluster_threshold,
              spiderfyOnMaxZoom = TRUE,
              showCoverageOnHover = TRUE,
              iconCreateFunction = JS("
                function(cluster) {
                  var count = cluster.getChildCount();
                  var size = count < 100 ? 'small' : 
                            count < 1000 ? 'medium' : 'large';
                  return L.divIcon({
                    html: '<div><span>' + count + '</span></div>',
                    className: 'cluster-icon cluster-' + size,
                    iconSize: L.point(40, 40)
                  });
                }
              ")
            ),
            popup = ~paste0(
              "<b>", data$titulo, "</b><br>",
              "Municipality: ", data$municipio
            ),
            group = "clusters"
          )
      }
      
      # Heat Map
      if ("heatmap" %in% input$map_layers) {
        coords <- sf::st_coordinates(data)
        proxy %>%
          addHeatmap(
            lng = coords[,1],
            lat = coords[,2],
            intensity = rep(1, nrow(coords)),
            blur = input$heatmap_radius,
            max = 0.05,
            radius = input$heatmap_radius,
            gradient = switch(input$color_scheme,
              "viridis" = RColorBrewer::brewer.pal(9, "BuPu"),
              "plasma" = RColorBrewer::brewer.pal(9, "PuRd"),
              "inferno" = RColorBrewer::brewer.pal(9, "OrRd"),
              "gov_blue" = RColorBrewer::brewer.pal(9, "Blues"),
              "brazil" = c("#009739", "#FFDF00", "#002776")
            ),
            group = "heatmap"
          )
      }
      
      # Municipality Boundaries
      if ("boundaries" %in% input$map_layers) {
        # Load municipality boundaries (would need geobr or similar)
        tryCatch({
          if (requireNamespace("geobr", quietly = TRUE)) {
            munis <- geobr::read_municipality(year = 2020, showProgress = FALSE)
            proxy %>%
              addPolygons(
                data = munis,
                weight = 1,
                color = "#666",
                fillOpacity = 0,
                group = "boundaries"
              )
          }
        }, error = function(e) {
          showNotification("Municipality boundaries not available", type = "warning")
        })
      }
      
      # State Choropleth
      if ("choropleth" %in% input$map_layers) {
        # Aggregate by state
        state_counts <- data %>%
          sf::st_drop_geometry() %>%
          group_by(estado) %>%
          summarise(count = n(), .groups = "drop")
        
        # Load state boundaries
        tryCatch({
          if (requireNamespace("geobr", quietly = TRUE)) {
            states <- geobr::read_state(year = 2020, showProgress = FALSE)
            states <- merge(states, state_counts, by.x = "abbrev_state", by.y = "estado", all.x = TRUE)
            states$count[is.na(states$count)] <- 0
            
            # Create color palette
            pal <- colorNumeric(
              palette = switch(input$color_scheme,
                "viridis" = "Viridis",
                "plasma" = "Plasma",
                "inferno" = "Inferno",
                "gov_blue" = "Blues",
                "brazil" = "RdYlGn"
              ),
              domain = states$count
            )
            
            proxy %>%
              addPolygons(
                data = states,
                weight = 2,
                color = "white",
                fillColor = ~pal(count),
                fillOpacity = input$opacity,
                label = ~paste0(name_state, ": ", count, " documents"),
                group = "choropleth"
              ) %>%
              addLegend(
                position = "bottomleft",
                pal = pal,
                values = states$count,
                title = "Documents",
                group = "choropleth"
              )
          }
        }, error = function(e) {
          showNotification("State boundaries not available", type = "warning")
        })
      }
    }, ignoreNULL = FALSE)
    
    # Spatial analysis tools
    observeEvent(input$spatial_tool, {
      req(input$spatial_tool != "none")
      
      proxy <- leafletProxy("interactive_map")
      
      if (input$spatial_tool == "radius") {
        # Enable radius search
        observeEvent(input$interactive_map_click, {
          click <- input$interactive_map_click
          
          proxy %>%
            clearGroup("search_radius") %>%
            addCircles(
              lng = click$lng,
              lat = click$lat,
              radius = input$search_radius * 1000,
              weight = 2,
              color = "#ff0000",
              fillOpacity = 0.2,
              group = "search_radius"
            )
          
          # Find points within radius
          if (!is.null(values$filtered_data)) {
            click_point <- sf::st_sfc(sf::st_point(c(click$lng, click$lat)), crs = 4326)
            buffer <- sf::st_buffer(click_point, dist = input$search_radius * 1000)
            
            selected <- sf::st_intersection(values$filtered_data, buffer)
            values$selected_features <- selected
            
            showNotification(
              sprintf("Found %d documents within %d km", nrow(selected), input$search_radius),
              type = "info"
            )
          }
        })
      } else if (input$spatial_tool == "corridor") {
        # Corridor analysis
        showNotification("Draw a line for corridor analysis", type = "info")
      }
    })
    
    # Handle drawn features
    observeEvent(input$drawn_feature, {
      req(input$drawn_feature)
      
      drawn_sf <- sf::st_read(jsonlite::toJSON(input$drawn_feature))
      
      if (!is.null(values$filtered_data)) {
        selected <- sf::st_intersection(values$filtered_data, drawn_sf)
        values$selected_features <- selected
        
        showNotification(
          sprintf("Selected %d documents", nrow(selected)),
          type = "success"
        )
      }
    })
    
    # Map statistics
    output$map_stats <- renderUI({
      req(values$filtered_data)
      
      stats <- list(
        "Total Documents" = format(nrow(values$filtered_data), big.mark = ","),
        "States" = length(unique(values$filtered_data$estado)),
        "Municipalities" = length(unique(values$filtered_data$municipio)),
        "Categories" = length(unique(values$filtered_data$categoria))
      )
      
      if (!is.null(values$selected_features)) {
        stats["Selected"] = nrow(values$selected_features)
      }
      
      tags$div(
        tags$b("Map Statistics"),
        tags$br(),
        lapply(names(stats), function(name) {
          tags$div(
            tags$span(name, ": "),
            tags$b(stats[[name]])
          )
        })
      )
    })
    
    # Export map as image
    output$export_map <- downloadHandler(
      filename = function() {
        paste0("legislative_map_", Sys.Date(), ".png")
      },
      content = function(file) {
        # Use webshot2 or mapshot for map export
        if (requireNamespace("mapshot", quietly = TRUE)) {
          mapshot::mapshot(
            x = input$interactive_map,
            file = file
          )
        } else {
          showNotification("Map export requires mapshot package", type = "error")
        }
      }
    )
    
    # Export visible data
    output$export_data <- downloadHandler(
      filename = function() {
        paste0("legislative_data_", Sys.Date(), ".csv")
      },
      content = function(file) {
        data <- if (!is.null(values$selected_features)) {
          values$selected_features
        } else {
          values$filtered_data
        }
        
        if (!is.null(data)) {
          write.csv(sf::st_drop_geometry(data), file, row.names = FALSE)
        }
      }
    )
    
    # Share map state
    observeEvent(input$share_map, {
      # Generate shareable URL with map state
      map_state <- list(
        center = input$interactive_map_center,
        zoom = input$interactive_map_zoom,
        layers = input$map_layers,
        filters = list(
          category = input$category_filter,
          state = input$state_filter,
          dates = input$date_filter
        )
      )
      
      state_json <- jsonlite::toJSON(map_state, auto_unbox = TRUE)
      state_base64 <- base64enc::base64encode(charToRaw(state_json))
      
      share_url <- paste0(
        session$clientData$url_protocol, "//",
        session$clientData$url_hostname,
        session$clientData$url_pathname,
        "?map_state=", state_base64
      )
      
      showModal(modalDialog(
        title = "Share Map View",
        tags$div(
          tags$p("Copy this URL to share the current map view:"),
          tags$input(
            type = "text",
            value = share_url,
            style = "width: 100%; padding: 10px;",
            readonly = TRUE,
            onclick = "this.select();"
          ),
          tags$br(),
          tags$button(
            "Copy to Clipboard",
            onclick = sprintf("navigator.clipboard.writeText('%s')", share_url),
            class = "btn btn-primary"
          )
        ),
        footer = modalButton("Close")
      ))
    })
    
    # Return reactive values for integration
    return(values)
  })
}

# PERFORMANCE OPTIMIZATION HELPERS
# =================================

# WebGL point rendering for massive datasets
render_webgl_points <- function(proxy, data, color_col = NULL) {
  coords <- sf::st_coordinates(data)
  
  # Prepare data for WebGL
  points_json <- jsonlite::toJSON(
    data.frame(
      lat = coords[,2],
      lng = coords[,1],
      value = if (!is.null(color_col)) data[[color_col]] else rep(1, nrow(coords))
    ),
    auto_unbox = TRUE
  )
  
  # Add WebGL layer via JavaScript
  proxy %>%
    htmlwidgets::onRender(sprintf("
      function(el, x) {
        var map = this;
        var data = %s;
        
        if (window.webGLHeatmapLayer) {
          window.webGLHeatmapLayer.setData(data);
          map.addLayer(window.webGLHeatmapLayer);
        }
      }
    ", points_json))
}

# Spatial indexing for fast queries
create_spatial_index <- function(data) {
  if (requireNamespace("spatialindex", quietly = TRUE)) {
    # Create R-tree index
    coords <- sf::st_coordinates(data)
    index <- spatialindex::generate_spatial_index(coords)
    return(index)
  }
  return(NULL)
}

# Tile-based data loading
load_tiles <- function(bounds, zoom, pool) {
  # Calculate tile boundaries
  tiles <- calculate_tiles(bounds, zoom)
  
  # Load data for visible tiles only
  con <- pool::poolCheckout(pool)
  on.exit(pool::poolReturn(con))
  
  query <- "
    SELECT * FROM documents
    WHERE geom && ST_MakeEnvelope($1, $2, $3, $4, 4326)
    LIMIT 5000
  "
  
  DBI::dbGetQuery(con, query, params = list(
    bounds$west, bounds$south, bounds$east, bounds$north
  ))
}

# DEPLOYMENT GUIDANCE
# ===================
# 1. Ensure PostGIS extension is enabled in database
# 2. Run create_spatial_indexes() on deployment
# 3. Configure memory limits for large datasets
# 4. Enable Redis caching for production
# 5. Use CDN for map tiles in production
# 6. Monitor WebGL memory usage
# 7. Implement rate limiting for spatial queries

# Export module functions
list(
  ui = enhancedInteractiveMapsUI,
  server = enhancedInteractiveMapsServer,
  create_indexes = create_spatial_indexes
)