# Interactive Maps Integration Module
# ====================================
# Seamless integration with existing Monitor Legislativo application
# Optimized for Railway deployment with 134k+ documents

# Load dependencies with fallback handling
required_packages <- c("leaflet", "sf", "data.table", "jsonlite")
optional_packages <- c("leaflet.extras", "leaflet.extras2", "geobr", "rmapshaper")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    stop(paste("Required package", pkg, "not installed"))
  }
  library(pkg, character.only = TRUE)
}

for (pkg in optional_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    library(pkg, character.only = TRUE)
  }
}

# SIMPLIFIED UI FOR INTEGRATION
# ==============================
interactiveMapsUI <- function(id) {
  ns <- NS(id)
  
  tabItem(
    tabName = "maps",
    
    # Performance warning for large datasets
    conditionalPanel(
      condition = "true",
      div(
        class = "alert alert-info",
        icon("info-circle"),
        "Interactive maps are optimized for performance. Large datasets are automatically clustered and filtered."
      )
    ),
    
    # Main control panel
    fluidRow(
      box(
        title = "Interactive Legislative Map Controls",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        collapsible = TRUE,
        
        fluidRow(
          # Quick filters
          column(width = 3,
            selectInput(ns("quick_view"),
              "Quick View:",
              choices = c(
                "National Overview" = "national",
                "State Density" = "state_density",
                "Municipality Clusters" = "municipal",
                "Transport Corridors" = "transport",
                "Recent Activity (30 days)" = "recent",
                "Historical Pattern" = "historical"
              ),
              selected = "national"
            ),
            
            selectInput(ns("data_type"),
              "Document Type:",
              choices = c(
                "All Documents" = "all",
                "Legislation" = "legislation",
                "Decrees" = "decree",
                "Jurisprudence" = "jurisprudence",
                "Transport Specific" = "transport"
              ),
              selected = "all"
            )
          ),
          
          column(width = 3,
            selectInput(ns("visualization"),
              "Visualization Type:",
              choices = c(
                "Cluster Markers" = "clusters",
                "Heat Map" = "heatmap",
                "Choropleth" = "choropleth",
                "Point Cloud" = "points",
                "Hexbin Grid" = "hexbin"
              ),
              selected = "clusters"
            ),
            
            sliderInput(ns("point_limit"),
              "Max Points to Display:",
              min = 100,
              max = 10000,
              value = 2000,
              step = 100
            )
          ),
          
          column(width = 3,
            dateRangeInput(ns("date_range"),
              "Date Filter:",
              start = Sys.Date() - 90,
              end = Sys.Date(),
              format = "dd/mm/yyyy"
            ),
            
            checkboxInput(ns("realtime_update"),
              "Auto-refresh (5 min)",
              value = FALSE
            )
          ),
          
          column(width = 3,
            br(),
            actionButton(ns("apply_filters"),
              "Apply Filters",
              icon = icon("filter"),
              class = "btn-primary btn-block"
            ),
            br(),
            actionButton(ns("reset_view"),
              "Reset Map",
              icon = icon("redo"),
              class = "btn-warning btn-block"
            )
          )
        )
      )
    ),
    
    # Map display area
    fluidRow(
      box(
        title = "Brazilian Legislative Document Distribution",
        status = "info",
        solidHeader = TRUE,
        width = 9,
        
        # Loading indicator
        conditionalPanel(
          condition = sprintf("$('#%s').hasClass('recalculating')", ns("main_map")),
          div(
            class = "text-center",
            style = "padding: 20px;",
            icon("spinner", class = "fa-spin fa-3x"),
            h4("Loading map data...")
          )
        ),
        
        # Main map
        leafletOutput(ns("main_map"), height = "600px"),
        
        # Map footer with stats
        wellPanel(
          style = "margin-top: 10px; padding: 10px;",
          fluidRow(
            column(3, 
              valueBoxOutput(ns("total_visible"), width = 12)
            ),
            column(3,
              valueBoxOutput(ns("states_covered"), width = 12)
            ),
            column(3,
              valueBoxOutput(ns("top_state"), width = 12)
            ),
            column(3,
              valueBoxOutput(ns("density_score"), width = 12)
            )
          )
        )
      ),
      
      # Side panel with details
      box(
        title = "Selection Details",
        status = "success",
        solidHeader = TRUE,
        width = 3,
        
        # Selection info
        div(id = ns("selection_info"),
          h5("Click on map features for details"),
          hr(),
          uiOutput(ns("selected_feature_info"))
        ),
        
        # Mini chart
        plotlyOutput(ns("selection_chart"), height = "200px"),
        
        hr(),
        
        # Quick actions
        h5("Quick Actions"),
        actionButton(ns("zoom_selection"),
          "Zoom to Selection",
          icon = icon("search-plus"),
          class = "btn-sm btn-info btn-block"
        ),
        downloadButton(ns("download_selection"),
          "Download Selection",
          class = "btn-sm btn-success btn-block"
        ),
        actionButton(ns("analyze_selection"),
          "Analyze Area",
          icon = icon("chart-bar"),
          class = "btn-sm btn-primary btn-block"
        )
      )
    ),
    
    # Analysis panels (collapsible)
    fluidRow(
      box(
        title = "Spatial Analysis Tools",
        status = "warning",
        solidHeader = TRUE,
        width = 12,
        collapsible = TRUE,
        collapsed = TRUE,
        
        fluidRow(
          column(width = 4,
            h4("Distance Analysis"),
            selectInput(ns("measure_from"),
              "Measure from:",
              choices = c(
                "Brasília (Capital)" = "brasilia",
                "São Paulo" = "saopaulo",
                "Rio de Janeiro" = "rio",
                "Custom Location" = "custom"
              )
            ),
            actionButton(ns("calculate_distances"),
              "Calculate Distances",
              icon = icon("ruler"),
              class = "btn-warning"
            )
          ),
          
          column(width = 4,
            h4("Corridor Analysis"),
            selectInput(ns("corridor_select"),
              "Select Corridor:",
              choices = c(
                "BR-116 Highway" = "br116",
                "BR-101 Coastal" = "br101",
                "Railway Networks" = "railway",
                "Major Ports" = "ports"
              )
            ),
            sliderInput(ns("buffer_km"),
              "Buffer (km):",
              min = 1, max = 50, value = 10
            ),
            actionButton(ns("analyze_corridor"),
              "Analyze Corridor",
              icon = icon("road"),
              class = "btn-warning"
            )
          ),
          
          column(width = 4,
            h4("Density Grid"),
            selectInput(ns("grid_size"),
              "Grid Resolution:",
              choices = c(
                "50km x 50km" = 50,
                "100km x 100km" = 100,
                "200km x 200km" = 200
              )
            ),
            actionButton(ns("generate_grid"),
              "Generate Grid",
              icon = icon("th"),
              class = "btn-warning"
            )
          )
        )
      )
    ),
    
    # Comparison view
    fluidRow(
      box(
        title = "Temporal Comparison",
        status = "info",
        solidHeader = TRUE,
        width = 12,
        collapsible = TRUE,
        collapsed = TRUE,
        
        fluidRow(
          column(width = 6,
            h4("Period 1"),
            dateRangeInput(ns("period1"),
              label = NULL,
              start = Sys.Date() - 365,
              end = Sys.Date() - 180
            ),
            leafletOutput(ns("comparison_map1"), height = "400px")
          ),
          column(width = 6,
            h4("Period 2"),
            dateRangeInput(ns("period2"),
              label = NULL,
              start = Sys.Date() - 180,
              end = Sys.Date()
            ),
            leafletOutput(ns("comparison_map2"), height = "400px")
          )
        ),
        
        hr(),
        
        h4("Change Analysis"),
        plotlyOutput(ns("change_chart"), height = "250px")
      )
    )
  )
}

# OPTIMIZED SERVER LOGIC
# ======================
interactiveMapsServer <- function(id, data_source = NULL) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values
    values <- reactiveValues(
      map_data = NULL,
      filtered_data = NULL,
      selection = NULL,
      last_update = Sys.time()
    )
    
    # Load and prepare data
    observe({
      # Try multiple data sources
      if (!is.null(data_source) && is.reactive(data_source)) {
        values$map_data <- data_source()
      } else {
        # Fallback to CSV/Parquet loading
        values$map_data <- load_map_data_fallback()
      }
      
      # Prepare spatial data if coordinates exist
      if (!is.null(values$map_data)) {
        values$map_data <- prepare_spatial_data(values$map_data)
      }
    })
    
    # Apply filters
    observeEvent(input$apply_filters, {
      req(values$map_data)
      
      filtered <- values$map_data
      
      # Type filter
      if (input$data_type != "all") {
        filtered <- filtered[filtered$type == input$data_type, ]
      }
      
      # Date filter
      if ("date" %in% names(filtered)) {
        filtered <- filtered[
          filtered$date >= input$date_range[1] &
          filtered$date <= input$date_range[2], ]
      }
      
      # Limit points for performance
      if (nrow(filtered) > input$point_limit) {
        # Smart sampling based on spatial distribution
        filtered <- spatial_sample(filtered, input$point_limit)
      }
      
      values$filtered_data <- filtered
      
      # Update map
      update_main_map()
    })
    
    # Main map rendering
    output$main_map <- renderLeaflet({
      leaflet() %>%
        addTiles() %>%
        setView(lng = -47.9, lat = -15.8, zoom = 4) %>%
        addScaleBar() %>%
        addMiniMap(toggleDisplay = TRUE)
    })
    
    # Update map function
    update_main_map <- function() {
      proxy <- leafletProxy("main_map")
      proxy %>% clearMarkers() %>% clearMarkerClusters() %>% clearHeatmap()
      
      req(values$filtered_data)
      data <- values$filtered_data
      
      if (nrow(data) == 0) {
        showNotification("No data to display", type = "warning")
        return()
      }
      
      # Render based on visualization type
      if (input$visualization == "clusters") {
        render_clusters(proxy, data)
      } else if (input$visualization == "heatmap") {
        render_heatmap(proxy, data)
      } else if (input$visualization == "choropleth") {
        render_choropleth(proxy, data)
      } else if (input$visualization == "hexbin") {
        render_hexbin(proxy, data)
      } else {
        render_points(proxy, data)
      }
    }
    
    # Rendering functions
    render_clusters <- function(proxy, data) {
      if ("lat" %in% names(data) && "lng" %in% names(data)) {
        proxy %>%
          addMarkers(
            data = data,
            lng = ~lng, lat = ~lat,
            clusterOptions = markerClusterOptions(
              maxClusterRadius = 80,
              spiderfyOnMaxZoom = TRUE,
              showCoverageOnHover = TRUE
            ),
            popup = ~paste0(
              "<b>", title, "</b><br>",
              "Type: ", type, "<br>",
              "Date: ", date
            )
          )
      }
    }
    
    render_heatmap <- function(proxy, data) {
      if ("lat" %in% names(data) && "lng" %in% names(data) && 
          requireNamespace("leaflet.extras", quietly = TRUE)) {
        proxy %>%
          leaflet.extras::addHeatmap(
            data = data,
            lng = ~lng, lat = ~lat,
            blur = 20,
            radius = 15,
            gradient = list(
              "0.0" = "blue",
              "0.5" = "yellow",
              "1.0" = "red"
            )
          )
      }
    }
    
    render_choropleth <- function(proxy, data) {
      # Aggregate by state
      if ("state" %in% names(data)) {
        state_counts <- data %>%
          group_by(state) %>%
          summarise(count = n(), .groups = "drop")
        
        # Load Brazil states shapefile
        if (requireNamespace("geobr", quietly = TRUE)) {
          states <- tryCatch({
            geobr::read_state(showProgress = FALSE)
          }, error = function(e) NULL)
          
          if (!is.null(states)) {
            states <- merge(states, state_counts, 
              by.x = "abbrev_state", by.y = "state", all.x = TRUE)
            states$count[is.na(states$count)] <- 0
            
            pal <- colorNumeric("Blues", domain = states$count)
            
            proxy %>%
              addPolygons(
                data = states,
                fillColor = ~pal(count),
                weight = 1,
                opacity = 1,
                color = "white",
                fillOpacity = 0.7,
                label = ~paste0(name_state, ": ", count, " documents")
              ) %>%
              addLegend(
                pal = pal,
                values = states$count,
                title = "Documents"
              )
          }
        }
      }
    }
    
    render_hexbin <- function(proxy, data) {
      # Create hexagonal bins
      if ("lat" %in% names(data) && "lng" %in% names(data)) {
        # Simple grid-based approach
        hex_size <- 0.5  # degrees
        data$hex_x <- round(data$lng / hex_size) * hex_size
        data$hex_y <- round(data$lat / hex_size) * hex_size
        
        hex_counts <- data %>%
          group_by(hex_x, hex_y) %>%
          summarise(count = n(), .groups = "drop")
        
        pal <- colorNumeric("YlOrRd", domain = hex_counts$count)
        
        for (i in 1:nrow(hex_counts)) {
          proxy %>%
            addCircles(
              lng = hex_counts$hex_x[i],
              lat = hex_counts$hex_y[i],
              radius = sqrt(hex_counts$count[i]) * 10000,
              fillColor = pal(hex_counts$count[i]),
              fillOpacity = 0.6,
              weight = 1,
              color = "white",
              popup = paste0("Documents: ", hex_counts$count[i])
            )
        }
      }
    }
    
    render_points <- function(proxy, data) {
      if ("lat" %in% names(data) && "lng" %in% names(data)) {
        proxy %>%
          addCircleMarkers(
            data = data,
            lng = ~lng, lat = ~lat,
            radius = 3,
            fillOpacity = 0.6,
            popup = ~title
          )
      }
    }
    
    # Statistics boxes
    output$total_visible <- renderValueBox({
      n_docs <- safe_nrow(values$filtered_data %||% values$map_data, default = 0L)

      safe_valueBox(
        value = value_box_scalar(n_docs, format_fn = function(x) format(x, big.mark = ",")),
        subtitle = "Visible Documents",
        icon = icon("file-alt"),
        color = "blue"
      )
    })
    
    output$states_covered <- renderValueBox({
      data <- values$filtered_data %||% values$map_data
      states <- safe_n_distinct(
        if (!is.null(data) && "state" %in% names(data)) data$state else NULL,
        default = 0L
      )

      safe_valueBox(
        value = value_box_scalar(states),
        subtitle = "States",
        icon = icon("map"),
        color = "green"
      )
    })
    
    output$top_state <- renderValueBox({
      data <- values$filtered_data %||% values$map_data
      top <- tryCatch({
        if (!is.null(data) && "state" %in% names(data) && nrow(data) > 0) {
          tbl <- table(data$state)
          scalar_chr(if (length(tbl) > 0) names(tbl)[which.max(tbl)] else NULL, default = "N/A")
        } else {
          "N/A"
        }
      }, error = function(e) "N/A")

      safe_valueBox(
        value = value_box_scalar(top),
        subtitle = "Most Active State",
        icon = icon("trophy"),
        color = "yellow"
      )
    })
    
    output$density_score <- renderValueBox({
      data <- values$filtered_data %||% values$map_data
      density <- tryCatch({
        n <- safe_nrow(data, default = 0L)
        scalar_int(if (n > 0) round(n / 27, 0) else NULL, default = 0L)
      }, error = function(e) 0L)

      safe_valueBox(
        value = value_box_scalar(density),
        subtitle = "Avg per State",
        icon = icon("chart-bar"),
        color = "red"
      )
    })
    
    # Selection handling
    observeEvent(input$main_map_marker_click, {
      click <- input$main_map_marker_click
      values$selection <- click
      
      output$selected_feature_info <- renderUI({
        tagList(
          h5("Selected Document"),
          p(strong("ID:"), click$id),
          p(strong("Location:"), round(click$lat, 4), ",", round(click$lng, 4)),
          actionButton(ns("view_document"), "View Full Document", 
            class = "btn-sm btn-primary")
        )
      })
    })
    
    # Download handler
    output$download_selection <- downloadHandler(
      filename = function() {
        paste0("legislative_selection_", Sys.Date(), ".csv")
      },
      content = function(file) {
        data <- values$filtered_data %||% values$map_data
        if (!is.null(data)) {
          write.csv(data, file, row.names = FALSE)
        }
      }
    )
    
    # Auto-refresh
    observeEvent(input$realtime_update, {
      if (input$realtime_update) {
        invalidateLater(300000)  # 5 minutes
        values$last_update <- Sys.time()
        update_main_map()
      }
    })
    
    # Return values for integration
    return(values)
  })
}

# HELPER FUNCTIONS
# ================

# Load data with multiple fallbacks
load_map_data_fallback <- function() {
  # Try multiple file paths - CORRECTED PRIORITY: Full dataset first
  paths <- c(
    "data_current/processed/production/lexml_unified_dataset.csv",
    "data_current/processed/production/lexml_enhanced_simple.csv",
    "data_current/processed/production/parquet/single_file/brazilian_legislative_complete.parquet",
    "railway_data_50k.csv"
  )
  
  for (path in paths) {
    if (file.exists(path)) {
      if (grepl("\\.parquet$", path)) {
        if (requireNamespace("arrow", quietly = TRUE)) {
          return(arrow::read_parquet(path))
        }
      } else {
        return(read.csv(path, stringsAsFactors = FALSE))
      }
    }
  }
  
  # Return sample data if nothing found
  return(data.frame(
    title = c("Sample Doc 1", "Sample Doc 2", "Sample Doc 3"),
    state = c("SP", "RJ", "MG"),
    lat = c(-23.5505, -22.9068, -19.9167),
    lng = c(-46.6333, -43.1729, -43.9345),
    date = Sys.Date() - 1:3,
    type = "legislation"
  ))
}

# Prepare spatial data
prepare_spatial_data <- function(data) {
  # Add coordinates if missing
  if (!("lat" %in% names(data)) || !("lng" %in% names(data))) {
    if ("estado" %in% names(data) || "state" %in% names(data)) {
      # Add state centroids
      state_coords <- data.frame(
        state = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
                 "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
                 "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
        lat = c(-9.0238, -9.5713, 1.4102, -3.4168, -12.9714, -5.4984, -15.7801,
               -19.1834, -16.6864, -2.5297, -12.6819, -20.5115, -18.5122, -5.5322,
               -7.0833, -25.2521, -8.3833, -8.2833, -22.9068, -5.22, -29.6842,
               -11.22, 2.8197, -27.2423, -23.5505, -10.9472, -10.1833),
        lng = c(-70.812, -35.7353, -51.9163, -65.8561, -38.5014, -39.3208, -47.9292,
               -40.3089, -49.2643, -44.3028, -56.0461, -54.7852, -44.555, -52.7264,
               -35.8833, -51.6253, -35.07, -42.8019, -43.1729, -36.52, -51.5,
               -62.8031, -60.7484, -48.6756, -46.6333, -37.32, -48.2772)
      )
      
      state_col <- if ("estado" %in% names(data)) "estado" else "state"
      data <- merge(data, state_coords, by.x = state_col, by.y = "state", all.x = TRUE)
      
      # Add jitter to prevent overlapping
      if (any(!is.na(data$lat))) {
        data$lat <- data$lat + runif(nrow(data), -0.1, 0.1)
        data$lng <- data$lng + runif(nrow(data), -0.1, 0.1)
      }
    }
  }
  
  return(data)
}

# Spatial sampling for performance
spatial_sample <- function(data, n) {
  if (nrow(data) <= n) return(data)
  
  # Try to maintain spatial distribution
  if ("state" %in% names(data)) {
    # Sample proportionally by state
    state_counts <- table(data$state)
    state_props <- state_counts / sum(state_counts)
    
    sampled <- NULL
    for (state in names(state_props)) {
      state_data <- data[data$state == state, ]
      n_state <- max(1, round(n * state_props[state]))
      n_state <- min(n_state, nrow(state_data))
      
      if (n_state > 0) {
        state_sample <- state_data[sample(nrow(state_data), n_state), ]
        sampled <- rbind(sampled, state_sample)
      }
    }
    return(sampled)
  } else {
    # Random sampling
    return(data[sample(nrow(data), n), ])
  }
}

# Export functions
list(
  ui = interactiveMapsUI,
  server = interactiveMapsServer
)