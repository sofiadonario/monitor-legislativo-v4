# Enhanced Maps Module Loader
# ============================
# Central loader for all interactive mapping capabilities
# Handles graceful degradation and Railway optimization

# Check for required packages
maps_packages_status <- list(
  leaflet = requireNamespace("leaflet", quietly = TRUE),
  sf = requireNamespace("sf", quietly = TRUE),
  plotly = requireNamespace("plotly", quietly = TRUE)
)

# Load modules based on availability
ENHANCED_MAP_MODULES <- list(
  basic = FALSE,
  interactive = FALSE,
  transport = FALSE,
  advanced = FALSE
)

# Try to load each module
tryCatch({
  # Basic interactive maps (always try to load)
  source("modules/maps/interactive_maps_integration.R")
  ENHANCED_MAP_MODULES$interactive <- TRUE
  cat("✅ Interactive Maps module loaded\n")
}, error = function(e) {
  cat("⚠️ Interactive Maps module not available:", e$message, "\n")
})

tryCatch({
  # Transport corridor analysis
  if (maps_packages_status$sf) {
    source("modules/maps/transport_corridor_analysis.R")
    ENHANCED_MAP_MODULES$transport <- TRUE
    cat("✅ Transport Corridor Analysis module loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Transport Corridor module not available:", e$message, "\n")
})

tryCatch({
  # Advanced features (WebGL, etc.)
  if (all(unlist(maps_packages_status))) {
    source("modules/maps/enhanced_interactive_maps.R")
    ENHANCED_MAP_MODULES$advanced <- TRUE
    cat("✅ Advanced Interactive Maps with WebGL loaded\n")
  }
}, error = function(e) {
  cat("⚠️ Advanced mapping features not available:", e$message, "\n")
})

# UNIFIED MAP UI FUNCTION
# ========================
enhancedMapUI <- function(id) {
  ns <- NS(id)
  
  # Choose best available UI
  if (ENHANCED_MAP_MODULES$advanced) {
    # Use full-featured WebGL maps
    enhancedInteractiveMapsUI(ns("advanced"))
  } else if (ENHANCED_MAP_MODULES$interactive) {
    # Use optimized interactive maps
    tagList(
      # Tab navigation for different map types
      tabsetPanel(
        id = ns("map_tabs"),
        type = "pills",
        
        # Main interactive map
        tabPanel(
          "Interactive Overview",
          icon = icon("map"),
          br(),
          interactiveMapsUI(ns("interactive"))
        ),
        
        # Transport corridor analysis
        if (ENHANCED_MAP_MODULES$transport) {
          tabPanel(
            "Transport Corridors",
            icon = icon("road"),
            br(),
            transportCorridorUI(ns("transport"))
          )
        } else { NULL },
        
        # Comparison view
        tabPanel(
          "Temporal Analysis",
          icon = icon("clock"),
          br(),
          temporalMapUI(ns("temporal"))
        ),
        
        # Density analysis
        tabPanel(
          "Density Heatmaps",
          icon = icon("fire"),
          br(),
          densityMapUI(ns("density"))
        )
      )
    )
  } else {
    # Fallback to simple map
    div(
      class = "alert alert-warning",
      icon("exclamation-triangle"),
      "Advanced mapping features require additional packages. Using simplified view.",
      br(), br(),
      simpleMapFallbackUI(ns("simple"))
    )
  }
}

# UNIFIED MAP SERVER FUNCTION
# ===========================
enhancedMapServer <- function(id, data_source = NULL, pool = NULL) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive data management
    map_data <- reactive({
      if (!is.null(data_source) && is.reactive(data_source)) {
        data_source()
      } else {
        # Load from file
        load_legislative_data()
      }
    })
    
    # Initialize appropriate servers
    if (ENHANCED_MAP_MODULES$advanced) {
      # Advanced WebGL maps
      enhancedInteractiveMapsServer("advanced", pool, map_data)
    } else if (ENHANCED_MAP_MODULES$interactive) {
      # Standard interactive maps
      interactive_values <- interactiveMapsServer("interactive", map_data)
      
      # Transport corridor analysis
      if (ENHANCED_MAP_MODULES$transport) {
        transport_values <- transportCorridorServer("transport", map_data)
      }
      
      # Temporal analysis
      temporal_values <- temporalMapServer("temporal", map_data)
      
      # Density analysis
      density_values <- densityMapServer("density", map_data)
      
    } else {
      # Simple fallback
      simpleMapServer("simple", map_data)
    }
  })
}

# TEMPORAL MAP MODULE
# ===================
temporalMapUI <- function(id) {
  ns <- NS(id)
  
  fluidRow(
    box(
      title = "Temporal Legislative Patterns",
      status = "info",
      solidHeader = TRUE,
      width = 12,
      
      fluidRow(
        column(width = 4,
          sliderInput(ns("year_range"),
            "Select Years:",
            min = 1988,
            max = as.numeric(format(Sys.Date(), "%Y")),
            value = c(2020, as.numeric(format(Sys.Date(), "%Y"))),
            step = 1,
            sep = "",
            animate = animationOptions(interval = 2000)
          )
        ),
        column(width = 4,
          selectInput(ns("temporal_metric"),
            "Metric:",
            choices = c(
              "Document Count" = "count",
              "Growth Rate" = "growth",
              "Cumulative" = "cumulative"
            )
          )
        ),
        column(width = 4,
          br(),
          actionButton(ns("play_animation"),
            "Play Animation",
            icon = icon("play"),
            class = "btn-primary"
          )
        )
      ),
      
      leafletOutput(ns("temporal_map"), height = "500px"),
      
      plotlyOutput(ns("temporal_chart"), height = "200px")
    )
  )
}

temporalMapServer <- function(id, data_source) {
  moduleServer(id, function(input, output, session) {
    
    # Animated map
    output$temporal_map <- renderLeaflet({
      leaflet() %>%
        addTiles() %>%
        setView(lng = -47.9, lat = -15.8, zoom = 4)
    })
    
    # Timeline chart
    output$temporal_chart <- renderPlotly({
      plot_ly(type = "scatter", mode = "lines") %>%
        layout(
          xaxis = list(title = "Year"),
          yaxis = list(title = "Documents"),
          margin = list(l = 50, r = 10, t = 10, b = 40)
        )
    })
    
    # Animation control
    observeEvent(input$play_animation, {
      # Trigger animation
      updateSliderInput(session, "year_range",
        value = c(input$year_range[1], input$year_range[1])
      )
    })
  })
}

# DENSITY MAP MODULE
# ==================
densityMapUI <- function(id) {
  ns <- NS(id)
  
  fluidRow(
    box(
      title = "Legislative Density Analysis",
      status = "warning",
      solidHeader = TRUE,
      width = 12,
      
      fluidRow(
        column(width = 3,
          selectInput(ns("density_type"),
            "Density Type:",
            choices = c(
              "Heat Map" = "heat",
              "Kernel Density" = "kernel",
              "Hexagonal Bins" = "hexbin",
              "Grid Cells" = "grid"
            )
          )
        ),
        column(width = 3,
          sliderInput(ns("bandwidth"),
            "Bandwidth/Radius:",
            min = 5, max = 100, value = 20
          )
        ),
        column(width = 3,
          selectInput(ns("color_palette"),
            "Color Palette:",
            choices = c(
              "Heat" = "heat",
              "Viridis" = "viridis",
              "Plasma" = "plasma",
              "Cool" = "cool"
            )
          )
        ),
        column(width = 3,
          br(),
          checkboxInput(ns("normalize"),
            "Normalize by Population",
            value = TRUE
          )
        )
      ),
      
      leafletOutput(ns("density_map"), height = "500px")
    )
  )
}

densityMapServer <- function(id, data_source) {
  moduleServer(id, function(input, output, session) {
    
    output$density_map <- renderLeaflet({
      leaflet() %>%
        addProviderTiles("CartoDB.DarkMatter") %>%
        setView(lng = -47.9, lat = -15.8, zoom = 4)
    })
    
    observe({
      req(data_source())
      data <- data_source()
      
      proxy <- leafletProxy("density_map")
      
      # Clear previous layers
      proxy %>% clearHeatmap() %>% clearShapes()
      
      # Add density visualization based on type
      if (input$density_type == "heat" && "lat" %in% names(data) && "lng" %in% names(data)) {
        if (requireNamespace("leaflet.extras", quietly = TRUE)) {
          proxy %>%
            leaflet.extras::addHeatmap(
              lng = data$lng,
              lat = data$lat,
              blur = input$bandwidth,
              radius = input$bandwidth
            )
        }
      }
    })
  })
}

# SIMPLE FALLBACK MAP
# ===================
simpleMapFallbackUI <- function(id) {
  ns <- NS(id)
  
  fluidRow(
    box(
      title = "Legislative Distribution Map",
      status = "primary",
      solidHeader = TRUE,
      width = 12,
      
      leafletOutput(ns("simple_map"), height = "500px"),
      
      p(class = "text-muted text-center",
        "Install additional packages for advanced features: leaflet.extras, sf, geobr")
    )
  )
}

simpleMapServer <- function(id, data_source) {
  moduleServer(id, function(input, output, session) {
    
    output$simple_map <- renderLeaflet({
      data <- if (!is.null(data_source) && is.reactive(data_source)) {
        data_source()
      } else {
        data.frame(
          lat = c(-23.5505, -22.9068, -19.9167),
          lng = c(-46.6333, -43.1729, -43.9345),
          city = c("São Paulo", "Rio de Janeiro", "Belo Horizonte")
        )
      }
      
      map <- leaflet(data) %>%
        addTiles() %>%
        setView(lng = -47.9, lat = -15.8, zoom = 4)
      
      if ("lat" %in% names(data) && "lng" %in% names(data)) {
        map %>%
          addMarkers(
            lng = ~lng,
            lat = ~lat,
            popup = ~if("title" %in% names(data)) title else "Document"
          )
      } else {
        map
      }
    })
  })
}

# DATA LOADING UTILITIES
# ======================
load_legislative_data <- function() {
  # Try multiple data sources - CORRECTED PRIORITY: Full dataset first
  if (file.exists("data_current/processed/production/lexml_unified_dataset.csv")) {
    data <- read.csv("data_current/processed/production/lexml_unified_dataset.csv", stringsAsFactors = FALSE)
  } else if (file.exists("data_current/processed/production/lexml_enhanced_simple.csv")) {
    data <- read.csv("data_current/processed/production/lexml_enhanced_simple.csv", stringsAsFactors = FALSE)  
  } else if (file.exists("railway_data_50k.csv")) {
    data <- read.csv("railway_data_50k.csv", stringsAsFactors = FALSE)
    
    # Add coordinates if missing
    if (!("lat" %in% names(data)) && "estado" %in% names(data)) {
      data <- add_state_coordinates(data)
    }
    
    return(data)
  }
  
  # Return sample data
  sample_legislative_data()
}

add_state_coordinates <- function(data) {
  state_coords <- data.frame(
    estado = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
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
  
  merged <- merge(data, state_coords, by = "estado", all.x = TRUE)
  
  # Add jitter to prevent overlap
  merged$lat <- merged$lat + runif(nrow(merged), -0.2, 0.2)
  merged$lng <- merged$lng + runif(nrow(merged), -0.2, 0.2)
  
  return(merged)
}

sample_legislative_data <- function() {
  data.frame(
    title = paste("Legislative Document", 1:100),
    estado = sample(c("SP", "RJ", "MG", "RS", "BA", "PR"), 100, replace = TRUE),
    date = seq(Sys.Date() - 365, Sys.Date(), length.out = 100),
    type = sample(c("lei", "decreto", "resolucao"), 100, replace = TRUE),
    stringsAsFactors = FALSE
  ) %>%
    add_state_coordinates()
}

# Export the unified interface
list(
  ui = enhancedMapUI,
  server = enhancedMapServer,
  status = ENHANCED_MAP_MODULES,
  packages = maps_packages_status
)