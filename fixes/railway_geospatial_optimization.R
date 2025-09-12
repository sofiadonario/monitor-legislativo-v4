# Railway Geospatial Package Optimization
# ========================================
# Handles missing geospatial packages gracefully for Railway deployment

cat("🗺️ Initializing Railway Geospatial Optimization\n")

# Check which geospatial packages are available
GEOSPATIAL_AVAILABLE <- list(
  leaflet = FALSE,
  sf = FALSE,
  geobr = FALSE,
  plotly = FALSE,
  leaflet.extras = FALSE
)

# Test package availability without throwing errors
geospatial_packages <- c("leaflet", "sf", "geobr", "plotly", "leaflet.extras")
for (pkg in geospatial_packages) {
  GEOSPATIAL_AVAILABLE[[pkg]] <- tryCatch({
    requireNamespace(pkg, quietly = TRUE) && 
    suppressMessages(suppressWarnings(library(pkg, character.only = TRUE, quietly = TRUE, warn.conflicts = FALSE)))
    TRUE
  }, error = function(e) {
    FALSE
  })
}

cat("📦 Package availability check:\n")
for (pkg in names(GEOSPATIAL_AVAILABLE)) {
  status <- if (GEOSPATIAL_AVAILABLE[[pkg]]) "✅" else "❌"
  cat(paste0("  ", status, " ", pkg, "\n"))
}

# Override package loading functions to prevent errors
original_library <- base::library
library <- function(package, ...) {
  pkg_name <- as.character(substitute(package))
  if (pkg_name %in% names(GEOSPATIAL_AVAILABLE) && !GEOSPATIAL_AVAILABLE[[pkg_name]]) {
    cat("⚠️ Package", pkg_name, "not available - using fallback\n")
    return(invisible(NULL))
  }
  original_library(package, ...)
}

# Create fallback implementations for missing functions
if (!GEOSPATIAL_AVAILABLE$leaflet) {
  # Leaflet fallbacks
  leaflet <- function(...) {
    list(
      addTiles = function(...) list(),
      setView = function(...) list(),
      addMarkers = function(...) list(),
      addPolygons = function(...) list()
    )
  }
  
  renderLeaflet <- function(expr, ...) {
    function() {
      div(
        class = "alert alert-warning text-center",
        style = "height: 400px; display: flex; align-items: center; justify-content: center;",
        div(
          h4("Interactive Map Not Available"),
          p("Leaflet package not installed on this deployment."),
          p("Showing fallback visualization.")
        )
      )
    }
  }
  
  leafletOutput <- function(outputId, width = "100%", height = "400px") {
    div(
      id = outputId,
      class = "map-fallback",
      style = paste0("width: ", width, "; height: ", height, ";"),
      div(
        class = "alert alert-info text-center",
        style = "height: 100%; display: flex; align-items: center; justify-content: center;",
        div(
          icon("map-o", class = "fa-3x"),
          h4("Map Loading..."),
          p("Geographic visualization will appear here when packages are available.")
        )
      )
    )
  }
  
  leafletProxy <- function(...) {
    list(
      clearMarkers = function(...) list(),
      clearShapes = function(...) list(),
      addMarkers = function(...) list(),
      addPolygons = function(...) list()
    )
  }
  
  cat("📍 Leaflet fallbacks implemented\n")
}

if (!GEOSPATIAL_AVAILABLE$sf) {
  # SF fallbacks
  st_read <- function(...) {
    data.frame(
      estado = c("SP", "RJ", "MG"),
      geometry = c("POLYGON", "POLYGON", "POLYGON"),
      stringsAsFactors = FALSE
    )
  }
  
  st_transform <- function(x, ...) x
  st_bbox <- function(x) c(xmin = -74, ymin = -34, xmax = -32, ymax = 6)
  st_geometry <- function(x) x$geometry
  
  cat("🌍 SF fallbacks implemented\n")
}

if (!GEOSPATIAL_AVAILABLE$geobr) {
  # GEOBR fallbacks - create state boundaries data
  read_state <- function(...) {
    # Brazilian state centroids as fallback
    data.frame(
      code_state = c(35, 33, 31, 43, 23, 41, 21, 32, 52, 25, 51, 50, 29, 11, 15, 24, 16, 22, 42, 26, 53, 27, 17, 14, 28, 12, 13),
      abbrev_state = c("SP", "RJ", "MG", "RS", "CE", "PR", "MA", "ES", "GO", "PB", "MT", "MS", "BA", "RO", "PA", "RN", "PI", "AL", "SC", "PE", "DF", "SE", "TO", "RR", "AC", "AP", "AM"),
      name_state = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", "Ceará", "Paraná", "Maranhão", "Espírito Santo", "Goiás", "Paraíba", "Mato Grosso", "Mato Grosso do Sul", "Bahia", "Rondônia", "Pará", "Rio Grande do Norte", "Piauí", "Alagoas", "Santa Catarina", "Pernambuco", "Distrito Federal", "Sergipe", "Tocantins", "Roraima", "Acre", "Amapá", "Amazonas"),
      lat = c(-23.5, -22.9, -19.9, -30.0, -5.5, -25.3, -2.5, -19.2, -16.7, -7.1, -12.7, -20.5, -12.9, -11.2, -5.5, -5.2, -8.3, -9.6, -27.2, -8.4, -15.8, -10.9, -10.2, 2.8, -9.0, 1.4, -3.4),
      lng = c(-46.6, -43.2, -44.6, -51.2, -39.3, -51.6, -44.3, -40.3, -49.3, -35.9, -56.0, -54.8, -38.5, -62.8, -52.7, -36.5, -42.8, -35.1, -48.7, -35.1, -47.9, -37.3, -48.3, -60.7, -70.8, -51.9, -65.9),
      geometry = I(lapply(1:27, function(i) paste0("POLYGON(", runif(1, -75, -30), " ", runif(1, -35, 10), ")"))),
      stringsAsFactors = FALSE
    )
  }
  
  read_municipality <- function(...) {
    # Fallback municipality data
    data.frame(
      code_muni = 1:100,
      name_muni = paste("Municipality", 1:100),
      code_state = sample(c(35, 33, 31), 100, replace = TRUE),
      abbrev_state = sample(c("SP", "RJ", "MG"), 100, replace = TRUE),
      lat = runif(100, -35, 10),
      lng = runif(100, -75, -30),
      stringsAsFactors = FALSE
    )
  }
  
  cat("🇧🇷 GEOBR fallbacks implemented\n")
}

if (!GEOSPATIAL_AVAILABLE$plotly) {
  # Plotly fallbacks
  renderPlotly <- function(expr, ...) {
    function() {
      div(
        class = "alert alert-warning text-center",
        style = "height: 300px; display: flex; align-items: center; justify-content: center;",
        div(
          icon("chart-line", class = "fa-2x"),
          h5("Chart Not Available"),
          p("Interactive charts require plotly package.")
        )
      )
    }
  }
  
  plotlyOutput <- function(outputId, width = "100%", height = "300px") {
    div(
      id = outputId,
      class = "chart-fallback",
      style = paste0("width: ", width, "; height: ", height, ";"),
      div(
        class = "alert alert-info text-center",
        style = "height: 100%; display: flex; align-items: center; justify-content: center;",
        div(
          icon("chart-bar", class = "fa-2x"),
          h5("Chart Loading..."),
          p("Interactive visualization will appear here.")
        )
      )
    )
  }
  
  plot_ly <- function(...) {
    list(
      layout = function(...) list(),
      add_trace = function(...) list()
    )
  }
  
  cat("📊 Plotly fallbacks implemented\n")
}

# Create enhanced map loading with fallbacks
enhanced_map_loader <- function() {
  tryCatch({
    if (file.exists("modules/maps/enhanced_maps_loader.R")) {
      # Override the package checking
      maps_packages_status <<- GEOSPATIAL_AVAILABLE
      source("modules/maps/enhanced_maps_loader.R")
      cat("✅ Enhanced maps loader with fallbacks\n")
    } else {
      cat("⚠️ Enhanced maps loader not found, using basic fallback\n")
    }
  }, error = function(e) {
    cat("⚠️ Error loading enhanced maps:", e$message, "\n")
  })
}

# Create optimized geographic data loading
load_geographic_boundaries <- function() {
  if (GEOSPATIAL_AVAILABLE$geobr && GEOSPATIAL_AVAILABLE$sf) {
    tryCatch({
      # Load real Brazilian state boundaries
      states <- geobr::read_state(year = 2020, simplified = TRUE, showProgress = FALSE)
      return(states)
    }, error = function(e) {
      cat("⚠️ Failed to load real boundaries, using fallback\n")
      return(create_fallback_boundaries())
    })
  } else {
    return(create_fallback_boundaries())
  }
}

create_fallback_boundaries <- function() {
  # Create simplified state boundary data
  states_data <- data.frame(
    code_state = c(35, 33, 31, 43, 23),
    abbrev_state = c("SP", "RJ", "MG", "RS", "CE"),
    name_state = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", "Ceará"),
    lat = c(-23.5, -22.9, -19.9, -30.0, -5.5),
    lng = c(-46.6, -43.2, -44.6, -51.2, -39.3),
    stringsAsFactors = FALSE
  )
  
  return(states_data)
}

# Enhanced coordinate system for state/municipality mapping
create_coordinate_system <- function() {
  list(
    states = data.frame(
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
             -62.8031, -60.7484, -48.6756, -46.6333, -37.32, -48.2772),
      region = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste", "Centro-Oeste",
                "Sudeste", "Centro-Oeste", "Nordeste", "Centro-Oeste", "Centro-Oeste", "Sudeste",
                "Norte", "Nordeste", "Sul", "Nordeste", "Nordeste", "Sudeste", "Nordeste",
                "Sul", "Norte", "Norte", "Sul", "Sudeste", "Nordeste", "Norte"),
      stringsAsFactors = FALSE
    )
  )
}

# Store coordinate system globally
BRAZIL_COORDINATES <- create_coordinate_system()

# Performance optimization functions
optimize_for_railway <- function(data) {
  if (!is.data.frame(data) || nrow(data) == 0) {
    return(data)
  }
  
  # Limit data size for Railway memory constraints
  if (nrow(data) > 10000) {
    # Stratified sampling to maintain geographic distribution
    if ("estado" %in% names(data)) {
      data <- data %>%
        group_by(estado) %>%
        slice_sample(n = min(500, n())) %>%
        ungroup()
    } else {
      data <- data[sample(nrow(data), 10000), ]
    }
  }
  
  # Add coordinates if missing
  if (!"lat" %in% names(data) && "estado" %in% names(data)) {
    data <- merge(data, BRAZIL_COORDINATES$states[, c("estado", "lat", "lng")], 
                 by = "estado", all.x = TRUE)
  }
  
  return(data)
}

# Export global status
RAILWAY_GEOSPATIAL_STATUS <- list(
  packages_available = GEOSPATIAL_AVAILABLE,
  fallbacks_enabled = TRUE,
  coordinate_system = BRAZIL_COORDINATES,
  optimization_active = TRUE
)

cat("✅ Railway Geospatial Optimization complete\n")
cat("📊 Available packages:", sum(unlist(GEOSPATIAL_AVAILABLE)), "of", length(GEOSPATIAL_AVAILABLE), "\n")

# Load enhanced maps with fallbacks
enhanced_map_loader()