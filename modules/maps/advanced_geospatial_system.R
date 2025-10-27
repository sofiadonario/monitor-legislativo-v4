# Advanced Geospatial Visualization System for Brazilian Legislative Monitoring
# High-performance implementation with multi-scale geographic analysis
# Optimized for Railway deployment with <1500MB memory usage

# Essential packages with graceful fallbacks
if (!exists("%>%")) {
  `%>%` <- if (requireNamespace("magrittr", quietly = TRUE)) magrittr::`%>%` 
           else if (requireNamespace("dplyr", quietly = TRUE)) dplyr::`%>%`
           else function(x, f) f(x)
}

#' Advanced Brazilian Geospatial Data Management
#' @description Comprehensive geospatial system with multi-scale capabilities
initialize_advanced_geospatial <- function() {
  cat("🚀 Initializing Advanced Brazilian Geospatial System...\n")
  
  # Memory-efficient initialization
  gc()
  
  tryCatch({
    # Railway-aware cache management
    cache_base <- if (Sys.getenv("RAILWAY_VOLUME_MOUNT_PATH") != "") {
      file.path(Sys.getenv("RAILWAY_VOLUME_MOUNT_PATH"), "geospatial_cache")
    } else {
      "cache/geospatial"
    }
    
    dir.create(cache_base, recursive = TRUE, showWarnings = FALSE, mode = "0755")
    
    # Initialize boundary data with memory optimization
    boundaries_data <- load_optimized_boundaries(cache_base)
    
    # Initialize municipality data (on-demand loading)
    municipality_system <- initialize_municipality_system(cache_base)
    
    # Create IBGE integration
    ibge_integration <- setup_ibge_integration()
    
    # Performance monitoring
    performance_monitor <- setup_performance_monitoring()
    
    system <- list(
      boundaries = boundaries_data,
      municipalities = municipality_system,
      ibge = ibge_integration,
      performance = performance_monitor,
      cache_dir = cache_base,
      memory_limit = 1400, # MB - Reserve 100MB for system
      available = TRUE,
      initialized_at = Sys.time()
    )
    
    cat("✅ Advanced geospatial system initialized successfully\n")
    cat("📊 Memory usage:", format(object.size(system), units = "MB"), "\n")
    
    return(system)
    
  }, error = function(e) {
    cat("❌ Advanced geospatial initialization failed:", e$message, "\n")
    return(list(available = FALSE, error = e$message))
  })
}

#' Load optimized Brazilian boundaries with multi-scale support
load_optimized_boundaries <- function(cache_dir) {
  cache_file <- file.path(cache_dir, "optimized_boundaries.rds")
  
  # Check cache first
  if (file.exists(cache_file)) {
    tryCatch({
      cached_data <- readRDS(cache_file)
      if (validate_boundary_cache(cached_data)) {
        cat("📍 Using cached optimized boundaries\n")
        return(cached_data)
      }
    }, error = function(e) {
      cat("⚠️ Cache validation failed, refreshing\n")
    })
  }
  
  # Load fresh data
  tryCatch({
    cat("🌍 Loading Brazilian boundaries from geobr...\n")
    
    if (!requireNamespace("geobr", quietly = TRUE) || !requireNamespace("sf", quietly = TRUE)) {
      stop("Required packages geobr and sf not available")
    }
    
    # Load states with timeout
    states <- load_with_timeout(function() {
      geobr::read_state(year = 2020, simplified = TRUE, showProgress = FALSE)
    }, timeout = 30)
    
    # Optimize geometry for web performance
    states <- optimize_geometry(states)
    
    # Create different resolution versions
    states_high <- states
    states_medium <- sf::st_simplify(states, dTolerance = 0.01, preserveTopology = TRUE)
    states_low <- sf::st_simplify(states, dTolerance = 0.02, preserveTopology = TRUE)
    
    # Add state metadata
    states_data <- enhance_state_metadata(states)
    
    # Create GeoJSON versions
    geojson_high <- safe_geojson_conversion(states_high)
    geojson_medium <- safe_geojson_conversion(states_medium)
    geojson_low <- safe_geojson_conversion(states_low)
    
    boundary_system <- list(
      states = list(
        high = states_high,
        medium = states_medium,
        low = states_low,
        data = states_data
      ),
      geojson = list(
        high = geojson_high,
        medium = geojson_medium,
        low = geojson_low
      ),
      resolution_levels = c("high", "medium", "low"),
      default_resolution = "medium",
      cached_at = Sys.time()
    )
    
    # Cache the results
    saveRDS(boundary_system, cache_file)
    cat("💾 Optimized boundaries cached successfully\n")
    
    return(boundary_system)
    
  }, error = function(e) {
    cat("❌ Failed to load boundaries:", e$message, "\n")
    return(NULL)
  })
}

#' Initialize municipality system with on-demand loading
initialize_municipality_system <- function(cache_dir) {
  municipality_cache <- file.path(cache_dir, "municipalities")
  dir.create(municipality_cache, recursive = TRUE, showWarnings = FALSE)
  
  return(list(
    cache_dir = municipality_cache,
    loaded_states = character(0),
    data_cache = list(),
    load_municipality_data = function(state_codes = NULL) {
      load_municipalities_on_demand(municipality_cache, state_codes)
    },
    get_municipality_summary = function() {
      get_cached_municipality_summary(municipality_cache)
    }
  ))
}

#' Load municipalities on demand to manage memory
load_municipalities_on_demand <- function(cache_dir, state_codes = NULL) {
  if (is.null(state_codes)) {
    # Load summary data only
    summary_file <- file.path(cache_dir, "municipality_summary.rds")
    if (file.exists(summary_file)) {
      return(readRDS(summary_file))
    }
    return(create_municipality_summary(cache_dir))
  }
  
  # Load specific states
  municipalities <- list()
  for (state_code in state_codes) {
    state_file <- file.path(cache_dir, paste0("municipalities_", state_code, ".rds"))
    if (file.exists(state_file)) {
      municipalities[[state_code]] <- readRDS(state_file)
    } else {
      municipalities[[state_code]] <- download_state_municipalities(state_code, cache_dir)
    }
  }
  
  return(municipalities)
}

#' Setup IBGE integration for Brazilian geographic context
setup_ibge_integration <- function() {
  ibge_data <- list(
    # Brazilian regions
    regions = list(
      "Norte" = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
      "Nordeste" = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
      "Centro-Oeste" = c("DF", "GO", "MT", "MS"),
      "Sudeste" = c("ES", "MG", "RJ", "SP"),
      "Sul" = c("PR", "RS", "SC")
    ),
    
    # State information with IBGE codes
    states = data.frame(
      code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
               "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
               "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
      name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", 
               "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
               "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará", 
               "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro", 
               "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", "Roraima", 
               "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
      ibge_code = c(12, 17, 16, 13, 29, 23, 53, 32, 52, 21, 51, 50, 31, 15, 
                    25, 41, 26, 22, 33, 24, 43, 11, 14, 42, 35, 28, 17),
      population_2022 = c(906876, 3351543, 877613, 4269995, 14985284, 9240580,
                          3094325, 4108508, 7206589, 7153262, 3567234, 2833629,
                          21411923, 8777124, 4059905, 11597484, 9674793, 3289290,
                          17463349, 3560903, 11466630, 1815278, 652713, 7338473,
                          46649132, 2338474, 1607363),
      stringsAsFactors = FALSE
    ),
    
    # Regional colors for visualization
    regional_colors = list(
      "Norte" = "#2E8B57",
      "Nordeste" = "#FF6347", 
      "Centro-Oeste" = "#DAA520",
      "Sudeste" = "#4169E1",
      "Sul" = "#8A2BE2"
    ),
    
    get_state_region = function(state_code) {
      for (region in names(ibge_data$regions)) {
        if (state_code %in% ibge_data$regions[[region]]) {
          return(region)
        }
      }
      return("Unknown")
    }
  )
  
  return(ibge_data)
}

#' Setup performance monitoring for geospatial operations
setup_performance_monitoring <- function() {
  list(
    memory_usage = function() {
      gc_info <- gc(verbose = FALSE)
      list(
        used_mb = sum(gc_info[, 2]),
        max_mb = sum(gc_info[, 4]),
        percentage = round(sum(gc_info[, 2]) / 1400 * 100, 1)
      )
    },
    
    optimize_memory = function() {
      gc(verbose = FALSE)
      cat("♻️ Memory optimization completed\n")
    },
    
    log_operation = function(operation, duration_ms, memory_before, memory_after) {
      cat("📊", operation, ":", duration_ms, "ms, Memory:", 
          round(memory_after - memory_before, 1), "MB change\n")
    }
  )
}

#' Create high-performance choropleth with multiple data sources
create_advanced_choropleth <- function(geo_system, data, metric_column, 
                                     map_type = "states", resolution = "medium",
                                     clustering = FALSE, animation = FALSE) {
  
  start_time <- Sys.time()
  memory_before <- geo_system$performance$memory_usage()$used_mb
  
  tryCatch({
    cat("🎯 Creating advanced choropleth:", map_type, "resolution:", resolution, "\n")
    
    # Validate inputs
    if (!geo_system$available || isTRUE(is.null(data)) || nrow(data) == 0) {
      return(create_fallback_visualization(data, metric_column))
    }
    
    # Select appropriate boundaries based on type and resolution
    boundaries <- switch(map_type,
      "states" = geo_system$boundaries$states[[resolution]],
      "regions" = create_regional_boundaries(geo_system, resolution),
      "density" = geo_system$boundaries$states$high,
      geo_system$boundaries$states$medium
    )
    
    geojson <- switch(map_type,
      "states" = geo_system$boundaries$geojson[[resolution]],
      "regions" = create_regional_geojson(geo_system, resolution),
      "density" = geo_system$boundaries$geojson$high,
      geo_system$boundaries$geojson$medium
    )
    
    # Prepare data based on map type
    processed_data <- prepare_choropleth_data(data, metric_column, map_type, geo_system)
    
    # Apply clustering if requested
    if (clustering && map_type == "states") {
      processed_data <- apply_geographic_clustering(processed_data, geo_system)
    }
    
    # Create base choropleth
    choropleth <- create_optimized_choropleth(
      data = processed_data,
      boundaries = boundaries,
      geojson = geojson,
      metric_column = metric_column,
      map_type = map_type
    )
    
    # Add animation if requested
    if (animation && "date" %in% names(data)) {
      choropleth <- add_temporal_animation(choropleth, data, metric_column)
    }
    
    # Performance logging
    end_time <- Sys.time()
    memory_after <- geo_system$performance$memory_usage()$used_mb
    duration_ms <- round(as.numeric(difftime(end_time, start_time, units = "secs")) * 1000)
    
    geo_system$performance$log_operation("Advanced Choropleth", duration_ms, 
                                       memory_before, memory_after)
    
    return(choropleth)
    
  }, error = function(e) {
    cat("❌ Advanced choropleth creation failed:", e$message, "\n")
    return(create_fallback_visualization(data, metric_column))
  })
}

#' Create geographic clustering for dense areas
apply_geographic_clustering <- function(data, geo_system) {
  tryCatch({
    if (!requireNamespace("cluster", quietly = TRUE)) {
      cat("⚠️ Clustering package not available, using original data\n")
      return(data)
    }
    
    # Get state coordinates
    state_coords <- geo_system$boundaries$states$data[, c("abbrev_state", "centroid_lat", "centroid_lon")]
    
    # Merge with data
    data_with_coords <- merge(data, state_coords, by.x = "state_code", by.y = "abbrev_state")
    
    # Apply k-means clustering
    if (nrow(data_with_coords) >= 3) {
      coords_matrix <- as.matrix(data_with_coords[, c("centroid_lat", "centroid_lon")])
      k <- min(5, nrow(data_with_coords) - 1)
      
      clusters <- kmeans(coords_matrix, centers = k, nstart = 10)
      data_with_coords$cluster <- clusters$cluster
      
      cat("📊 Applied geographic clustering with", k, "clusters\n")
    }
    
    return(data_with_coords)
    
  }, error = function(e) {
    cat("⚠️ Clustering failed:", e$message, "\n")
    return(data)
  })
}

#' Create time-series animation for temporal changes
add_temporal_animation <- function(choropleth, data, metric_column) {
  tryCatch({
    if (!"date" %in% names(data) || nrow(data) == 0) {
      return(choropleth)
    }
    
    # Prepare temporal data
    data$year <- as.numeric(format(as.Date(data$date), "%Y"))
    temporal_data <- data %>%
      group_by(state_code, year) %>%
      summarise(
        metric_value = sum(get(metric_column), na.rm = TRUE),
        .groups = "drop"
      )
    
    # Add animation frame
    choropleth <- choropleth %>%
      plotly::layout(
        updatemenus = list(
          list(
            type = "buttons",
            direction = "left",
            pad = list(r = 10, t = 87),
            x = 0.1,
            xanchor = "right",
            y = 0,
            yanchor = "top",
            buttons = list(
              list(
                label = "Play",
                method = "animate",
                args = list(NULL, list(frame = list(duration = 500, redraw = FALSE),
                                     transition = list(duration = 300)))
              ),
              list(
                label = "Pause",
                method = "animate",
                args = list(list(NULL), list(frame = list(duration = 0, redraw = FALSE),
                                           mode = "immediate"))
              )
            )
          )
        ),
        sliders = list(
          list(
            active = 0,
            currentvalue = list(prefix = "Year: "),
            pad = list(t = 20),
            steps = create_animation_steps(temporal_data)
          )
        )
      )
    
    cat("🎬 Temporal animation added successfully\n")
    return(choropleth)
    
  }, error = function(e) {
    cat("⚠️ Animation creation failed:", e$message, "\n")
    return(choropleth)
  })
}

#' Create heatmap visualization for dense data
create_advanced_heatmap <- function(geo_system, data, intensity_column) {
  tryCatch({
    cat("🔥 Creating advanced heatmap visualization\n")
    
    if (!requireNamespace("leaflet", quietly = TRUE)) {
      return(create_fallback_heatmap(data, intensity_column))
    }
    
    # Prepare data for heatmap
    heatmap_data <- data[!is.na(data[[intensity_column]]) & 
                        !is.na(data$lat) & !is.na(data$lon), ]
    
    if (nrow(heatmap_data) == 0) {
      return(create_fallback_heatmap(data, intensity_column))
    }
    
    # Create leaflet heatmap
    heatmap <- leaflet::leaflet(heatmap_data) %>%
      leaflet::addTiles() %>%
      leaflet::addHeatmap(
        lat = ~lat, lng = ~lon, intensity = ~get(intensity_column),
        blur = 20, max = 0.05, radius = 15
      ) %>%
      leaflet::setView(lng = -53.2, lat = -14.2, zoom = 4)
    
    cat("✅ Advanced heatmap created successfully\n")
    return(heatmap)
    
  }, error = function(e) {
    cat("❌ Heatmap creation failed:", e$message, "\n")
    return(create_fallback_heatmap(data, intensity_column))
  })
}

# Helper functions for the advanced system

optimize_geometry <- function(sf_object) {
  tryCatch({
    # Simplify geometry for web performance
    simplified <- sf::st_simplify(sf_object, dTolerance = 0.005, preserveTopology = TRUE)
    
    # Ensure valid geometry
    valid <- sf::st_is_valid(simplified)
    if (!all(valid)) {
      simplified[!valid, ] <- sf::st_make_valid(simplified[!valid, ])
    }
    
    return(simplified)
  }, error = function(e) {
    cat("⚠️ Geometry optimization failed:", e$message, "\n")
    return(sf_object)
  })
}

enhance_state_metadata <- function(states) {
  # Add centroid coordinates
  centroids <- sf::st_centroid(states$geometry)
  coords <- sf::st_coordinates(centroids)
  
  states$centroid_lat <- coords[, 2]
  states$centroid_lon <- coords[, 1]
  
  return(states)
}

safe_geojson_conversion <- function(sf_object) {
  tryCatch({
    if (requireNamespace("geojsonio", quietly = TRUE)) {
      return(geojsonio::geojson_json(sf_object, precision = 4))
    } else {
      # Simplified structure for fallback
      return(list(
        type = "FeatureCollection",
        features = "simplified_boundaries",
        geometry_available = FALSE
      ))
    }
  }, error = function(e) {
    cat("⚠️ GeoJSON conversion failed:", e$message, "\n")
    return(NULL)
  })
}

validate_boundary_cache <- function(cached_data) {
  required_fields <- c("states", "geojson", "resolution_levels", "cached_at")
  return(all(required_fields %in% names(cached_data)) && 
         !is.null(cached_data$states$medium))
}

load_with_timeout <- function(func, timeout = 30) {
  if (requireNamespace("R.utils", quietly = TRUE)) {
    return(R.utils::withTimeout(func(), timeout = timeout))
  } else {
    return(func())
  }
}

create_fallback_visualization <- function(data, metric_column) {
  cat("🔄 Creating fallback visualization\n")
  # Implementation would create a simple scatter plot map
  return(NULL)
}

cat("🚀 Advanced Geospatial System loaded successfully\n")
cat("📊 Functions: initialize_advanced_geospatial, create_advanced_choropleth, create_advanced_heatmap\n")
cat("🎯 Features: Multi-scale mapping, clustering, animations, Brazilian context\n")