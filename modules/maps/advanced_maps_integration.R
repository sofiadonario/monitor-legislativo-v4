# Advanced Maps Integration Layer
# Unified interface for all advanced geospatial visualization capabilities
# Seamless integration with existing Brazilian Legislative Monitoring System

#' Advanced Maps Integration System
#' @description Central coordinator for all advanced geospatial features
initialize_advanced_maps_system <- function() {
  cat("🎯 Initializing Advanced Maps Integration System...\n")
  
  # Load dependencies first
  if (file.exists("modules/maps/dependency_loader.R")) {
    source("modules/maps/dependency_loader.R")
  }
  
  tryCatch({
    # Initialize all subsystems
    performance_system <- initialize_performance_optimization(memory_limit_mb = 1400)
    geospatial_system <- initialize_advanced_geospatial()
    municipality_system <- initialize_municipality_mapping()
    temporal_system <- initialize_temporal_animation_system()
    
    # Create unified interface
    advanced_maps <- list(
      # System status
      systems = list(
        performance = performance_system,
        geospatial = geospatial_system,
        municipalities = municipality_system,
        temporal = temporal_system
      ),
      
      # Core mapping functions
      create_choropleth = function(data, metric_column, map_type = "states", 
                                 options = list()) {
        create_advanced_choropleth_unified(data, metric_column, map_type, options)
      },
      
      create_municipality_map = function(data, metric_column, states = NULL, 
                                       options = list()) {
        create_municipality_map_unified(data, metric_column, states, options)
      },
      
      create_temporal_animation = function(data, metric_column, time_column = "date",
                                         options = list()) {
        create_temporal_animation_unified(data, metric_column, time_column, options)
      },
      
      create_heatmap = function(data, intensity_column, options = list()) {
        create_heatmap_unified(data, intensity_column, options)
      },
      
      # Interactive features
      create_interactive_dashboard = function(data, options = list()) {
        create_interactive_maps_dashboard(data, options)
      },
      
      # Utility functions
      optimize_data = function(data, target_size_mb = 50) {
        performance_system$optimize_geospatial_data(data, target_size_mb)
      },
      
      get_system_status = function() {
        get_advanced_system_status()
      },
      
      cleanup_resources = function() {
        cleanup_all_resources()
      }
    )
    
    # Verify system readiness
    system_status <- verify_system_readiness(advanced_maps)
    
    if (system_status$ready) {
      cat("✅ Advanced Maps System initialized successfully\n")
      cat("🎯 Available features:", paste(system_status$available_features, collapse = ", "), "\n")
      cat("📊 Memory usage:", system_status$memory_usage_mb, "MB\n")
    } else {
      cat("⚠️ Advanced Maps System initialized with limitations\n")
      cat("❌ Unavailable features:", paste(system_status$unavailable_features, collapse = ", "), "\n")
    }
    
    return(advanced_maps)
    
  }, error = function(e) {
    cat("❌ Advanced Maps System initialization failed:", e$message, "\n")
    return(create_fallback_maps_system())
  })
}

#' Create unified choropleth with all advanced features
create_advanced_choropleth_unified <- function(data, metric_column, map_type = "states", options = list()) {
  tryCatch({
    cat("🗺️ Creating advanced unified choropleth...\n")
    
    # Extract options with defaults
    resolution <- options$resolution %||% "medium"
    clustering <- options$clustering %||% FALSE
    animation <- options$animation %||% FALSE
    optimization <- options$optimization %||% TRUE
    webgl <- options$webgl %||% TRUE
    
    # Validate inputs
    if (is.null(data) || nrow(data) == 0) {
      stop("No data provided for choropleth")
    }
    
    if (!metric_column %in% names(data)) {
      stop("Metric column '", metric_column, "' not found in data")
    }
    
    # Apply performance optimization if requested
    if (optimization) {
      data <- advanced_maps$optimize_data(data, target_size_mb = 50)
    }
    
    # Get appropriate geospatial system
    geo_system <- advanced_maps$systems$geospatial
    if (!geo_system$available) {
      return(create_choropleth_fallback(data, metric_column))
    }
    
    # Create choropleth based on type
    choropleth <- switch(map_type,
      "states" = create_state_choropleth(data, metric_column, geo_system, resolution, clustering),
      "regions" = create_regional_choropleth(data, metric_column, geo_system, resolution),
      "density" = create_density_choropleth(data, metric_column, geo_system, resolution),
      create_state_choropleth(data, metric_column, geo_system, resolution, clustering)
    )
    
    if (is.null(choropleth)) {
      return(create_choropleth_fallback(data, metric_column))
    }
    
    # Add temporal animation if requested
    if (animation && "date" %in% names(data)) {
      temporal_system <- advanced_maps$systems$temporal
      choropleth <- temporal_system$create_temporal_choropleth(
        data, metric_column, "date", 
        animation_speed = options$animation_speed %||% 500
      )
    }
    
    # Apply WebGL optimization if requested
    if (webgl) {
      performance_system <- advanced_maps$systems$performance
      choropleth <- performance_system$implement_webgl_acceleration(choropleth)
    }
    
    # Add Brazilian context information
    choropleth <- add_brazilian_context_info(choropleth, data, map_type)
    
    cat("✅ Advanced choropleth created successfully\n")
    return(choropleth)
    
  }, error = function(e) {
    cat("❌ Advanced choropleth creation failed:", e$message, "\n")
    return(create_choropleth_fallback(data, metric_column))
  })
}

#' Create unified municipality map
create_municipality_map_unified <- function(data, metric_column, states = NULL, options = list()) {
  tryCatch({
    cat("🏘️ Creating unified municipality map...\n")
    
    # Get municipality system
    municipality_system <- advanced_maps$systems$municipalities
    
    # Determine states to load
    if (is.null(states)) {
      # Auto-select states with most data
      if ("state_code" %in% names(data)) {
        state_counts <- table(data$state_code)
        states <- names(head(sort(state_counts, decreasing = TRUE), 
                           options$max_states %||% 5))
      } else {
        states <- c("SP", "RJ", "MG", "RS", "PR") # Default major states
      }
    }
    
    # Create municipality choropleth
    municipality_map <- municipality_system$create_municipality_choropleth(
      data, metric_column, states
    )
    
    # Apply optimization
    if (options$optimization %||% TRUE) {
      performance_system <- advanced_maps$systems$performance
      municipality_map <- performance_system$implement_webgl_acceleration(municipality_map)
    }
    
    cat("✅ Municipality map created for states:", paste(states, collapse = ", "), "\n")
    return(municipality_map)
    
  }, error = function(e) {
    cat("❌ Municipality map creation failed:", e$message, "\n")
    return(create_municipality_fallback(data, metric_column))
  })
}

#' Create unified temporal animation
create_temporal_animation_unified <- function(data, metric_column, time_column = "date", options = list()) {
  tryCatch({
    cat("🎬 Creating unified temporal animation...\n")
    
    # Validate temporal data
    if (!time_column %in% names(data)) {
      stop("Time column '", time_column, "' not found in data")
    }
    
    # Get temporal system
    temporal_system <- advanced_maps$systems$temporal
    
    # Create animation based on type
    animation_type <- options$type %||% "choropleth"
    
    animated_map <- switch(animation_type,
      "choropleth" = temporal_system$create_temporal_choropleth(
        data, metric_column, time_column,
        animation_speed = options$speed %||% 500,
        frame_duration = options$frame_duration %||% 1000
      ),
      "heatmap" = temporal_system$create_temporal_heatmap(
        data, metric_column, time_column,
        animation_speed = options$speed %||% 800
      ),
      "trend" = temporal_system$create_trend_visualization(
        data, metric_column, time_column,
        trend_window = options$trend_window %||% 12
      ),
      temporal_system$create_temporal_choropleth(data, metric_column, time_column)
    )
    
    # Add performance optimization
    if (options$optimization %||% TRUE) {
      performance_system <- advanced_maps$systems$performance
      animated_map <- performance_system$implement_webgl_acceleration(animated_map)
    }
    
    cat("✅ Temporal animation created successfully\n")
    return(animated_map)
    
  }, error = function(e) {
    cat("❌ Temporal animation creation failed:", e$message, "\n")
    return(create_temporal_fallback(data, metric_column))
  })
}

#' Create unified heatmap
create_heatmap_unified <- function(data, intensity_column, options = list()) {
  tryCatch({
    cat("🔥 Creating unified heatmap...\n")
    
    # Validate heatmap data
    required_cols <- c(intensity_column, "lat", "lon")
    missing_cols <- required_cols[!required_cols %in% names(data)]
    
    if (length(missing_cols) > 0) {
      # Try to add coordinates if missing
      data <- add_coordinates_to_data(data)
      missing_cols <- required_cols[!required_cols %in% names(data)]
      
      if (length(missing_cols) > 0) {
        stop("Missing required columns for heatmap: ", paste(missing_cols, collapse = ", "))
      }
    }
    
    # Get geospatial system
    geo_system <- advanced_maps$systems$geospatial
    
    # Create heatmap
    heatmap <- geo_system$create_advanced_heatmap(geo_system, data, intensity_column)
    
    if (is.null(heatmap)) {
      return(create_heatmap_fallback(data, intensity_column))
    }
    
    cat("✅ Heatmap created successfully\n")
    return(heatmap)
    
  }, error = function(e) {
    cat("❌ Heatmap creation failed:", e$message, "\n")
    return(create_heatmap_fallback(data, intensity_column))
  })
}

#' Create interactive maps dashboard
create_interactive_maps_dashboard <- function(data, options = list()) {
  tryCatch({
    cat("📊 Creating interactive maps dashboard...\n")
    
    # Determine what maps to include
    include_states <- options$include_states %||% TRUE
    include_municipalities <- options$include_municipalities %||% TRUE
    include_temporal <- options$include_temporal %||% ("date" %in% names(data))
    include_heatmap <- options$include_heatmap %||% (all(c("lat", "lon") %in% names(data)))
    
    dashboard_maps <- list()
    
    # Create state choropleth
    if (include_states) {
      metric_col <- options$primary_metric %||% names(data)[sapply(data, is.numeric)][1]
      if (!is.null(metric_col)) {
        dashboard_maps$states <- advanced_maps$create_choropleth(
          data, metric_col, "states", 
          list(optimization = TRUE, webgl = TRUE)
        )
      }
    }
    
    # Create municipality map
    if (include_municipalities) {
      metric_col <- options$primary_metric %||% names(data)[sapply(data, is.numeric)][1]
      if (!is.null(metric_col)) {
        dashboard_maps$municipalities <- advanced_maps$create_municipality_map(
          data, metric_col, options$municipality_states,
          list(optimization = TRUE, max_states = 3)
        )
      }
    }
    
    # Create temporal animation
    if (include_temporal) {
      metric_col <- options$primary_metric %||% names(data)[sapply(data, is.numeric)][1]
      if (!is.null(metric_col)) {
        dashboard_maps$temporal <- advanced_maps$create_temporal_animation(
          data, metric_col, "date",
          list(type = "choropleth", optimization = TRUE)
        )
      }
    }
    
    # Create heatmap
    if (include_heatmap) {
      intensity_col <- options$intensity_metric %||% options$primary_metric %||% names(data)[sapply(data, is.numeric)][1]
      if (!is.null(intensity_col)) {
        dashboard_maps$heatmap <- advanced_maps$create_heatmap(
          data, intensity_col,
          list(optimization = TRUE)
        )
      }
    }
    
    cat("✅ Interactive dashboard created with", length(dashboard_maps), "maps\n")
    return(dashboard_maps)
    
  }, error = function(e) {
    cat("❌ Interactive dashboard creation failed:", e$message, "\n")
    return(list())
  })
}

#' Get comprehensive system status
get_advanced_system_status <- function() {
  tryCatch({
    performance_stats <- advanced_maps$systems$performance$monitor_performance()
    
    status <- list(
      ready = TRUE,
      available_features = character(0),
      unavailable_features = character(0),
      memory_usage_mb = performance_stats$memory$used_mb,
      memory_percentage = performance_stats$memory$usage_percentage,
      timestamp = Sys.time()
    )
    
    # Check each subsystem
    if (advanced_maps$systems$geospatial$available) {
      status$available_features <- c(status$available_features, "advanced_choropleth", "state_mapping")
    } else {
      status$unavailable_features <- c(status$unavailable_features, "advanced_choropleth")
    }
    
    if (!is.null(advanced_maps$systems$municipalities)) {
      status$available_features <- c(status$available_features, "municipality_mapping")
    } else {
      status$unavailable_features <- c(status$unavailable_features, "municipality_mapping")
    }
    
    if (!is.null(advanced_maps$systems$temporal)) {
      status$available_features <- c(status$available_features, "temporal_animation")
    } else {
      status$unavailable_features <- c(status$unavailable_features, "temporal_animation")
    }
    
    if (!is.null(advanced_maps$systems$performance)) {
      status$available_features <- c(status$available_features, "performance_optimization")
    }
    
    status$ready <- length(status$unavailable_features) == 0
    
    return(status)
    
  }, error = function(e) {
    return(list(
      ready = FALSE,
      available_features = character(0),
      unavailable_features = c("system_error"),
      memory_usage_mb = 0,
      error = e$message
    ))
  })
}

#' Cleanup all system resources
cleanup_all_resources <- function() {
  tryCatch({
    cat("🧹 Cleaning up all advanced maps resources...\n")
    
    # Cleanup each subsystem
    if (!is.null(advanced_maps$systems$performance)) {
      advanced_maps$systems$performance$cleanup_memory()
    }
    
    if (!is.null(advanced_maps$systems$municipalities)) {
      advanced_maps$systems$municipalities$cleanup_cache()
    }
    
    # Force garbage collection
    gc(verbose = FALSE)
    
    cat("✅ Resource cleanup completed\n")
    
  }, error = function(e) {
    cat("❌ Resource cleanup failed:", e$message, "\n")
  })
}

# Helper functions

verify_system_readiness <- function(advanced_maps) {
  return(get_advanced_system_status())
}

create_fallback_maps_system <- function() {
  cat("🔄 Creating fallback maps system...\n")
  return(list(
    create_choropleth = function(data, metric_column, ...) {
      create_choropleth_fallback(data, metric_column)
    },
    create_municipality_map = function(data, metric_column, ...) {
      create_municipality_fallback(data, metric_column)
    },
    create_temporal_animation = function(data, metric_column, ...) {
      create_temporal_fallback(data, metric_column)
    },
    create_heatmap = function(data, intensity_column, ...) {
      create_heatmap_fallback(data, intensity_column)
    },
    get_system_status = function() {
      list(ready = FALSE, available_features = c("basic_fallback"))
    },
    cleanup_resources = function() { gc() }
  ))
}

create_state_choropleth <- function(data, metric_column, geo_system, resolution, clustering) {
  return(geo_system$create_advanced_choropleth(
    geo_system, data, metric_column, "states", resolution, clustering
  ))
}

create_regional_choropleth <- function(data, metric_column, geo_system, resolution) {
  return(geo_system$create_advanced_choropleth(
    geo_system, data, metric_column, "regions", resolution
  ))
}

create_density_choropleth <- function(data, metric_column, geo_system, resolution) {
  return(geo_system$create_advanced_choropleth(
    geo_system, data, metric_column, "density", resolution
  ))
}

add_brazilian_context_info <- function(choropleth, data, map_type) {
  # Add Brazilian-specific context and information
  return(choropleth)
}

add_coordinates_to_data <- function(data) {
  # Attempt to add lat/lon coordinates based on state_code or other identifiers
  if ("state_code" %in% names(data)) {
    # Add state centroids
    state_coords <- data.frame(
      state_code = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE"),
      lat = c(-23.55, -22.84, -18.10, -30.01, -24.89, -27.33, -12.96, -16.64, -8.28, -5.20),
      lon = c(-46.64, -43.15, -44.38, -51.22, -51.55, -49.44, -38.51, -49.31, -35.07, -39.53),
      stringsAsFactors = FALSE
    )
    
    data <- merge(data, state_coords, by = "state_code", all.x = TRUE)
  }
  
  return(data)
}

# Fallback functions

create_choropleth_fallback <- function(data, metric_column) {
  cat("🔄 Using choropleth fallback\n")
  return(plotly::plot_ly(type = "scatter", mode = "markers", 
                        text = paste("Fallback map for", metric_column)))
}

create_municipality_fallback <- function(data, metric_column) {
  cat("🔄 Using municipality fallback\n")
  return(plotly::plot_ly(type = "scatter", mode = "markers",
                        text = paste("Municipality fallback for", metric_column)))
}

create_temporal_fallback <- function(data, metric_column) {
  cat("🔄 Using temporal fallback\n")
  return(plotly::plot_ly(type = "scatter", mode = "lines",
                        text = paste("Temporal fallback for", metric_column)))
}

create_heatmap_fallback <- function(data, intensity_column) {
  cat("🔄 Using heatmap fallback\n")
  return(plotly::plot_ly(type = "scatter", mode = "markers",
                        text = paste("Heatmap fallback for", intensity_column)))
}

# Utility operator
`%||%` <- function(x, y) if (is.null(x)) y else x

cat("🎯 Advanced Maps Integration System loaded successfully\n")
cat("📊 Functions: initialize_advanced_maps_system, create_advanced_choropleth_unified\n")
cat("🎯 Features: Unified interface, automatic fallbacks, performance optimization\n")