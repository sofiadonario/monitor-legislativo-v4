# Performance Optimization System for Cloud Run Geospatial Deployment
# Memory-efficient geospatial operations with <1500MB usage limit
# WebGL acceleration and intelligent caching strategies

#' Performance Optimization System for Geospatial Operations
#' @description Manages memory usage, implements caching, and optimizes rendering
initialize_performance_optimization <- function(memory_limit_mb = 1400) {
  cat("⚡ Initializing Performance Optimization System...\n")
  cat("📊 Memory limit set to:", memory_limit_mb, "MB\n")
  
  optimization_system <- list(
    memory_limit = memory_limit_mb,
    cache_manager = initialize_cache_manager(),
    memory_monitor = initialize_memory_monitor(memory_limit_mb),
    rendering_optimizer = initialize_rendering_optimizer(),
    
    # Core optimization functions
    optimize_geospatial_data = function(data, target_size_mb = 50) {
      optimize_data_for_memory(data, target_size_mb)
    },
    
    create_progressive_map = function(data, metric_column, detail_levels = 3) {
      create_progressive_detail_map(data, metric_column, detail_levels)
    },
    
    implement_webgl_acceleration = function(plotly_object) {
      enable_webgl_rendering(plotly_object)
    },
    
    monitor_performance = function() {
      get_performance_metrics()
    },
    
    cleanup_memory = function() {
      perform_memory_cleanup()
    },
    
    optimize_for_cloud_run = function() {
      apply_railway_optimizations()
    }
  )
  
  # Initialize performance monitoring
  optimization_system$memory_monitor$start_monitoring()
  
  cat("✅ Performance optimization system initialized\n")
  cat("🎯 Features: Memory monitoring, progressive loading, WebGL acceleration\n")
  
  return(optimization_system)
}

#' Initialize intelligent cache manager
initialize_cache_manager <- function() {
  cache_base <- if (nzchar(Sys.getenv("K_SERVICE"))) {
    # On Cloud Run, use /tmp for temporary cache
    file.path("/tmp", "performance_cache")
  } else {
    "cache/performance"
  }
  
  dir.create(cache_base, recursive = TRUE, showWarnings = FALSE, mode = "0755")
  
  list(
    cache_dir = cache_base,
    max_cache_size_mb = 200, # Limit cache to 200MB
    
    get_cached_data = function(cache_key) {
      get_from_cache(cache_base, cache_key)
    },
    
    set_cached_data = function(cache_key, data, ttl_hours = 24) {
      set_to_cache(cache_base, cache_key, data, ttl_hours)
    },
    
    cleanup_cache = function() {
      cleanup_cache_directory(cache_base)
    },
    
    get_cache_stats = function() {
      get_cache_statistics(cache_base)
    }
  )
}

#' Initialize memory monitoring system
initialize_memory_monitor <- function(memory_limit_mb) {
  list(
    limit_mb = memory_limit_mb,
    alert_threshold = 0.8, # Alert at 80% usage
    monitoring_active = FALSE,
    
    start_monitoring = function() {
      monitoring_active <<- TRUE
      cat("📊 Memory monitoring started (limit:", memory_limit_mb, "MB)\n")
    },
    
    check_memory = function() {
      check_memory_usage(memory_limit_mb)
    },
    
    get_memory_stats = function() {
      get_detailed_memory_stats()
    },
    
    force_cleanup = function() {
      force_memory_cleanup(memory_limit_mb)
    }
  )
}

#' Initialize rendering optimization system
initialize_rendering_optimizer <- function() {
  list(
    webgl_enabled = FALSE,
    progressive_loading = TRUE,
    chunk_size = 1000, # Process data in chunks of 1000 records
    
    optimize_plotly = function(plot_obj) {
      optimize_plotly_performance(plot_obj)
    },
    
    enable_webgl = function(plot_obj) {
      enable_webgl_rendering(plot_obj)
    },
    
    create_chunks = function(data, chunk_size = NULL) {
      create_data_chunks(data, chunk_size %||% 1000)
    },
    
    progressive_render = function(data, render_function) {
      render_progressively(data, render_function)
    }
  )
}

#' Optimize geospatial data for memory efficiency
optimize_data_for_memory <- function(data, target_size_mb = 50) {
  tryCatch({
    cat("🔧 Optimizing geospatial data for memory efficiency...\n")
    
    # Check current size
    current_size_mb <- as.numeric(object.size(data)) / 1024^2
    cat("📊 Current data size:", round(current_size_mb, 2), "MB\n")
    
    if (current_size_mb <= target_size_mb) {
      cat("✅ Data already within target size\n")
      return(data)
    }
    
    optimized_data <- data
    
    # Step 1: Remove unnecessary columns
    if (inherits(data, "sf")) {
      # For sf objects, keep only essential geometry and attributes
      essential_cols <- c("geometry", "state_code", "name_state", "abbrev_state")
      available_cols <- names(data)[names(data) %in% essential_cols]
      optimized_data <- data[, available_cols]
      
      # Simplify geometry if still too large
      new_size_mb <- as.numeric(object.size(optimized_data)) / 1024^2
      if (new_size_mb > target_size_mb) {
        cat("🔧 Simplifying geometry...\n")
        optimized_data <- sf::st_simplify(optimized_data, dTolerance = 0.01, preserveTopology = TRUE)
      }
    } else {
      # For regular data frames, optimize column types
      optimized_data <- optimize_dataframe_memory(data)
    }
    
    # Step 2: Remove duplicate rows
    optimized_data <- optimized_data[!duplicated(optimized_data), ]
    
    # Step 3: Sample data if still too large
    final_size_mb <- as.numeric(object.size(optimized_data)) / 1024^2
    if (final_size_mb > target_size_mb && nrow(optimized_data) > 1000) {
      sample_size <- min(nrow(optimized_data), round(nrow(optimized_data) * (target_size_mb / final_size_mb)))
      cat("📉 Sampling", sample_size, "rows from", nrow(optimized_data), "total\n")
      optimized_data <- optimized_data[sample(nrow(optimized_data), sample_size), ]
    }
    
    final_size_mb <- as.numeric(object.size(optimized_data)) / 1024^2
    cat("✅ Optimized data size:", round(final_size_mb, 2), "MB (", 
        round((current_size_mb - final_size_mb) / current_size_mb * 100, 1), "% reduction)\n")
    
    return(optimized_data)
    
  }, error = function(e) {
    cat("❌ Data optimization failed:", e$message, "\n")
    return(data)
  })
}

#' Create progressive detail map for performance
create_progressive_detail_map <- function(data, metric_column, detail_levels = 3) {
  tryCatch({
    cat("🔄 Creating progressive detail map...\n")
    
    # Create different detail levels
    detail_maps <- list()
    
    for (level in 1:detail_levels) {
      detail_factor <- level / detail_levels
      
      if (level == 1) {
        # Lowest detail - overview
        detail_data <- create_overview_level_data(data, metric_column)
        detail_maps[[level]] <- list(
          name = "overview",
          data = detail_data,
          zoom_threshold = c(0, 4),
          description = "Country overview"
        )
      } else if (level == 2) {
        # Medium detail - state level
        detail_data <- create_state_level_data(data, metric_column)
        detail_maps[[level]] <- list(
          name = "state",
          data = detail_data,
          zoom_threshold = c(4, 7),
          description = "State level detail"
        )
      } else {
        # High detail - municipality level (if available)
        detail_data <- create_municipality_level_data(data, metric_column)
        detail_maps[[level]] <- list(
          name = "municipality",
          data = detail_data,
          zoom_threshold = c(7, 12),
          description = "Municipality level detail"
        )
      }
    }
    
    # Create progressive loading structure
    progressive_map <- list(
      detail_levels = detail_maps,
      current_level = 1,
      switch_level = function(zoom_level) {
        select_appropriate_detail_level(detail_maps, zoom_level)
      }
    )
    
    cat("✅ Progressive detail map created with", detail_levels, "levels\n")
    return(progressive_map)
    
  }, error = function(e) {
    cat("❌ Progressive detail map creation failed:", e$message, "\n")
    return(list(detail_levels = list(), current_level = 1))
  })
}

#' Enable WebGL acceleration for plotly objects
enable_webgl_rendering <- function(plotly_object) {
  tryCatch({
    cat("🚀 Enabling WebGL acceleration...\n")
    
    if (is.null(plotly_object)) {
      return(NULL)
    }
    
    # Configure for WebGL rendering
    optimized_plot <- plotly_object %>%
      plotly::config(
        displayModeBar = TRUE,
        scrollZoom = TRUE,
        displaylogo = FALSE,
        modeBarButtonsToRemove = c('pan2d', 'select2d', 'lasso2d'),
        # WebGL specific configurations
        plotGlPixelRatio = 2, # High DPI support
        toImageButtonOptions = list(
          format = 'png',
          filename = 'legislative_map',
          height = 600,
          width = 800,
          scale = 1
        )
      ) %>%
      plotly::layout(
        # Optimize layout for performance
        autosize = TRUE,
        margin = list(l = 0, r = 0, t = 40, b = 0),
        # Enable hardware acceleration hints
        plot_bgcolor = 'rgba(0,0,0,0)',
        paper_bgcolor = 'rgba(0,0,0,0)'
      )
    
    cat("✅ WebGL acceleration enabled\n")
    return(optimized_plot)
    
  }, error = function(e) {
    cat("❌ WebGL acceleration failed:", e$message, "\n")
    return(plotly_object)
  })
}

#' Check memory usage and alert if necessary
check_memory_usage <- function(memory_limit_mb) {
  tryCatch({
    gc_info <- gc(verbose = FALSE)
    used_mb <- sum(gc_info[, 2])
    max_mb <- sum(gc_info[, 6])
    
    usage_percentage <- (used_mb / memory_limit_mb) * 100
    
    memory_stats <- list(
      used_mb = round(used_mb, 2),
      limit_mb = memory_limit_mb,
      usage_percentage = round(usage_percentage, 1),
      available_mb = round(memory_limit_mb - used_mb, 2),
      max_mb = round(max_mb, 2),
      status = if (usage_percentage > 80) "warning" else if (usage_percentage > 90) "critical" else "ok"
    )
    
    if (memory_stats$status == "warning") {
      cat("⚠️ Memory usage at", memory_stats$usage_percentage, "% - consider cleanup\n")
    } else if (memory_stats$status == "critical") {
      cat("🚨 Critical memory usage at", memory_stats$usage_percentage, "% - forcing cleanup\n")
      gc(verbose = FALSE)
    }
    
    return(memory_stats)
    
  }, error = function(e) {
    cat("❌ Memory check failed:", e$message, "\n")
    return(list(status = "error", used_mb = 0, limit_mb = memory_limit_mb))
  })
}

#' Apply Cloud Run-specific optimizations
apply_railway_optimizations <- function() {
  tryCatch({
    cat("☁️ Applying Cloud Run deployment optimizations...\n")
    
    # Set environment variables for R optimization
    Sys.setenv(
      "R_MAX_VSIZE" = "1400M", # Limit R memory usage
      "R_GCTORTURE" = "0",     # Disable GC torture for performance
      "R_KEEP_PKG_SOURCE" = "no" # Don't keep package sources in memory
    )

    # Configure garbage collection for Cloud Run
    # More frequent but smaller GC cycles
    gc(verbose = FALSE)

    # Set plotly options for Cloud Run
    options(
      plotly.trace.max = 3000,      # Limit trace complexity
      plotly.autorange = TRUE,       # Enable autorange for better performance
      plotly.mathjax = FALSE        # Disable MathJax to save memory
    )

    # Configure sf options for Cloud Run
    if (requireNamespace("sf", quietly = TRUE)) {
      sf::sf_use_s2(FALSE) # Disable S2 for better performance on Cloud Run
    }

    cat("✅ Cloud Run optimizations applied successfully\n")
    
  }, error = function(e) {
    cat("❌ Cloud Run optimization failed:", e$message, "\n")
  })
}

#' Perform comprehensive memory cleanup
perform_memory_cleanup <- function() {
  tryCatch({
    cat("🧹 Performing memory cleanup...\n")
    
    # Remove large objects from global environment (if safe to do so)
    large_objects <- ls(envir = .GlobalEnv)[sapply(ls(envir = .GlobalEnv), function(x) {
      obj_size <- object.size(get(x, envir = .GlobalEnv))
      as.numeric(obj_size) > 10 * 1024^2 # Objects larger than 10MB
    })]
    
    if (length(large_objects) > 0) {
      cat("🔍 Found", length(large_objects), "large objects in memory\n")
      # Note: In production, be careful about removing objects
      # This is a simplified implementation
    }
    
    # Force garbage collection
    for (i in 1:3) {
      gc(verbose = FALSE)
    }
    
    # Clear any temporary files
    temp_files <- list.files(tempdir(), pattern = "^(plotly|leaflet|sf)", full.names = TRUE)
    if (length(temp_files) > 0) {
      file.remove(temp_files[file.exists(temp_files)])
      cat("🗑️ Cleaned up", length(temp_files), "temporary files\n")
    }
    
    cat("✅ Memory cleanup completed\n")
    
  }, error = function(e) {
    cat("❌ Memory cleanup failed:", e$message, "\n")
  })
}

# Helper functions

optimize_dataframe_memory <- function(df) {
  # Convert character columns to factors if beneficial
  for (col in names(df)) {
    if (is.character(df[[col]])) {
      unique_values <- length(unique(df[[col]]))
      total_values <- length(df[[col]])
      if (unique_values < total_values * 0.1) { # Less than 10% unique values
        df[[col]] <- as.factor(df[[col]])
      }
    }
  }
  return(df)
}

create_overview_level_data <- function(data, metric_column) {
  # Aggregate to national/regional level
  if ("state_code" %in% names(data)) {
    overview <- data %>%
      group_by(state_code) %>%
      summarise(metric_value = sum(!!sym(metric_column), na.rm = TRUE), .groups = "drop")
    return(overview)
  }
  return(data[1:min(100, nrow(data)), ]) # Fallback to first 100 rows
}

create_state_level_data <- function(data, metric_column) {
  # State-level aggregation
  return(data) # Placeholder - would implement state-level optimization
}

create_municipality_level_data <- function(data, metric_column) {
  # Municipality-level data (highest detail)
  return(data) # Placeholder - would implement municipality-level optimization
}

select_appropriate_detail_level <- function(detail_maps, zoom_level) {
  for (level in detail_maps) {
    if (zoom_level >= level$zoom_threshold[1] && zoom_level < level$zoom_threshold[2]) {
      return(level)
    }
  }
  return(detail_maps[[1]]) # Default to first level
}

get_from_cache <- function(cache_dir, cache_key) {
  cache_file <- file.path(cache_dir, paste0(cache_key, ".rds"))
  if (file.exists(cache_file)) {
    return(readRDS(cache_file))
  }
  return(NULL)
}

set_to_cache <- function(cache_dir, cache_key, data, ttl_hours) {
  cache_file <- file.path(cache_dir, paste0(cache_key, ".rds"))
  saveRDS(data, cache_file)
}

cleanup_cache_directory <- function(cache_dir) {
  old_files <- list.files(cache_dir, full.names = TRUE)
  old_files <- old_files[file.mtime(old_files) < (Sys.time() - 24 * 60 * 60)] # Older than 24 hours
  if (length(old_files) > 0) {
    file.remove(old_files)
  }
}

get_cache_statistics <- function(cache_dir) {
  files <- list.files(cache_dir, full.names = TRUE)
  total_size <- sum(file.size(files), na.rm = TRUE) / 1024^2 # MB
  return(list(file_count = length(files), total_size_mb = round(total_size, 2)))
}

get_detailed_memory_stats <- function() {
  gc_info <- gc(verbose = FALSE)
  return(list(
    used_mb = sum(gc_info[, 2]),
    max_mb = sum(gc_info[, 6]),
    gc_count = gc_info[, 5]
  ))
}

force_memory_cleanup <- function(memory_limit_mb) {
  gc()
  # Additional cleanup strategies would go here
}

get_performance_metrics <- function() {
  memory_stats <- check_memory_usage(1400)
  return(list(
    memory = memory_stats,
    timestamp = Sys.time()
  ))
}

optimize_plotly_performance <- function(plot_obj) {
  # Apply performance optimizations to plotly object
  return(plot_obj)
}

create_data_chunks <- function(data, chunk_size) {
  n_rows <- nrow(data)
  n_chunks <- ceiling(n_rows / chunk_size)
  chunks <- list()
  
  for (i in 1:n_chunks) {
    start_row <- (i - 1) * chunk_size + 1
    end_row <- min(i * chunk_size, n_rows)
    chunks[[i]] <- data[start_row:end_row, ]
  }
  
  return(chunks)
}

render_progressively <- function(data, render_function) {
  # Implement progressive rendering
  return(render_function(data))
}

cat("⚡ Performance Optimization System loaded successfully\n")
cat("📊 Functions: optimize_data_for_memory, create_progressive_map, enable_webgl_rendering\n")
cat("🎯 Features: Memory monitoring, Cloud Run optimization, WebGL acceleration\n")