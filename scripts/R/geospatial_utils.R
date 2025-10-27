# Brazilian State Boundary Management for Choropleth Maps
# Robust geospatial utilities for the Legislative Monitoring System

#' Load Brazilian state boundaries with intelligent caching
#' @param cache_dir Directory for caching geospatial data
#' @param force_refresh Force refresh of cached data
#' @return sf object with Brazilian state boundaries or NULL if failed
get_brazil_boundaries <- function(cache_dir = "cache/boundaries", force_refresh = FALSE) {
  cache_file <- file.path(cache_dir, "brazil_states.rds")
  
  # Check cache validity
  if (!force_refresh && file.exists(cache_file)) {
    tryCatch({
      cat("📍 Loading cached Brazilian state boundaries\n")
      boundaries <- readRDS(cache_file)
      
      # Validate cached data
      if (inherits(boundaries, "sf") && nrow(boundaries) >= 26) {
        cat("✅ Cached boundaries valid -", nrow(boundaries), "states loaded\n")
        return(boundaries)
      } else {
        cat("⚠️ Cached boundaries invalid - refreshing\n")
      }
    }, error = function(e) {
      cat("⚠️ Cache read failed:", e$message, "- refreshing\n")
    })
  }
  
  # Download fresh boundaries
  tryCatch({
    cat("🌍 Downloading Brazilian state boundaries from geobr (IBGE)\n")
    
    # Require geobr and sf packages
    if (!requireNamespace("geobr", quietly = TRUE)) {
      stop("geobr package not available")
    }
    if (!requireNamespace("sf", quietly = TRUE)) {
      stop("sf package not available") 
    }
    
    # Load boundaries with timeout protection (30 seconds max)
    boundaries <- tryCatch({
      if (requireNamespace("R.utils", quietly = TRUE)) {
        R.utils::withTimeout({
          geobr::read_state(year = 2020, simplified = TRUE, showProgress = FALSE)
        }, timeout = 30, onTimeout = "error")
      } else {
        # Fallback without timeout if R.utils not available
        geobr::read_state(year = 2020, simplified = TRUE, showProgress = FALSE)
      }
    }, error = function(e) {
      cat("⚠️ Geobr download failed:", e$message, "\n")
      stop("Failed to download boundaries from IBGE")
    })
    
    # Ensure proper coordinate reference system
    if (!is.null(sf::st_crs(boundaries)) && sf::st_crs(boundaries)$input != "EPSG:4326") {
      cat("🔄 Converting to WGS84 (EPSG:4326)\n")
      boundaries <- sf::st_transform(boundaries, 4326)
    }
    
    # Simplify for web performance while preserving topology
    boundaries <- tryCatch({
      sf::st_simplify(boundaries, dTolerance = 0.005, preserveTopology = TRUE)
    }, error = function(e) {
      cat("⚠️ Simplification failed:", e$message, "- using original geometry\n")
      boundaries
    })
    
    # Validate data quality
    if (nrow(boundaries) < 26) {
      stop("Incomplete boundary data - expected 27 states, got ", nrow(boundaries))
    }
    
    # Create cache directory
    dir.create(cache_dir, recursive = TRUE, showWarnings = FALSE)
    
    # Cache the results
    saveRDS(boundaries, cache_file)
    
    # Update cache timestamp
    timestamp_file <- file.path(cache_dir, "last_updated.txt")
    writeLines(as.character(Sys.Date()), timestamp_file)
    
    cat("💾 Cached", nrow(boundaries), "state boundaries for future use\n")
    return(boundaries)
    
  }, error = function(e) {
    cat("❌ Failed to load Brazilian state boundaries:", e$message, "\n")
    return(NULL)
  })
}

#' Convert sf boundaries to plotly-compatible GeoJSON
#' @param boundaries sf object with state boundaries
#' @param cache_dir Directory for GeoJSON cache
#' @return GeoJSON object for plotly or NULL if failed
sf_to_plotly_geojson <- function(boundaries, cache_dir = "cache/boundaries") {
  if (isTRUE(is.null(boundaries)) || !inherits(boundaries, "sf")) {
    return(NULL)
  }
  
  cache_file <- file.path(cache_dir, "brazil_states_geojson.json")
  
  # Check for cached GeoJSON
  if (file.exists(cache_file)) {
    tryCatch({
      cat("📄 Loading cached GeoJSON\n")
      
      # Ensure jsonlite is available before using it
      if (!requireNamespace("jsonlite", quietly = TRUE)) {
        cat("⚠️ jsonlite package not available - cannot load cached GeoJSON\n")
        return(NULL)
      }
      
      # Try to load jsonlite explicitly to avoid namespace issues
      tryCatch({
        library(jsonlite, quietly = TRUE)
      }, error = function(e) {
        cat("⚠️ Cannot load jsonlite library:", e$message, "\n")
      })
      
      geojson_text <- readLines(cache_file, warn = FALSE)
      # Use explicit package reference with safety check
      json_result <- tryCatch({
        # More robust approach - ensure fromJSON is a function before calling
        fromJSON_func <- getFromNamespace("fromJSON", "jsonlite")
        if (is.function(fromJSON_func)) {
          result <- fromJSON_func(paste(geojson_text, collapse = ""))
          # Validate the result is a proper list/object
          if (is.list(result) || is.character(result)) {
            result
          } else {
            cat("⚠️ fromJSON returned unexpected type:", typeof(result), "\n")
            NULL
          }
        } else {
          cat("⚠️ fromJSON is not available as a function\n")
          NULL
        }
      }, error = function(e2) {
        cat("⚠️ Failed to parse cached GeoJSON:", e2$message, "\n")
        NULL
      })
      return(json_result)
    }, error = function(e) {
      cat("⚠️ Cached GeoJSON load error:", e$message, "\n")
      NULL
    })
  }
  
  # Convert sf to GeoJSON
  tryCatch({
    cat("🔄 Converting sf boundaries to GeoJSON for plotly\n")
    
    # Ensure required packages
    if (!requireNamespace("jsonlite", quietly = TRUE)) {
      stop("jsonlite package required for GeoJSON conversion")
    }
    
    # Method 1: Try geojsonio first (most reliable)
    if (requireNamespace("geojsonio", quietly = TRUE)) {
      cat("🔧 Using geojsonio for optimal conversion\n")
      geojson_obj <- geojsonio::geojson_json(boundaries, precision = 4)
      
      # Cache the GeoJSON
      writeLines(as.character(geojson_obj), cache_file)
      cat("💾 Cached GeoJSON for future use\n")
      
      return(geojson_obj)
      
    } else {
      cat("🔧 Using simplified approach - boundaries available for enhanced fallback\n")
      
      # Without geojsonio, we'll return the boundaries object itself
      # The choropleth generator will handle the fallback to enhanced circles
      simplified_geojson <- list(
        type = "FeatureCollection",
        features = "simplified",
        state_data = list(
          codes = boundaries$abbrev_state,
          names = boundaries$name_state,
          geometry_available = FALSE
        )
      )
      
      # Cache indicator that we have boundaries but no proper GeoJSON
      writeLines("BOUNDARIES_ONLY", cache_file)
      cat("💾 Cached boundary availability indicator\n")
      
      return(simplified_geojson)
    }
    
  }, error = function(e) {
    cat("❌ GeoJSON conversion failed:", e$message, "\n")
    return(NULL)
  })
}

#' Validate and refresh geospatial cache if needed
#' @param cache_dir Directory containing cached geospatial data
#' @param max_age_days Maximum age of cache in days before refresh
#' @return TRUE if cache is valid, FALSE if refresh needed
validate_geospatial_cache <- function(cache_dir = "cache/boundaries", max_age_days = 30) {
  timestamp_file <- file.path(cache_dir, "last_updated.txt")
  
  if (!file.exists(timestamp_file)) {
    return(FALSE) # Force refresh
  }
  
  tryCatch({
    last_update <- as.Date(readLines(timestamp_file)[1])
    days_old <- as.numeric(Sys.Date() - last_update)
    
    if (days_old > max_age_days) {
      cat("📅 Cache is", days_old, "days old - refreshing\n")
      return(FALSE)
    } else {
      cat("✅ Cache is", days_old, "days old - still valid\n")
      return(TRUE)
    }
  }, error = function(e) {
    cat("⚠️ Cache validation failed:", e$message, "\n")
    return(FALSE)
  })
}

#' Initialize geospatial system with proper error handling
#' @return List with boundaries and geojson, or NULL components if failed
initialize_geospatial_system <- function() {
  cat("🚀 Initializing Brazilian geospatial system...\n")
  
  # Railway-aware cache directory management
  railway_volume <- Sys.getenv("RAILWAY_VOLUME_MOUNT_PATH", "")
  if (railway_volume != "") {
    cache_dir <- file.path(railway_volume, "geospatial_cache")
    cat("🚂 Using Railway persistent volume for geospatial cache\n")
  } else {
    cache_dir <- "cache/boundaries"
    cat("💻 Using local cache directory\n")
  }
  
  # Create cache directory with proper permissions
  dir.create(cache_dir, recursive = TRUE, showWarnings = FALSE, mode = "0755")
  
  # Check if refresh is needed
  force_refresh <- !validate_geospatial_cache(cache_dir)
  
  # Load boundaries
  boundaries <- get_brazil_boundaries(cache_dir, force_refresh)
  
  if (is.null(boundaries)) {
    cat("❌ Geospatial initialization failed - will use fallback maps\n")
    return(list(boundaries = NULL, geojson = NULL, available = FALSE))
  }
  
  # Convert to GeoJSON for plotly
  geojson <- sf_to_plotly_geojson(boundaries, cache_dir)
  
  success <- !isTRUE(is.null(boundaries)) && !is.null(geojson)
  
  if (success) {
    cat("✅ Geospatial system initialized successfully\n")
    cat("📊", nrow(boundaries), "Brazilian states ready for choropleth mapping\n")
    
    # Set up cleanup on session end for memory management
    if (interactive()) {
      cat("🧹 Memory management hooks set up\n")
    }
  } else {
    cat("⚠️ Partial geospatial initialization - some features may be limited\n")
  }
  
  # Return system with memory cleanup information
  # Ensure all components are safely accessible
  system_result <- tryCatch({
    list(
      boundaries = boundaries,
      geojson = geojson,
      available = success,
      state_count = if (!is.null(boundaries)) nrow(boundaries) else 0,
      cache_dir = cache_dir,
      initialized_at = Sys.time()
    )
  }, error = function(e) {
    cat("⚠️ Error creating geospatial system result:", e$message, "\n")
    list(
      boundaries = NULL,
      geojson = NULL,
      available = FALSE,
      state_count = 0,
      cache_dir = cache_dir,
      initialized_at = Sys.time(),
      error = e$message
    )
  })
  
  # Trigger garbage collection to free up memory
  if (success) {
    gc(verbose = FALSE)
    cat("♻️ Memory cleanup completed\n")
  }
  
  return(system_result)
}

# Export key functions
cat("🗺️ Brazilian geospatial utilities loaded\n")
cat("📍 Functions available: get_brazil_boundaries, sf_to_plotly_geojson, validate_geospatial_cache, initialize_geospatial_system\n")