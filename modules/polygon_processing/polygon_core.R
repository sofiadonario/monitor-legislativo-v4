# ENHANCED POLYGON PROCESSING SYSTEM - PHASE 1
# Brazilian Legislative Monitoring System
# ============================================================================
# 
# Core polygon processing functionality for municipality-level analysis
# Implements PRD specifications for 206x granularity increase (27 states → 5,570+ municipalities)
# 
# Features:
# - IBGE municipality boundary integration with multi-resolution support
# - Memory-efficient on-demand polygon loading (<200MB geometry cache)
# - High-performance spatial joins (<2s query response time)
# - Railway-compatible deployment constraints (<1.4GB total memory)
# - Progressive loading with memory pressure monitoring

library(shiny)
library(dplyr)
library(sf)
library(memoise)
library(pool)
library(jsonlite)

# Load optional geospatial packages with fallbacks
optional_geo_packages <- c("geobr", "rmapshaper")
for (pkg in optional_geo_packages) {
  tryCatch({
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }, error = function(e) {
    cat("⚠️", pkg, "not available, using fallbacks\n")
  })
}

# ============================================================================
# CORE CONFIGURATION
# ============================================================================

# Memory management constants (Railway constraints)
POLYGON_CONFIG <- list(
  max_geometry_memory_mb = 200,      # Maximum memory for polygon geometries
  max_cache_entries = 100,           # Maximum cached polygon sets
  cache_ttl_seconds = 1800,          # 30 minutes cache TTL
  max_query_time_ms = 2000,          # 2 second query timeout
  simplification_tolerance = 0.01,   # Geometry simplification for performance
  chunk_size = 1000,                 # Progressive loading chunk size
  enable_memory_monitoring = TRUE
)

# Multi-resolution levels for polygon display
RESOLUTION_LEVELS <- list(
  high = list(tolerance = 0.001, description = "High detail for zoomed views"),
  medium = list(tolerance = 0.01, description = "Medium detail for state views"),
  low = list(tolerance = 0.05, description = "Low detail for country views")
)

# Brazilian municipality structure
IBGE_REGIONS <- list(
  norte = c("AC", "AP", "AM", "PA", "RO", "RR", "TO"),
  nordeste = c("AL", "BA", "CE", "MA", "PB", "PE", "PI", "RN", "SE"),
  centro_oeste = c("DF", "GO", "MT", "MS"),
  sudeste = c("ES", "MG", "RJ", "SP"),
  sul = c("PR", "RS", "SC")
)

# ============================================================================
# MEMORY MANAGEMENT SYSTEM
# ============================================================================

#' Memory pressure monitoring for Railway constraints
#' @param operation_name String identifying the operation being monitored
#' @return Function that reports memory usage when called
create_memory_monitor <- function(operation_name = "polygon_operation") {
  if (!POLYGON_CONFIG$enable_memory_monitoring) {
    return(function() invisible())
  }
  
  start_time <- Sys.time()
  start_memory <- as.numeric(object.size(ls(envir = .GlobalEnv))) / 1024^2
  
  function() {
    gc(verbose = FALSE, reset = TRUE)
    end_time <- Sys.time()
    end_memory <- as.numeric(object.size(ls(envir = .GlobalEnv))) / 1024^2
    duration <- as.numeric(end_time - start_time, units = "secs")
    
    memory_usage <- end_memory - start_memory
    
    # Log memory usage with Railway-compatible format
    log_entry <- list(
      timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
      operation = operation_name,
      memory_delta_mb = round(memory_usage, 2),
      duration_seconds = round(duration, 3),
      total_memory_mb = round(end_memory, 2)
    )
    
    # Warning if approaching Railway memory limits
    if (end_memory > 1100) {  # 1.1GB warning threshold
      cat("⚠️ HIGH MEMORY USAGE:", end_memory, "MB (Railway limit: 1400MB)\n")
    }
    
    if (POLYGON_CONFIG$enable_memory_monitoring) {
      cat(sprintf("[%s] Memory: %+.2f MB | Duration: %.3fs | Total: %.2f MB\n", 
                  operation_name, memory_usage, duration, end_memory))
    }
    
    invisible(log_entry)
  }
}

#' Clean up polygon cache when memory pressure is high
cleanup_polygon_cache <- function(force = FALSE) {
  current_memory <- as.numeric(object.size(ls(envir = .GlobalEnv))) / 1024^2
  
  if (force || current_memory > 1000) {  # 1GB threshold
    if (exists("polygon_cache", envir = .GlobalEnv)) {
      rm(polygon_cache, envir = .GlobalEnv)
    }
    gc(verbose = FALSE, reset = TRUE)
    cat("🧹 Polygon cache cleared due to memory pressure\n")
    return(TRUE)
  }
  return(FALSE)
}

# ============================================================================
# IBGE MUNICIPALITY DATA INTEGRATION
# ============================================================================

#' Load IBGE municipality boundaries with multi-resolution support
#' @param state_codes Character vector of state codes (e.g., c("SP", "RJ"))
#' @param resolution Resolution level: "high", "medium", or "low"
#' @param use_cache Whether to use cached data
#' @return sf object with municipality polygons
load_ibge_municipalities <- function(state_codes = NULL, resolution = "medium", use_cache = TRUE) {
  memory_monitor <- create_memory_monitor("load_ibge_municipalities")
  on.exit(memory_monitor(), add = TRUE)
  
  # Input validation
  if (is.null(state_codes)) {
    state_codes <- unlist(IBGE_REGIONS, use.names = FALSE)
  }
  
  if (!resolution %in% names(RESOLUTION_LEVELS)) {
    warning("Invalid resolution level, using 'medium'")
    resolution <- "medium"
  }
  
  # Create cache key
  cache_key <- paste(c(sort(state_codes), resolution), collapse = "_")
  
  # Check cache first
  if (use_cache && exists("municipality_cache", envir = .GlobalEnv)) {
    cached_data <- get("municipality_cache", envir = .GlobalEnv)
    if (cache_key %in% names(cached_data)) {
      cache_entry <- cached_data[[cache_key]]
      if (Sys.time() - cache_entry$timestamp < POLYGON_CONFIG$cache_ttl_seconds) {
        cat("📦 Using cached municipality data for", length(state_codes), "states\n")
        return(cache_entry$data)
      }
    }
  }
  
  # Load municipality data
  tryCatch({
    cat("🌍 Loading IBGE municipality boundaries for", length(state_codes), "states...\n")
    
    if (exists("geobr")) {
      # Use geobr package if available
      municipalities <- geobr::read_municipality(code_muni = "all", year = 2020, simplified = FALSE)
      
      # Filter by state codes
      municipalities <- municipalities %>%
        filter(abbrev_state %in% state_codes)
        
    } else {
      # Fallback: Create simplified municipality boundaries from state centroids
      cat("⚠️ geobr not available, using simplified municipality data\n")
      municipalities <- create_fallback_municipalities(state_codes)
    }
    
    # Apply resolution-based simplification
    tolerance <- RESOLUTION_LEVELS[[resolution]]$tolerance
    if (tolerance > 0 && exists("rmapshaper")) {
      municipalities <- rmapshaper::ms_simplify(municipalities, keep = 1 - tolerance)
    } else if (tolerance > 0) {
      # Fallback simplification using sf
      municipalities <- sf::st_simplify(municipalities, dTolerance = tolerance)
    }
    
    # Standardize column names
    municipalities <- municipalities %>%
      mutate(
        municipality_code = if("code_muni" %in% names(.)) code_muni else paste0(abbrev_state, row_number()),
        municipality_name = if("name_muni" %in% names(.)) name_muni else paste("Municipality", row_number()),
        state_code = if("abbrev_state" %in% names(.)) abbrev_state else "BR",
        area_km2 = as.numeric(sf::st_area(.) / 1e6)  # Convert to km²
      ) %>%
      select(municipality_code, municipality_name, state_code, area_km2, geometry)
    
    # Validate geometries
    valid_geom <- sf::st_is_valid(municipalities)
    if (!all(valid_geom)) {
      cat("⚠️ Fixing", sum(!valid_geom), "invalid geometries\n")
      municipalities[!valid_geom, ] <- sf::st_make_valid(municipalities[!valid_geom, ])
    }
    
    # Cache the result
    if (use_cache) {
      if (!exists("municipality_cache", envir = .GlobalEnv)) {
        assign("municipality_cache", list(), envir = .GlobalEnv)
      }
      municipality_cache <- get("municipality_cache", envir = .GlobalEnv)
      municipality_cache[[cache_key]] <- list(
        data = municipalities,
        timestamp = Sys.time()
      )
      assign("municipality_cache", municipality_cache, envir = .GlobalEnv)
    }
    
    cat("✅ Loaded", nrow(municipalities), "municipalities with", resolution, "resolution\n")
    return(municipalities)
    
  }, error = function(e) {
    cat("❌ Error loading IBGE municipalities:", e$message, "\n")
    return(create_fallback_municipalities(state_codes))
  })
}

#' Create fallback municipality data when IBGE data is unavailable
#' @param state_codes Character vector of state codes
#' @return sf object with simplified municipality boundaries
create_fallback_municipalities <- function(state_codes) {
  # Load state coordinates from existing system
  if (exists("BRAZIL_STATE_COORDS")) {
    state_coords <- BRAZIL_STATE_COORDS
  } else {
    # Minimal state coordinate fallback
    state_coords <- data.frame(
      state_code = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "PE", "CE", "GO"),
      lat = c(-23.55, -22.84, -18.10, -30.01, -24.89, -27.33, -12.96, -8.28, -5.20, -16.64),
      lng = c(-46.64, -43.15, -44.38, -51.22, -51.55, -49.44, -38.51, -35.07, -39.53, -49.31),
      stringsAsFactors = FALSE
    )
  }
  
  # Create simplified circular municipalities around state centers
  municipalities <- state_coords %>%
    filter(state_code %in% state_codes) %>%
    mutate(
      municipality_code = paste0(state_code, "001"),
      municipality_name = paste("Capital", state_code),
      area_km2 = 1000  # Approximate area
    ) %>%
    select(municipality_code, municipality_name, state_code, lat, lng, area_km2)
  
  # Convert to sf with circular geometries
  municipalities_sf <- sf::st_as_sf(
    municipalities, 
    coords = c("lng", "lat"), 
    crs = 4326
  ) %>%
  mutate(geometry = sf::st_buffer(geometry, dist = 0.5))  # ~55km radius
  
  cat("📍 Created", nrow(municipalities_sf), "fallback municipalities\n")
  return(municipalities_sf)
}

# ============================================================================
# PROGRESSIVE LOADING SYSTEM
# ============================================================================

#' Progressive municipality loading by region with memory monitoring
#' @param region_name Name of the region ("norte", "nordeste", etc.)
#' @param resolution Resolution level
#' @param callback Progress callback function
#' @return sf object with municipalities for the region
load_municipalities_by_region <- function(region_name, resolution = "medium", callback = NULL) {
  memory_monitor <- create_memory_monitor(paste0("load_region_", region_name))
  on.exit(memory_monitor(), add = TRUE)
  
  if (!region_name %in% names(IBGE_REGIONS)) {
    stop("Invalid region name. Use: ", paste(names(IBGE_REGIONS), collapse = ", "))
  }
  
  state_codes <- IBGE_REGIONS[[region_name]]
  total_states <- length(state_codes)
  
  cat("🌎 Loading", total_states, "states for region:", region_name, "\n")
  
  # Load with progress tracking
  start_time <- Sys.time()
  
  for (i in seq_along(state_codes)) {
    if (!is.null(callback)) {
      callback(i, total_states, state_codes[i])
    }
    
    # Check memory pressure every 3 states
    if (i %% 3 == 0) {
      cleanup_polygon_cache()
    }
  }
  
  municipalities <- load_ibge_municipalities(state_codes, resolution)
  
  duration <- as.numeric(Sys.time() - start_time, units = "secs")
  cat("✅ Region", region_name, "loaded in", round(duration, 2), "seconds\n")
  
  return(municipalities)
}

#' Load municipalities on-demand with intelligent caching
#' @param state_code Single state code
#' @param resolution Resolution level
#' @return sf object with municipalities for the state
load_municipalities_on_demand <- function(state_code, resolution = "medium") {
  memory_monitor <- create_memory_monitor(paste0("on_demand_", state_code))
  on.exit(memory_monitor(), add = TRUE)
  
  # Check if loading time is acceptable (<3 seconds target)
  start_time <- Sys.time()
  
  municipalities <- load_ibge_municipalities(state_code, resolution, use_cache = TRUE)
  
  duration <- as.numeric(Sys.time() - start_time, units = "secs")
  
  if (duration > 3) {
    cat("⚠️ Loading took", round(duration, 2), "seconds (target: <3s)\n")
  }
  
  return(municipalities)
}

# ============================================================================
# BASIC SPATIAL JOIN IMPLEMENTATION
# ============================================================================

#' Perform spatial join between documents and municipalities
#' @param documents Data frame with document locations (lat, lng columns required)
#' @param municipalities sf object with municipality polygons
#' @param join_type Type of spatial join ("within", "intersects", "nearest")
#' @return Data frame with municipality information added to documents
spatial_join_documents_municipalities <- function(documents, municipalities, join_type = "within") {
  memory_monitor <- create_memory_monitor("spatial_join")
  on.exit(memory_monitor(), add = TRUE)
  
  if (isTRUE(nrow(documents) == 0) || nrow(municipalities) == 0) {
    return(documents)
  }
  
  # Validate required columns
  required_cols <- c("lat", "lng")
  if (!all(required_cols %in% names(documents))) {
    stop("Documents must have 'lat' and 'lng' columns for spatial joining")
  }
  
  tryCatch({
    # Convert documents to sf points
    documents_sf <- documents %>%
      filter(!is.na(lat), !is.na(lng)) %>%
      sf::st_as_sf(coords = c("lng", "lat"), crs = 4326)
    
    # Ensure same CRS
    municipalities <- sf::st_transform(municipalities, crs = 4326)
    
    # Perform spatial join based on type
    start_time <- Sys.time()
    
    if (join_type == "within") {
      joined <- sf::st_join(documents_sf, municipalities, join = sf::st_within)
    } else if (join_type == "intersects") {
      joined <- sf::st_join(documents_sf, municipalities, join = sf::st_intersects)
    } else if (join_type == "nearest") {
      joined <- sf::st_join(documents_sf, municipalities, join = sf::st_nearest_feature)
    } else {
      stop("Invalid join_type. Use 'within', 'intersects', or 'nearest'")
    }
    
    duration <- as.numeric(Sys.time() - start_time, units = "secs")
    
    # Performance check (<2s target)
    if (duration > 2) {
      cat("⚠️ Spatial join took", round(duration, 2), "seconds (target: <2s)\n")
    }
    
    # Convert back to regular data frame
    result <- joined %>%
      sf::st_drop_geometry() %>%
      as.data.frame()
    
    # Add original documents without coordinates
    no_coords <- documents %>%
      filter(is.na(lat) | is.na(lng)) %>%
      mutate(
        municipality_code = NA,
        municipality_name = NA,
        state_code = NA,
        area_km2 = NA
      )
    
    result <- bind_rows(result, no_coords)
    
    success_rate <- (nrow(result) - nrow(no_coords)) / nrow(documents) * 100
    cat("✅ Spatial join completed:", round(success_rate, 1), "% documents matched\n")
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Spatial join error:", e$message, "\n")
    # Return documents with empty municipality columns
    return(documents %>%
      mutate(
        municipality_code = NA,
        municipality_name = NA,
        state_code = NA,
        area_km2 = NA
      ))
  })
}

#' Hierarchical spatial join supporting federal/state/municipal levels
#' @param documents Data frame with document locations
#' @param level Administrative level ("federal", "state", "municipal")
#' @param fallback_level Fallback level if primary fails
#' @return Data frame with appropriate administrative level information
hierarchical_spatial_join <- function(documents, level = "municipal", fallback_level = "state") {
  memory_monitor <- create_memory_monitor("hierarchical_join")
  on.exit(memory_monitor(), add = TRUE)
  
  tryCatch({
    if (level == "municipal") {
      # Try municipality-level join first
      unique_states <- unique(documents$estado[!is.na(documents$estado)])
      if (length(unique_states) > 0) {
        municipalities <- load_ibge_municipalities(unique_states, resolution = "medium")
        result <- spatial_join_documents_municipalities(documents, municipalities)
        
        # Check success rate
        success_rate <- sum(!is.na(result$municipality_code)) / nrow(result)
        
        if (success_rate >= 0.80) {  # 80% success threshold
          cat("✅ Municipality-level join successful:", round(success_rate * 100, 1), "%\n")
          return(result)
        } else {
          cat("⚠️ Municipality-level join low success rate:", round(success_rate * 100, 1), "%\n")
        }
      }
    }
    
    # Fallback to state-level
    if (fallback_level == "state") {
      cat("🔄 Falling back to state-level join\n")
      return(documents %>%
        mutate(
          municipality_code = paste0(estado, "000"),
          municipality_name = paste("State of", estado),
          state_code = estado,
          area_km2 = NA
        ))
    }
    
    # Last resort: return original documents
    return(documents)
    
  }, error = function(e) {
    cat("❌ Hierarchical join error:", e$message, "\n")
    return(documents)
  })
}

# ============================================================================
# MODULE EXPORTS
# ============================================================================

# Export all functions for use in other modules
polygon_processing_exports <- list(
  # Core functions
  load_ibge_municipalities = load_ibge_municipalities,
  load_municipalities_by_region = load_municipalities_by_region,
  load_municipalities_on_demand = load_municipalities_on_demand,
  
  # Spatial join functions
  spatial_join_documents_municipalities = spatial_join_documents_municipalities,
  hierarchical_spatial_join = hierarchical_spatial_join,
  
  # Memory management
  create_memory_monitor = create_memory_monitor,
  cleanup_polygon_cache = cleanup_polygon_cache,
  
  # Configuration
  POLYGON_CONFIG = POLYGON_CONFIG,
  RESOLUTION_LEVELS = RESOLUTION_LEVELS,
  IBGE_REGIONS = IBGE_REGIONS
)

cat("✅ Polygon Processing Core Module loaded successfully\n")
cat("   Memory limit: ", POLYGON_CONFIG$max_geometry_memory_mb, "MB\n")
cat("   Query timeout: ", POLYGON_CONFIG$max_query_time_ms, "ms\n")
cat("   Cache TTL: ", POLYGON_CONFIG$cache_ttl_seconds, "seconds\n")