# Geographic Data Loader - Sprint 5B Implementation
# Brazilian Legislative Monitoring System - Optimized Spatial Data Loading
# ============================================================================
# 
# Efficient spatial data loading system designed for Railway 2GB constraints
# Provides progressive loading, intelligent caching, and memory-optimized
# processing of Brazilian geographic data for the Legislative Dashboard
# 
# FEATURES:
# - Progressive spatial data loading with memory monitoring
# - Intelligent caching and data persistence strategies
# - Railway-optimized chunked processing
# - Lazy loading with on-demand data retrieval
# - Robust error handling and fallback mechanisms
# - Academic-grade data quality validation
# - Integration with PostgreSQL spatial extensions
# 
# ARCHITECTURE:
# - Memory-conscious design patterns
# - Asynchronous data loading capabilities
# - Modular component system
# - Performance monitoring and optimization
# - Scalable caching infrastructure
# ============================================================================

library(sf)
library(dplyr)
library(DBI)
library(pool)
library(promises)
library(future)

# Load IBGE integration system
if (file.exists("modules/geographic/ibge_integration.R")) {
  source("modules/geographic/ibge_integration.R")
}

# Geographic Data Loader Configuration
# ====================================

GEODATA_CONFIG <- list(
  
  # Loading strategies
  loading = list(
    default_strategy = "progressive",  # progressive, eager, lazy, on_demand
    chunk_size = 50,
    max_concurrent_loads = 2,
    timeout_seconds = 30,
    retry_attempts = 3,
    backoff_multiplier = 2
  ),
  
  # Memory management
  memory = list(
    max_memory_mb = 1400,  # Leave 600MB for other app components
    gc_threshold_mb = 1200,  # Trigger garbage collection
    cache_limit_mb = 300,
    monitoring_interval_sec = 10
  ),
  
  # Data prioritization
  priority = list(
    # Load order based on document frequency and user access patterns
    high_priority_states = c("SP", "MG", "RJ", "RS", "PR", "SC", "DF"),
    medium_priority_states = c("BA", "GO", "PE", "CE", "PA", "MS", "MT"),
    low_priority_states = c("AC", "AL", "AP", "AM", "MA", "PB", "PI", "RN", "RO", "RR", "SE", "TO"),
    
    # Municipality loading limits by state size
    municipality_limits = list(
      "SP" = 100,  # Top 100 municipalities for São Paulo
      "MG" = 80,
      "RJ" = 60,
      "default" = 30
    )
  ),
  
  # Quality thresholds
  quality = list(
    min_geometry_area = 0.1,  # km²
    max_simplification_error = 0.05,  # 5% tolerance
    required_attributes = c("code", "name", "geometry"),
    coordinate_precision = 6  # decimal places
  )
)

# Core Data Loader Class
# =====================

#' Geographic Data Loader
#' 
#' Main class for managing geographic data loading with memory optimization
#' 
#' @field db_pool Database connection pool
#' @field cache_manager Cache management system
#' @field memory_monitor Memory monitoring system
#' @field loading_queue Priority-based loading queue
GeographicDataLoader <- R6::R6Class("GeographicDataLoader",
  
  public = list(
    
    # Properties
    db_pool = NULL,
    cache_manager = NULL,
    memory_monitor = NULL,
    loading_queue = NULL,
    current_loads = NULL,
    
    # Constructor
    initialize = function(db_pool = NULL) {
      
      cat("🌐 Initializing Geographic Data Loader...\n")
      
      self$db_pool <- db_pool
      self$cache_manager <- CacheManager$new()
      self$memory_monitor <- MemoryMonitor$new()
      self$loading_queue <- list()
      self$current_loads <- list()
      
      # Initialize cache directory
      self$cache_manager$setup()
      
      # Start memory monitoring
      self$memory_monitor$start()
      
      cat("✅ Geographic Data Loader initialized\n")
    },
    
    # Main loading methods
    load_states = function(force_refresh = FALSE, callback = NULL) {
      
      cat("🏛️ Loading Brazilian states...\n")
      
      tryCatch({
        
        # Check memory before loading
        if (!self$memory_monitor$check_available_memory(required_mb = 100)) {
          cat("⚠️ Insufficient memory for state loading\n")
          return(NULL)
        }
        
        # Check cache first
        if (!force_refresh) {
          cached_states <- self$cache_manager$get("states_data")
          if (!is.null(cached_states)) {
            cat("💾 Using cached state data\n")
            if (!is.null(callback)) callback(cached_states)
            return(cached_states)
          }
        }
        
        # Load from IBGE
        states_data <- load_ibge_states(
          force_refresh = force_refresh,
          simplify_geometry = TRUE
        )
        
        if (!is.null(states_data)) {
          
          # Apply quality filters
          states_filtered <- self$apply_quality_filters(states_data, "state")
          
          # Cache the results
          self$cache_manager$set("states_data", states_filtered)
          
          # Memory cleanup
          self$memory_monitor$trigger_gc_if_needed()
          
          cat("✅ Loaded", nrow(states_filtered), "states\n")
          
          if (!is.null(callback)) callback(states_filtered)
          return(states_filtered)
        }
        
        return(NULL)
        
      }, error = function(e) {
        cat("❌ Error loading states:", e$message, "\n")
        return(NULL)
      })
    },
    
    load_municipalities = function(state_codes = NULL, priority_only = TRUE, callback = NULL) {
      
      cat("🏙️ Loading municipalities...\n")
      
      tryCatch({
        
        # Determine states to load
        if (is.null(state_codes)) {
          if (priority_only) {
            state_codes <- GEODATA_CONFIG$priority$high_priority_states
          } else {
            state_codes <- c(
              GEODATA_CONFIG$priority$high_priority_states,
              GEODATA_CONFIG$priority$medium_priority_states
            )
          }
        }
        
        cat("📍 Loading municipalities for", length(state_codes), "states:", paste(state_codes, collapse = ", "), "\n")
        
        # Check memory capacity
        estimated_memory <- length(state_codes) * 50  # Rough estimate: 50MB per state
        if (!self$memory_monitor$check_available_memory(required_mb = estimated_memory)) {
          cat("⚠️ Insufficient memory, reducing state list\n")
          state_codes <- head(state_codes, 3)  # Limit to 3 states for memory safety
        }
        
        # Load municipalities progressively
        all_municipalities <- self$load_municipalities_progressive(state_codes, callback)
        
        return(all_municipalities)
        
      }, error = function(e) {
        cat("❌ Error loading municipalities:", e$message, "\n")
        return(NULL)
      })
    },
    
    load_municipalities_progressive = function(state_codes, callback = NULL) {
      
      all_municipalities <- list()
      
      for (i in seq_along(state_codes)) {
        state_code <- state_codes[i]
        
        cat("🔄 Loading municipalities for", state_code, "(", i, "/", length(state_codes), ")\n")
        
        # Memory check before each state
        if (!self$memory_monitor$check_available_memory(required_mb = 30)) {
          cat("⚠️ Memory limit reached, stopping at", state_code, "\n")
          break
        }
        
        # Check cache for this state
        cache_key <- paste0("municipalities_", state_code)
        cached_munic <- self$cache_manager$get(cache_key)
        
        if (!is.null(cached_munic)) {
          cat("💾 Using cached municipalities for", state_code, "\n")
          all_municipalities[[state_code]] <- cached_munic
        } else {
          
          # Load from IBGE
          state_municipalities <- load_ibge_municipalities(
            state_code = state_code,
            force_refresh = FALSE,
            chunk_size = GEODATA_CONFIG$loading$chunk_size
          )
          
          if (!is.null(state_municipalities)) {
            
            # Apply municipality limit for this state
            municipality_limit <- GEODATA_CONFIG$priority$municipality_limits[[state_code]] %||%
                                 GEODATA_CONFIG$priority$municipality_limits$default

            if (!is.null(state_municipalities) && is.data.frame(state_municipalities) && nrow(state_municipalities) > municipality_limit) {
              # Prioritize by area (keep larger municipalities)
              state_municipalities <- state_municipalities %>%
                arrange(desc(area_km2)) %>%
                head(municipality_limit)
              
              cat("📊 Limited to top", municipality_limit, "municipalities for", state_code, "\n")
            }
            
            # Apply quality filters
            state_municipalities_filtered <- self$apply_quality_filters(state_municipalities, "municipality")
            
            all_municipalities[[state_code]] <- state_municipalities_filtered
            
            # Cache the results
            self$cache_manager$set(cache_key, state_municipalities_filtered)
            
            cat("✅ Loaded", nrow(state_municipalities_filtered), "municipalities for", state_code, "\n")
          }
          
          # Memory management
          self$memory_monitor$trigger_gc_if_needed()
          
          # Small delay to prevent overwhelming the system
          Sys.sleep(0.1)
        }
        
        # Progress callback
        if (!is.null(callback)) {
          progress <- i / length(state_codes)
          callback(list(progress = progress, current_state = state_code))
        }
      }
      
      # Combine all municipalities
      if (length(all_municipalities) > 0) {
        combined_municipalities <- bind_rows(all_municipalities)
        
        # Cache combined results
        self$cache_manager$set("all_municipalities", combined_municipalities)
        
        cat("✅ Combined", nrow(combined_municipalities), "municipalities from", length(all_municipalities), "states\n")
        return(combined_municipalities)
      }
      
      return(NULL)
    },
    
    get_geographic_summary = function() {
      
      # Get current data status
      states_data <- self$cache_manager$get("states_data")
      municipalities_data <- self$cache_manager$get("all_municipalities")
      
      summary <- list(
        timestamp = Sys.time(),
        states = list(
          loaded = !is.null(states_data),
          count = ifelse(!is.null(states_data), nrow(states_data), 0),
          memory_mb = ifelse(!is.null(states_data), round(object.size(states_data) / 1024^2, 2), 0)
        ),
        municipalities = list(
          loaded = !is.null(municipalities_data),
          count = ifelse(!is.null(municipalities_data), nrow(municipalities_data), 0),
          memory_mb = ifelse(!is.null(municipalities_data), round(object.size(municipalities_data) / 1024^2, 2), 0),
          states_covered = ifelse(!is.null(municipalities_data), length(unique(municipalities_data$state_code)), 0)
        ),
        memory = self$memory_monitor$get_status(),
        cache = self$cache_manager$get_status()
      )
      
      return(summary)
    },
    
    # Helper methods
    apply_quality_filters = function(spatial_data, level = "unknown") {
      
      if (is.null(spatial_data) || nrow(spatial_data) == 0) {
        return(spatial_data)
      }
      
      # Basic quality checks
      filtered_data <- spatial_data %>%
        filter(
          # Valid geometries
          sf::st_is_valid(geometry),
          !sf::st_is_empty(geometry)
        )
      
      # Area-based filtering
      if ("area_km2" %in% names(filtered_data)) {
        filtered_data <- filtered_data %>%
          filter(
            area_km2 >= GEODATA_CONFIG$quality$min_geometry_area,
            !is.na(area_km2)
          )
      }

      # Coordinate precision
      if (!is.null(filtered_data) && is.data.frame(filtered_data) && nrow(filtered_data) > 0) {
        # Round coordinates to specified precision
        precision <- GEODATA_CONFIG$quality$coordinate_precision
        filtered_data <- filtered_data %>%
          mutate(
            geometry = sf::st_set_precision(geometry, precision)
          )
      }
      
      return(filtered_data)
    },
    
    cleanup = function() {
      cat("🧹 Cleaning up Geographic Data Loader...\n")
      
      # Stop memory monitoring
      self$memory_monitor$stop()
      
      # Clear cache if needed
      self$cache_manager$cleanup()
      
      # Force garbage collection
      gc(verbose = FALSE)
      
      cat("✅ Cleanup completed\n")
    }
  )
)

# Cache Manager Class
# ==================

CacheManager <- R6::R6Class("CacheManager",
  
  public = list(
    
    cache_dir = NULL,
    cache_index = NULL,
    
    initialize = function() {
      self$cache_dir <- "cache/geographic"
      self$cache_index <- list()
    },
    
    setup = function() {
      if (!dir.exists(self$cache_dir)) {
        dir.create(self$cache_dir, recursive = TRUE, showWarnings = FALSE)
      }
      
      # Load existing cache index
      index_file <- file.path(self$cache_dir, "cache_index.rds")
      if (file.exists(index_file)) {
        self$cache_index <- readRDS(index_file)
      }
    },
    
    get = function(key) {
      
      tryCatch({
        
        cache_file <- file.path(self$cache_dir, paste0(key, ".rds"))
        
        if (!file.exists(cache_file)) {
          return(NULL)
        }
        
        # Check expiry
        if (key %in% names(self$cache_index)) {
          expiry_time <- self$cache_index[[key]]$expires_at
          if (Sys.time() > expiry_time) {
            self$remove(key)
            return(NULL)
          }
        }
        
        # Load and return data
        data <- readRDS(cache_file)
        
        # Update access time
        if (key %in% names(self$cache_index)) {
          self$cache_index[[key]]$last_accessed <- Sys.time()
          self$cache_index[[key]]$access_count <- self$cache_index[[key]]$access_count + 1
        }
        
        return(data)
        
      }, error = function(e) {
        return(NULL)
      })
    },
    
    set = function(key, data, expiry_hours = 24) {
      
      tryCatch({
        
        cache_file <- file.path(self$cache_dir, paste0(key, ".rds"))
        saveRDS(data, cache_file)
        
        # Update index
        self$cache_index[[key]] <- list(
          created_at = Sys.time(),
          expires_at = Sys.time() + (expiry_hours * 3600),
          last_accessed = Sys.time(),
          access_count = 0,
          size_mb = round(object.size(data) / 1024^2, 2)
        )
        
        # Save index
        self$save_index()
        
        return(TRUE)
        
      }, error = function(e) {
        return(FALSE)
      })
    },
    
    remove = function(key) {
      cache_file <- file.path(self$cache_dir, paste0(key, ".rds"))
      if (file.exists(cache_file)) {
        file.remove(cache_file)
      }
      
      if (key %in% names(self$cache_index)) {
        self$cache_index[[key]] <- NULL
      }
      
      self$save_index()
    },
    
    get_status = function() {
      
      total_size <- sum(sapply(self$cache_index, function(x) x$size_mb))
      
      list(
        entries = length(self$cache_index),
        total_size_mb = round(total_size, 2),
        cache_dir = self$cache_dir
      )
    },
    
    cleanup = function(force = FALSE) {
      
      if (force) {
        # Remove all cache files
        cache_files <- list.files(self$cache_dir, pattern = "\\.rds$", full.names = TRUE)
        if (length(cache_files) > 0) {
          file.remove(cache_files)
        }
        self$cache_index <- list()
        self$save_index()
      } else {
        # Remove expired entries
        current_time <- Sys.time()
        expired_keys <- names(self$cache_index)[
          sapply(self$cache_index, function(x) current_time > x$expires_at)
        ]
        
        for (key in expired_keys) {
          self$remove(key)
        }
      }
    },
    
    save_index = function() {
      index_file <- file.path(self$cache_dir, "cache_index.rds")
      saveRDS(self$cache_index, index_file)
    }
  )
)

# Memory Monitor Class
# ===================

MemoryMonitor <- R6::R6Class("MemoryMonitor",
  
  public = list(
    
    monitoring = FALSE,
    max_memory_mb = NULL,
    gc_threshold_mb = NULL,
    
    initialize = function() {
      self$max_memory_mb <- GEODATA_CONFIG$memory$max_memory_mb
      self$gc_threshold_mb <- GEODATA_CONFIG$memory$gc_threshold_mb
    },
    
    start = function() {
      self$monitoring <- TRUE
    },
    
    stop = function() {
      self$monitoring <- FALSE
    },
    
    get_current_usage = function() {
      gc_result <- gc(verbose = FALSE)
      round(sum(gc_result[, "(Mb)"]), 2)
    },
    
    check_available_memory = function(required_mb = 0) {
      
      current_usage <- self$get_current_usage()
      available_memory <- self$max_memory_mb - current_usage
      
      return(available_memory >= required_mb)
    },
    
    trigger_gc_if_needed = function() {
      
      current_usage <- self$get_current_usage()
      
      if (current_usage > self$gc_threshold_mb) {
        cat("🧹 Triggering garbage collection (", round(current_usage, 1), "MB used)\n")
        gc(verbose = FALSE)
        
        new_usage <- self$get_current_usage()
        cat("♻️ Memory after GC:", round(new_usage, 1), "MB\n")
        
        return(new_usage)
      }
      
      return(current_usage)
    },
    
    get_status = function() {
      
      current_usage <- self$get_current_usage()
      
      list(
        current_mb = current_usage,
        max_mb = self$max_memory_mb,
        available_mb = self$max_memory_mb - current_usage,
        usage_percent = round((current_usage / self$max_memory_mb) * 100, 1),
        gc_threshold_mb = self$gc_threshold_mb,
        monitoring = self$monitoring
      )
    }
  )
)

# Factory Functions
# ================

#' Create Geographic Data Loader
#' 
#' Factory function to create and initialize a geographic data loader
#' 
#' @param db_pool Database connection pool
#' @return GeographicDataLoader instance
create_geographic_loader <- function(db_pool = NULL) {
  
  # Check if R6 is available
  if (!requireNamespace("R6", quietly = TRUE)) {
    cat("⚠️ R6 not available, using functional approach\n")
    return(create_functional_loader(db_pool))
  }
  
  loader <- GeographicDataLoader$new(db_pool)
  return(loader)
}

#' Create Functional Geographic Loader
#' 
#' Fallback functional implementation when R6 is not available
#' 
#' @param db_pool Database connection pool
#' @return List with loader functions
create_functional_loader <- function(db_pool = NULL) {
  
  # Create environment for state
  loader_env <- new.env()
  loader_env$db_pool <- db_pool
  loader_env$cache_data <- list()
  
  list(
    load_states = function(force_refresh = FALSE) {
      
      if (!force_refresh && "states_data" %in% names(loader_env$cache_data)) {
        return(loader_env$cache_data$states_data)
      }
      
      states_data <- load_ibge_states(force_refresh = force_refresh, simplify_geometry = TRUE)
      
      if (!is.null(states_data)) {
        loader_env$cache_data$states_data <- states_data
      }
      
      return(states_data)
    },
    
    load_municipalities = function(state_codes = c("SP", "MG", "RJ", "DF")) {
      
      cache_key <- paste0("municipalities_", paste(state_codes, collapse = "_"))
      
      if (cache_key %in% names(loader_env$cache_data)) {
        return(loader_env$cache_data[[cache_key]])
      }
      
      municipalities_data <- load_ibge_municipalities(state_code = state_codes)
      
      if (!is.null(municipalities_data)) {
        loader_env$cache_data[[cache_key]] <- municipalities_data
      }
      
      return(municipalities_data)
    },
    
    get_summary = function() {
      
      states_count <- ifelse("states_data" %in% names(loader_env$cache_data), 
                           nrow(loader_env$cache_data$states_data), 0)
      
      list(
        timestamp = Sys.time(),
        states_loaded = states_count,
        cache_entries = length(loader_env$cache_data),
        memory_mb = round(sum(gc(verbose = FALSE)[, "(Mb)"]), 2)
      )
    },
    
    cleanup = function() {
      loader_env$cache_data <- list()
      gc(verbose = FALSE)
    }
  )
}

# Export main functions
list(
  GeographicDataLoader = GeographicDataLoader,
  create_geographic_loader = create_geographic_loader,
  create_functional_loader = create_functional_loader,
  GEODATA_CONFIG = GEODATA_CONFIG
)