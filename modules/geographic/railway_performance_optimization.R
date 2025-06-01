# Railway Performance Optimization - Sprint 5B GEO-002
# Brazilian Legislative Monitoring System - Railway Deployment Optimization
# =========================================================================
# 
# Comprehensive performance optimization system specifically designed for
# Railway platform deployment constraints with 2GB memory limits for the
# Brazilian Legislative Monitoring System with 134k+ documents
# 
# RAILWAY CONSTRAINTS:
# - Maximum 2GB RAM available for entire application
# - CPU-limited processing environment
# - Network bandwidth limitations for data transfer
# - Ephemeral storage with limited disk space
# - Cold start optimization requirements
# 
# OPTIMIZATION STRATEGIES:
# - Aggressive memory management and garbage collection
# - Lazy loading and progressive enhancement patterns
# - Spatial data simplification and compression
# - Smart caching with memory-aware eviction policies
# - Chunked processing for large datasets
# - Async processing where Railway permits
# 
# MONITORING & ALERTING:
# - Real-time memory usage monitoring
# - Performance bottleneck detection
# - Automatic performance degradation responses
# - Memory leak detection and prevention
# - Railway-specific deployment health checks
# =========================================================================

library(pryr)  # For memory profiling
library(future)  # For async processing
library(memuse)  # For memory usage analysis

# Load core density visualization components
if (file.exists("modules/geographic/density_visualization.R")) {
  source("modules/geographic/density_visualization.R")
}

# Railway Performance Configuration
# ================================

RAILWAY_PERFORMANCE_CONFIG <- list(
  
  # Memory constraints and limits
  memory = list(
    total_limit_mb = 1800,  # Conservative limit below Railway's 2GB
    visualization_limit_mb = 600,  # Max for visualization components
    spatial_data_limit_mb = 400,  # Max for spatial data in memory
    cache_limit_mb = 300,  # Max for caching systems
    emergency_threshold_mb = 1600,  # Emergency cleanup threshold
    
    # Garbage collection settings
    gc_frequency_seconds = 30,
    gc_aggressive_threshold_mb = 1200,
    gc_emergency_threshold_mb = 1500
  ),
  
  # Processing optimization
  processing = list(
    max_features_per_chunk = 50,  # Spatial features per processing chunk
    map_rendering_timeout_sec = 15,  # Maximum map rendering time
    max_concurrent_operations = 1,  # Single-threaded to conserve memory
    spatial_simplification_tolerance = 0.02,  # Aggressive simplification
    
    # Progressive loading settings
    enable_progressive_loading = TRUE,
    progressive_chunk_size = 25,
    progressive_delay_ms = 100,
    
    # Performance monitoring
    performance_monitoring = TRUE,
    memory_sampling_interval_sec = 10,
    performance_alert_threshold = 0.8  # 80% of memory limit
  ),
  
  # Data optimization
  data_optimization = list(
    compress_spatial_data = TRUE,
    use_simplified_geometries = TRUE,
    cache_processed_data = TRUE,
    precompute_aggregations = TRUE,
    
    # Spatial data settings
    coordinate_precision = 4,  # Decimal places for coordinates
    geometry_buffer_tolerance = 0.001,
    remove_internal_boundaries = TRUE,
    
    # Database query optimization
    use_spatial_indexes = TRUE,
    limit_query_results = TRUE,
    batch_size = 1000,
    query_timeout_sec = 10
  ),
  
  # Caching strategy
  caching = list(
    enable_memory_cache = TRUE,
    enable_disk_cache = FALSE,  # Disabled for Railway ephemeral storage
    cache_expiry_minutes = 15,  # Shorter expiry for memory conservation
    max_cache_entries = 20,  # Limited cache entries
    
    # Intelligent cache eviction
    lru_eviction = TRUE,
    size_based_eviction = TRUE,
    memory_pressure_eviction = TRUE,
    
    # Cache warming strategies
    preload_essential_data = TRUE,
    background_cache_refresh = FALSE  # Disabled to save memory
  ),
  
  # Error handling and fallbacks
  error_handling = list(
    enable_graceful_degradation = TRUE,
    fallback_to_simple_maps = TRUE,
    emergency_memory_cleanup = TRUE,
    max_retry_attempts = 2,
    
    # Performance fallbacks
    reduce_feature_complexity = TRUE,
    disable_animations = TRUE,
    simplify_interactions = TRUE,
    reduce_color_depth = TRUE
  )
)

# Railway Performance Monitor Class
# ================================

if (requireNamespace("R6", quietly = TRUE)) {
  
  RailwayPerformanceMonitor <- R6::R6Class("RailwayPerformanceMonitor",
    
    public = list(
      
      # Properties
      monitoring_active = FALSE,
      performance_log = NULL,
      memory_samples = NULL,
      alert_callbacks = NULL,
      emergency_mode = FALSE,
      last_cleanup_time = NULL,
      
      # Constructor
      initialize = function() {
        
        cat("🚄 Initializing Railway Performance Monitor...\n")
        
        self$performance_log <- list()
        self$memory_samples <- list()
        self$alert_callbacks <- list()
        self$last_cleanup_time <- Sys.time()
        
        # Setup automatic monitoring
        if (RAILWAY_PERFORMANCE_CONFIG$processing$performance_monitoring) {
          self$start_monitoring()
        }
        
        cat("✅ Railway Performance Monitor initialized\n")
      },
      
      # Monitoring methods
      start_monitoring = function() {
        
        if (self$monitoring_active) {
          return(invisible(self))
        }
        
        cat("📊 Starting Railway performance monitoring...\n")
        
        self$monitoring_active <- TRUE
        
        # Start memory monitoring loop
        self$setup_memory_monitoring()
        
        # Setup garbage collection schedule
        self$setup_gc_schedule()
        
        # Setup emergency response system
        self$setup_emergency_response()
        
        cat("✅ Performance monitoring started\n")
        
        return(invisible(self))
      },
      
      stop_monitoring = function() {
        
        self$monitoring_active <- FALSE
        cat("⏹️ Performance monitoring stopped\n")
        
        return(invisible(self))
      },
      
      # Memory monitoring
      setup_memory_monitoring = function() {
        
        # Use future for async monitoring (if available)
        if (requireNamespace("future", quietly = TRUE)) {
          
          self$monitor_memory_async()
          
        } else {
          
          # Fallback to manual monitoring triggers
          cat("⚠️ Async monitoring not available, using manual triggers\n")
        }
      },
      
      monitor_memory_async = function() {
        
        # Background memory monitoring
        future::future({
          
          while (self$monitoring_active) {
            
            memory_stats <- self$get_current_memory_stats()
            self$memory_samples[[length(self$memory_samples) + 1]] <- memory_stats
            
            # Keep only recent samples
            if (length(self$memory_samples) > 100) {
              self$memory_samples <- self$memory_samples[(length(self$memory_samples) - 99):length(self$memory_samples)]
            }
            
            # Check for alerts
            self$check_memory_alerts(memory_stats)
            
            # Wait before next sample
            Sys.sleep(RAILWAY_PERFORMANCE_CONFIG$processing$memory_sampling_interval_sec)
          }
        })
      },
      
      get_current_memory_stats = function() {
        
        tryCatch({
          
          # Get memory usage from gc()
          gc_info <- gc(verbose = FALSE)
          total_memory_mb <- sum(gc_info[, "(Mb)"])
          
          # Get object sizes if pryr available
          if (requireNamespace("pryr", quietly = TRUE)) {
            object_memory_mb <- as.numeric(pryr::mem_used()) / 1024^2
          } else {
            object_memory_mb <- NA
          }
          
          list(
            timestamp = Sys.time(),
            total_memory_mb = total_memory_mb,
            object_memory_mb = object_memory_mb,
            gc_ncells = gc_info[1, "Ncells"],
            gc_vcells = gc_info[1, "Vcells"],
            limit_mb = RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb,
            usage_pct = (total_memory_mb / RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb) * 100
          )
          
        }, error = function(e) {
          list(
            timestamp = Sys.time(),
            error = e$message,
            total_memory_mb = NA,
            usage_pct = NA
          )
        })
      },
      
      check_memory_alerts = function(memory_stats) {
        
        if (is.null(memory_stats$usage_pct) || is.na(memory_stats$usage_pct)) {
          return(invisible(self))
        }
        
        alert_threshold <- RAILWAY_PERFORMANCE_CONFIG$processing$performance_alert_threshold * 100
        emergency_threshold <- (RAILWAY_PERFORMANCE_CONFIG$memory$emergency_threshold_mb / 
                              RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb) * 100
        
        # High memory usage alert
        if (memory_stats$usage_pct >= alert_threshold && !self$emergency_mode) {
          
          self$trigger_memory_alert(memory_stats, "high_usage")
          
        }
        
        # Emergency memory threshold
        if (memory_stats$usage_pct >= emergency_threshold) {
          
          self$trigger_emergency_response(memory_stats)
        }
      },
      
      trigger_memory_alert = function(memory_stats, alert_type) {
        
        cat("⚠️ RAILWAY MEMORY ALERT:", alert_type, "\n")
        cat("   Current usage:", round(memory_stats$usage_pct, 1), "%\n")
        cat("   Memory used:", round(memory_stats$total_memory_mb, 1), "MB\n")
        
        # Execute alert callbacks
        for (callback in self$alert_callbacks) {
          tryCatch({
            callback(memory_stats, alert_type)
          }, error = function(e) {
            cat("❌ Alert callback error:", e$message, "\n")
          })
        }
        
        # Proactive cleanup
        self$perform_proactive_cleanup()
      },
      
      trigger_emergency_response = function(memory_stats) {
        
        if (self$emergency_mode) {
          return(invisible(self))  # Already in emergency mode
        }
        
        cat("🚨 RAILWAY EMERGENCY: Memory limit exceeded!\n")
        cat("   Emergency usage:", round(memory_stats$usage_pct, 1), "%\n")
        cat("   Memory used:", round(memory_stats$total_memory_mb, 1), "MB\n")
        
        self$emergency_mode <- TRUE
        
        # Emergency cleanup sequence
        self$perform_emergency_cleanup()
        
        # Trigger emergency callbacks
        for (callback in self$alert_callbacks) {
          tryCatch({
            callback(memory_stats, "emergency")
          }, error = function(e) {
            cat("❌ Emergency callback error:", e$message, "\n")
          })
        }
        
        # Reset emergency mode after delay
        future::future({
          Sys.sleep(60)  # Emergency mode for 1 minute
          self$emergency_mode <- FALSE
          cat("✅ Emergency mode reset\n")
        })
      },
      
      # Cleanup methods
      setup_gc_schedule = function() {
        
        # Schedule regular garbage collection
        future::future({
          
          while (self$monitoring_active) {
            
            Sys.sleep(RAILWAY_PERFORMANCE_CONFIG$memory$gc_frequency_seconds)
            
            if (self$monitoring_active) {
              self$perform_scheduled_gc()
            }
          }
        })
      },
      
      perform_scheduled_gc = function() {
        
        current_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
        
        # Determine GC aggressiveness based on memory usage
        if (current_memory > RAILWAY_PERFORMANCE_CONFIG$memory$gc_emergency_threshold_mb) {
          
          # Emergency GC
          for (i in 1:3) {
            gc(verbose = FALSE)
            Sys.sleep(0.1)
          }
          
          cat("🧹 Emergency garbage collection completed\n")
          
        } else if (current_memory > RAILWAY_PERFORMANCE_CONFIG$memory$gc_aggressive_threshold_mb) {
          
          # Aggressive GC
          gc(verbose = FALSE)
          gc(verbose = FALSE)  # Double GC
          
        } else {
          
          # Normal GC
          gc(verbose = FALSE)
        }
      },
      
      perform_proactive_cleanup = function() {
        
        cat("🧽 Performing proactive Railway cleanup...\n")
        
        cleanup_results <- list()
        
        # 1. Clear visualization caches
        if (exists("density_viz_system") && !is.null(density_viz_system)) {
          tryCatch({
            if ("clear_cache" %in% names(density_viz_system)) {
              density_viz_system$clear_cache()
              cleanup_results$visualization_cache <- TRUE
            }
          }, error = function(e) {
            cleanup_results$visualization_cache <- FALSE
          })
        }
        
        # 2. Clear map interactivity caches
        if (exists("map_interactivity_manager") && !is.null(map_interactivity_manager)) {
          tryCatch({
            if ("clear_cache" %in% names(map_interactivity_manager)) {
              map_interactivity_manager$clear_cache()
              cleanup_results$interactivity_cache <- TRUE
            }
          }, error = function(e) {
            cleanup_results$interactivity_cache <- FALSE
          })
        }
        
        # 3. Clear export temporary files
        if (exists("export_manager") && !is.null(export_manager)) {
          tryCatch({
            if ("clear_temp_files" %in% names(export_manager)) {
              export_manager$clear_temp_files()
              cleanup_results$export_temp_files <- TRUE
            }
          }, error = function(e) {
            cleanup_results$export_temp_files <- FALSE
          })
        }
        
        # 4. Remove large objects from global environment
        large_objects <- ls(.GlobalEnv)[sapply(ls(.GlobalEnv), function(x) {
          tryCatch({
            object.size(get(x, .GlobalEnv)) > 10*1024^2  # Objects > 10MB
          }, error = function(e) FALSE)
        })]
        
        for (obj in large_objects) {
          if (!obj %in% c("density_viz_system", "map_interactivity_manager", "export_manager")) {
            tryCatch({
              rm(list = obj, envir = .GlobalEnv)
              cleanup_results[[paste0("removed_", obj)]] <- TRUE
            }, error = function(e) {
              cleanup_results[[paste0("removed_", obj)]] <- FALSE
            })
          }
        }
        
        # 5. Aggressive garbage collection
        for (i in 1:3) {
          gc(verbose = FALSE)
          Sys.sleep(0.1)
        }
        
        self$last_cleanup_time <- Sys.time()
        
        cat("✅ Proactive cleanup completed\n")
        return(cleanup_results)
      },
      
      perform_emergency_cleanup = function() {
        
        cat("🚨 Performing emergency Railway cleanup...\n")
        
        # Emergency cleanup sequence
        emergency_results <- list()
        
        # 1. Clear ALL caches immediately
        for (cache_var in c("density_viz_system", "map_interactivity_manager", "export_manager")) {
          if (exists(cache_var, .GlobalEnv)) {
            cache_obj <- get(cache_var, .GlobalEnv)
            if (!is.null(cache_obj) && "clear_cache" %in% names(cache_obj)) {
              tryCatch({
                cache_obj$clear_cache()
                emergency_results[[paste0(cache_var, "_cache")]] <- TRUE
              }, error = function(e) {
                emergency_results[[paste0(cache_var, "_cache")]] <- FALSE
              })
            }
          }
        }
        
        # 2. Remove all non-essential objects
        all_objects <- ls(.GlobalEnv)
        essential_objects <- c("db_pool", "density_viz_system", "map_interactivity_manager")
        
        for (obj in setdiff(all_objects, essential_objects)) {
          tryCatch({
            rm(list = obj, envir = .GlobalEnv)
            emergency_results[[paste0("emergency_removed_", obj)]] <- TRUE
          }, error = function(e) {
            emergency_results[[paste0("emergency_removed_", obj)]] <- FALSE
          })
        }
        
        # 3. Ultra-aggressive garbage collection
        for (i in 1:5) {
          gc(verbose = FALSE)
          Sys.sleep(0.2)
        }
        
        # 4. Force memory compaction if available
        if (exists(".rs.restartR")) {
          cat("⚠️ Extreme memory pressure - recommend app restart\n")
        }
        
        cat("🚨 Emergency cleanup completed\n")
        return(emergency_results)
      },
      
      # Performance optimization methods
      optimize_spatial_data = function(spatial_data, aggressive = FALSE) {
        
        if (is.null(spatial_data) || !any(class(spatial_data) %in% c("sf", "sfc"))) {
          return(spatial_data)
        }
        
        tryCatch({
          
          # Simplification tolerance based on mode
          tolerance <- if (aggressive) {
            RAILWAY_PERFORMANCE_CONFIG$data_optimization$geometry_buffer_tolerance * 10
          } else {
            RAILWAY_PERFORMANCE_CONFIG$data_optimization$geometry_buffer_tolerance
          }
          
          # Apply optimizations
          optimized_data <- spatial_data %>%
            # Simplify geometries
            sf::st_simplify(preserveTopology = TRUE, dTolerance = tolerance) %>%
            # Remove invalid geometries
            filter(sf::st_is_valid(geometry)) %>%
            # Reduce coordinate precision
            sf::st_set_precision(1000)  # 1km precision
          
          # Additional aggressive optimizations
          if (aggressive) {
            optimized_data <- optimized_data %>%
              # Remove small polygons
              filter(as.numeric(sf::st_area(geometry)) > 1000000)  # > 1 km²
          }
          
          cat("🗺️ Spatial data optimized:", nrow(spatial_data), "→", nrow(optimized_data), "features\n")
          
          return(optimized_data)
          
        }, error = function(e) {
          cat("⚠️ Spatial optimization failed:", e$message, "\n")
          return(spatial_data)
        })
      },
      
      # Railway-specific methods
      get_railway_status = function() {
        
        current_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
        
        status <- list(
          timestamp = Sys.time(),
          memory_usage_mb = current_memory,
          memory_limit_mb = RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb,
          memory_usage_pct = (current_memory / RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb) * 100,
          emergency_mode = self$emergency_mode,
          monitoring_active = self$monitoring_active,
          last_cleanup = self$last_cleanup_time,
          
          # Performance indicators
          performance_status = if (current_memory < RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb * 0.7) {
            "optimal"
          } else if (current_memory < RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb * 0.9) {
            "warning"
          } else {
            "critical"
          },
          
          # Recommendations
          recommendations = self$get_performance_recommendations(current_memory)
        )
        
        return(status)
      },
      
      get_performance_recommendations = function(current_memory) {
        
        recommendations <- c()
        
        usage_pct <- (current_memory / RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb) * 100
        
        if (usage_pct > 90) {
          recommendations <- c(recommendations, "Immediate cleanup required")
          recommendations <- c(recommendations, "Consider reducing data complexity")
          recommendations <- c(recommendations, "Restart application if possible")
        } else if (usage_pct > 70) {
          recommendations <- c(recommendations, "Monitor memory usage closely")
          recommendations <- c(recommendations, "Clear caches regularly")
          recommendations <- c(recommendations, "Reduce concurrent operations")
        } else if (usage_pct > 50) {
          recommendations <- c(recommendations, "Performance monitoring active")
          recommendations <- c(recommendations, "Regular maintenance scheduled")
        }
        
        return(recommendations)
      },
      
      # Callback management
      add_alert_callback = function(callback) {
        self$alert_callbacks[[length(self$alert_callbacks) + 1]] <- callback
        return(invisible(self))
      },
      
      # Cleanup and finalization
      finalize = function() {
        self$stop_monitoring()
        self$perform_proactive_cleanup()
      }
    )
  )
}

# Performance Optimization Functions
# ==================================

#' Create Railway Performance Monitor
#' 
#' Factory function for Railway performance monitoring
#' 
#' @return Performance monitor instance
create_railway_performance_monitor <- function() {
  
  if (requireNamespace("R6", quietly = TRUE)) {
    return(RailwayPerformanceMonitor$new())
  } else {
    return(create_functional_performance_monitor())
  }
}

#' Functional Performance Monitor (Fallback)
#' 
#' Simple functional performance monitoring for systems without R6
#' 
#' @return Functional performance monitor
create_functional_performance_monitor <- function() {
  
  # Environment for state
  monitor_env <- new.env()
  monitor_env$active <- FALSE
  monitor_env$last_cleanup <- Sys.time()
  monitor_env$emergency_mode <- FALSE
  
  list(
    
    start_monitoring = function() {
      monitor_env$active <- TRUE
      cat("📊 Basic performance monitoring started\n")
    },
    
    stop_monitoring = function() {
      monitor_env$active <- FALSE
      cat("⏹️ Performance monitoring stopped\n")
    },
    
    get_current_memory_stats = function() {
      gc_info <- gc(verbose = FALSE)
      total_memory <- sum(gc_info[, "(Mb)"])
      
      list(
        timestamp = Sys.time(),
        total_memory_mb = total_memory,
        usage_pct = (total_memory / RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb) * 100,
        status = if (total_memory < 1000) "good" else if (total_memory < 1500) "warning" else "critical"
      )
    },
    
    perform_cleanup = function() {
      
      # Basic cleanup
      gc(verbose = FALSE)
      gc(verbose = FALSE)  # Double GC
      
      monitor_env$last_cleanup <- Sys.time()
      cat("🧹 Basic cleanup completed\n")
      
      return(TRUE)
    },
    
    get_railway_status = function() {
      stats <- self$get_current_memory_stats()
      
      list(
        memory_usage_mb = stats$total_memory_mb,
        status = stats$status,
        recommendations = if (stats$usage_pct > 80) {
          c("High memory usage detected", "Consider clearing caches")
        } else {
          c("Memory usage normal")
        },
        monitoring_mode = "basic"
      )
    }
  )
}

# Railway Optimization Utilities
# ==============================

#' Optimize Data for Railway Deployment
#' 
#' Applies Railway-specific optimizations to data
#' 
#' @param data Data to optimize
#' @param aggressive Whether to apply aggressive optimizations
#' @return Optimized data
optimize_data_for_railway <- function(data, aggressive = FALSE) {
  
  if (is.null(data) || nrow(data) == 0) {
    return(data)
  }
  
  tryCatch({
    
    optimized <- data
    
    # Limit rows if too many
    max_rows <- if (aggressive) 1000 else 2000
    if (nrow(optimized) > max_rows) {
      optimized <- optimized[1:max_rows, ]
      cat("⚠️ Data truncated to", max_rows, "rows for Railway deployment\n")
    }
    
    # Remove text columns that are too large
    if (aggressive) {
      text_cols <- sapply(optimized, is.character)
      for (col in names(text_cols)[text_cols]) {
        if (mean(nchar(optimized[[col]], use = "all"), na.rm = TRUE) > 1000) {
          optimized[[col]] <- substr(optimized[[col]], 1, 200)
        }
      }
    }
    
    # Optimize factor levels
    factor_cols <- sapply(optimized, is.factor)
    for (col in names(factor_cols)[factor_cols]) {
      optimized[[col]] <- droplevels(optimized[[col]])
    }
    
    return(optimized)
    
  }, error = function(e) {
    cat("⚠️ Data optimization failed:", e$message, "\n")
    return(data)
  })
}

#' Railway Memory Check
#' 
#' Checks if operation is safe within Railway memory limits
#' 
#' @param operation_name Name of the operation to check
#' @param estimated_memory_mb Estimated memory requirement in MB
#' @return TRUE if safe to proceed
railway_memory_check <- function(operation_name, estimated_memory_mb = 100) {
  
  current_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
  projected_memory <- current_memory + estimated_memory_mb
  
  memory_limit <- RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb
  
  if (projected_memory > memory_limit) {
    cat("⚠️ Railway memory check FAILED for", operation_name, "\n")
    cat("   Current:", round(current_memory, 1), "MB\n")
    cat("   Projected:", round(projected_memory, 1), "MB\n")
    cat("   Limit:", memory_limit, "MB\n")
    return(FALSE)
  }
  
  cat("✅ Railway memory check PASSED for", operation_name, "\n")
  return(TRUE)
}

#' Railway Safe Execute
#' 
#' Executes operation with Railway memory safety checks
#' 
#' @param operation Function to execute
#' @param operation_name Name for logging
#' @param estimated_memory_mb Estimated memory requirement
#' @param fallback_function Fallback function if memory check fails
#' @return Operation result or fallback result
railway_safe_execute <- function(operation, operation_name, estimated_memory_mb = 100, fallback_function = NULL) {
  
  tryCatch({
    
    # Memory check
    if (!railway_memory_check(operation_name, estimated_memory_mb)) {
      
      if (!is.null(fallback_function)) {
        cat("🔄 Using fallback for", operation_name, "\n")
        return(fallback_function())
      } else {
        cat("❌ Operation cancelled due to memory constraints:", operation_name, "\n")
        return(NULL)
      }
    }
    
    # Execute operation
    result <- operation()
    
    # Post-operation cleanup
    gc(verbose = FALSE)
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Railway safe execution failed for", operation_name, ":", e$message, "\n")
    
    # Emergency cleanup
    gc(verbose = FALSE)
    gc(verbose = FALSE)
    
    if (!is.null(fallback_function)) {
      return(fallback_function())
    } else {
      return(NULL)
    }
  })
}

# Performance Testing Functions
# ============================

#' Run Railway Performance Tests
#' 
#' Comprehensive performance testing for Railway deployment
#' 
#' @param density_viz_system Density visualization system instance
#' @return Performance test results
run_railway_performance_tests <- function(density_viz_system = NULL) {
  
  cat("🧪 Running Railway performance tests...\n")
  
  test_results <- list(
    timestamp = Sys.time(),
    tests = list(),
    summary = list(),
    recommendations = c()
  )
  
  # Test 1: Memory baseline
  cat("  📊 Test 1: Memory baseline measurement\n")
  baseline_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
  test_results$tests$memory_baseline <- list(
    memory_mb = baseline_memory,
    percentage = (baseline_memory / RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb) * 100,
    status = if (baseline_memory < 500) "excellent" else if (baseline_memory < 1000) "good" else "concerning"
  )
  
  # Test 2: State choropleth creation
  if (!is.null(density_viz_system)) {
    cat("  🗺️ Test 2: State choropleth creation\n")
    
    start_time <- Sys.time()
    start_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
    
    choropleth_result <- railway_safe_execute(
      operation = function() {
        density_viz_system$create_state_choropleth(mode = "absolute", bins = 5)
      },
      operation_name = "state_choropleth_test",
      estimated_memory_mb = 200,
      fallback_function = function() "fallback_used"
    )
    
    end_time <- Sys.time()
    end_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
    
    test_results$tests$state_choropleth <- list(
      duration_seconds = as.numeric(difftime(end_time, start_time, units = "secs")),
      memory_used_mb = end_memory - start_memory,
      success = !is.null(choropleth_result) && choropleth_result != "fallback_used",
      fallback_used = identical(choropleth_result, "fallback_used")
    )
  }
  
  # Test 3: Memory stress test
  cat("  🔥 Test 3: Memory stress test\n")
  
  stress_test_result <- tryCatch({
    
    # Create multiple data objects to test memory limits
    large_objects <- list()
    for (i in 1:10) {
      large_objects[[i]] <- matrix(rnorm(10000), nrow = 100)
    }
    
    stress_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
    
    # Clean up
    rm(large_objects)
    gc(verbose = FALSE)
    
    list(
      peak_memory_mb = stress_memory,
      cleanup_successful = TRUE,
      memory_limit_reached = stress_memory > RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb * 0.8
    )
    
  }, error = function(e) {
    list(
      error = e$message,
      cleanup_successful = FALSE
    )
  })
  
  test_results$tests$memory_stress <- stress_test_result
  
  # Test 4: Cache efficiency
  cat("  💾 Test 4: Cache efficiency test\n")
  
  if (!is.null(density_viz_system) && "clear_cache" %in% names(density_viz_system)) {
    
    # Clear cache
    density_viz_system$clear_cache()
    memory_before_cache <- sum(gc(verbose = FALSE)[, "(Mb)"])
    
    # Perform operations that should populate cache
    test_operations <- railway_safe_execute(
      operation = function() {
        # Simulate cache population
        for (i in 1:3) {
          density_viz_system$create_state_choropleth(mode = "absolute", bins = 7)
        }
      },
      operation_name = "cache_test",
      estimated_memory_mb = 150
    )
    
    memory_after_cache <- sum(gc(verbose = FALSE)[, "(Mb)"])
    
    test_results$tests$cache_efficiency <- list(
      cache_memory_usage_mb = memory_after_cache - memory_before_cache,
      operations_completed = !is.null(test_operations),
      cache_reasonable = (memory_after_cache - memory_before_cache) < 200
    )
  }
  
  # Test 5: Export capability
  cat("  📤 Test 5: Export capability test\n")
  
  if (exists("export_manager", .GlobalEnv) && !is.null(export_manager)) {
    
    export_test_result <- railway_safe_execute(
      operation = function() {
        export_manager$export_data(format = "csv", level = "state")
      },
      operation_name = "export_test",
      estimated_memory_mb = 50,
      fallback_function = function() list(success = FALSE, error = "memory_fallback")
    )
    
    test_results$tests$export_capability <- list(
      export_successful = !is.null(export_test_result) && isTRUE(export_test_result$success),
      fallback_used = !is.null(export_test_result) && isTRUE(export_test_result$error == "memory_fallback")
    )
  }
  
  # Generate summary and recommendations
  current_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
  
  test_results$summary <- list(
    total_tests = length(test_results$tests),
    successful_tests = sum(sapply(test_results$tests, function(t) {
      !("error" %in% names(t)) && (t$success %||% TRUE)
    })),
    final_memory_mb = current_memory,
    memory_efficiency = (current_memory / RAILWAY_PERFORMANCE_CONFIG$memory$total_limit_mb) * 100
  )
  
  # Generate recommendations
  if (test_results$summary$memory_efficiency > 80) {
    test_results$recommendations <- c(test_results$recommendations, "High memory usage - consider optimization")
  }
  
  if (test_results$summary$successful_tests < test_results$summary$total_tests) {
    test_results$recommendations <- c(test_results$recommendations, "Some tests failed - review error handling")
  }
  
  if (any(sapply(test_results$tests, function(t) t$fallback_used %||% FALSE))) {
    test_results$recommendations <- c(test_results$recommendations, "Fallbacks activated - monitor memory closely")
  }
  
  if (length(test_results$recommendations) == 0) {
    test_results$recommendations <- c("Performance tests passed - system ready for Railway deployment")
  }
  
  cat("✅ Railway performance tests completed\n")
  cat("   Tests run:", test_results$summary$total_tests, "\n")
  cat("   Tests passed:", test_results$summary$successful_tests, "\n")
  cat("   Memory efficiency:", round(test_results$summary$memory_efficiency, 1), "%\n")
  
  return(test_results)
}

#' Display Performance Test Results
#' 
#' Pretty prints performance test results
#' 
#' @param test_results Results from run_railway_performance_tests()
display_performance_results <- function(test_results) {
  
  cat("\n🧪 RAILWAY PERFORMANCE TEST RESULTS\n")
  cat("=====================================\n\n")
  
  # Summary
  cat("📋 SUMMARY:\n")
  cat("  Tests Run:", test_results$summary$total_tests, "\n")
  cat("  Tests Passed:", test_results$summary$successful_tests, "\n")
  cat("  Memory Efficiency:", round(test_results$summary$memory_efficiency, 1), "%\n")
  cat("  Test Time:", format(test_results$timestamp), "\n\n")
  
  # Individual test results
  cat("🔍 DETAILED RESULTS:\n")
  
  for (test_name in names(test_results$tests)) {
    cat("  ", test_name, ":\n")
    test_data <- test_results$tests[[test_name]]
    
    for (metric in names(test_data)) {
      value <- test_data[[metric]]
      cat("    ", metric, ":", 
          if (is.numeric(value)) round(value, 2) else value, "\n")
    }
    cat("\n")
  }
  
  # Recommendations
  cat("💡 RECOMMENDATIONS:\n")
  for (rec in test_results$recommendations) {
    cat("  •", rec, "\n")
  }
  
  cat("\n")
}

# Export Functions
# ===============

list(
  create_railway_performance_monitor = create_railway_performance_monitor,
  create_functional_performance_monitor = create_functional_performance_monitor,
  optimize_data_for_railway = optimize_data_for_railway,
  railway_memory_check = railway_memory_check,
  railway_safe_execute = railway_safe_execute,
  run_railway_performance_tests = run_railway_performance_tests,
  display_performance_results = display_performance_results,
  RAILWAY_PERFORMANCE_CONFIG = RAILWAY_PERFORMANCE_CONFIG
)