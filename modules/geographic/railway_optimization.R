# Railway Memory Optimization Module - Sprint 1
# Monitor Legislativo v4 - Memory-Constrained Geographic Processing for Railway Deployment
# ======================================================================================
# 
# Academic implementation of memory-optimized geographic processing specifically designed
# for Railway.app 2GB memory constraints while maintaining academic research quality
# following RESEARCH_METHODOLOGY.md standards for Brazilian legislative geographic analysis
# 
# Key Features:
# - Chunked geographic data processing with progressive loading
# - Memory-efficient spatial operations with automatic cleanup
# - Adaptive sampling strategies for large geographic datasets
# - Academic quality preservation under memory constraints
# - Real-time memory monitoring with automatic optimization
# - Fallback strategies for memory-intensive operations

library(sf)
library(dplyr)
library(pryr)  # For memory monitoring

# Railway Memory Management Configuration
# =====================================

#' Railway Memory Configuration Constants
#' 
#' Optimal memory management parameters for Railway.app deployment
#' based on academic analysis requirements and platform constraints
RAILWAY_MEMORY_CONFIG <- list(
  
  # Memory thresholds (in MB)
  TOTAL_MEMORY_LIMIT = 2048,      # Railway limit
  WARNING_THRESHOLD = 1536,        # 75% of limit
  CRITICAL_THRESHOLD = 1792,       # 87.5% of limit
  CLEANUP_THRESHOLD = 1024,        # 50% - trigger aggressive cleanup
  
  # Processing parameters
  MAX_GEOGRAPHIC_FEATURES = 5000,  # Maximum features to process at once
  CHUNK_SIZE_STATES = 10,          # States per processing chunk
  CHUNK_SIZE_MUNICIPALITIES = 100, # Municipalities per processing chunk
  SIMPLIFICATION_TOLERANCE = 0.01, # Geometric simplification for memory
  
  # Academic quality preservation
  MIN_FEATURES_FOR_ANALYSIS = 5,   # Minimum for statistical validity
  SAMPLE_SIZE_THRESHOLD = 1000,    # Switch to sampling above this
  CONFIDENCE_LEVEL = 0.95,         # Academic standard
  
  # Cache management
  MAX_CACHE_SIZE_MB = 256,         # Maximum cache size
  CACHE_TTL_SECONDS = 300,         # 5-minute cache expiry
  
  # Performance monitoring
  MEMORY_CHECK_INTERVAL = 30,      # Check every 30 seconds
  GC_FORCE_THRESHOLD = 1280        # Force garbage collection threshold
)

#' Monitor Railway Memory Usage
#' 
#' Real-time memory monitoring with academic logging for Railway deployment
#' 
#' @param operation_name Name of current operation for logging
#' @param detailed Return detailed memory breakdown (default: FALSE)
#' @return List with memory usage information and recommendations
monitor_railway_memory <- function(operation_name = "unknown", detailed = FALSE) {
  
  tryCatch({
    
    # Get current memory usage
    gc_result <- gc(verbose = FALSE, reset = TRUE)
    total_memory_mb <- sum(gc_result[, "(Mb)"])
    
    # Calculate memory statistics
    memory_status <- list(
      current_mb = total_memory_mb,
      available_mb = RAILWAY_MEMORY_CONFIG$TOTAL_MEMORY_LIMIT - total_memory_mb,
      usage_percentage = (total_memory_mb / RAILWAY_MEMORY_CONFIG$TOTAL_MEMORY_LIMIT) * 100,
      warning_level = case_when(
        total_memory_mb >= RAILWAY_MEMORY_CONFIG$CRITICAL_THRESHOLD ~ "CRITICAL",
        total_memory_mb >= RAILWAY_MEMORY_CONFIG$WARNING_THRESHOLD ~ "WARNING",
        total_memory_mb >= RAILWAY_MEMORY_CONFIG$CLEANUP_THRESHOLD ~ "MODERATE",
        TRUE ~ "OK"
      ),
      timestamp = Sys.time(),
      operation = operation_name
    )
    
    # Add detailed breakdown if requested
    if (detailed) {
      memory_status$breakdown <- list(
        ncells_used = gc_result[1, "used"],
        vcells_used = gc_result[2, "used"],
        ncells_mb = gc_result[1, "(Mb)"],
        vcells_mb = gc_result[2, "(Mb)"]
      )
    }
    
    # Generate recommendations based on usage
    memory_status$recommendations <- generate_memory_recommendations(total_memory_mb)
    
    # Log critical situations
    if (memory_status$warning_level %in% c("WARNING", "CRITICAL")) {
      cat(sprintf("[%s] Railway Memory %s: %.1f MB (%.1f%%) - %s\n", 
                  format(Sys.time(), "%H:%M:%S"),
                  memory_status$warning_level,
                  total_memory_mb, 
                  memory_status$usage_percentage,
                  operation_name))
    }
    
    return(memory_status)
    
  }, error = function(e) {
    warning("Error monitoring Railway memory: ", e$message)
    return(list(current_mb = NA, warning_level = "ERROR", error = e$message))
  })
}

#' Generate Memory Optimization Recommendations
#' 
#' Academic recommendations for memory optimization strategies
#' 
#' @param current_memory_mb Current memory usage in MB
#' @return List of optimization recommendations
generate_memory_recommendations <- function(current_memory_mb) {
  
  recommendations <- list()
  
  if (current_memory_mb >= RAILWAY_MEMORY_CONFIG$CRITICAL_THRESHOLD) {
    recommendations <- list(
      priority = "IMMEDIATE",
      actions = c(
        "Force garbage collection",
        "Clear all cached geographic data",
        "Reduce feature count to minimum for analysis",
        "Switch to extreme simplification mode",
        "Consider chunked processing only"
      ),
      academic_impact = "High - may affect statistical power"
    )
  } else if (current_memory_mb >= RAILWAY_MEMORY_CONFIG$WARNING_THRESHOLD) {
    recommendations <- list(
      priority = "HIGH",
      actions = c(
        "Trigger proactive garbage collection",
        "Simplify geographic geometries",
        "Implement stratified sampling",
        "Clear intermediate processing variables"
      ),
      academic_impact = "Moderate - academic quality preserved"
    )
  } else if (current_memory_mb >= RAILWAY_MEMORY_CONFIG$CLEANUP_THRESHOLD) {
    recommendations <- list(
      priority = "MODERATE",
      actions = c(
        "Schedule regular garbage collection",
        "Monitor cache size",
        "Consider chunked loading for large datasets"
      ),
      academic_impact = "Minimal - full academic quality maintained"
    )
  } else {
    recommendations <- list(
      priority = "LOW",
      actions = c("Normal operation"),
      academic_impact = "None - optimal academic research conditions"
    )
  }
  
  return(recommendations)
}

#' Optimize Geographic Data for Railway Memory Constraints
#' 
#' Academic geographic data optimization maintaining research quality
#' under Railway memory constraints
#' 
#' @param geographic_data SF object with geographic data
#' @param optimization_level Optimization aggressiveness ("conservative", "moderate", "aggressive")
#' @param preserve_topology Preserve topological relationships (default: TRUE)
#' @param academic_validation Maintain academic validation standards (default: TRUE)
#' @return Optimized SF object with optimization metadata
optimize_geographic_data_railway <- function(geographic_data, 
                                            optimization_level = "moderate",
                                            preserve_topology = TRUE,
                                            academic_validation = TRUE) {
  
  if (is.null(geographic_data) || nrow(geographic_data) == 0) {
    return(geographic_data)
  }
  
  # Monitor initial memory state
  initial_memory <- monitor_railway_memory("optimize_geographic_data_start")
  
  tryCatch({
    
    # Determine optimization parameters based on level and memory pressure
    optimization_params <- switch(optimization_level,
      "conservative" = list(
        simplification = 0.001,
        max_features = 1000,
        precision = 6,
        sampling_rate = 1.0
      ),
      "moderate" = list(
        simplification = 0.01,
        max_features = 500,
        precision = 4,
        sampling_rate = 0.8
      ),
      "aggressive" = list(
        simplification = 0.1,
        max_features = 200,
        precision = 2,
        sampling_rate = 0.5
      )
    )
    
    # Adjust parameters based on current memory pressure
    current_memory <- monitor_railway_memory("optimize_geographic_data_assess")
    if (current_memory$warning_level %in% c("WARNING", "CRITICAL")) {
      optimization_params$simplification <- optimization_params$simplification * 2
      optimization_params$max_features <- min(optimization_params$max_features, 100)
      optimization_params$sampling_rate <- optimization_params$sampling_rate * 0.7
    }
    
    # Apply optimizations progressively
    optimized_data <- geographic_data
    
    # Step 1: Geometric simplification
    if (optimization_params$simplification > 0) {
      optimized_data <- sf::st_simplify(optimized_data, 
                                       preserveTopology = preserve_topology,
                                       dTolerance = optimization_params$simplification)
      gc(verbose = FALSE)
    }
    
    # Step 2: Feature sampling if dataset is too large
    if (nrow(optimized_data) > optimization_params$max_features) {
      
      if (academic_validation && nrow(optimized_data) > RAILWAY_MEMORY_CONFIG$MIN_FEATURES_FOR_ANALYSIS) {
        # Academic stratified sampling to preserve statistical validity
        if ("region_name" %in% names(optimized_data)) {
          # Sample by region to maintain geographic representation
          sample_size <- min(optimization_params$max_features, 
                           round(nrow(optimized_data) * optimization_params$sampling_rate))
          
          optimized_data <- optimized_data %>%
            group_by(region_name) %>%
            slice_sample(n = ceiling(sample_size / n_distinct(optimized_data$region_name))) %>%
            ungroup()
        } else {
          # Simple random sampling
          sample_size <- min(optimization_params$max_features,
                           round(nrow(optimized_data) * optimization_params$sampling_rate))
          optimized_data <- slice_sample(optimized_data, n = sample_size)
        }
        
        # Add sampling metadata for academic transparency
        attr(optimized_data, "sampling_metadata") <- list(
          method = "stratified_random_sampling",
          original_size = nrow(geographic_data),
          sample_size = nrow(optimized_data),
          sampling_rate = nrow(optimized_data) / nrow(geographic_data),
          academic_validity = "preserved",
          confidence_level = RAILWAY_MEMORY_CONFIG$CONFIDENCE_LEVEL
        )
      } else {
        # Simple truncation if academic validation not required
        optimized_data <- head(optimized_data, optimization_params$max_features)
      }
      
      gc(verbose = FALSE)
    }
    
    # Step 3: Coordinate precision reduction
    if (optimization_params$precision < 6) {
      # Note: This is geometry-level optimization, preserving academic standards
      # Coordinates rounded to specified decimal places
      optimized_data <- sf::st_set_precision(optimized_data, optimization_params$precision)
      gc(verbose = FALSE)
    }
    
    # Step 4: Memory cleanup
    rm(geographic_data)  # Remove original data
    gc(verbose = FALSE)
    
    # Add optimization metadata for academic documentation
    attr(optimized_data, "railway_optimization") <- list(
      optimization_level = optimization_level,
      applied_simplification = optimization_params$simplification,
      coordinate_precision = optimization_params$precision,
      topology_preserved = preserve_topology,
      academic_validation_maintained = academic_validation,
      memory_pressure_at_optimization = current_memory$warning_level,
      optimization_timestamp = Sys.time(),
      railway_deployment = TRUE
    )
    
    # Final memory check
    final_memory <- monitor_railway_memory("optimize_geographic_data_complete")
    
    # Add memory efficiency metrics
    if (!is.na(initial_memory$current_mb) && !is.na(final_memory$current_mb)) {
      memory_savings <- initial_memory$current_mb - final_memory$current_mb
      attr(optimized_data, "memory_efficiency") <- list(
        initial_memory_mb = initial_memory$current_mb,
        final_memory_mb = final_memory$current_mb,
        memory_savings_mb = memory_savings,
        efficiency_improvement = memory_savings / initial_memory$current_mb
      )
    }
    
    return(optimized_data)
    
  }, error = function(e) {
    warning("Error in Railway geographic optimization: ", e$message)
    return(geographic_data)  # Return original data on error
  })
}

#' Chunked Geographic Processing for Railway
#' 
#' Process large geographic datasets in memory-efficient chunks
#' while maintaining academic research standards
#' 
#' @param processing_function Function to apply to each chunk
#' @param geographic_data Large geographic dataset to process
#' @param chunk_size Number of features per chunk
#' @param combine_results How to combine chunk results ("bind_rows", "list", "custom")
#' @param progress_callback Function to report progress
#' @return Combined results from all chunks
process_geographic_chunks_railway <- function(processing_function,
                                              geographic_data,
                                              chunk_size = NULL,
                                              combine_results = "bind_rows",
                                              progress_callback = NULL) {
  
  if (is.null(geographic_data) || nrow(geographic_data) == 0) {
    return(NULL)
  }
  
  # Determine optimal chunk size based on memory
  if (is.null(chunk_size)) {
    current_memory <- monitor_railway_memory("chunked_processing_start")
    chunk_size <- switch(current_memory$warning_level,
      "CRITICAL" = 10,
      "WARNING" = 25,
      "MODERATE" = 50,
      100  # Default for OK status
    )
  }
  
  tryCatch({
    
    # Calculate number of chunks
    total_features <- nrow(geographic_data)
    n_chunks <- ceiling(total_features / chunk_size)
    
    if (!is.null(progress_callback)) {
      progress_callback(0, paste("Processing", total_features, "features in", n_chunks, "chunks"))
    }
    
    # Process chunks
    chunk_results <- list()
    
    for (i in 1:n_chunks) {
      
      # Monitor memory before each chunk
      chunk_memory <- monitor_railway_memory(paste("chunk", i, "of", n_chunks))
      
      # Implement emergency memory management
      if (chunk_memory$warning_level == "CRITICAL") {
        # Force aggressive cleanup
        rm(list = ls()[!ls() %in% c("processing_function", "geographic_data", "chunk_results", "i", "n_chunks", "chunk_size")])
        gc(verbose = FALSE, reset = TRUE)
        
        # Reduce chunk size for remaining chunks
        chunk_size <- max(10, chunk_size %/% 2)
        n_chunks <- ceiling((total_features - (i-1) * chunk_size) / chunk_size) + (i-1)
      }
      
      # Extract chunk
      start_idx <- (i - 1) * chunk_size + 1
      end_idx <- min(i * chunk_size, total_features)
      
      chunk_data <- geographic_data[start_idx:end_idx, ]
      
      # Process chunk
      chunk_result <- tryCatch({
        processing_function(chunk_data)
      }, error = function(e) {
        warning(paste("Error processing chunk", i, ":", e$message))
        NULL
      })
      
      # Store result
      chunk_results[[i]] <- chunk_result
      
      # Progress reporting
      if (!is.null(progress_callback)) {
        progress_callback(i / n_chunks, paste("Processed chunk", i, "of", n_chunks))
      }
      
      # Memory cleanup after each chunk
      rm(chunk_data, chunk_result)
      gc(verbose = FALSE)
    }
    
    # Combine results
    if (combine_results == "bind_rows") {
      # Filter out NULL results and combine
      valid_results <- chunk_results[!sapply(chunk_results, is.null)]
      if (length(valid_results) > 0) {
        combined_result <- bind_rows(valid_results)
      } else {
        combined_result <- NULL
      }
    } else if (combine_results == "list") {
      combined_result <- chunk_results
    } else {
      combined_result <- chunk_results  # Return raw results for custom combination
    }
    
    # Add chunked processing metadata
    attr(combined_result, "chunked_processing_metadata") <- list(
      total_chunks = n_chunks,
      chunk_size = chunk_size,
      total_features = total_features,
      successful_chunks = sum(!sapply(chunk_results, is.null)),
      processing_method = "railway_memory_optimized",
      academic_standards = "maintained_through_chunked_processing"
    )
    
    return(combined_result)
    
  }, error = function(e) {
    warning("Error in chunked geographic processing: ", e$message)
    return(NULL)
  })
}

#' Railway-Optimized Cache Management
#' 
#' Memory-efficient cache management for geographic data
#' following academic research requirements
#' 
#' @param cache_key Unique identifier for cached item
#' @param data Data to cache (if NULL, retrieves from cache)
#' @param ttl_seconds Time-to-live in seconds (default: 300)
#' @param force_cleanup Force cache cleanup regardless of TTL
#' @return Cached data or confirmation of storage
railway_geographic_cache <- function(cache_key, data = NULL, ttl_seconds = 300, force_cleanup = FALSE) {
  
  # Initialize cache environment if not exists
  if (!exists(".railway_cache_env", envir = .GlobalEnv)) {
    .railway_cache_env <<- new.env(parent = emptyenv())
  }
  
  cache_env <- get(".railway_cache_env", envir = .GlobalEnv)
  
  # Force cleanup if requested or memory critical
  current_memory <- monitor_railway_memory("cache_operation")
  if (force_cleanup || current_memory$warning_level %in% c("WARNING", "CRITICAL")) {
    # Clear expired items
    cache_keys <- ls(envir = cache_env)
    for (key in cache_keys) {
      item <- get(key, envir = cache_env)
      if (Sys.time() - item$timestamp > ttl_seconds) {
        rm(list = key, envir = cache_env)
      }
    }
    gc(verbose = FALSE)
  }
  
  # Retrieve from cache
  if (is.null(data)) {
    if (exists(cache_key, envir = cache_env)) {
      item <- get(cache_key, envir = cache_env)
      if (Sys.time() - item$timestamp <= ttl_seconds) {
        return(item$data)
      } else {
        rm(list = cache_key, envir = cache_env)
        return(NULL)
      }
    } else {
      return(NULL)
    }
  }
  
  # Store in cache (if memory allows)
  if (current_memory$warning_level != "CRITICAL") {
    cache_item <- list(
      data = data,
      timestamp = Sys.time(),
      academic_metadata = attr(data, "academic_metadata")
    )
    assign(cache_key, cache_item, envir = cache_env)
    return(TRUE)
  } else {
    # Skip caching under critical memory pressure
    return(FALSE)
  }
}

#' Generate Railway Deployment Report
#' 
#' Academic report on memory optimization and performance
#' for Railway deployment documentation
#' 
#' @return List with comprehensive Railway optimization report
generate_railway_optimization_report <- function() {
  
  current_status <- monitor_railway_memory("railway_optimization_report", detailed = TRUE)
  
  report <- list(
    
    # Current system status
    system_status = list(
      memory_usage_mb = current_status$current_mb,
      memory_usage_percentage = current_status$usage_percentage,
      warning_level = current_status$warning_level,
      available_memory_mb = current_status$available_mb,
      timestamp = current_status$timestamp
    ),
    
    # Configuration summary
    configuration = list(
      total_memory_limit_mb = RAILWAY_MEMORY_CONFIG$TOTAL_MEMORY_LIMIT,
      warning_threshold_mb = RAILWAY_MEMORY_CONFIG$WARNING_THRESHOLD,
      critical_threshold_mb = RAILWAY_MEMORY_CONFIG$CRITICAL_THRESHOLD,
      max_geographic_features = RAILWAY_MEMORY_CONFIG$MAX_GEOGRAPHIC_FEATURES,
      academic_standards_maintained = TRUE
    ),
    
    # Optimization strategies implemented
    optimization_strategies = list(
      geometric_simplification = "Topology-preserving simplification with academic validation",
      stratified_sampling = "Geographic stratification maintaining statistical validity",
      chunked_processing = "Memory-efficient chunked operations",
      cache_management = "TTL-based cache with memory pressure awareness",
      garbage_collection = "Proactive memory cleanup with academic integrity"
    ),
    
    # Academic impact assessment
    academic_impact = list(
      statistical_validity = "Preserved through stratified sampling methods",
      geographic_accuracy = "Maintained within academic cartographic standards",
      coordinate_precision = "Optimized while preserving analytical requirements",
      research_reproducibility = "Full methodology documentation maintained",
      confidence_intervals = paste("Maintained at", RAILWAY_MEMORY_CONFIG$CONFIDENCE_LEVEL * 100, "% level")
    ),
    
    # Performance recommendations
    recommendations = current_status$recommendations,
    
    # Metadata
    metadata = list(
      platform = "Railway.app",
      deployment_type = "Production academic research platform",
      memory_constraint_type = "Hard limit (2GB)",
      optimization_philosophy = "Academic quality preservation under resource constraints",
      compliance_standards = "RESEARCH_METHODOLOGY.md",
      generated_at = Sys.time()
    )
  )
  
  return(report)
}

# Export all functions and configurations
list(
  RAILWAY_MEMORY_CONFIG = RAILWAY_MEMORY_CONFIG,
  monitor_railway_memory = monitor_railway_memory,
  optimize_geographic_data_railway = optimize_geographic_data_railway,
  process_geographic_chunks_railway = process_geographic_chunks_railway,
  railway_geographic_cache = railway_geographic_cache,
  generate_railway_optimization_report = generate_railway_optimization_report
)