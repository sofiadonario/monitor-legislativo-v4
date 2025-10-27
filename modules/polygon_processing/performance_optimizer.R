# PERFORMANCE OPTIMIZATION FRAMEWORK - PHASE 1
# Brazilian Legislative Monitoring System - Polygon Processing
# ============================================================================
# 
# High-performance optimization system for municipality-level analysis
# Railway deployment constraints: <1.4GB memory, <2s query response
# 
# Features:
# - R-tree spatial indexing equivalent for fast spatial queries
# - TTL-based caching system with automatic cleanup
# - Memory pressure monitoring and adaptive management
# - Progressive loading with intelligent chunking
# - Query optimization for 134k+ documents

library(shiny)
library(dplyr)
library(memoise)
library(pool)
library(sf)

# ============================================================================
# SPATIAL INDEXING SYSTEM (R-tree equivalent)
# ============================================================================

#' Create spatial index for fast polygon queries
#' @param polygons sf object with polygon geometries
#' @param grid_size Number of grid cells per dimension for spatial partitioning
#' @return List with spatial index structure
create_spatial_index <- function(polygons, grid_size = 10) {
  if (nrow(polygons) == 0) {
    return(list(grid = NULL, bbox = NULL, grid_size = 0))
  }
  
  tryCatch({
    # Get overall bounding box
    bbox <- sf::st_bbox(polygons)
    
    # Create grid boundaries
    x_breaks <- seq(bbox["xmin"], bbox["xmax"], length.out = grid_size + 1)
    y_breaks <- seq(bbox["ymin"], bbox["ymax"], length.out = grid_size + 1)
    
    # Assign each polygon to grid cells
    centroids <- sf::st_centroid(polygons)
    coords <- sf::st_coordinates(centroids)
    
    # Find grid cell for each polygon
    x_indices <- findInterval(coords[, 1], x_breaks)
    y_indices <- findInterval(coords[, 2], y_breaks)
    
    # Clamp indices to valid range
    x_indices <- pmax(1, pmin(x_indices, grid_size))
    y_indices <- pmax(1, pmin(y_indices, grid_size))
    
    # Create grid index
    grid_index <- list()
    for (i in 1:nrow(polygons)) {
      cell_key <- paste(x_indices[i], y_indices[i], sep = "_")
      if (is.null(grid_index[[cell_key]])) {
        grid_index[[cell_key]] <- c()
      }
      grid_index[[cell_key]] <- c(grid_index[[cell_key]], i)
    }
    
    index_structure <- list(
      grid = grid_index,
      bbox = bbox,
      grid_size = grid_size,
      x_breaks = x_breaks,
      y_breaks = y_breaks,
      total_polygons = nrow(polygons),
      created_at = Sys.time()
    )
    
    cat("🔍 Spatial index created:", length(grid_index), "grid cells,", 
        nrow(polygons), "polygons\n")
    
    return(index_structure)
    
  }, error = function(e) {
    cat("❌ Error creating spatial index:", e$message, "\n")
    return(list(grid = NULL, bbox = NULL, grid_size = 0))
  })
}

#' Query spatial index for polygons near a point
#' @param spatial_index Spatial index structure from create_spatial_index()
#' @param point_lng Longitude of query point
#' @param point_lat Latitude of query point
#' @param search_radius_cells Number of adjacent cells to search
#' @return Vector of polygon indices that might contain the point
query_spatial_index <- function(spatial_index, point_lng, point_lat, search_radius_cells = 1) {
  if (isTRUE(is.null(spatial_index$grid)) || spatial_index$grid_size == 0) {
    return(integer(0))
  }
  
  tryCatch({
    # Find grid cell for the query point
    x_cell <- findInterval(point_lng, spatial_index$x_breaks)
    y_cell <- findInterval(point_lat, spatial_index$y_breaks)
    
    # Clamp to valid range
    x_cell <- pmax(1, pmin(x_cell, spatial_index$grid_size))
    y_cell <- pmax(1, pmin(y_cell, spatial_index$grid_size))
    
    # Search in current cell and adjacent cells
    candidate_indices <- c()
    
    for (dx in -search_radius_cells:search_radius_cells) {
      for (dy in -search_radius_cells:search_radius_cells) {
        search_x <- x_cell + dx
        search_y <- y_cell + dy
        
        # Check bounds
        if (search_x >= 1 && search_x <= spatial_index$grid_size &&
            search_y >= 1 && search_y <= spatial_index$grid_size) {
          
          cell_key <- paste(search_x, search_y, sep = "_")
          if (cell_key %in% names(spatial_index$grid)) {
            candidate_indices <- c(candidate_indices, spatial_index$grid[[cell_key]])
          }
        }
      }
    }
    
    return(unique(candidate_indices))
    
  }, error = function(e) {
    cat("❌ Error querying spatial index:", e$message, "\n")
    return(integer(0))
  })
}

# ============================================================================
# TTL-BASED CACHING SYSTEM
# ============================================================================

#' Create TTL-based cache for polygon operations
#' @param ttl_seconds Time-to-live for cache entries
#' @param max_entries Maximum number of cached entries
#' @return List with cache operations
create_polygon_cache <- function(ttl_seconds = 1800, max_entries = 100) {
  cache_env <- new.env(parent = emptyenv())
  
  list(
    get = function(key) {
      if (exists(key, envir = cache_env)) {
        entry <- get(key, envir = cache_env)
        
        # Check TTL
        if (Sys.time() - entry$timestamp < ttl_seconds) {
          entry$hit_count <- entry$hit_count + 1
          entry$last_accessed <- Sys.time()
          assign(key, entry, envir = cache_env)
          return(entry$data)
        } else {
          # Remove expired entry
          rm(key, envir = cache_env)
        }
      }
      return(NULL)
    },
    
    set = function(key, value, metadata = list()) {
      # Check cache size limit
      if (length(ls(envir = cache_env)) >= max_entries) {
        # Remove least recently used entries
        cache_keys <- ls(envir = cache_env)
        lru_timestamps <- sapply(cache_keys, function(k) {
          entry <- get(k, envir = cache_env)
          entry$last_accessed %||% entry$timestamp
        })
        
        # Remove oldest 20% of entries
        oldest_keys <- names(sort(lru_timestamps)[1:max(1, floor(length(lru_timestamps) * 0.2))])
        rm(list = oldest_keys, envir = cache_env)
        cat("🧹 Cache cleanup: removed", length(oldest_keys), "old entries\n")
      }
      
      entry <- list(
        data = value,
        timestamp = Sys.time(),
        last_accessed = Sys.time(),
        hit_count = 0,
        metadata = metadata
      )
      
      assign(key, entry, envir = cache_env)
    },
    
    clear = function(pattern = NULL) {
      if (is.null(pattern)) {
        rm(list = ls(envir = cache_env), envir = cache_env)
        cat("🧹 Cache cleared completely\n")
      } else {
        matching_keys <- ls(envir = cache_env, pattern = pattern)
        rm(list = matching_keys, envir = cache_env)
        cat("🧹 Cache cleared:", length(matching_keys), "entries matching", pattern, "\n")
      }
    },
    
    stats = function() {
      keys <- ls(envir = cache_env)
      if (length(keys) == 0) {
        return(list(size = 0, total_hits = 0))
      }
      
      entries <- lapply(keys, function(k) get(k, envir = cache_env))
      total_hits <- sum(sapply(entries, function(e) e$hit_count))
      
      list(
        size = length(keys),
        total_hits = total_hits,
        avg_age_minutes = mean(as.numeric(Sys.time() - sapply(entries, function(e) e$timestamp), units = "mins"))
      )
    },
    
    size_mb = function() {
      total_size <- sum(sapply(ls(envir = cache_env), function(k) {
        object.size(get(k, envir = cache_env))
      }))
      return(as.numeric(total_size) / 1024^2)
    }
  )
}

# ============================================================================
# MEMORY PRESSURE MONITORING
# ============================================================================

#' Monitor memory pressure and trigger cleanup when needed
#' @param warning_threshold_mb Memory usage warning threshold in MB
#' @param critical_threshold_mb Critical memory usage threshold in MB
#' @return List with memory monitoring functions
create_memory_pressure_monitor <- function(warning_threshold_mb = 1100, critical_threshold_mb = 1350) {
  last_check <- Sys.time()
  check_interval <- 30  # seconds
  
  list(
    check = function() {
      current_time <- Sys.time()
      
      # Only check if enough time has passed
      if (as.numeric(current_time - last_check, units = "secs") < check_interval) {
        return(invisible())
      }
      
      last_check <<- current_time
      
      # Get memory usage
      gc_info <- gc(verbose = FALSE, reset = FALSE)
      memory_mb <- sum(gc_info[, "used"] * c(gc_info[1, "Ncells"], gc_info[2, "Vcells"]) * c(8, 8)) / 1024^2
      
      memory_status <- list(
        timestamp = current_time,
        memory_mb = round(memory_mb, 2),
        status = "normal"
      )
      
      if (memory_mb > critical_threshold_mb) {
        memory_status$status <- "critical"
        cat("🚨 CRITICAL MEMORY PRESSURE:", memory_mb, "MB (limit: 1400MB)\n")
        
        # Emergency cleanup
        if (exists("polygon_cache", envir = .GlobalEnv)) {
          polygon_cache <- get("polygon_cache", envir = .GlobalEnv)
          if ("clear" %in% names(polygon_cache)) {
            polygon_cache$clear()
          }
        }
        
        # Force garbage collection
        gc(verbose = FALSE, reset = TRUE)
        
      } else if (memory_mb > warning_threshold_mb) {
        memory_status$status <- "warning"
        cat("⚠️ Memory pressure:", memory_mb, "MB\n")
        
        # Partial cleanup
        gc(verbose = FALSE)
      }
      
      return(memory_status)
    },
    
    force_cleanup = function() {
      # Clear all polygon-related caches
      pattern_list <- c("municipality_cache", "polygon_cache", "spatial_index_cache")
      for (pattern in pattern_list) {
        if (exists(pattern, envir = .GlobalEnv)) {
          rm(list = pattern, envir = .GlobalEnv)
        }
      }
      
      # Force comprehensive garbage collection
      for (i in 1:3) {
        gc(verbose = FALSE, reset = TRUE)
      }
      
      cat("🧹 Force cleanup completed\n")
    }
  )
}

# ============================================================================
# PROGRESSIVE LOADING SYSTEM
# ============================================================================

#' Progressive data loader with intelligent chunking
#' @param total_size Total number of items to load
#' @param chunk_function Function to load a chunk (receives offset and limit)
#' @param chunk_size Size of each chunk
#' @param memory_limit_mb Memory limit for progressive loading
#' @return Combined result from all chunks
progressive_loader <- function(total_size, chunk_function, chunk_size = 1000, memory_limit_mb = 200) {
  if (total_size == 0) {
    return(NULL)
  }
  
  chunks_needed <- ceiling(total_size / chunk_size)
  all_results <- list()
  memory_monitor <- create_memory_pressure_monitor()
  
  cat("📊 Progressive loading:", total_size, "items in", chunks_needed, "chunks\n")
  
  for (i in 1:chunks_needed) {
    offset <- (i - 1) * chunk_size
    limit <- min(chunk_size, total_size - offset)
    
    # Memory check before loading chunk
    memory_status <- memory_monitor$check()
    if (memory_status$status == "critical") {
      cat("🛑 Stopping progressive load due to memory pressure\n")
      break
    }
    
    tryCatch({
      chunk_result <- chunk_function(offset, limit)
      if (!isTRUE(is.null(chunk_result)) && nrow(chunk_result) > 0) {
        all_results[[i]] <- chunk_result
      }
      
      # Progress indicator
      progress <- round((i / chunks_needed) * 100, 1)
      cat(sprintf("📈 Progress: %d/%d chunks (%.1f%%)\n", i, chunks_needed, progress))
      
      # Memory management every 5 chunks
      if (i %% 5 == 0) {
        gc(verbose = FALSE)
        
        # Check if we're approaching memory limits
        current_memory <- memory_monitor$check()$memory_mb
        if (current_memory > memory_limit_mb) {
          cat("⚠️ Approaching memory limit, adjusting chunk size\n")
          chunk_size <- max(100, chunk_size * 0.8)  # Reduce chunk size by 20%
        }
      }
      
    }, error = function(e) {
      cat("❌ Error loading chunk", i, ":", e$message, "\n")
    })
  }
  
  # Combine all results
  if (length(all_results) > 0) {
    combined_result <- bind_rows(all_results)
    cat("✅ Progressive loading complete:", nrow(combined_result), "items loaded\n")
    return(combined_result)
  } else {
    return(NULL)
  }
}

# ============================================================================
# QUERY OPTIMIZATION
# ============================================================================

#' Optimize spatial queries for large document datasets
#' @param query_function Function that performs the query
#' @param cache_key Unique key for caching the query result
#' @param timeout_ms Maximum query time in milliseconds
#' @return Optimized query result
optimize_spatial_query <- function(query_function, cache_key = NULL, timeout_ms = 2000) {
  start_time <- Sys.time()
  
  # Check cache first if key provided
  if (!isTRUE(is.null(cache_key)) && exists("polygon_cache", envir = .GlobalEnv)) {
    polygon_cache <- get("polygon_cache", envir = .GlobalEnv)
    cached_result <- polygon_cache$get(cache_key)
    if (!is.null(cached_result)) {
      cat("⚡ Using cached query result for", cache_key, "\n")
      return(cached_result)
    }
  }
  
  # Execute query with timeout protection
  tryCatch({
    # Create a promise for the query (simplified timeout simulation)
    query_result <- query_function()
    
    execution_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
    
    # Performance check
    if (execution_time > timeout_ms) {
      cat("⚠️ Query exceeded timeout:", round(execution_time, 0), "ms (limit:", timeout_ms, "ms)\n")
    } else {
      cat("⚡ Query completed in", round(execution_time, 0), "ms\n")
    }
    
    # Cache the result if key provided
    if (!isTRUE(is.null(cache_key)) && exists("polygon_cache", envir = .GlobalEnv)) {
      polygon_cache <- get("polygon_cache", envir = .GlobalEnv)
      polygon_cache$set(cache_key, query_result, list(
        execution_time_ms = execution_time,
        cached_at = Sys.time()
      ))
    }
    
    return(query_result)
    
  }, error = function(e) {
    execution_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
    cat("❌ Query failed after", round(execution_time, 0), "ms:", e$message, "\n")
    return(NULL)
  })
}

#' Create batch processor for multiple spatial operations
#' @param operations List of operations to batch process
#' @param batch_size Size of each batch
#' @return List of results from batch processing
batch_process_spatial_operations <- function(operations, batch_size = 10) {
  if (length(operations) == 0) {
    return(list())
  }
  
  batches <- split(operations, ceiling(seq_along(operations) / batch_size))
  all_results <- list()
  memory_monitor <- create_memory_pressure_monitor()
  
  cat("⚙️ Batch processing", length(operations), "operations in", length(batches), "batches\n")
  
  for (i in seq_along(batches)) {
    batch <- batches[[i]]
    
    # Memory check
    memory_status <- memory_monitor$check()
    if (memory_status$status == "critical") {
      cat("🛑 Stopping batch processing due to memory pressure\n")
      break
    }
    
    tryCatch({
      batch_results <- lapply(batch, function(op) {
        if (is.function(op)) {
          return(op())
        } else if (is.list(op) && "func" %in% names(op)) {
          return(do.call(op$func, op$args %||% list()))
        } else {
          return(NULL)
        }
      })
      
      all_results <- c(all_results, batch_results)
      
      cat("📊 Batch", i, "/", length(batches), "completed\n")
      
      # Memory management between batches
      if (i %% 3 == 0) {
        gc(verbose = FALSE)
      }
      
    }, error = function(e) {
      cat("❌ Error processing batch", i, ":", e$message, "\n")
    })
  }
  
  cat("✅ Batch processing complete:", length(all_results), "results\n")
  return(all_results)
}

# ============================================================================
# MODULE EXPORTS
# ============================================================================

# Initialize global cache if not exists
if (!exists("polygon_cache", envir = .GlobalEnv)) {
  assign("polygon_cache", create_polygon_cache(), envir = .GlobalEnv)
}

performance_optimizer_exports <- list(
  # Spatial indexing
  create_spatial_index = create_spatial_index,
  query_spatial_index = query_spatial_index,
  
  # Caching system
  create_polygon_cache = create_polygon_cache,
  
  # Memory monitoring
  create_memory_pressure_monitor = create_memory_pressure_monitor,
  
  # Progressive loading
  progressive_loader = progressive_loader,
  
  # Query optimization
  optimize_spatial_query = optimize_spatial_query,
  batch_process_spatial_operations = batch_process_spatial_operations
)

cat("✅ Performance Optimization Framework loaded successfully\n")
cat("   Spatial indexing: ENABLED\n")
cat("   TTL caching: ENABLED (", exists("polygon_cache", envir = .GlobalEnv), ")\n")
cat("   Memory monitoring: ENABLED\n")
cat("   Progressive loading: ENABLED\n")