#!/usr/bin/env Rscript
#' Performance Optimization for Large-Scale Spatial Analytics
#' 
#' Optimized algorithms and data structures for processing 134k+ legislative documents
#' across 5,570+ municipalities with Railway deployment compatibility.
#' Memory-efficient, parallel-processed, and scalable implementations.
#' 
#' @author Brazilian Legislative Analytics Framework - Performance Module
#' @date 2025-09-01
#' @version 2.0.0

suppressPackageStartupMessages({
  # High-performance computing
  library(data.table)
  library(dtplyr)
  library(future)
  library(future.apply)
  library(furrr)
  library(parallel)
  library(doParallel)
  library(foreach)
  
  # Memory management
  library(memoise)
  library(R.utils)
  library(pryr)
  library(gc)
  
  # Fast algorithms
  library(RcppArmadillo)
  library(RcppEigen)
  library(fastmap)
  library(fastmatch)
  library(collapse)
  
  # Efficient spatial processing
  library(sf)
  library(lwgeom)
  library(stars)
  library(exactextractr)
  
  # Database optimization
  library(DBI)
  library(RSQLite)
  library(arrow)
  library(duckdb)
  
  # Sampling and approximation
  library(sampling)
  library(VIM)
  library(mice)
  
  library(logger)
})

#' Performance Optimization Framework
#' ==================================

#' Initialize High-Performance Computing Environment
#' @param max_workers Maximum number of parallel workers
#' @param memory_limit Memory limit in GB
#' @param cache_size Cache size in MB
#' @return Optimized computing environment
initialize_hpc_environment <- function(max_workers = NULL, memory_limit = 8, cache_size = 1000) {
  
  log_info("Initializing high-performance computing environment...")
  
  # Determine optimal number of workers
  if (is.null(max_workers)) {
    available_cores <- parallel::detectCores()
    max_workers <- max(1, min(available_cores - 1, 8))  # Conservative for Railway
  }
  
  # Set up parallel processing
  plan(multisession, workers = max_workers)
  
  # Configure memory management
  memory_limit_bytes <- memory_limit * 1024^3
  if (.Platform$OS.type == "unix") {
    try(R.utils::setOption("future.globals.maxSize", memory_limit_bytes), silent = TRUE)
  }
  
  # Initialize caching system
  cache_options <- list(
    cache_size_mb = cache_size,
    evict_policy = "lru",
    compress = TRUE
  )
  
  # Optimize garbage collection
  gcinfo(TRUE)
  
  # Configure data.table
  setDTthreads(max_workers)
  
  # Set up optimized spatial operations
  sf_use_s2(FALSE)  # Use planar coordinates for better performance
  
  environment_config <- list(
    max_workers = max_workers,
    memory_limit_gb = memory_limit,
    cache_size_mb = cache_size,
    available_cores = available_cores,
    cache_options = cache_options,
    
    # Performance monitoring
    start_time = Sys.time(),
    memory_usage = pryr::mem_used(),
    
    # Utility functions
    monitor_performance = function() {
      list(
        current_memory = pryr::mem_used(),
        elapsed_time = difftime(Sys.time(), environment_config$start_time, units = "mins"),
        active_workers = future::nbrOfWorkers()
      )
    },
    
    cleanup = function() {
      plan(sequential)
      gc(verbose = FALSE)
      log_info("HPC environment cleaned up")
    }
  )
  
  log_info("HPC environment initialized: {max_workers} workers, {memory_limit}GB memory limit")
  
  return(environment_config)
}

#' Memory-Efficient Municipality Data Loading
#' @param data_source Data source path or connection
#' @param chunk_size Number of rows to process at once
#' @param states Optional state filter for memory savings
#' @return Optimized municipality data loader
create_optimized_municipality_loader <- function(data_source, chunk_size = 10000, states = NULL) {
  
  log_info("Creating optimized municipality data loader...")
  
  # Create data reader with chunking
  if (is.character(data_source) && grepl("\\.parquet$", data_source)) {
    # Arrow-based parquet reading
    data_reader <- function() {
      arrow::open_dataset(data_source) %>%
        {if (!is.null(states)) filter(., estado %in% states) else .} %>%
        collect()
    }
  } else {
    # Generic data reader
    data_reader <- function() {
      if (is.character(data_source)) {
        data.table::fread(data_source)
      } else {
        as.data.table(data_source)
      }
    }
  }
  
  # Memoized data loader
  cached_loader <- memoise::memoise(data_reader, cache = memoise::cache_filesystem(".cache/data"))
  
  # Chunked processing function
  process_in_chunks <- function(processing_function, ...) {
    
    log_info("Processing data in chunks of {chunk_size}...")
    
    # Load data
    full_data <- cached_loader()
    
    # Calculate chunks
    n_rows <- nrow(full_data)
    n_chunks <- ceiling(n_rows / chunk_size)
    
    # Process chunks in parallel
    chunk_results <- future_map(1:n_chunks, function(i) {
      start_row <- (i - 1) * chunk_size + 1
      end_row <- min(i * chunk_size, n_rows)
      
      chunk_data <- full_data[start_row:end_row, ]
      
      tryCatch({
        processing_function(chunk_data, ...)
      }, error = function(e) {
        log_warn("Chunk {i} processing failed: {e$message}")
        return(NULL)
      })
    }, .progress = TRUE)
    
    # Combine results
    chunk_results[!sapply(chunk_results, is.null)]
  }
  
  loader_system <- list(
    data_reader = cached_loader,
    process_in_chunks = process_in_chunks,
    chunk_size = chunk_size,
    states_filter = states,
    
    # Utility functions
    get_data_info = function() {
      data <- cached_loader()
      list(
        n_rows = nrow(data),
        n_cols = ncol(data),
        memory_size = object.size(data),
        column_names = names(data)
      )
    },
    
    clear_cache = function() {
      memoise::forget(cached_loader)
      log_info("Data cache cleared")
    }
  )
  
  log_info("Optimized municipality loader created")
  
  return(loader_system)
}

#' Fast Spatial Operations
#' @param boundaries Municipality boundaries
#' @param max_simplification Maximum simplification tolerance
#' @return Optimized spatial operations
create_fast_spatial_operations <- function(boundaries, max_simplification = 0.001) {
  
  log_info("Creating fast spatial operations...")
  
  # Pre-process boundaries for performance
  optimized_boundaries <- boundaries %>%
    # Simplify geometry for faster operations
    st_simplify(dTolerance = max_simplification, preserveTopology = TRUE) %>%
    # Ensure valid geometry
    st_make_valid() %>%
    # Convert to planar coordinate system for faster calculations
    st_transform(crs = 3857)  # Web Mercator for fast calculations
  
  # Pre-compute centroids
  centroids <- st_centroid(optimized_boundaries)
  centroid_coords <- st_coordinates(centroids)
  
  # Pre-compute spatial weights matrices (memoized)
  create_weights_fast <- memoise::memoise(function(method = "queen", k = 6) {
    
    log_info("Computing spatial weights: {method}")
    
    if (method == "queen") {
      # Fast contiguity weights
      neighbors <- spdep::poly2nb(as(optimized_boundaries, "Spatial"), queen = TRUE)
      weights <- spdep::nb2listw(neighbors, style = "W", zero.policy = TRUE)
      
    } else if (method == "knn") {
      # K-nearest neighbors
      knn_nb <- spdep::knn2nb(spdep::knearneigh(centroid_coords, k = k))
      weights <- spdep::nb2listw(knn_nb, style = "W", zero.policy = TRUE)
      
    } else if (method == "distance") {
      # Distance-based (with optimized threshold)
      threshold <- estimate_optimal_distance_threshold(centroid_coords)
      dist_nb <- spdep::dnearneigh(centroid_coords, 0, threshold)
      weights <- spdep::nb2listw(dist_nb, style = "W", zero.policy = TRUE)
    }
    
    return(weights)
  }, cache = memoise::cache_memory())
  
  # Fast spatial join function
  fast_spatial_join <- function(points_data, aggregate_function = "count") {
    
    # Convert points to spatial
    if (!inherits(points_data, "sf")) {
      points_sf <- st_as_sf(points_data, 
                           coords = c("longitude", "latitude"), 
                           crs = 4326) %>%
        st_transform(3857)
    } else {
      points_sf <- st_transform(points_data, 3857)
    }
    
    # Fast spatial join using sf
    joined <- st_join(optimized_boundaries, points_sf, join = st_intersects)
    
    # Aggregate by municipality
    if (aggregate_function == "count") {
      result <- joined %>%
        st_drop_geometry() %>%
        group_by(code_muni, name_muni) %>%
        summarise(count = n(), .groups = "drop")
    }
    
    return(result)
  }
  
  # Fast hotspot detection
  fast_hotspot_detection <- function(values, method = "getis_ord", significance = 0.05) {
    
    weights <- create_weights_fast("queen")
    
    if (method == "getis_ord") {
      # Getis-Ord Gi* statistics
      gi_star <- spdep::localG(values, weights, zero.policy = TRUE)
      
      # Classification
      hotspots <- case_when(
        gi_star > qnorm(1 - significance/2) ~ "Hot",
        gi_star < qnorm(significance/2) ~ "Cold",
        TRUE ~ "Not significant"
      )
      
    } else if (method == "lisa") {
      # Local Moran's I
      lisa <- spdep::localmoran(values, weights, zero.policy = TRUE)
      
      hotspots <- case_when(
        lisa[, 5] < significance & lisa[, 1] > 0 & values > median(values, na.rm = TRUE) ~ "High-High",
        lisa[, 5] < significance & lisa[, 1] > 0 & values <= median(values, na.rm = TRUE) ~ "Low-Low",
        lisa[, 5] < significance & lisa[, 1] < 0 & values > median(values, na.rm = TRUE) ~ "High-Low",
        lisa[, 5] < significance & lisa[, 1] < 0 & values <= median(values, na.rm = TRUE) ~ "Low-High",
        TRUE ~ "Not significant"
      )
    }
    
    return(list(
      classification = hotspots,
      statistics = if (method == "getis_ord") gi_star else lisa,
      method = method
    ))
  }
  
  spatial_ops <- list(
    boundaries = optimized_boundaries,
    centroids = centroids,
    centroid_coords = centroid_coords,
    create_weights = create_weights_fast,
    spatial_join = fast_spatial_join,
    hotspot_detection = fast_hotspot_detection,
    
    # Performance utilities
    get_memory_usage = function() {
      object.size(optimized_boundaries) + object.size(centroids)
    },
    
    benchmark_operation = function(operation_function, n_iterations = 10) {
      times <- replicate(n_iterations, {
        system.time(operation_function())[["elapsed"]]
      })
      
      list(
        mean_time = mean(times),
        sd_time = sd(times),
        min_time = min(times),
        max_time = max(times)
      )
    }
  )
  
  log_info("Fast spatial operations created for {nrow(optimized_boundaries)} boundaries")
  
  return(spatial_ops)
}

#' Intelligent Sampling for Large Datasets
#' @param data Full dataset
#' @param target_size Target sample size
#' @param sampling_method Sampling method
#' @param stratify_by Stratification variables
#' @return Optimized sampling system
create_intelligent_sampling_system <- function(data, target_size = 50000, 
                                              sampling_method = "stratified", 
                                              stratify_by = c("estado", "year")) {
  
  log_info("Creating intelligent sampling system...")
  
  # Assess data characteristics
  data_summary <- data %>%
    summarise(
      n_rows = n(),
      n_municipalities = n_distinct(municipio, na.rm = TRUE),
      n_states = n_distinct(estado, na.rm = TRUE),
      year_range = paste(min(year(data), na.rm = TRUE), "-", max(year(data), na.rm = TRUE)),
      memory_size = object.size(cur_data())
    )
  
  log_info("Dataset summary: {data_summary$n_rows} rows, {data_summary$n_municipalities} municipalities")
  
  # Create sampling function
  create_sample <- function(method = sampling_method, size = target_size) {
    
    if (nrow(data) <= size) {
      log_info("Dataset smaller than target size, returning full data")
      return(data)
    }
    
    sample_data <- switch(method,
      "simple" = {
        data %>% slice_sample(n = size)
      },
      
      "stratified" = {
        # Stratified sampling preserving structure
        data %>%
          group_by(across(all_of(stratify_by))) %>%
          slice_sample(n = max(1, round(size / n_distinct(interaction(!!!syms(stratify_by)))))) %>%
          ungroup() %>%
          slice_sample(n = min(nrow(.), size))
      },
      
      "systematic" = {
        # Systematic sampling
        sampling_interval <- ceiling(nrow(data) / size)
        data %>% slice(seq(1, nrow(.), by = sampling_interval))
      },
      
      "balanced" = {
        # Balanced sampling using auxiliary information
        # This would use the 'sampling' package for complex balanced sampling
        data %>% slice_sample(n = size, weight_by = importance_weight)
      }
    )
    
    log_info("Sample created: {nrow(sample_data)} rows ({round(nrow(sample_data)/nrow(data)*100, 1)}%)")
    
    return(sample_data)
  }
  
  # Validate sample representativeness
  validate_sample <- function(sample_data) {
    
    # Compare distributions
    original_distribution <- data %>%
      group_by(across(all_of(stratify_by))) %>%
      summarise(count = n(), .groups = "drop") %>%
      mutate(proportion = count / sum(count))
    
    sample_distribution <- sample_data %>%
      group_by(across(all_of(stratify_by))) %>%
      summarise(count = n(), .groups = "drop") %>%
      mutate(proportion = count / sum(count))
    
    # Calculate representativeness metrics
    comparison <- original_distribution %>%
      left_join(sample_distribution, by = stratify_by, suffix = c("_orig", "_sample")) %>%
      mutate(
        proportion_diff = abs(proportion_orig - proportion_sample),
        relative_error = proportion_diff / proportion_orig
      )
    
    validation_metrics <- list(
      max_absolute_diff = max(comparison$proportion_diff, na.rm = TRUE),
      mean_relative_error = mean(comparison$relative_error, na.rm = TRUE),
      coverage = sum(!is.na(comparison$proportion_sample)) / nrow(original_distribution),
      representativeness_score = 1 - mean(comparison$relative_error, na.rm = TRUE)
    )
    
    return(validation_metrics)
  }
  
  # Adaptive sampling
  create_adaptive_sample <- function(initial_size = target_size, quality_threshold = 0.9) {
    
    current_size <- initial_size
    best_sample <- NULL
    best_quality <- 0
    
    for (attempt in 1:5) {
      sample_candidate <- create_sample(size = current_size)
      quality <- validate_sample(sample_candidate)$representativeness_score
      
      if (quality > best_quality) {
        best_sample <- sample_candidate
        best_quality <- quality
      }
      
      if (best_quality >= quality_threshold) break
      
      # Adjust sample size
      current_size <- round(current_size * 1.2)  # Increase by 20%
    }
    
    log_info("Adaptive sampling completed: quality = {round(best_quality, 3)}")
    
    return(list(
      sample = best_sample,
      quality = best_quality,
      final_size = nrow(best_sample)
    ))
  }
  
  sampling_system <- list(
    create_sample = create_sample,
    validate_sample = validate_sample,
    create_adaptive_sample = create_adaptive_sample,
    data_summary = data_summary,
    sampling_method = sampling_method,
    target_size = target_size,
    stratify_by = stratify_by
  )
  
  log_info("Intelligent sampling system created")
  
  return(sampling_system)
}

#' Efficient Caching System
#' @param cache_dir Cache directory
#' @param max_cache_size Maximum cache size in MB
#' @return Advanced caching system
create_efficient_caching_system <- function(cache_dir = ".cache/spatial", max_cache_size = 2000) {
  
  log_info("Creating efficient caching system...")
  
  dir.create(cache_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Cache management utilities
  get_cache_info <- function() {
    cache_files <- list.files(cache_dir, recursive = TRUE, full.names = TRUE)
    
    if (length(cache_files) == 0) {
      return(list(n_files = 0, total_size_mb = 0, files = character(0)))
    }
    
    file_sizes <- file.size(cache_files)
    total_size <- sum(file_sizes, na.rm = TRUE) / (1024^2)  # Convert to MB
    
    list(
      n_files = length(cache_files),
      total_size_mb = total_size,
      files = data.frame(
        path = cache_files,
        size_mb = file_sizes / (1024^2),
        modified = file.mtime(cache_files),
        stringsAsFactors = FALSE
      )
    )
  }
  
  # Cleanup old cache files
  cleanup_cache <- function(max_age_days = 7) {
    cache_info <- get_cache_info()
    
    if (cache_info$n_files == 0) return()
    
    old_files <- cache_info$files[
      difftime(Sys.time(), cache_info$files$modified, units = "days") > max_age_days, 
    ]
    
    if (nrow(old_files) > 0) {
      file.remove(old_files$path)
      log_info("Removed {nrow(old_files)} old cache files")
    }
    
    # Size-based cleanup
    current_info <- get_cache_info()
    if (current_info$total_size_mb > max_cache_size) {
      # Remove largest files first
      files_by_size <- current_info$files[order(-current_info$files$size_mb), ]
      size_removed <- 0
      
      for (i in 1:nrow(files_by_size)) {
        file.remove(files_by_size$path[i])
        size_removed <- size_removed + files_by_size$size_mb[i]
        
        if (size_removed > (current_info$total_size_mb - max_cache_size)) break
      }
      
      log_info("Cache size reduced by {round(size_removed, 1)} MB")
    }
  }
  
  # Smart cache key generation
  generate_cache_key <- function(...) {
    args <- list(...)
    key_string <- paste(sapply(args, function(x) {
      if (is.data.frame(x)) {
        return(paste(dim(x), collapse = "x"))
      } else if (is.function(x)) {
        return(deparse(substitute(x)))
      } else {
        return(as.character(x))
      }
    }), collapse = "_")
    
    # Create hash
    digest::digest(key_string, algo = "sha256", serialize = FALSE)
  }
  
  # Cached computation wrapper
  cached_compute <- function(computation_function, key_components, force_refresh = FALSE) {
    
    cache_key <- generate_cache_key(key_components)
    cache_file <- file.path(cache_dir, paste0(cache_key, ".rds"))
    
    # Check if cached result exists
    if (!force_refresh && file.exists(cache_file)) {
      tryCatch({
        cached_result <- readRDS(cache_file)
        log_info("Using cached result: {substr(cache_key, 1, 8)}...")
        return(cached_result)
      }, error = function(e) {
        log_warn("Cache read failed: {e$message}")
      })
    }
    
    # Compute result
    log_info("Computing result for cache key: {substr(cache_key, 1, 8)}...")
    result <- computation_function()
    
    # Cache result
    tryCatch({
      saveRDS(result, cache_file)
      log_info("Result cached: {substr(cache_key, 1, 8)}...")
    }, error = function(e) {
      log_warn("Cache write failed: {e$message}")
    })
    
    return(result)
  }
  
  caching_system <- list(
    cache_dir = cache_dir,
    get_cache_info = get_cache_info,
    cleanup_cache = cleanup_cache,
    generate_cache_key = generate_cache_key,
    cached_compute = cached_compute,
    
    # Convenience functions
    clear_all_cache = function() {
      unlink(cache_dir, recursive = TRUE)
      dir.create(cache_dir, recursive = TRUE)
      log_info("All cache cleared")
    },
    
    cache_statistics = function() {
      info <- get_cache_info()
      list(
        files = info$n_files,
        size_mb = round(info$total_size_mb, 2),
        utilization = round(info$total_size_mb / max_cache_size * 100, 1)
      )
    }
  )
  
  # Initial cleanup
  cleanup_cache()
  
  log_info("Efficient caching system created in {cache_dir}")
  
  return(caching_system)
}

#' Performance Monitoring and Profiling
#' @param analysis_function Function to profile
#' @return Performance analysis results
create_performance_profiler <- function() {
  
  log_info("Creating performance profiler...")
  
  # Memory monitoring
  monitor_memory <- function(func, ...) {
    
    gc(verbose = FALSE)  # Clean up before measuring
    
    start_memory <- pryr::mem_used()
    start_time <- Sys.time()
    
    result <- func(...)
    
    end_time <- Sys.time()
    end_memory <- pryr::mem_used()
    
    performance_metrics <- list(
      execution_time = difftime(end_time, start_time, units = "secs"),
      memory_used = end_memory - start_memory,
      peak_memory = pryr::mem_used(),
      result = result
    )
    
    return(performance_metrics)
  }
  
  # Parallel performance testing
  test_parallel_performance <- function(func, data, worker_counts = c(1, 2, 4, 8)) {
    
    results <- map_dfr(worker_counts, function(workers) {
      
      # Set up parallel processing
      plan(multisession, workers = workers)
      
      # Measure performance
      performance <- monitor_memory(func, data)
      
      data.frame(
        workers = workers,
        execution_time = as.numeric(performance$execution_time),
        memory_used = as.numeric(performance$memory_used),
        speedup = ifelse(workers == 1, 1, 
                        results$execution_time[results$workers == 1] / as.numeric(performance$execution_time))
      )
    })
    
    # Reset to sequential
    plan(sequential)
    
    return(results)
  }
  
  # Benchmark different approaches
  benchmark_approaches <- function(approaches, data, n_iterations = 5) {
    
    benchmark_results <- map_dfr(names(approaches), function(approach_name) {
      
      approach_func <- approaches[[approach_name]]
      
      times <- replicate(n_iterations, {
        performance <- monitor_memory(approach_func, data)
        as.numeric(performance$execution_time)
      })
      
      data.frame(
        approach = approach_name,
        mean_time = mean(times),
        sd_time = sd(times),
        min_time = min(times),
        max_time = max(times)
      )
    })
    
    # Add relative performance
    benchmark_results$relative_performance <- benchmark_results$mean_time / min(benchmark_results$mean_time)
    
    return(benchmark_results)
  }
  
  profiler <- list(
    monitor_memory = monitor_memory,
    test_parallel_performance = test_parallel_performance,
    benchmark_approaches = benchmark_approaches,
    
    # System information
    get_system_info = function() {
      list(
        r_version = R.version.string,
        platform = R.version$platform,
        cores = parallel::detectCores(),
        memory_gb = round(as.numeric(system("awk '/MemTotal/ {print $2}' /proc/meminfo", intern = TRUE)) / 1024^2, 2),
        current_workers = future::nbrOfWorkers()
      )
    }
  )
  
  log_info("Performance profiler created")
  
  return(profiler)
}

# Utility functions
estimate_optimal_distance_threshold <- function(coords, target_neighbors = 6) {
  # Estimate optimal distance threshold for spatial weights
  n_points <- nrow(coords)
  sample_size <- min(1000, n_points)  # Use sample for large datasets
  
  if (n_points > sample_size) {
    sample_idx <- sample(n_points, sample_size)
    sample_coords <- coords[sample_idx, ]
  } else {
    sample_coords <- coords
  }
  
  # Calculate distances to k-th nearest neighbor
  distances <- fields::rdist(sample_coords)
  kth_distances <- apply(distances, 1, function(x) sort(x)[target_neighbors + 1])  # +1 to exclude self
  
  # Use median as threshold
  threshold <- median(kth_distances, na.rm = TRUE)
  
  return(threshold)
}

log_info("Performance optimization framework loaded successfully")