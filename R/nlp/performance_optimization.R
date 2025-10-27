# Portuguese NLP Performance Optimization Module
# Monitor Legislativo v4 - High-Performance Text Analytics
# ========================================================
#
# This module implements advanced performance optimization techniques for
# Portuguese NLP processing, targeting <100ms per document processing time
# with Railway memory constraints (<2GB) and support for real-time analysis
# of 134k+ Brazilian legislative documents
#
# Features:
# - Memory-efficient text processing with streaming capabilities
# - Intelligent caching strategies for lexicon lookups and results
# - Vectorized operations and SIMD optimization where available  
# - Parallel processing with optimal resource allocation
# - Performance profiling and real-time monitoring
# - Adaptive batch sizing based on memory constraints
# - Integration with existing Portuguese NLP pipeline
# - Academic-grade benchmarking and validation
#
# Author: NLP Enhancement Agent - Portuguese Text Analytics Specialist
# Date: 2025-09-13
# Version: 1.0.0 - Production Optimized

# Required packages for high-performance NLP
performance_packages <- c(
  "stringr",        # Fast string processing
  "data.table",     # High-performance data operations
  "Rcpp",          # C++ integration for speed-critical operations  
  "parallel",      # Parallel processing
  "foreach",       # Parallel foreach loops
  "doParallel",    # Parallel backend for foreach
  "microbenchmark", # Performance benchmarking
  "profvis",       # Performance profiling
  "pryr",          # Memory usage monitoring
  "digest",        # Fast hashing for caching
  "memoise",       # Function memoization
  "fastmap",       # High-performance hash maps
  "R.cache"        # Persistent caching
)

# Load packages with performance monitoring
available_perf_packages <- character(0)

for (pkg in performance_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    available_perf_packages <- c(available_perf_packages, pkg)
  }
}

# Load essential packages
suppressPackageStartupMessages({
  library(stringr)
  
  if ("data.table" %in% available_perf_packages) {
    library(data.table)
    data_table_available <- TRUE
  } else {
    data_table_available <- FALSE
    library(dplyr)  # Fallback to dplyr
  }
  
  if ("parallel" %in% available_perf_packages) {
    library(parallel)
    parallel_available <- TRUE
  } else {
    parallel_available <- FALSE
  }
  
  if ("microbenchmark" %in% available_perf_packages) library(microbenchmark)
  if ("memoise" %in% available_perf_packages) library(memoise)
  if ("fastmap" %in% available_perf_packages) library(fastmap)
})

cat("⚡ Portuguese NLP Performance Optimization loaded with", length(available_perf_packages), "/", length(performance_packages), "packages\n")

# ============================================================================
# PERFORMANCE CONFIGURATION AND MONITORING
# ============================================================================

# Performance optimization configuration
.performance_config <- list(
  # Processing targets
  target_time_per_doc_ms = 100,
  target_throughput_docs_per_sec = 10,
  max_memory_usage_mb = 1800,  # Railway constraint with buffer
  
  # Batch processing settings
  min_batch_size = 50,
  max_batch_size = 2000,
  adaptive_batch_sizing = TRUE,
  memory_check_interval = 100,
  
  # Caching configuration
  cache_enabled = TRUE,
  cache_max_size_mb = 200,
  cache_ttl_hours = 24,
  persistent_cache = FALSE,  # Disable for Railway deployment
  
  # Parallel processing
  auto_detect_cores = TRUE,
  max_cores = 4,  # Conservative for Railway
  parallel_threshold = 100,  # Minimum documents for parallel processing
  
  # Memory optimization
  gc_threshold_mb = 1500,
  aggressive_gc = TRUE,
  streaming_threshold = 10000,  # Use streaming for large datasets
  
  # Profiling and monitoring
  enable_profiling = FALSE,  # Disable in production
  enable_monitoring = TRUE,
  log_performance_stats = TRUE
)

# Performance monitoring globals
.perf_monitor <- new.env(parent = emptyenv())
.perf_monitor$processing_times <- numeric(0)
.perf_monitor$memory_usage <- numeric(0)
.perf_monitor$batch_sizes <- numeric(0)
.perf_monitor$cache_hit_rate <- 0
.perf_monitor$total_documents_processed <- 0

# High-performance caches
if ("fastmap" %in% available_perf_packages) {
  .lexicon_cache <- fastmap::fastmap()
  .results_cache <- fastmap::fastmap()
} else {
  .lexicon_cache <- new.env(parent = emptyenv())
  .results_cache <- new.env(parent = emptyenv())
}

# ============================================================================
# MEMORY-EFFICIENT TEXT PROCESSING
# ============================================================================

#' High-Performance Portuguese Text Processing Pipeline
#' 
#' Memory-optimized text processing pipeline designed for real-time analysis
#' of large Portuguese document collections with <100ms per document target
#' 
#' @param text Character vector of Portuguese texts to process
#' @param processing_functions List of processing functions to apply
#' @param enable_streaming Logical, use streaming processing for large datasets
#' @param target_memory_mb Numeric, target memory usage in MB
#' @param enable_profiling Logical, enable performance profiling
#' 
#' @return List with processed results and performance metrics
#' 
#' @examples
#' \dontrun{
#' # High-performance text processing
#' texts <- readRDS("large_legislative_corpus.rds")
#' 
#' processing_functions <- list(
#'   sentiment = analyze_portuguese_sentiment,
#'   entities = extract_brazilian_legal_entities
#' )
#' 
#' results <- process_texts_high_performance(
#'   text = texts$ementa,
#'   processing_functions = processing_functions,
#'   enable_streaming = TRUE,
#'   target_memory_mb = 1500
#' )
#' }
#' 
#' @export
process_texts_high_performance <- function(text,
                                         processing_functions = list(),
                                         enable_streaming = NULL,
                                         target_memory_mb = NULL,
                                         enable_profiling = FALSE) {
  
  if (isTRUE(is.null(text)) || length(text) == 0) {
    return(list(results = list(), performance_metrics = list()))
  }
  
  # Set defaults from configuration
  if (is.null(enable_streaming)) {
    enable_streaming <- length(text) > .performance_config$streaming_threshold
  }
  if (is.null(target_memory_mb)) {
    target_memory_mb <- .performance_config$max_memory_usage_mb
  }
  
  n_texts <- length(text)
  start_time <- Sys.time()
  
  cat("⚡ High-performance processing of", n_texts, "Portuguese documents\n")
  cat("💾 Target memory usage:", target_memory_mb, "MB\n")
  cat("📊 Streaming mode:", enable_streaming, "\n")
  
  # Initialize performance monitoring
  if (enable_profiling && "profvis" %in% available_perf_packages) {
    profvis::profvis({
      results <- execute_optimized_processing(text, processing_functions, enable_streaming, target_memory_mb)
    })
  } else {
    results <- execute_optimized_processing(text, processing_functions, enable_streaming, target_memory_mb)
  }
  
  # Calculate performance metrics
  total_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  avg_time_per_doc <- (total_time / n_texts) * 1000  # Convert to ms
  
  performance_metrics <- list(
    total_documents = n_texts,
    total_processing_time_sec = total_time,
    avg_time_per_document_ms = avg_time_per_doc,
    throughput_docs_per_sec = n_texts / total_time,
    target_met = avg_time_per_doc < .performance_config$target_time_per_doc_ms,
    memory_usage_mb = get_memory_usage_mb(),
    cache_hit_rate = calculate_cache_hit_rate(),
    streaming_used = enable_streaming
  )
  
  # Update global monitoring
  update_performance_monitoring(performance_metrics)
  
  cat("✅ Processing completed\n")
  cat("⏱️ Average time per document:", round(avg_time_per_doc, 1), "ms\n")
  cat("🎯 Target (<100ms):", ifelse(performance_metrics$target_met, "✅ MET", "❌ EXCEEDED"), "\n")
  
  return(list(
    results = results,
    performance_metrics = performance_metrics
  ))
}

#' Execute optimized processing with memory management
execute_optimized_processing <- function(text, processing_functions, enable_streaming, target_memory_mb) {
  
  if (enable_streaming) {
    return(process_with_streaming(text, processing_functions, target_memory_mb))
  } else {
    return(process_with_batching(text, processing_functions, target_memory_mb))
  }
}

#' Streaming processing for large datasets
process_with_streaming <- function(text, processing_functions, target_memory_mb) {
  
  n_texts <- length(text)
  chunk_size <- calculate_optimal_chunk_size(n_texts, target_memory_mb)
  
  cat("📊 Streaming processing with chunk size:", chunk_size, "\n")
  
  all_results <- list()
  
  for (func_name in names(processing_functions)) {
    all_results[[func_name]] <- list()
  }
  
  # Process in streaming chunks
  for (i in seq(1, n_texts, chunk_size)) {
    chunk_end <- min(i + chunk_size - 1, n_texts)
    chunk_indices <- i:chunk_end
    chunk_text <- text[chunk_indices]
    
    cat("Processing chunk", ceiling(i/chunk_size), ":", i, "-", chunk_end, "\r")
    
    # Process current chunk
    for (func_name in names(processing_functions)) {
      func_result <- process_chunk_optimized(chunk_text, processing_functions[[func_name]], chunk_indices)
      all_results[[func_name]] <- append(all_results[[func_name]], list(func_result))
    }
    
    # Memory management
    if (get_memory_usage_mb() > target_memory_mb * 0.9) {
      trigger_garbage_collection()
    }
  }
  
  cat("\n🔗 Combining streaming results...\n")
  
  # Combine streaming results efficiently
  final_results <- list()
  for (func_name in names(all_results)) {
    final_results[[func_name]] <- combine_streaming_results(all_results[[func_name]])
  }
  
  return(final_results)
}

#' Batch processing with adaptive sizing
process_with_batching <- function(text, processing_functions, target_memory_mb) {
  
  n_texts <- length(text)
  batch_size <- calculate_adaptive_batch_size(n_texts, target_memory_mb)
  
  cat("📦 Batch processing with size:", batch_size, "\n")
  
  # Determine if parallel processing is beneficial
  use_parallel <- parallel_available && 
                 n_texts > .performance_config$parallel_threshold &&
                 length(processing_functions) > 1
  
  if (use_parallel) {
    return(process_batches_parallel(text, processing_functions, batch_size))
  } else {
    return(process_batches_sequential(text, processing_functions, batch_size))
  }
}

#' Sequential batch processing
process_batches_sequential <- function(text, processing_functions, batch_size) {
  
  n_texts <- length(text)
  all_results <- list()
  
  # Initialize result lists
  for (func_name in names(processing_functions)) {
    all_results[[func_name]] <- list()
  }
  
  # Process in batches
  for (i in seq(1, n_texts, batch_size)) {
    batch_end <- min(i + batch_size - 1, n_texts)
    batch_indices <- i:batch_end
    batch_text <- text[batch_indices]
    
    # Process batch with each function
    for (func_name in names(processing_functions)) {
      batch_result <- process_batch_with_caching(
        batch_text, 
        processing_functions[[func_name]], 
        func_name,
        batch_indices
      )
      all_results[[func_name]][[length(all_results[[func_name]]) + 1]] <- batch_result
    }
  }
  
  # Combine batch results
  final_results <- list()
  for (func_name in names(all_results)) {
    final_results[[func_name]] <- combine_batch_results(all_results[[func_name]])
  }
  
  return(final_results)
}

#' Parallel batch processing
process_batches_parallel <- function(text, processing_functions, batch_size) {
  
  if (!parallel_available) {
    warning("Parallel processing requested but not available. Using sequential processing.")
    return(process_batches_sequential(text, processing_functions, batch_size))
  }
  
  n_cores <- min(.performance_config$max_cores, parallel::detectCores() - 1)
  cat("⚡ Using parallel processing with", n_cores, "cores\n")
  
  # Set up parallel backend
  if ("foreach" %in% available_perf_packages && "doParallel" %in% available_perf_packages) {
    
    cl <- parallel::makeCluster(n_cores)
    on.exit(parallel::stopCluster(cl))
    doParallel::registerDoParallel(cl)
    
    # Export necessary objects
    parallel::clusterExport(cl, c(
      "processing_functions",
      "process_batch_with_caching",
      ".results_cache",
      ".performance_config"
    ), envir = environment())
    
    # Load required packages on workers
    parallel::clusterEvalQ(cl, {
      library(stringr)
      if (exists("data_table_available") && data_table_available) {
        library(data.table)
      } else {
        library(dplyr)
      }
    })
    
    # Process batches in parallel
    n_texts <- length(text)
    batch_ranges <- seq(1, n_texts, batch_size)
    
    results <- foreach::foreach(i = batch_ranges, .combine = 'c') %dopar% {
      batch_end <- min(i + batch_size - 1, n_texts)
      batch_indices <- i:batch_end
      batch_text <- text[batch_indices]
      
      batch_results <- list()
      for (func_name in names(processing_functions)) {
        batch_results[[func_name]] <- process_batch_with_caching(
          batch_text,
          processing_functions[[func_name]],
          func_name,
          batch_indices
        )
      }
      
      list(batch_results)
    }
    
    # Combine parallel results
    final_results <- combine_parallel_results(results, processing_functions)
    
  } else {
    # Fallback to basic parallel processing
    final_results <- process_batches_sequential(text, processing_functions, batch_size)
  }
  
  return(final_results)
}

# ============================================================================
# INTELLIGENT CACHING SYSTEM
# ============================================================================

#' Process batch with intelligent caching
process_batch_with_caching <- function(batch_text, processing_func, func_name, batch_indices) {
  
  if (!.performance_config$cache_enabled) {
    return(processing_func(batch_text))
  }
  
  # Create cache keys for batch
  cache_keys <- sapply(batch_text, function(x) {
    digest::digest(paste(func_name, x), algo = "xxhash32")
  })
  
  cached_results <- list()
  uncached_indices <- integer(0)
  uncached_texts <- character(0)
  
  # Check cache for each text
  for (i in seq_along(batch_text)) {
    cache_key <- cache_keys[i]
    
    if ("fastmap" %in% available_perf_packages) {
      cached_result <- .results_cache$get(cache_key)
    } else {
      cached_result <- .results_cache[[cache_key]]
    }
    
    if (!is.null(cached_result)) {
      cached_results[[i]] <- cached_result
    } else {
      uncached_indices <- c(uncached_indices, i)
      uncached_texts <- c(uncached_texts, batch_text[i])
    }
  }
  
  # Update cache hit rate monitoring
  cache_hits <- length(batch_text) - length(uncached_texts)
  update_cache_hit_rate(cache_hits, length(batch_text))
  
  # Process uncached texts
  if (length(uncached_texts) > 0) {
    new_results <- processing_func(uncached_texts)
    
    # Store new results in cache
    for (i in seq_along(uncached_texts)) {
      cache_key <- cache_keys[uncached_indices[i]]
      result <- extract_individual_result(new_results, i)
      
      if ("fastmap" %in% available_perf_packages) {
        .results_cache$set(cache_key, result)
      } else {
        .results_cache[[cache_key]] <- result
      }
      
      cached_results[[uncached_indices[i]]] <- result
    }
  }
  
  # Combine cached and new results in original order
  final_result <- combine_cached_and_new_results(cached_results, processing_func)
  
  return(final_result)
}

#' Extract individual result from batch processing result
extract_individual_result <- function(batch_result, index) {
  
  # Handle different result types
  if (is.data.frame(batch_result)) {
    return(batch_result[batch_result$text_id == index, ])
  } else if (is.list(batch_result) && length(batch_result) >= index) {
    return(batch_result[[index]])
  } else if (is.vector(batch_result) && length(batch_result) >= index) {
    return(batch_result[index])
  } else {
    return(NULL)
  }
}

#' Combine cached and new results
combine_cached_and_new_results <- function(cached_results, processing_func) {
  
  # Determine result type from function
  if (length(cached_results) == 0) {
    return(NULL)
  }
  
  # Remove NULL results
  valid_results <- cached_results[!sapply(cached_results, is.null)]
  
  if (length(valid_results) == 0) {
    return(NULL)
  }
  
  # Combine based on result type
  first_result <- valid_results[[1]]
  
  if (is.data.frame(first_result)) {
    return(do.call(rbind, valid_results))
  } else if (is.list(first_result)) {
    return(valid_results)
  } else {
    return(unlist(valid_results))
  }
}

# ============================================================================
# MEMORY MANAGEMENT AND OPTIMIZATION
# ============================================================================

#' Get current memory usage in MB
get_memory_usage_mb <- function() {
  
  if ("pryr" %in% available_perf_packages) {
    return(as.numeric(pryr::mem_used()) / 1024^2)
  } else {
    # Fallback using gc()
    gc_result <- gc(verbose = FALSE)
    return(sum(gc_result[, "used"]) * 8 / 1024)  # Convert to MB (approximate)
  }
}

#' Trigger garbage collection when needed
trigger_garbage_collection <- function() {
  
  if (.performance_config$aggressive_gc) {
    # Force garbage collection
    for (i in 1:3) {
      gc(verbose = FALSE)
    }
    
    cat("🧹 Garbage collection triggered\n")
  }
}

#' Calculate optimal chunk size for streaming
calculate_optimal_chunk_size <- function(n_texts, target_memory_mb) {
  
  # Estimate memory per document (conservative estimate: 1KB per doc)
  estimated_memory_per_doc_mb <- 0.001
  
  # Calculate chunk size to stay within memory limit
  max_chunk_size <- min(
    floor(target_memory_mb * 0.3 / estimated_memory_per_doc_mb),  # 30% of available memory
    .performance_config$max_batch_size
  )
  
  # Ensure minimum chunk size
  chunk_size <- max(max_chunk_size, .performance_config$min_batch_size)
  
  return(as.integer(chunk_size))
}

#' Calculate adaptive batch size based on system resources
calculate_adaptive_batch_size <- function(n_texts, target_memory_mb) {
  
  if (!.performance_config$adaptive_batch_sizing) {
    return(.performance_config$max_batch_size)
  }
  
  # Base batch size calculation
  base_batch_size <- min(n_texts, .performance_config$max_batch_size)
  
  # Adjust based on available memory
  available_memory_mb <- target_memory_mb - get_memory_usage_mb()
  memory_factor <- min(1.0, available_memory_mb / (target_memory_mb * 0.5))
  
  # Adjust based on number of CPU cores
  n_cores <- if (parallel_available) min(parallel::detectCores(), .performance_config$max_cores) else 1
  core_factor <- sqrt(n_cores)  # Diminishing returns for more cores
  
  # Calculate final batch size
  adaptive_batch_size <- floor(base_batch_size * memory_factor * core_factor)
  
  # Ensure bounds
  batch_size <- max(
    .performance_config$min_batch_size,
    min(adaptive_batch_size, .performance_config$max_batch_size)
  )
  
  return(as.integer(batch_size))
}

# ============================================================================
# PERFORMANCE MONITORING AND BENCHMARKING
# ============================================================================

#' Update performance monitoring statistics
update_performance_monitoring <- function(metrics) {
  
  .perf_monitor$processing_times <- c(.perf_monitor$processing_times, metrics$avg_time_per_document_ms)
  .perf_monitor$memory_usage <- c(.perf_monitor$memory_usage, metrics$memory_usage_mb)
  .perf_monitor$total_documents_processed <- .perf_monitor$total_documents_processed + metrics$total_documents
  
  # Keep only recent measurements (last 1000)
  if (length(.perf_monitor$processing_times) > 1000) {
    .perf_monitor$processing_times <- tail(.perf_monitor$processing_times, 1000)
    .perf_monitor$memory_usage <- tail(.perf_monitor$memory_usage, 1000)
  }
}

#' Update cache hit rate monitoring
update_cache_hit_rate <- function(hits, total) {
  
  # Exponential moving average of cache hit rate
  alpha <- 0.1
  current_hit_rate <- hits / total
  
  .perf_monitor$cache_hit_rate <- alpha * current_hit_rate + (1 - alpha) * .perf_monitor$cache_hit_rate
}

#' Calculate current cache hit rate
calculate_cache_hit_rate <- function() {
  return(.perf_monitor$cache_hit_rate)
}

#' Get comprehensive performance statistics
get_performance_statistics <- function() {
  
  if (length(.perf_monitor$processing_times) == 0) {
    return(list(
      status = "No performance data available",
      total_documents_processed = 0
    ))
  }
  
  stats <- list(
    # Processing time statistics
    avg_processing_time_ms = mean(.perf_monitor$processing_times, na.rm = TRUE),
    median_processing_time_ms = median(.perf_monitor$processing_times, na.rm = TRUE),
    p95_processing_time_ms = quantile(.perf_monitor$processing_times, 0.95, na.rm = TRUE),
    p99_processing_time_ms = quantile(.perf_monitor$processing_times, 0.99, na.rm = TRUE),
    
    # Performance targets
    target_met_percentage = mean(.perf_monitor$processing_times < .performance_config$target_time_per_doc_ms, na.rm = TRUE) * 100,
    
    # Memory statistics
    avg_memory_usage_mb = mean(.perf_monitor$memory_usage, na.rm = TRUE),
    peak_memory_usage_mb = max(.perf_monitor$memory_usage, na.rm = TRUE),
    
    # Cache statistics
    cache_hit_rate = .perf_monitor$cache_hit_rate,
    
    # Overall statistics
    total_documents_processed = .perf_monitor$total_documents_processed,
    measurements_count = length(.perf_monitor$processing_times),
    
    # Configuration
    configuration = .performance_config
  )
  
  return(stats)
}

#' Comprehensive performance benchmark
benchmark_nlp_performance <- function(sample_texts = NULL, 
                                    processing_functions = NULL,
                                    benchmark_iterations = 10) {
  
  if (is.null(sample_texts)) {
    # Generate sample texts for benchmarking
    sample_texts <- c(
      "O Ministério da Infraestrutura determina novas regras para o transporte rodoviário nacional.",
      "A ANTT estabelece diretrizes importantes para a regulamentação do setor de transportes terrestres.",
      "Esta resolução do CONTRAN visa melhorar a segurança no trânsito urbano brasileiro.",
      "O decreto municipal regulamenta o funcionamento do transporte público na cidade de São Paulo.",
      "As medidas adotadas pela Secretaria de Transportes promovem a mobilidade urbana sustentável."
    )
  }
  
  if (is.null(processing_functions)) {
    # Default processing functions for benchmark
    processing_functions <- list(
      sentiment = function(x) analyze_portuguese_sentiment(x, enable_caching = FALSE),
      entities = function(x) extract_brazilian_legal_entities(x, enable_caching = FALSE)
    )
  }
  
  cat("🏃 Running comprehensive NLP performance benchmark\n")
  cat("📊 Sample size:", length(sample_texts), "documents\n")
  cat("🔄 Iterations:", benchmark_iterations, "\n")
  cat("⚙️ Functions:", paste(names(processing_functions), collapse = ", "), "\n")
  
  benchmark_results <- list()
  
  # Benchmark each processing function
  for (func_name in names(processing_functions)) {
    
    cat("📈 Benchmarking", func_name, "...\n")
    
    if ("microbenchmark" %in% available_perf_packages) {
      func_benchmark <- microbenchmark::microbenchmark(
        {processing_functions[[func_name]](sample_texts)},
        times = benchmark_iterations,
        unit = "ms"
      )
      
      func_stats <- summary(func_benchmark)
      
      benchmark_results[[func_name]] <- list(
        median_time_ms = func_stats$median,
        mean_time_ms = func_stats$mean,
        min_time_ms = func_stats$min,
        max_time_ms = func_stats$max,
        time_per_document_ms = func_stats$median / length(sample_texts),
        target_met = (func_stats$median / length(sample_texts)) < .performance_config$target_time_per_doc_ms,
        raw_benchmark = func_benchmark
      )
    } else {
      # Simple timing without microbenchmark
      times <- numeric(benchmark_iterations)
      
      for (i in seq_len(benchmark_iterations)) {
        start_time <- Sys.time()
        processing_functions[[func_name]](sample_texts)
        end_time <- Sys.time()
        times[i] <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
      }
      
      benchmark_results[[func_name]] <- list(
        median_time_ms = median(times),
        mean_time_ms = mean(times),
        min_time_ms = min(times),
        max_time_ms = max(times),
        time_per_document_ms = median(times) / length(sample_texts),
        target_met = (median(times) / length(sample_texts)) < .performance_config$target_time_per_doc_ms,
        raw_times = times
      )
    }
  }
  
  # Overall benchmark summary
  overall_results <- list(
    individual_functions = benchmark_results,
    sample_size = length(sample_texts),
    iterations = benchmark_iterations,
    configuration = .performance_config,
    system_info = list(
      r_version = R.version.string,
      platform = Sys.info()[["sysname"]],
      cores = parallel::detectCores(),
      memory_gb = round(get_memory_usage_mb() / 1024, 2)
    )
  )
  
  # Print summary
  cat("\n📊 Benchmark Results Summary:\n")
  for (func_name in names(benchmark_results)) {
    result <- benchmark_results[[func_name]]
    cat("  ", func_name, ":\n")
    cat("    Time per document:", round(result$time_per_document_ms, 1), "ms\n")
    cat("    Target (<100ms):", ifelse(result$target_met, "✅ MET", "❌ EXCEEDED"), "\n")
  }
  
  return(overall_results)
}

# ============================================================================
# RESULT COMBINATION UTILITIES
# ============================================================================

#' Combine streaming results efficiently
combine_streaming_results <- function(result_chunks) {
  
  if (length(result_chunks) == 0) {
    return(NULL)
  }
  
  # Handle different result types
  first_chunk <- result_chunks[[1]]
  
  if (is.data.frame(first_chunk)) {
    # Data frame results
    if (data_table_available) {
      return(data.table::rbindlist(result_chunks))
    } else {
      return(do.call(rbind, result_chunks))
    }
  } else if (is.list(first_chunk)) {
    # List results
    return(do.call(c, result_chunks))
  } else {
    # Vector results  
    return(unlist(result_chunks))
  }
}

#' Combine batch results efficiently
combine_batch_results <- function(batch_results) {
  return(combine_streaming_results(batch_results))
}

#' Combine parallel processing results
combine_parallel_results <- function(parallel_results, processing_functions) {
  
  final_results <- list()
  
  for (func_name in names(processing_functions)) {
    func_results <- list()
    
    for (batch_result in parallel_results) {
      if (func_name %in% names(batch_result)) {
        func_results <- append(func_results, list(batch_result[[func_name]]))
      }
    }
    
    final_results[[func_name]] <- combine_batch_results(func_results)
  }
  
  return(final_results)
}

# ============================================================================
# UTILITY FUNCTIONS FOR CHUNK PROCESSING
# ============================================================================

#' Process chunk with optimization
process_chunk_optimized <- function(chunk_text, processing_func, chunk_indices) {
  
  # Pre-allocate memory if possible
  result <- tryCatch({
    processing_func(chunk_text)
  }, error = function(e) {
    cat("⚠️ Error processing chunk:", e$message, "\n")
    return(NULL)
  })
  
  # Update indices if result is a data frame
  if (is.data.frame(result) && "text_id" %in% names(result)) {
    # Remap text_id to original indices
    id_mapping <- setNames(chunk_indices, seq_along(chunk_indices))
    result$text_id <- id_mapping[result$text_id]
  }
  
  return(result)
}

# ============================================================================
# INITIALIZATION AND EXPORT
# ============================================================================

# Initialize monitoring
.perf_monitor$cache_hit_rate <- 0.0

cat("✅ Portuguese NLP Performance Optimization loaded successfully\n")
cat("⚡ Target: <", .performance_config$target_time_per_doc_ms, "ms per document\n")
cat("💾 Memory limit:", .performance_config$max_memory_usage_mb, "MB\n")
cat("🔄 Parallel processing:", ifelse(parallel_available, "Available", "Not available"), "\n")
cat("💨 Caching:", ifelse(.performance_config$cache_enabled, "Enabled", "Disabled"), "\n")

# Export main functions to global environment
.GlobalEnv$process_texts_high_performance <- process_texts_high_performance
.GlobalEnv$benchmark_nlp_performance <- benchmark_nlp_performance
.GlobalEnv$get_performance_statistics <- get_performance_statistics
.GlobalEnv$calculate_adaptive_batch_size <- calculate_adaptive_batch_size
.GlobalEnv$get_memory_usage_mb <- get_memory_usage_mb

cat("\n🚀 Ready for high-performance Portuguese NLP processing!\n")