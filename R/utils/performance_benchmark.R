# Performance Benchmark Module
# Monitor Legislativo v4 - System Performance Testing and Optimization
# =====================================================================

#' Performance Benchmarking for Monitor Legislativo v4
#' 
#' Comprehensive performance testing suite for the refactored modular architecture
#' including database queries, cache performance, module loading times, and
#' overall system responsiveness under various load conditions.

library(microbenchmark)
library(profvis)

# Benchmarking configuration
BENCHMARK_CONFIG <- list(
  iterations = 100,
  timeout_seconds = 30,
  sample_sizes = c(100, 1000, 5000, 10000),
  cache_warmup_enabled = TRUE,
  detailed_profiling = FALSE
)

#' Run Comprehensive Performance Benchmark
#' 
#' @param modules Character vector of modules to test (default: all)
#' @param include_database Boolean to include database benchmarks
#' @param include_cache Boolean to include cache benchmarks
#' @return List with benchmark results and recommendations
#' @export
run_performance_benchmark <- function(modules = "all", include_database = TRUE, include_cache = TRUE) {
  cat("🚀 Starting Monitor Legislativo v4 Performance Benchmark...\n")
  cat("=" , rep("=", 60), "\n", sep = "")
  
  start_time <- Sys.time()
  
  results <- list(
    benchmark_info = list(
      start_time = start_time,
      system_info = get_system_info(),
      config = BENCHMARK_CONFIG
    ),
    module_benchmarks = list(),
    database_benchmarks = list(),
    cache_benchmarks = list(),
    overall_metrics = list(),
    recommendations = list()
  )
  
  # Warm up cache if enabled
  if (BENCHMARK_CONFIG$cache_warmup_enabled && include_cache) {
    cat("🔥 Warming up cache system...\n")
    tryCatch({
      if (exists("cache_warmup")) {
        cache_warmup()
      }
    }, error = function(e) {
      cat("⚠️ Cache warmup failed:", e$message, "\n")
    })
  }
  
  # Test modular architecture performance
  if ("all" %in% modules || "modules" %in% modules) {
    cat("📦 Benchmarking modular architecture...\n")
    results$module_benchmarks <- benchmark_modules()
  }
  
  # Test database performance
  if (include_database) {
    cat("🗄️ Benchmarking database operations...\n")
    results$database_benchmarks <- benchmark_database_operations()
  }
  
  # Test cache performance
  if (include_cache) {
    cat("⚡ Benchmarking cache system...\n")
    results$cache_benchmarks <- benchmark_cache_operations()
  }
  
  # Test UI responsiveness
  if ("ui" %in% modules || "all" %in% modules) {
    cat("🖥️ Benchmarking UI components...\n")
    results$ui_benchmarks <- benchmark_ui_components()
  }
  
  # Calculate overall metrics
  results$overall_metrics <- calculate_overall_metrics(results)
  
  # Generate recommendations
  results$recommendations <- generate_performance_recommendations(results)
  
  end_time <- Sys.time()
  results$benchmark_info$end_time <- end_time
  results$benchmark_info$total_duration <- difftime(end_time, start_time, units = "secs")
  
  cat("✅ Benchmark completed in", round(as.numeric(results$benchmark_info$total_duration), 2), "seconds\n")
  
  return(results)
}

#' Get System Information
#' 
#' @return List with system specifications
get_system_info <- function() {
  return(list(
    r_version = paste(R.version$major, R.version$minor, sep = "."),
    platform = R.version$platform,
    os = Sys.info()["sysname"],
    memory_limit = if(exists("memory.limit")) memory.limit() else "Unknown",
    cpu_cores = parallel::detectCores(),
    shiny_version = if(requireNamespace("shiny", quietly = TRUE)) packageVersion("shiny") else "Not installed",
    timestamp = Sys.time()
  ))
}

#' Benchmark Module Loading Performance
#' 
#' @return List with module loading benchmarks
benchmark_modules <- function() {
  modules <- list(
    search_module = "R/modules/search_module.R",
    geographic_module = "R/modules/geographic_module.R", 
    citation_module = "R/modules/citation_module.R",
    export_module = "R/modules/export_module.R",
    admin_module = "R/modules/admin_module.R"
  )
  
  results <- list()
  
  for (module_name in names(modules)) {
    module_path <- modules[[module_name]]
    
    if (file.exists(module_path)) {
      cat("  Testing", module_name, "...\n")
      
      # Benchmark module loading time
      loading_time <- microbenchmark(
        source(module_path, local = FALSE),
        times = 5,
        unit = "ms"
      )
      
      results[[module_name]] <- list(
        loading_time_ms = summary(loading_time)$mean,
        loading_time_median_ms = summary(loading_time)$median,
        file_size_kb = round(file.size(module_path) / 1024, 2),
        status = "success"
      )
    } else {
      results[[module_name]] <- list(
        status = "file_not_found",
        error = paste("Module file not found:", module_path)
      )
    }
  }
  
  return(results)
}

#' Benchmark Database Operations
#' 
#' @return List with database performance metrics
benchmark_database_operations <- function() {
  if (!exists("get_library_documents")) {
    return(list(error = "Database functions not available"))
  }
  
  results <- list()
  
  # Test different query sizes
  for (sample_size in BENCHMARK_CONFIG$sample_sizes) {
    cat("  Testing database query with", sample_size, "records...\n")
    
    tryCatch({
      query_time <- microbenchmark(
        get_library_documents(limit = sample_size),
        times = 10,
        unit = "ms"
      )
      
      results[[paste0("query_", sample_size, "_records")]] <- list(
        avg_time_ms = summary(query_time)$mean,
        median_time_ms = summary(query_time)$median,
        max_time_ms = summary(query_time)$max,
        records_per_second = round(sample_size / (summary(query_time)$mean / 1000), 0),
        status = "success"
      )
    }, error = function(e) {
      results[[paste0("query_", sample_size, "_records")]] <- list(
        status = "error",
        error = e$message
      )
    })
  }
  
  # Test database connection health
  if (exists("get_database_health")) {
    tryCatch({
      health_check_time <- microbenchmark(
        get_database_health(),
        times = 20,
        unit = "ms"
      )
      
      results$health_check <- list(
        avg_time_ms = summary(health_check_time)$mean,
        status = "success"
      )
    }, error = function(e) {
      results$health_check <- list(
        status = "error",
        error = e$message
      )
    })
  }
  
  return(results)
}

#' Benchmark Cache Operations
#' 
#' @return List with cache performance metrics
benchmark_cache_operations <- function() {
  if (!exists("cache_set") || !exists("cache_get")) {
    return(list(error = "Cache functions not available"))
  }
  
  results <- list()
  
  # Test cache set operations
  cat("  Testing cache SET operations...\n")
  test_data <- list(
    small = rep("test", 10),
    medium = rep("test", 1000),
    large = rep("test", 10000)
  )
  
  for (data_size in names(test_data)) {
    tryCatch({
      set_time <- microbenchmark(
        cache_set(paste0("benchmark_", data_size), test_data[[data_size]]),
        times = 50,
        unit = "ms"
      )
      
      results[[paste0("set_", data_size)]] <- list(
        avg_time_ms = summary(set_time)$mean,
        median_time_ms = summary(set_time)$median,
        status = "success"
      )
    }, error = function(e) {
      results[[paste0("set_", data_size)]] <- list(
        status = "error",
        error = e$message
      )
    })
  }
  
  # Test cache get operations
  cat("  Testing cache GET operations...\n")
  for (data_size in names(test_data)) {
    tryCatch({
      get_time <- microbenchmark(
        cache_get(paste0("benchmark_", data_size)),
        times = 50,
        unit = "ms"
      )
      
      results[[paste0("get_", data_size)]] <- list(
        avg_time_ms = summary(get_time)$mean,
        median_time_ms = summary(get_time)$median,
        status = "success"
      )
    }, error = function(e) {
      results[[paste0("get_", data_size)]] <- list(
        status = "error",
        error = e$message
      )
    })
  }
  
  # Test cache statistics retrieval
  if (exists("get_cache_stats")) {
    tryCatch({
      stats_time <- microbenchmark(
        get_cache_stats(),
        times = 20,
        unit = "ms"
      )
      
      results$stats_retrieval <- list(
        avg_time_ms = summary(stats_time)$mean,
        status = "success"
      )
    }, error = function(e) {
      results$stats_retrieval <- list(
        status = "error",
        error = e$message
      )
    })
  }
  
  return(results)
}

#' Benchmark UI Components
#' 
#' @return List with UI performance metrics
benchmark_ui_components <- function() {
  results <- list()
  
  # Test UI utility functions
  if (exists("create_info_box")) {
    cat("  Testing UI utility functions...\n")
    
    tryCatch({
      ui_time <- microbenchmark(
        create_info_box("Test", "123", "Test subtitle", "info"),
        times = 100,
        unit = "ms"
      )
      
      results$ui_utilities <- list(
        avg_time_ms = summary(ui_time)$mean,
        status = "success"
      )
    }, error = function(e) {
      results$ui_utilities <- list(
        status = "error",
        error = e$message
      )
    })
  }
  
  return(results)
}

#' Calculate Overall Performance Metrics
#' 
#' @param results Benchmark results list
#' @return List with overall metrics
calculate_overall_metrics <- function(results) {
  metrics <- list()
  
  # Module loading performance
  if (!is.null(results$module_benchmarks)) {
    module_times <- sapply(results$module_benchmarks, function(x) {
      if (x$status == "success") x$loading_time_ms else NA
    })
    module_times <- module_times[!is.na(module_times)]
    
    if (length(module_times) > 0) {
      metrics$avg_module_loading_ms <- mean(module_times)
      metrics$total_module_loading_ms <- sum(module_times)
      metrics$slowest_module <- names(which.max(module_times))
    }
  }
  
  # Database query performance
  if (!is.null(results$database_benchmarks)) {
    db_times <- sapply(names(results$database_benchmarks), function(name) {
      if (grepl("query_", name) && results$database_benchmarks[[name]]$status == "success") {
        results$database_benchmarks[[name]]$avg_time_ms
      } else {
        NA
      }
    })
    db_times <- db_times[!is.na(db_times)]
    
    if (length(db_times) > 0) {
      metrics$avg_database_query_ms <- mean(db_times)
      metrics$database_performance_grade <- if (mean(db_times) < 100) "Excellent" else 
                                           if (mean(db_times) < 500) "Good" else 
                                           if (mean(db_times) < 1000) "Fair" else "Poor"
    }
  }
  
  # Cache performance
  if (!is.null(results$cache_benchmarks)) {
    cache_get_times <- sapply(names(results$cache_benchmarks), function(name) {
      if (grepl("get_", name) && results$cache_benchmarks[[name]]$status == "success") {
        results$cache_benchmarks[[name]]$avg_time_ms
      } else {
        NA
      }
    })
    cache_get_times <- cache_get_times[!is.na(cache_get_times)]
    
    if (length(cache_get_times) > 0) {
      metrics$avg_cache_get_ms <- mean(cache_get_times)
      metrics$cache_performance_grade <- if (mean(cache_get_times) < 1) "Excellent" else 
                                         if (mean(cache_get_times) < 5) "Good" else 
                                         if (mean(cache_get_times) < 10) "Fair" else "Poor"
    }
  }
  
  return(metrics)
}

#' Generate Performance Recommendations
#' 
#' @param results Benchmark results list
#' @return List with performance recommendations
generate_performance_recommendations <- function(results) {
  recommendations <- list(
    architecture = c(),
    database = c(),
    cache = c(),
    deployment = c()
  )
  
  # Architecture recommendations
  if (!is.null(results$overall_metrics$avg_module_loading_ms)) {
    if (results$overall_metrics$avg_module_loading_ms > 100) {
      recommendations$architecture <- c(recommendations$architecture,
        "Module loading time is high - consider code optimization")
    }
    
    if (results$overall_metrics$total_module_loading_ms > 500) {
      recommendations$architecture <- c(recommendations$architecture,
        "Consider lazy loading for non-critical modules")
    }
  }
  
  # Database recommendations
  if (!is.null(results$overall_metrics$database_performance_grade)) {
    grade <- results$overall_metrics$database_performance_grade
    
    if (grade == "Poor") {
      recommendations$database <- c(recommendations$database,
        "Database queries are slow - implement connection pooling",
        "Consider adding database indexes for frequent queries",
        "Review query optimization and use LIMIT clauses")
    } else if (grade == "Fair") {
      recommendations$database <- c(recommendations$database,
        "Database performance is acceptable but could be improved",
        "Consider implementing query result caching")
    }
  }
  
  # Cache recommendations  
  if (!is.null(results$overall_metrics$cache_performance_grade)) {
    grade <- results$overall_metrics$cache_performance_grade
    
    if (grade == "Poor") {
      recommendations$cache <- c(recommendations$cache,
        "Cache performance is suboptimal - check Redis configuration",
        "Consider increasing memory allocation for cache")
    }
  }
  
  # Deployment recommendations
  recommendations$deployment <- c(
    "Monitor memory usage regularly on Railway platform",
    "Implement health checks for all critical components",
    "Set up performance monitoring alerts"
  )
  
  return(recommendations)
}

#' Print Benchmark Summary Report
#' 
#' @param results Benchmark results from run_performance_benchmark
#' @export
print_benchmark_report <- function(results) {
  cat("\n")
  cat("📊 MONITOR LEGISLATIVO v4 - PERFORMANCE BENCHMARK REPORT\n")
  cat("========================================================\n\n")
  
  # System info
  cat("🖥️  SYSTEM INFORMATION\n")
  cat("R Version:", results$benchmark_info$system_info$r_version, "\n")
  cat("Platform:", results$benchmark_info$system_info$platform, "\n")
  cat("CPU Cores:", results$benchmark_info$system_info$cpu_cores, "\n")
  cat("Total Duration:", round(as.numeric(results$benchmark_info$total_duration), 2), "seconds\n\n")
  
  # Overall metrics
  if (!is.null(results$overall_metrics)) {
    cat("📈 OVERALL PERFORMANCE METRICS\n")
    
    if (!is.null(results$overall_metrics$avg_module_loading_ms)) {
      cat("Average Module Loading:", round(results$overall_metrics$avg_module_loading_ms, 2), "ms\n")
    }
    
    if (!is.null(results$overall_metrics$avg_database_query_ms)) {
      cat("Average Database Query:", round(results$overall_metrics$avg_database_query_ms, 2), "ms")
      cat(" (", results$overall_metrics$database_performance_grade, ")\n")
    }
    
    if (!is.null(results$overall_metrics$avg_cache_get_ms)) {
      cat("Average Cache Retrieval:", round(results$overall_metrics$avg_cache_get_ms, 2), "ms")
      cat(" (", results$overall_metrics$cache_performance_grade, ")\n")
    }
    
    cat("\n")
  }
  
  # Recommendations
  if (!is.null(results$recommendations)) {
    cat("💡 PERFORMANCE RECOMMENDATIONS\n")
    
    if (length(results$recommendations$architecture) > 0) {
      cat("\n🏗️  Architecture:\n")
      for (rec in results$recommendations$architecture) {
        cat("  •", rec, "\n")
      }
    }
    
    if (length(results$recommendations$database) > 0) {
      cat("\n🗄️  Database:\n") 
      for (rec in results$recommendations$database) {
        cat("  •", rec, "\n")
      }
    }
    
    if (length(results$recommendations$cache) > 0) {
      cat("\n⚡ Cache:\n")
      for (rec in results$recommendations$cache) {
        cat("  •", rec, "\n")
      }
    }
    
    if (length(results$recommendations$deployment) > 0) {
      cat("\n🚀 Deployment:\n")
      for (rec in results$recommendations$deployment) {
        cat("  •", rec, "\n")
      }
    }
  }
  
  cat("\n✅ Benchmark report completed.\n")
}

cat("✅ Performance benchmark module loaded successfully\n")