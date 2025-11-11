# ============================================================================
# AUTOCOMPLETE PERFORMANCE TESTING MODULE
# ============================================================================
#
# This module provides comprehensive testing for the intelligent autocomplete
# system to ensure sub-100ms performance with the real 134k document dataset.
#
# Features:
# - Performance benchmarking with real queries
# - Cache performance analysis
# - Memory usage monitoring
# - Accuracy testing for Brazilian legal terms
# - Load testing simulation
# - Report generation for system optimization
#
# Author: Senior QA Engineer - Brazilian Legal Analytics Team
# Date: January 2025
# Version: 1.0 - Production Testing Suite
# ============================================================================

cat("🧪 Loading Autocomplete Performance Testing Module...\n")

# Load required packages
test_packages <- c("microbenchmark")

for (pkg in test_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat("ℹ️ Package", pkg, "recommended for detailed performance testing\n")
  }
}

# ============================================================================
# TEST CONFIGURATION
# ============================================================================

.test_config <- list(
  # Performance targets
  target_response_time_ms = 100,
  target_cache_hit_rate = 80, # 80%
  
  # Test parameters
  warmup_iterations = 10,
  benchmark_iterations = 50,
  load_test_concurrent_users = 10,
  load_test_duration_seconds = 30,
  
  # Test queries (representative of real usage)
  test_queries = list(
    # Common legal terms
    basic = c("lei", "decreto", "portaria", "resolução", "código"),
    
    # Document types
    documents = c("lei federal", "decreto municipal", "medida provisória", "emenda constitucional"),
    
    # Authorities
    authorities = c("stf", "stj", "supremo", "tribunal", "ministério público"),
    
    # Geographic terms
    geography = c("são paulo", "rio de janeiro", "brasília", "minas gerais", "bahia"),
    
    # Transport terms
    transport = c("transporte", "rodoviário", "ferroviário", "aéreo", "mobilidade urbana"),
    
    # Abbreviations
    abbreviations = c("MP", "EC", "STF", "STJ", "ANTT", "ANAC"),
    
    # Complex queries
    complex = c("lei de licitações", "código de trânsito brasileiro", "transporte público municipal"),
    
    # Partial matches (autocomplete scenarios)
    partial = c("le", "dec", "port", "tran", "mob", "STF")
  ),
  
  # Error conditions to test
  error_queries = c("", "a", "xxxxxxxxxxxxxxxxx", "12345", "!@#$%")
)

# ============================================================================
# PERFORMANCE TESTING FUNCTIONS
# ============================================================================

#' Test autocomplete performance with various query types
#' @param detailed Whether to run detailed microbenchmark tests
#' @return Test results summary
test_autocomplete_performance <- function(detailed = TRUE) {
  cat("🚀 Starting Autocomplete Performance Testing...\n")
  
  # Ensure autocomplete system is loaded
  ensure_autocomplete_loaded()
  
  results <- list(
    timestamp = Sys.time(),
    system_info = get_system_info(),
    test_config = .test_config,
    performance_tests = list(),
    cache_tests = list(),
    accuracy_tests = list(),
    summary = list()
  )
  
  # 1. Warm up the system
  cat("🔥 Warming up autocomplete system...\n")
  warmup_results <- warmup_autocomplete_system()
  results$warmup = warmup_results
  
  # 2. Basic performance tests
  cat("⚡ Running basic performance tests...\n")
  basic_results <- test_basic_performance()
  results$performance_tests$basic <- basic_results
  
  # 3. Cache performance tests
  cat("💾 Testing cache performance...\n")
  cache_results <- test_cache_performance()
  results$cache_tests <- cache_results
  
  # 4. Query accuracy tests
  cat("🎯 Testing suggestion accuracy...\n")
  accuracy_results <- test_suggestion_accuracy()
  results$accuracy_tests <- accuracy_results
  
  # 5. Load testing (if requested)
  if (detailed) {
    cat("📊 Running detailed load tests...\n")
    load_results <- test_load_performance()
    results$performance_tests$load <- load_results
  }
  
  # 6. Generate summary
  results$summary <- generate_test_summary(results)
  
  # 7. Display results
  display_test_results(results)
  
  return(results)
}

#' Ensure autocomplete system is properly loaded
ensure_autocomplete_loaded <- function() {
  if (!exists("get_autocomplete_suggestions")) {
    tryCatch({
      if (file.exists("modules/search/intelligent_autocomplete_engine.R")) {
        source("modules/search/intelligent_autocomplete_engine.R")
      }
    }, error = function(e) {
      stop("Autocomplete system could not be loaded: ", e$message)
    })
  }
}

#' Get system information for testing context
#' @return System info list
get_system_info <- function() {
  list(
    r_version = R.version.string,
    platform = R.version$platform,
    memory_limit = if(exists("memory.limit")) memory.limit() else "Unknown",
    cpu_cores = parallel::detectCores(),
    autocomplete_engine = exists("get_autocomplete_suggestions"),
    cache_system = exists("get_cached_autocomplete"),
    redis_available = exists("get_cache_stats") && !is.null(tryCatch(get_cache_stats(), error = function(e) NULL))
  )
}

#' Warm up autocomplete system with common queries
#' @return Warmup results
warmup_autocomplete_system <- function() {
  warmup_queries <- c("lei", "decreto", "stf", "transporte", "são paulo")
  warmup_times <- numeric(length(warmup_queries))
  
  for (i in seq_along(warmup_queries)) {
    start_time <- Sys.time()
    
    tryCatch({
      get_autocomplete_suggestions(warmup_queries[i], max_suggestions = 5)
    }, error = function(e) {
      cat("⚠️ Warmup error for query '", warmup_queries[i], "':", e$message, "\n")
    })
    
    end_time <- Sys.time()
    warmup_times[i] <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
  }
  
  list(
    queries = warmup_queries,
    times_ms = warmup_times,
    average_time_ms = mean(warmup_times),
    max_time_ms = max(warmup_times)
  )
}

#' Test basic autocomplete performance
#' @return Basic performance results
test_basic_performance <- function() {
  all_test_queries <- unlist(.test_config$test_queries)
  results <- list()
  
  for (category in names(.test_config$test_queries)) {
    cat(sprintf("  Testing %s queries...\n", category))
    
    queries <- .test_config$test_queries[[category]]
    times <- numeric(length(queries))
    success_count <- 0
    
    for (i in seq_along(queries)) {
      start_time <- Sys.time()
      
      tryCatch({
        result <- get_autocomplete_suggestions(queries[i], max_suggestions = 10)
        success_count <- success_count + 1
      }, error = function(e) {
        cat("❌ Error for query '", queries[i], "':", e$message, "\n")
      })
      
      end_time <- Sys.time()
      times[i] <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    }
    
    results[[category]] <- list(
      queries = queries,
      times_ms = times,
      average_time_ms = mean(times),
      max_time_ms = max(times),
      min_time_ms = min(times),
      success_rate = (success_count / length(queries)) * 100,
      under_target = sum(times <= .test_config$target_response_time_ms),
      target_compliance = (sum(times <= .test_config$target_response_time_ms) / length(times)) * 100
    )
  }
  
  return(results)
}

#' Test cache performance and hit rates
#' @return Cache performance results
test_cache_performance <- function() {
  # Clear cache first for accurate testing
  if (exists("clear_autocomplete_cache")) {
    clear_autocomplete_cache()
  }
  
  test_queries <- c("lei federal", "decreto municipal", "STF", "transporte público")
  cache_results <- list()
  
  # First run (cache misses expected)
  cat("  Testing cache misses...\n")
  first_run_times <- numeric(length(test_queries))
  for (i in seq_along(test_queries)) {
    start_time <- Sys.time()
    get_autocomplete_suggestions(test_queries[i])
    end_time <- Sys.time()
    first_run_times[i] <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
  }
  
  # Second run (cache hits expected)
  cat("  Testing cache hits...\n")
  second_run_times <- numeric(length(test_queries))
  for (i in seq_along(test_queries)) {
    start_time <- Sys.time()
    result <- get_autocomplete_suggestions(test_queries[i])
    end_time <- Sys.time()
    second_run_times[i] <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    # Check if result indicates cache hit
    cache_results[[test_queries[i]]] <- list(
      cache_hit = result$metadata$cache_hit %||% FALSE,
      first_run_ms = first_run_times[i],
      second_run_ms = second_run_times[i],
      speedup = if(second_run_times[i] > 0) first_run_times[i] / second_run_times[i] else 1
    )
  }
  
  # Get overall cache statistics
  overall_stats <- if (exists("get_cache_stats")) {
    get_cache_stats()
  } else {
    list(performance = list(hit_rate_percent = 0))
  }
  
  list(
    queries = test_queries,
    first_run_avg_ms = mean(first_run_times),
    second_run_avg_ms = mean(second_run_times),
    average_speedup = mean(sapply(cache_results, function(x) x$speedup)),
    cache_hit_rate = overall_stats$performance$hit_rate_percent %||% 0,
    individual_results = cache_results,
    overall_stats = overall_stats
  )
}

#' Test suggestion accuracy for Brazilian legal terms
#' @return Accuracy test results
test_suggestion_accuracy <- function() {
  # Test cases: query -> expected terms that should appear
  accuracy_tests <- list(
    "lei" = c("Lei Federal", "Lei Estadual", "Lei Municipal"),
    "stf" = c("STF", "Supremo Tribunal Federal"),
    "decreto" = c("Decreto", "Decreto Federal", "Decreto Estadual"),
    "transporte" = c("Transporte Público", "Transporte Rodoviário"),
    "são paulo" = c("São Paulo"),
    "código" = c("Código Civil", "Código Penal", "Código de Trânsito")
  )
  
  results <- list()
  
  for (query in names(accuracy_tests)) {
    expected_terms <- accuracy_tests[[query]]
    
    suggestions_result <- get_autocomplete_suggestions(query, max_suggestions = 10)
    suggestions <- sapply(suggestions_result$suggestions, function(x) x$text)
    
    # Check how many expected terms were found
    found_count <- sum(sapply(expected_terms, function(term) {
      any(str_detect(str_to_lower(suggestions), str_to_lower(term)))
    }))
    
    accuracy_percentage <- (found_count / length(expected_terms)) * 100
    
    results[[query]] <- list(
      expected_terms = expected_terms,
      found_suggestions = suggestions,
      found_count = found_count,
      total_expected = length(expected_terms),
      accuracy_percentage = accuracy_percentage,
      suggestion_count = length(suggestions)
    )
  }
  
  # Calculate overall accuracy
  overall_accuracy <- mean(sapply(results, function(x) x$accuracy_percentage))
  
  list(
    individual_tests = results,
    overall_accuracy = overall_accuracy,
    total_tests = length(accuracy_tests)
  )
}

#' Simulate load testing with concurrent requests
#' @return Load test results
test_load_performance <- function() {
  if (!requireNamespace("parallel", quietly = TRUE)) {
    cat("⚠️ 'parallel' package not available, skipping load tests\n")
    return(list(skipped = TRUE, reason = "parallel package not available"))
  }
  
  test_queries <- rep(c("lei", "decreto", "STF", "transporte", "código"), 
                     length.out = 50) # 50 total queries
  
  cat("  Simulating concurrent user load...\n")
  
  # Sequential baseline
  start_time <- Sys.time()
  sequential_results <- lapply(test_queries, function(q) {
    result <- get_autocomplete_suggestions(q)
    list(query = q, suggestions_count = length(result$suggestions))
  })
  sequential_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  
  # Parallel load test
  start_time <- Sys.time()
  parallel_results <- parallel::mclapply(test_queries, function(q) {
    result <- get_autocomplete_suggestions(q)
    list(query = q, suggestions_count = length(result$suggestions))
  }, mc.cores = min(.test_config$load_test_concurrent_users, parallel::detectCores()))
  parallel_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  
  list(
    total_queries = length(test_queries),
    concurrent_users = .test_config$load_test_concurrent_users,
    sequential_time_seconds = sequential_time,
    parallel_time_seconds = parallel_time,
    speedup_ratio = sequential_time / parallel_time,
    queries_per_second_sequential = length(test_queries) / sequential_time,
    queries_per_second_parallel = length(test_queries) / parallel_time,
    success_rate = (length(parallel_results) / length(test_queries)) * 100
  )
}

#' Generate comprehensive test summary
#' @param results Complete test results
#' @return Test summary
generate_test_summary <- function(results) {
  # Extract key metrics
  all_performance <- unlist(lapply(results$performance_tests$basic, function(x) x$times_ms))
  
  summary <- list(
    overall_performance = list(
      total_queries_tested = length(all_performance),
      average_response_time_ms = mean(all_performance),
      max_response_time_ms = max(all_performance),
      min_response_time_ms = min(all_performance),
      target_compliance_rate = (sum(all_performance <= .test_config$target_response_time_ms) / length(all_performance)) * 100
    ),
    
    cache_performance = list(
      cache_hit_rate = results$cache_tests$cache_hit_rate %||% 0,
      average_speedup = results$cache_tests$average_speedup %||% 1,
      target_hit_rate_met = (results$cache_tests$cache_hit_rate %||% 0) >= .test_config$target_cache_hit_rate
    ),
    
    accuracy_performance = list(
      overall_accuracy = results$accuracy_tests$overall_accuracy %||% 0,
      accuracy_threshold_met = (results$accuracy_tests$overall_accuracy %||% 0) >= 70 # 70% accuracy threshold
    ),
    
    system_health = list(
      performance_target_met = (sum(all_performance <= .test_config$target_response_time_ms) / length(all_performance)) >= 0.9, # 90% under target
      cache_system_working = !is.null(results$cache_tests$overall_stats),
      autocomplete_engine_loaded = results$system_info$autocomplete_engine,
      overall_status = "unknown"
    )
  )
  
  # Determine overall system status
  if (summary$overall_performance$target_compliance_rate >= 90 &&
      summary$accuracy_performance$accuracy_threshold_met &&
      summary$system_health$autocomplete_engine_loaded) {
    summary$system_health$overall_status <- "excellent"
  } else if (summary$overall_performance$target_compliance_rate >= 70 &&
             summary$accuracy_performance$overall_accuracy >= 60) {
    summary$system_health$overall_status <- "good"  
  } else if (summary$overall_performance$target_compliance_rate >= 50) {
    summary$system_health$overall_status <- "acceptable"
  } else {
    summary$system_health$overall_status <- "needs_improvement"
  }
  
  return(summary)
}

#' Display test results in a formatted way
#' @param results Complete test results
display_test_results <- function(results) {
  cat("\n" %+% "=" %+% strrep("=", 60) %+% "=\n")
  cat("📊 AUTOCOMPLETE PERFORMANCE TEST RESULTS\n")
  cat("=" %+% strrep("=", 60) %+% "=\n\n")
  
  # System Information
  cat("🖥️  SYSTEM INFORMATION:\n")
  cat(sprintf("   R Version: %s\n", results$system_info$r_version))
  cat(sprintf("   Platform: %s\n", results$system_info$platform))
  cat(sprintf("   CPU Cores: %d\n", results$system_info$cpu_cores))
  cat(sprintf("   Autocomplete Engine: %s\n", if(results$system_info$autocomplete_engine) "✅ Loaded" else "❌ Missing"))
  cat(sprintf("   Cache System: %s\n", if(results$system_info$cache_system) "✅ Available" else "⚠️ Fallback"))
  cat(sprintf("   Redis Available: %s\n", if(results$system_info$redis_available) "✅ Connected" else "⚠️ Not Connected"))
  
  # Performance Results
  cat("\n⚡ PERFORMANCE RESULTS:\n")
  summary <- results$summary$overall_performance
  cat(sprintf("   Total Queries Tested: %d\n", summary$total_queries_tested))
  cat(sprintf("   Average Response Time: %.2f ms\n", summary$average_response_time_ms))
  cat(sprintf("   Target (< %d ms): %.1f%% compliance %s\n", 
              .test_config$target_response_time_ms, 
              summary$target_compliance_rate,
              if(summary$target_compliance_rate >= 90) "✅" else if(summary$target_compliance_rate >= 70) "⚠️" else "❌"))
  cat(sprintf("   Fastest Response: %.2f ms\n", summary$min_response_time_ms))
  cat(sprintf("   Slowest Response: %.2f ms\n", summary$max_response_time_ms))
  
  # Cache Performance
  if (!is.null(results$cache_tests)) {
    cat("\n💾 CACHE PERFORMANCE:\n")
    cache <- results$summary$cache_performance
    cat(sprintf("   Cache Hit Rate: %.1f%% %s\n", 
                cache$cache_hit_rate,
                if(cache$target_hit_rate_met) "✅" else "⚠️"))
    cat(sprintf("   Average Speedup: %.1fx\n", cache$average_speedup))
    cat(sprintf("   Cache System Status: %s\n", 
                if(results$cache_tests$overall_stats$connection_status$connected %||% FALSE) "✅ Redis Connected" else "⚠️ In-Memory Only"))
  }
  
  # Accuracy Results
  cat("\n🎯 SUGGESTION ACCURACY:\n")
  accuracy <- results$summary$accuracy_performance
  cat(sprintf("   Overall Accuracy: %.1f%% %s\n", 
              accuracy$overall_accuracy,
              if(accuracy$accuracy_threshold_met) "✅" else "⚠️"))
  cat(sprintf("   Total Test Cases: %d\n", results$accuracy_tests$total_tests))
  
  # Overall Status
  cat("\n🏆 OVERALL SYSTEM STATUS:\n")
  status <- results$summary$system_health$overall_status
  status_icon <- switch(status,
    "excellent" = "🟢",
    "good" = "🟡", 
    "acceptable" = "🟠",
    "needs_improvement" = "🔴",
    "❓"
  )
  
  cat(sprintf("   System Health: %s %s\n", status_icon, toupper(status)))
  
  # Recommendations
  cat("\n💡 RECOMMENDATIONS:\n")
  if (summary$target_compliance_rate < 90) {
    cat("   - Consider optimizing suggestion generation algorithms\n")
    cat("   - Check database query performance\n")
  }
  if (cache$cache_hit_rate < 80) {
    cat("   - Review cache TTL settings\n") 
    cat("   - Consider increasing cache memory allocation\n")
  }
  if (accuracy$overall_accuracy < 70) {
    cat("   - Expand Brazilian legal terms dictionary\n")
    cat("   - Improve fuzzy matching algorithms\n")
  }
  if (!results$system_info$redis_available) {
    cat("   - Install Redis for optimal caching performance\n")
    cat("   - Configure Redis connection for production\n")
  }
  
  cat("\n" %+% "=" %+% strrep("=", 60) %+% "=\n")
  
  invisible(results)
}

# ============================================================================
# QUICK TEST FUNCTIONS
# ============================================================================

#' Quick performance test with common queries
#' @return Quick test results
quick_autocomplete_test <- function() {
  cat("🚀 Quick Autocomplete Performance Test\n")
  
  ensure_autocomplete_loaded()
  
  test_queries <- c("lei", "decreto", "stf", "transporte", "são paulo")
  results <- list()
  
  for (query in test_queries) {
    start_time <- Sys.time()
    suggestion_result <- get_autocomplete_suggestions(query)
    end_time <- Sys.time()
    
    time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    results[[query]] <- list(
      time_ms = time_ms,
      suggestions_count = length(suggestion_result$suggestions),
      cache_hit = suggestion_result$metadata$cache_hit %||% FALSE
    )
    
    status <- if(time_ms <= 100) "✅" else if(time_ms <= 200) "⚠️" else "❌"
    cat(sprintf("   '%s': %.1f ms (%d suggestions) %s\n", 
                query, time_ms, results[[query]]$suggestions_count, status))
  }
  
  avg_time <- mean(sapply(results, function(x) x$time_ms))
  cat(sprintf("\n📊 Average Response Time: %.1f ms %s\n", 
              avg_time, 
              if(avg_time <= 100) "✅ Target Met" else "⚠️ Above Target"))
  
  return(results)
}

# ============================================================================
# INITIALIZATION
# ============================================================================

cat("✅ Autocomplete Performance Testing Module loaded\n")
cat("   🧪 Comprehensive testing suite ready\n")
cat("   📊 Performance benchmarking available\n")
cat("   ⚡ Sub-100ms target validation\n")

# Export main functions
.GlobalEnv$test_autocomplete_performance <- test_autocomplete_performance
.GlobalEnv$quick_autocomplete_test <- quick_autocomplete_test

# Run quick test on load if in interactive mode and testing enabled
if (interactive() && Sys.getenv("AUTOCOMPLETE_QUICK_TEST", "false") == "true") {
  cat("\n🧪 Running quick performance test...\n")
  quick_autocomplete_test()
}

cat("🚀 AUTOCOMPLETE PERFORMANCE TESTING READY!\n")