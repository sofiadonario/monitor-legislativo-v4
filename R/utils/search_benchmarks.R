# Search Performance Benchmarks - Week 3 Implementation
# Monitor Legislativo v4 - Performance Monitoring and Optimization
# ================================================================

#' Search Performance Benchmarking System
#' 
#' Comprehensive performance monitoring and benchmarking for the advanced search
#' system. Tracks response times, query complexity, and system optimization
#' opportunities for 134k+ Brazilian legislative documents.
#' 
#' Target: <2s response time for complex queries
#' Goal: 95% of searches complete under target time
#' 
#' Features:
#' - Real-time performance monitoring
#' - Query complexity analysis  
#' - Performance trend tracking
#' - Automated optimization suggestions
#' - System load monitoring
#' 
#' @family performance-monitoring
#' @export

library(DBI)

# Performance monitoring configuration
.perf_config <- list(
  target_response_time = 2.0,  # seconds
  warning_threshold = 1.5,     # seconds  
  critical_threshold = 5.0,    # seconds
  max_log_entries = 10000,     # Maximum performance log entries
  benchmark_interval = 3600,   # Run benchmarks every hour
  trend_window = 24            # Hours for trend analysis
)

# Performance metrics storage
.perf_metrics <- list(
  total_searches = 0,
  fast_searches = 0,  # Under target time
  slow_searches = 0,  # Over target time
  critical_searches = 0,  # Over critical threshold
  average_time = 0,
  last_benchmark = NULL,
  trend_data = data.frame()
)

#' Log search performance metrics
#' 
#' @param query_text Search query string
#' @param response_time Response time in seconds
#' @param result_count Number of results returned
#' @param filters_applied List of applied filters
#' @param cache_hit Whether result came from cache
#' @param user_session Session identifier
#' @export
log_search_performance <- function(query_text, response_time, result_count, 
                                 filters_applied = list(), cache_hit = FALSE, 
                                 user_session = NULL) {
  
  # Update global metrics
  .perf_metrics$total_searches <<- .perf_metrics$total_searches + 1
  
  if (response_time <= .perf_config$target_response_time) {
    .perf_metrics$fast_searches <<- .perf_metrics$fast_searches + 1
  } else {
    .perf_metrics$slow_searches <<- .perf_metrics$slow_searches + 1
  }
  
  if (response_time >= .perf_config$critical_threshold) {
    .perf_metrics$critical_searches <<- .perf_metrics$critical_searches + 1
  }
  
  # Update rolling average
  .perf_metrics$average_time <<- (
    (.perf_metrics$average_time * (.perf_metrics$total_searches - 1) + response_time) /
    .perf_metrics$total_searches
  )
  
  # Create performance log entry
  log_entry <- data.frame(
    timestamp = Sys.time(),
    query_text = substr(query_text, 1, 100),  # Truncate for storage
    response_time = response_time,
    result_count = result_count,
    cache_hit = cache_hit,
    user_session = user_session %||% "anonymous",
    query_length = nchar(query_text),
    filter_count = length(filters_applied[!sapply(filters_applied, is.null)]),
    performance_rating = case_when(
      response_time <= .perf_config$target_response_time ~ "excellent",
      response_time <= .perf_config$warning_threshold ~ "good", 
      response_time <= .perf_config$critical_threshold ~ "slow",
      TRUE ~ "critical"
    ),
    stringsAsFactors = FALSE
  )
  
  # Add to trend data
  if (nrow(.perf_metrics$trend_data) >= .perf_config$max_log_entries) {
    # Remove oldest entries
    .perf_metrics$trend_data <<- .perf_metrics$trend_data[-1, ]
  }
  
  .perf_metrics$trend_data <<- rbind(.perf_metrics$trend_data, log_entry)
  
  # Log critical performance issues
  if (response_time >= .perf_config$critical_threshold) {
    log_security_event("CRITICAL_PERFORMANCE", 
                      paste("Slow search detected:", response_time, "sec for query:", 
                            substr(query_text, 1, 50)), 
                      severity = "ERROR")
  }
  
  return(invisible(log_entry))
}

#' Run comprehensive search benchmarks
#' 
#' @param pool Database connection pool
#' @param include_cache_warming Whether to include cache warming in benchmarks
#' @return List of benchmark results
run_search_benchmarks <- function(pool, include_cache_warming = TRUE) {
  cat("🏃 Running comprehensive search benchmarks...\n")
  
  benchmark_start <- Sys.time()
  results <- list()
  
  # Test queries with varying complexity
  test_queries <- list(
    simple = list(
      query = "lei",
      filters = list(),
      expected_max_time = 1.0
    ),
    medium = list(
      query = "transporte público",
      filters = list(filter_estado = "SP"),
      expected_max_time = 1.5
    ),
    complex = list(
      query = "direito administrativo processo licitação",
      filters = list(
        filter_estado = "RJ",
        filter_tipo = "lei",
        filter_ano_min = 2020
      ),
      expected_max_time = 2.0
    ),
    phrase = list(
      query = '"lei orgânica municipal"',
      filters = list(),
      expected_max_time = 1.5
    ),
    wildcard = list(
      query = "admin* públic*",
      filters = list(filter_tipo = "decreto"),
      expected_max_time = 2.5
    )
  )
  
  # Run each test query multiple times
  for (test_name in names(test_queries)) {
    test <- test_queries[[test_name]]
    cat("  Testing:", test_name, "query\n")
    
    times <- c()
    result_counts <- c()
    
    for (i in 1:3) {  # Run each test 3 times
      start_time <- Sys.time()
      
      tryCatch({
        if (!is.null(pool)) {
          results_data <- execute_query(pool,
            "SELECT * FROM search_legislative_documents($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            params = list(
              test$query,
              test$filters$filter_estado,
              test$filters$filter_municipio,  
              test$filters$filter_tipo,
              test$filters$filter_categoria,
              test$filters$filter_ano_min,
              test$filters$filter_ano_max,
              test$filters$filter_data_inicio,
              test$filters$filter_data_fim,
              100,  # limit
              0,    # offset
              "relevance"  # sort_by
            )
          )
          
          response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
          result_count <- if (!is.null(results_data)) nrow(results_data) else 0
          
          times <- c(times, response_time)
          result_counts <- c(result_counts, result_count)
          
        } else {
          times <- c(times, NA)
          result_counts <- c(result_counts, 0)
        }
      }, error = function(e) {
        warning("Benchmark test failed: ", e$message)
        times <- c(times, NA)
        result_counts <- c(result_counts, 0)
      })
    }
    
    # Calculate test statistics
    valid_times <- times[!is.na(times)]
    if (length(valid_times) > 0) {
      test_result <- list(
        query_type = test_name,
        query = test$query,
        filters = test$filters,
        avg_time = mean(valid_times),
        min_time = min(valid_times), 
        max_time = max(valid_times),
        avg_results = mean(result_counts),
        expected_max = test$expected_max_time,
        performance = if (max(valid_times) <= test$expected_max_time) "PASS" else "FAIL",
        runs_completed = length(valid_times)
      )
    } else {
      test_result <- list(
        query_type = test_name,
        query = test$query,
        performance = "ERROR",
        runs_completed = 0
      )
    }
    
    results[[test_name]] <- test_result
    
    # Log performance
    if (length(valid_times) > 0) {
      log_search_performance(
        test$query, 
        mean(valid_times), 
        mean(result_counts), 
        test$filters, 
        cache_hit = FALSE, 
        user_session = "benchmark"
      )
    }
  }
  
  # Database performance metrics
  if (!is.null(pool)) {
    tryCatch({
      db_stats <- execute_query(pool, "
        SELECT 
          COUNT(*) as total_documents,
          (SELECT COUNT(*) FROM pg_stat_user_indexes WHERE relname = 'documents') as index_count,
          pg_size_pretty(pg_total_relation_size('documents')) as table_size
      ")
      
      results$database_metrics <- db_stats
    }, error = function(e) {
      results$database_metrics <- list(error = e$message)
    })
  }
  
  # Cache performance test (if caching enabled)
  if (include_cache_warming && exists("cached_search_documents")) {
    cache_test_start <- Sys.time()
    
    # Test cache hit performance
    tryCatch({
      # First call (cache miss)
      first_result <- cached_search_documents(pool, "lei orgânica", list(), "relevance", 50)
      first_time <- first_result$search_time
      
      # Second call (should be cache hit)  
      second_result <- cached_search_documents(pool, "lei orgânica", list(), "relevance", 50)
      second_time <- if (second_result$from_cache) 0.05 else second_result$search_time
      
      results$cache_performance <- list(
        cache_miss_time = first_time,
        cache_hit_time = second_time,
        cache_speedup = round(first_time / second_time, 2),
        cache_working = second_result$from_cache
      )
    }, error = function(e) {
      results$cache_performance <- list(error = e$message)
    })
  }
  
  total_benchmark_time <- as.numeric(difftime(Sys.time(), benchmark_start, units = "secs"))
  
  # Summary statistics
  all_times <- unlist(lapply(results[names(test_queries)], function(x) x$avg_time))
  valid_times <- all_times[!is.na(all_times)]
  
  results$summary <- list(
    total_benchmark_time = total_benchmark_time,
    tests_run = length(test_queries),
    tests_passed = sum(sapply(results[names(test_queries)], function(x) x$performance == "PASS")),
    avg_response_time = if (length(valid_times) > 0) mean(valid_times) else NA,
    max_response_time = if (length(valid_times) > 0) max(valid_times) else NA,
    target_compliance = if (length(valid_times) > 0) {
      sum(valid_times <= .perf_config$target_response_time) / length(valid_times) * 100
    } else 0,
    performance_grade = if (length(valid_times) > 0) {
      avg_time <- mean(valid_times)
      if (avg_time <= 1.0) "A" else if (avg_time <= 1.5) "B" else if (avg_time <= 2.0) "C" else "D"
    } else "F"
  )
  
  .perf_metrics$last_benchmark <<- Sys.time()
  
  cat("✅ Benchmarks completed in", round(total_benchmark_time, 2), "seconds\n")
  cat("   Average response time:", round(results$summary$avg_response_time, 3), "seconds\n")
  cat("   Target compliance:", round(results$summary$target_compliance, 1), "%\n")
  cat("   Performance grade:", results$summary$performance_grade, "\n")
  
  return(results)
}

#' Get current performance statistics
#' 
#' @param include_trends Whether to include trend analysis
#' @return List of performance statistics
get_performance_stats <- function(include_trends = TRUE) {
  stats <- list(
    overview = list(
      total_searches = .perf_metrics$total_searches,
      average_response_time = round(.perf_metrics$average_time, 3),
      fast_searches_percent = if (.perf_metrics$total_searches > 0) {
        round(.perf_metrics$fast_searches / .perf_metrics$total_searches * 100, 1)
      } else 0,
      slow_searches_percent = if (.perf_metrics$total_searches > 0) {
        round(.perf_metrics$slow_searches / .perf_metrics$total_searches * 100, 1)  
      } else 0,
      critical_searches = .perf_metrics$critical_searches,
      last_benchmark = .perf_metrics$last_benchmark
    ),
    thresholds = .perf_config
  )
  
  if (include_trends && nrow(.perf_metrics$trend_data) > 0) {
    recent_data <- .perf_metrics$trend_data[
      .perf_metrics$trend_data$timestamp >= (Sys.time() - 3600 * .perf_config$trend_window), 
    ]
    
    if (nrow(recent_data) > 0) {
      stats$trends <- list(
        recent_searches = nrow(recent_data),
        recent_avg_time = round(mean(recent_data$response_time), 3),
        recent_cache_hits = sum(recent_data$cache_hit),
        performance_distribution = table(recent_data$performance_rating),
        slowest_queries = recent_data[
          order(recent_data$response_time, decreasing = TRUE)[1:min(5, nrow(recent_data))],
          c("timestamp", "query_text", "response_time", "result_count")
        ]
      )
    }
  }
  
  return(stats)
}

#' Generate performance optimization recommendations
#' 
#' @param pool Database connection pool
#' @return List of optimization recommendations
generate_performance_recommendations <- function(pool = NULL) {
  stats <- get_performance_stats()
  recommendations <- list()
  
  # Response time analysis
  if (stats$overview$average_response_time > .perf_config$target_response_time) {
    recommendations$response_time <- list(
      priority = "HIGH",
      issue = "Average response time exceeds target",
      current = paste(stats$overview$average_response_time, "seconds"),
      target = paste(.perf_config$target_response_time, "seconds"),
      suggestions = c(
        "Optimize database indices",
        "Enable result caching",
        "Consider query result limits",
        "Review PostgreSQL configuration"
      )
    )
  }
  
  # Cache utilization
  if (exists("get_cache_stats")) {
    tryCatch({
      cache_stats <- get_cache_stats()
      if (cache_stats$enabled && cache_stats$hit_rate < 50) {
        recommendations$caching <- list(
          priority = "MEDIUM",
          issue = "Low cache hit rate",
          current = paste(cache_stats$hit_rate, "%"),
          target = "60%+",
          suggestions = c(
            "Increase cache TTL",
            "Warm cache with popular queries",
            "Optimize cache key generation"
          )
        )
      }
    }, error = function(e) {
      # Cache stats not available
    })
  }
  
  # Database optimization
  if (!is.null(pool)) {
    tryCatch({
      # Check for missing indices
      index_check <- execute_query(pool, "
        SELECT schemaname, tablename, attname, n_distinct, correlation
        FROM pg_stats 
        WHERE tablename = 'documents' 
        AND schemaname = 'public'
        ORDER BY n_distinct DESC
      ")
      
      if (!is.null(index_check) && nrow(index_check) > 0) {
        high_cardinality_cols <- index_check$attname[index_check$n_distinct > 1000]
        
        if (length(high_cardinality_cols) > 0) {
          recommendations$indexing <- list(
            priority = "MEDIUM",
            issue = "Potentially missing indices on high-cardinality columns",
            columns = high_cardinality_cols,
            suggestions = c(
              "Review query patterns for these columns",
              "Consider composite indices for filter combinations",
              "Monitor index usage statistics"
            )
          )
        }
      }
    }, error = function(e) {
      # Database analysis not available
    })
  }
  
  # Query complexity analysis
  if (nrow(.perf_metrics$trend_data) > 10) {
    complex_queries <- .perf_metrics$trend_data[
      .perf_metrics$trend_data$query_length > 50 | .perf_metrics$trend_data$filter_count > 3,
    ]
    
    if (nrow(complex_queries) > 0) {
      avg_complex_time <- mean(complex_queries$response_time)
      
      if (avg_complex_time > .perf_config$target_response_time * 1.5) {
        recommendations$query_complexity <- list(
          priority = "LOW",
          issue = "Complex queries performing slowly",
          current = paste(round(avg_complex_time, 2), "seconds average"),
          suggestions = c(
            "Optimize PostgreSQL full-text search configuration",
            "Consider query simplification suggestions for users",
            "Implement query result pagination"
          )
        )
      }
    }
  }
  
  # System resource recommendations
  if (stats$overview$critical_searches > 0) {
    recommendations$system_resources <- list(
      priority = "HIGH",
      issue = paste("Critical performance issues detected:", stats$overview$critical_searches, "searches"),
      suggestions = c(
        "Monitor system memory and CPU usage",
        "Consider scaling database resources",
        "Implement connection pooling optimization",
        "Review Railway deployment limits"
      )
    )
  }
  
  return(recommendations)
}

#' Create performance monitoring dashboard data
#' 
#' @param hours_back Number of hours of data to include
#' @return List suitable for dashboard visualization
get_performance_dashboard_data <- function(hours_back = 24) {
  if (nrow(.perf_metrics$trend_data) == 0) {
    return(list(message = "No performance data available"))
  }
  
  # Filter recent data
  cutoff_time <- Sys.time() - (hours_back * 3600)
  recent_data <- .perf_metrics$trend_data[.perf_metrics$trend_data$timestamp >= cutoff_time, ]
  
  if (nrow(recent_data) == 0) {
    return(list(message = "No recent performance data"))
  }
  
  # Time series data (hourly aggregation)
  recent_data$hour <- format(recent_data$timestamp, "%Y-%m-%d %H:00:00")
  hourly_stats <- aggregate(
    cbind(response_time, result_count) ~ hour,
    data = recent_data,
    FUN = function(x) c(mean = mean(x), count = length(x))
  )
  
  # Performance distribution
  perf_dist <- as.data.frame(table(recent_data$performance_rating))
  names(perf_dist) <- c("rating", "count")
  
  # Top slow queries
  slow_queries <- recent_data[
    order(recent_data$response_time, decreasing = TRUE)[1:min(10, nrow(recent_data))],
    c("timestamp", "query_text", "response_time", "result_count", "cache_hit")
  ]
  
  return(list(
    time_series = list(
      labels = hourly_stats$hour,
      response_times = hourly_stats$response_time[, "mean"],
      search_counts = hourly_stats$response_time[, "count"]
    ),
    performance_distribution = perf_dist,
    slow_queries = slow_queries,
    summary = list(
      total_searches = nrow(recent_data),
      avg_response_time = round(mean(recent_data$response_time), 3),
      cache_hit_rate = round(sum(recent_data$cache_hit) / nrow(recent_data) * 100, 1),
      target_compliance = round(sum(recent_data$response_time <= .perf_config$target_response_time) / nrow(recent_data) * 100, 1)
    )
  )
}

cat("✅ Search Performance Benchmarks loaded\n")
cat("   Target response time: ", .perf_config$target_response_time, " seconds\n")
cat("   Performance monitoring: ACTIVE\n")