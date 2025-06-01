# INTELLIGENT SPATIAL QUERY PLANNING SYSTEM  
# Brazilian Legislative Monitoring System - Query Optimization
# ============================================================================
#
# Advanced query planning system with cost-based optimization for spatial operations:
# - Adaptive query plan selection based on data distribution and system state
# - Dynamic batch sizing with memory pressure monitoring
# - Intelligent caching strategy with cache warming
# - Fallback mechanisms for system overload and errors
# - Real-time performance analysis and query plan adjustment
# - Predictive scaling for large document processing batches
#
# Optimization targets:
# - <2s average query response time across 134k+ documents
# - <1.4GB memory footprint (Railway compatible)
# - >99% system availability with graceful degradation
# - Adaptive performance under varying load conditions

library(shiny)
library(dplyr) 
library(pool)
library(DBI)
library(memoise)
library(jsonlite)
library(lubridate)

# ============================================================================
# QUERY PLANNING CONFIGURATION
# ============================================================================

QUERY_PLANNER_CONFIG <- list(
  # Performance thresholds and targets
  target_response_time_ms = 2000,     # Primary target: 2 second response
  warning_response_time_ms = 3000,    # Warning threshold: 3 seconds  
  critical_response_time_ms = 5000,   # Critical threshold: 5 seconds
  max_memory_usage_mb = 1200,         # Railway constraint minus buffer
  
  # Adaptive batch sizing
  min_batch_size = 100,               # Minimum documents per batch
  max_batch_size = 5000,              # Maximum documents per batch  
  default_batch_size = 1000,          # Starting batch size
  batch_size_adjustment_factor = 0.8, # Reduction factor when performance degrades
  
  # Query planning strategies
  strategies = list(
    direct_materialized = list(
      description = "Query materialized views directly", 
      cost_factor = 1.0,
      memory_factor = 0.5,
      conditions = list("materialized_views_available", "small_result_set")
    ),
    indexed_spatial = list(
      description = "Use spatial indexes with geometric joins",
      cost_factor = 2.0,
      memory_factor = 1.0,
      conditions = list("spatial_indexes_available", "coordinates_available")
    ),
    progressive_batch = list(
      description = "Process in small batches with progress tracking",
      cost_factor = 3.0,
      memory_factor = 0.7,
      conditions = list("large_dataset", "memory_constrained")
    ),
    hybrid_text_spatial = list(
      description = "Combine text matching with spatial verification",
      cost_factor = 3.5,
      memory_factor = 1.2,
      conditions = list("mixed_quality_data", "high_accuracy_required")
    ),
    fallback_sequential = list(
      description = "Sequential processing with maximum compatibility",
      cost_factor = 5.0,
      memory_factor = 0.3,
      conditions = list("system_overload", "error_recovery")
    )
  ),
  
  # Cache management
  enable_query_caching = TRUE,
  cache_hit_boost_factor = 0.1,       # Cost reduction for cached queries
  cache_warming_threshold = 0.7,      # Cache queries with >70% similarity
  max_cache_entries = 1000,
  
  # Performance monitoring
  enable_adaptive_planning = TRUE,
  performance_history_window = 100,   # Keep last 100 query performance records
  plan_adjustment_threshold = 0.2     # Adjust plan if performance degrades >20%
)

# System state indicators for query planning decisions
SYSTEM_STATE_INDICATORS <- list(
  memory_pressure_levels = list(
    low = list(threshold_mb = 800, batch_multiplier = 1.2),
    medium = list(threshold_mb = 1000, batch_multiplier = 1.0),
    high = list(threshold_mb = 1200, batch_multiplier = 0.8),
    critical = list(threshold_mb = 1350, batch_multiplier = 0.5)
  ),
  
  query_load_categories = list(
    light = list(queries_per_minute = 10, complexity_multiplier = 1.0),
    moderate = list(queries_per_minute = 30, complexity_multiplier = 1.2),
    heavy = list(queries_per_minute = 50, complexity_multiplier = 1.5),
    overload = list(queries_per_minute = 100, complexity_multiplier = 2.0)
  )
)

# ============================================================================
# QUERY PERFORMANCE MONITORING
# ============================================================================

#' Initialize query performance tracking system
#' @param pool Database connection pool
#' @return Performance tracker object
init_query_performance_tracker <- function(pool) {
  
  # Create in-memory performance history
  performance_history <- list(
    queries = list(),
    system_metrics = list(),
    plan_adjustments = list(),
    last_cleanup = Sys.time()
  )
  
  # Performance tracker functions
  tracker <- list(
    
    # Record query performance
    record_query = function(query_info) {
      timestamp <- Sys.time()
      
      query_record <- list(
        timestamp = timestamp,
        query_id = query_info$query_id %||% digest::digest(query_info$query),
        query_type = query_info$query_type,
        execution_plan = query_info$execution_plan,
        duration_ms = query_info$duration_ms,
        memory_used_mb = query_info$memory_used_mb,
        documents_processed = query_info$documents_processed %||% 0,
        success = query_info$success %||% TRUE,
        cache_hit = query_info$cache_hit %||% FALSE,
        batch_size = query_info$batch_size %||% 1
      )
      
      # Add to history (maintain window size)
      performance_history$queries <<- append(performance_history$queries, list(query_record))
      if (length(performance_history$queries) > QUERY_PLANNER_CONFIG$performance_history_window) {
        performance_history$queries <<- tail(performance_history$queries, 
                                           QUERY_PLANNER_CONFIG$performance_history_window)
      }
      
      # Log to database for long-term analysis
      if (!is.null(pool)) {
        log_query_performance_to_db(pool, query_record)
      }
      
      invisible(query_record)
    },
    
    # Get recent performance statistics
    get_performance_stats = function(minutes_back = 15) {
      cutoff_time <- Sys.time() - minutes(minutes_back)
      recent_queries <- Filter(function(q) q$timestamp > cutoff_time, performance_history$queries)
      
      if (length(recent_queries) == 0) {
        return(list(
          avg_duration_ms = QUERY_PLANNER_CONFIG$target_response_time_ms,
          success_rate = 1.0,
          cache_hit_rate = 0.0,
          queries_per_minute = 0,
          memory_trend = "stable"
        ))
      }
      
      durations <- sapply(recent_queries, function(q) q$duration_ms)
      successes <- sapply(recent_queries, function(q) q$success)
      cache_hits <- sapply(recent_queries, function(q) q$cache_hit)
      
      list(
        avg_duration_ms = mean(durations, na.rm = TRUE),
        p95_duration_ms = quantile(durations, 0.95, na.rm = TRUE),
        success_rate = mean(successes, na.rm = TRUE),
        cache_hit_rate = mean(cache_hits, na.rm = TRUE),
        queries_per_minute = length(recent_queries) / minutes_back,
        total_queries = length(recent_queries),
        memory_trend = calculate_memory_trend(recent_queries)
      )
    },
    
    # Analyze system state for planning decisions
    analyze_system_state = function() {
      current_memory <- get_current_memory_usage()
      perf_stats <- tracker$get_performance_stats()
      
      # Determine memory pressure level
      memory_pressure <- "low"
      for (level_name in names(SYSTEM_STATE_INDICATORS$memory_pressure_levels)) {
        level <- SYSTEM_STATE_INDICATORS$memory_pressure_levels[[level_name]]
        if (current_memory >= level$threshold_mb) {
          memory_pressure <- level_name
        }
      }
      
      # Determine query load level  
      query_load <- "light"
      qpm <- perf_stats$queries_per_minute
      for (load_name in names(SYSTEM_STATE_INDICATORS$query_load_categories)) {
        load <- SYSTEM_STATE_INDICATORS$query_load_categories[[load_name]]
        if (qpm >= load$queries_per_minute) {
          query_load <- load_name
        }
      }
      
      list(
        memory_pressure = memory_pressure,
        current_memory_mb = current_memory,
        query_load = query_load,
        performance_grade = calculate_performance_grade(perf_stats),
        system_health = calculate_system_health(perf_stats, memory_pressure, query_load)
      )
    },
    
    # Get performance history for analysis
    get_history = function() performance_history
  )
  
  cat("✅ Query performance tracker initialized\n")
  return(tracker)
}

#' Calculate memory usage trend from recent queries
#' @param recent_queries List of recent query performance records
#' @return String indicating trend: "increasing", "decreasing", "stable"
calculate_memory_trend <- function(recent_queries) {
  if (length(recent_queries) < 5) return("stable")
  
  memory_usage <- sapply(recent_queries, function(q) q$memory_used_mb %||% 0)
  recent_half <- tail(memory_usage, ceiling(length(memory_usage) / 2))
  earlier_half <- head(memory_usage, floor(length(memory_usage) / 2))
  
  recent_avg <- mean(recent_half, na.rm = TRUE)
  earlier_avg <- mean(earlier_half, na.rm = TRUE)
  
  if (recent_avg > earlier_avg * 1.1) return("increasing")
  if (recent_avg < earlier_avg * 0.9) return("decreasing")
  return("stable")
}

#' Calculate overall performance grade based on recent metrics
#' @param perf_stats Performance statistics object
#' @return Single letter grade: A, B, C, D, or F
calculate_performance_grade <- function(perf_stats) {
  score <- 100
  
  # Deduct points for slow response times
  if (perf_stats$avg_duration_ms > QUERY_PLANNER_CONFIG$target_response_time_ms) {
    slowdown_factor <- perf_stats$avg_duration_ms / QUERY_PLANNER_CONFIG$target_response_time_ms
    score <- score - (slowdown_factor - 1) * 30
  }
  
  # Deduct points for low success rate
  if (perf_stats$success_rate < 1.0) {
    score <- score - (1 - perf_stats$success_rate) * 50
  }
  
  # Bonus points for high cache hit rate
  score <- score + perf_stats$cache_hit_rate * 10
  
  if (score >= 90) return("A")
  if (score >= 80) return("B")  
  if (score >= 70) return("C")
  if (score >= 60) return("D")
  return("F")
}

#' Calculate overall system health score
#' @param perf_stats Performance statistics
#' @param memory_pressure Memory pressure level
#' @param query_load Query load level
#' @return Numeric health score 0-100
calculate_system_health <- function(perf_stats, memory_pressure, query_load) {
  health_score <- 100
  
  # Memory pressure penalties
  memory_penalty <- switch(memory_pressure,
    "low" = 0,
    "medium" = 5,
    "high" = 15,
    "critical" = 30
  )
  health_score <- health_score - memory_penalty
  
  # Query load penalties
  load_penalty <- switch(query_load,
    "light" = 0,
    "moderate" = 5,
    "heavy" = 15,
    "overload" = 25
  )
  health_score <- health_score - load_penalty
  
  # Performance penalties
  if (perf_stats$avg_duration_ms > QUERY_PLANNER_CONFIG$warning_response_time_ms) {
    health_score <- health_score - 20
  }
  
  if (perf_stats$success_rate < 0.95) {
    health_score <- health_score - (1 - perf_stats$success_rate) * 30
  }
  
  max(0, min(100, health_score))
}

# ============================================================================
# INTELLIGENT QUERY PLANNING ENGINE
# ============================================================================

#' Create intelligent query planner with adaptive optimization
#' @param pool Database connection pool
#' @param performance_tracker Performance tracking object
#' @return Query planner object
create_intelligent_query_planner <- function(pool, performance_tracker = NULL) {
  
  if (is.null(performance_tracker)) {
    performance_tracker <- init_query_performance_tracker(pool)
  }
  
  planner <- list(
    
    # Plan optimal query execution strategy
    plan_query = function(query_request) {
      system_state <- performance_tracker$analyze_system_state()
      
      # Evaluate available strategies
      strategy_scores <- list()
      
      for (strategy_name in names(QUERY_PLANNER_CONFIG$strategies)) {
        strategy <- QUERY_PLANNER_CONFIG$strategies[[strategy_name]]
        
        score <- evaluate_strategy(strategy, query_request, system_state)
        strategy_scores[[strategy_name]] <- score
      }
      
      # Select best strategy
      best_strategy_name <- names(which.max(strategy_scores))
      best_strategy <- QUERY_PLANNER_CONFIG$strategies[[best_strategy_name]]
      
      # Generate execution plan
      execution_plan <- list(
        strategy = best_strategy_name,
        strategy_config = best_strategy,
        estimated_cost = strategy_scores[[best_strategy_name]],
        batch_size = calculate_optimal_batch_size(query_request, system_state),
        cache_strategy = determine_cache_strategy(query_request),
        fallback_strategies = get_fallback_strategies(best_strategy_name),
        system_state = system_state,
        estimated_duration_ms = estimate_execution_time(query_request, best_strategy, system_state),
        memory_estimate_mb = estimate_memory_usage(query_request, best_strategy)
      )
      
      cat("🎯 Query plan selected:", best_strategy_name, 
          sprintf("| Est. duration: %.0fms | Batch size: %d\n", 
                  execution_plan$estimated_duration_ms, execution_plan$batch_size))
      
      return(execution_plan)
    },
    
    # Execute query with planned strategy
    execute_planned_query = function(query_request, execution_plan = NULL) {
      
      if (is.null(execution_plan)) {
        execution_plan <- planner$plan_query(query_request)
      }
      
      start_time <- Sys.time()
      execution_id <- paste0("query_", format(start_time, "%Y%m%d_%H%M%S_%OS3"))
      
      cat("🚀 Executing query:", execution_id, "using strategy:", execution_plan$strategy, "\n")
      
      # Execute with performance monitoring
      result <- tryCatch({
        
        # Check memory before execution
        pre_memory <- get_current_memory_usage()
        if (pre_memory > QUERY_PLANNER_CONFIG$max_memory_usage_mb) {
          cat("⚠️ Memory pressure detected, reducing batch size\n")
          execution_plan$batch_size <- max(QUERY_PLANNER_CONFIG$min_batch_size,
                                         execution_plan$batch_size * 0.5)
        }
        
        # Execute based on selected strategy
        query_result <- switch(execution_plan$strategy,
          "direct_materialized" = execute_materialized_view_query(pool, query_request, execution_plan),
          "indexed_spatial" = execute_indexed_spatial_query(pool, query_request, execution_plan),
          "progressive_batch" = execute_progressive_batch_query(pool, query_request, execution_plan),
          "hybrid_text_spatial" = execute_hybrid_text_spatial_query(pool, query_request, execution_plan),
          "fallback_sequential" = execute_fallback_sequential_query(pool, query_request, execution_plan),
          stop("Unknown execution strategy: ", execution_plan$strategy)
        )
        
        query_result
        
      }, error = function(e) {
        cat("❌ Query execution failed:", e$message, "\n")
        
        # Try fallback strategy
        if (length(execution_plan$fallback_strategies) > 0) {
          cat("🔄 Attempting fallback strategy:", execution_plan$fallback_strategies[1], "\n")
          fallback_plan <- execution_plan
          fallback_plan$strategy <- execution_plan$fallback_strategies[1]
          
          return(planner$execute_planned_query(query_request, fallback_plan))
        }
        
        # Return empty result with error info
        list(
          data = data.frame(),
          success = FALSE,
          error = e$message,
          execution_id = execution_id
        )
      })
      
      # Record performance metrics
      end_time <- Sys.time()
      duration_ms <- as.numeric(end_time - start_time, units = "secs") * 1000
      post_memory <- get_current_memory_usage()
      
      performance_record <- list(
        query_id = execution_id,
        query_type = query_request$type %||% "unknown",
        execution_plan = execution_plan$strategy,
        duration_ms = duration_ms,
        memory_used_mb = post_memory,
        documents_processed = nrow(result$data %||% data.frame()),
        success = result$success %||% TRUE,
        cache_hit = result$cache_hit %||% FALSE,
        batch_size = execution_plan$batch_size
      )
      
      performance_tracker$record_query(performance_record)
      
      # Add execution metadata to result
      result$execution_metadata <- list(
        execution_id = execution_id,
        strategy_used = execution_plan$strategy,
        duration_ms = duration_ms,
        performance_grade = calculate_performance_grade(list(
          avg_duration_ms = duration_ms,
          success_rate = as.numeric(result$success %||% TRUE)
        ))
      )
      
      return(result)
    },
    
    # Get performance tracker
    get_performance_tracker = function() performance_tracker,
    
    # Analyze query patterns and suggest optimizations
    analyze_query_patterns = function() {
      history <- performance_tracker$get_history()
      
      if (length(history$queries) < 10) {
        return(list(
          message = "Insufficient query history for pattern analysis",
          recommendations = character(0)
        ))
      }
      
      # Analyze common patterns
      query_types <- sapply(history$queries, function(q) q$query_type %||% "unknown")
      strategy_usage <- sapply(history$queries, function(q) q$execution_plan %||% "unknown")
      
      pattern_analysis <- list(
        most_common_query_types = names(sort(table(query_types), decreasing = TRUE)),
        most_effective_strategies = names(sort(table(strategy_usage), decreasing = TRUE)),
        avg_performance_by_strategy = tapply(
          sapply(history$queries, function(q) q$duration_ms), 
          strategy_usage, 
          mean, na.rm = TRUE
        ),
        recommendations = generate_optimization_recommendations(history$queries)
      )
      
      return(pattern_analysis)
    }
  )
  
  cat("✅ Intelligent Query Planner created\n")
  cat("   Strategies available:", length(QUERY_PLANNER_CONFIG$strategies), "\n")
  cat("   Adaptive planning:", QUERY_PLANNER_CONFIG$enable_adaptive_planning, "\n")
  
  return(planner)
}

# ============================================================================
# STRATEGY EVALUATION AND EXECUTION
# ============================================================================

#' Evaluate strategy fitness for current query and system state
#' @param strategy Strategy configuration
#' @param query_request Query request details
#' @param system_state Current system state
#' @return Numeric fitness score (higher = better)
evaluate_strategy <- function(strategy, query_request, system_state) {
  base_score <- 100
  
  # Apply cost factor (lower cost = higher score)
  cost_penalty <- (strategy$cost_factor - 1) * 20
  base_score <- base_score - cost_penalty
  
  # Apply memory factor based on current pressure
  memory_multiplier <- switch(system_state$memory_pressure,
    "low" = 1.0,
    "medium" = 0.9,
    "high" = 0.7,
    "critical" = 0.5
  )
  
  if (strategy$memory_factor > 1.0 && system_state$memory_pressure %in% c("high", "critical")) {
    base_score <- base_score * memory_multiplier
  }
  
  # Check strategy conditions
  condition_bonus <- 0
  if ("materialized_views_available" %in% strategy$conditions) {
    if (check_materialized_views_available()) condition_bonus <- condition_bonus + 15
  }
  
  if ("coordinates_available" %in% strategy$conditions) {
    coord_rate <- calculate_coordinate_availability_rate(query_request)
    condition_bonus <- condition_bonus + (coord_rate * 10)
  }
  
  if ("large_dataset" %in% strategy$conditions) {
    dataset_size <- estimate_dataset_size(query_request)
    if (dataset_size > 1000) condition_bonus <- condition_bonus + 10
  }
  
  # Performance history bonus
  if (system_state$performance_grade %in% c("A", "B")) {
    base_score <- base_score + 5
  }
  
  max(0, base_score + condition_bonus)
}

#' Calculate optimal batch size based on system state
#' @param query_request Query request details
#' @param system_state Current system state
#' @return Optimal batch size
calculate_optimal_batch_size <- function(query_request, system_state) {
  base_size <- QUERY_PLANNER_CONFIG$default_batch_size
  
  # Adjust for memory pressure
  memory_multiplier <- SYSTEM_STATE_INDICATORS$memory_pressure_levels[[system_state$memory_pressure]]$batch_multiplier
  adjusted_size <- base_size * memory_multiplier
  
  # Adjust for query load
  if (system_state$query_load %in% c("heavy", "overload")) {
    adjusted_size <- adjusted_size * 0.8
  }
  
  # Ensure within bounds
  max(QUERY_PLANNER_CONFIG$min_batch_size, 
      min(QUERY_PLANNER_CONFIG$max_batch_size, round(adjusted_size)))
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

#' Get current memory usage in MB
#' @return Current memory usage
get_current_memory_usage <- function() {
  gc_result <- gc(verbose = FALSE, reset = FALSE)
  sum(gc_result[, "used"]) * 8 / 1024 # Convert to MB (approximation)
}

#' Check if materialized views are available and current
#' @return Boolean indicating availability
check_materialized_views_available <- function() {
  # Placeholder - would check database for materialized view status
  TRUE
}

#' Calculate coordinate availability rate from query request
#' @param query_request Query request details
#' @return Rate of documents with coordinates (0-1)
calculate_coordinate_availability_rate <- function(query_request) {
  # Placeholder - would analyze document batch for coordinate availability
  0.7 # Assume 70% have coordinates
}

#' Estimate dataset size from query request
#' @param query_request Query request details
#' @return Estimated number of records
estimate_dataset_size <- function(query_request) {
  query_request$estimated_size %||% 1000
}

#' Get fallback strategies for a given primary strategy
#' @param strategy_name Primary strategy name
#' @return Vector of fallback strategy names
get_fallback_strategies <- function(strategy_name) {
  fallback_map <- list(
    "direct_materialized" = c("indexed_spatial", "progressive_batch"),
    "indexed_spatial" = c("progressive_batch", "hybrid_text_spatial"),
    "progressive_batch" = c("fallback_sequential"),
    "hybrid_text_spatial" = c("progressive_batch", "fallback_sequential"),
    "fallback_sequential" = c() # No fallback for fallback strategy
  )
  
  fallback_map[[strategy_name]] %||% c("fallback_sequential")
}

# ============================================================================
# STRATEGY EXECUTION FUNCTIONS (PLACEHOLDER IMPLEMENTATIONS)
# ============================================================================

# Note: These are simplified placeholder implementations
# In production, these would integrate with the actual spatial join algorithms

execute_materialized_view_query <- function(pool, query_request, execution_plan) {
  cat("📊 Executing materialized view query\n")
  list(data = data.frame(), success = TRUE, cache_hit = TRUE)
}

execute_indexed_spatial_query <- function(pool, query_request, execution_plan) {
  cat("🗺️ Executing indexed spatial query\n")
  list(data = data.frame(), success = TRUE, cache_hit = FALSE)
}

execute_progressive_batch_query <- function(pool, query_request, execution_plan) {
  cat("📦 Executing progressive batch query\n")
  list(data = data.frame(), success = TRUE, cache_hit = FALSE)
}

execute_hybrid_text_spatial_query <- function(pool, query_request, execution_plan) {
  cat("🔍 Executing hybrid text-spatial query\n")
  list(data = data.frame(), success = TRUE, cache_hit = FALSE)
}

execute_fallback_sequential_query <- function(pool, query_request, execution_plan) {
  cat("⚠️ Executing fallback sequential query\n")
  list(data = data.frame(), success = TRUE, cache_hit = FALSE)
}

#' Generate optimization recommendations from query history
#' @param query_history List of historical queries
#' @return Vector of recommendation strings
generate_optimization_recommendations <- function(query_history) {
  recommendations <- character(0)
  
  avg_duration <- mean(sapply(query_history, function(q) q$duration_ms), na.rm = TRUE)
  if (avg_duration > QUERY_PLANNER_CONFIG$target_response_time_ms) {
    recommendations <- c(recommendations, "Consider reducing batch sizes to improve response times")
  }
  
  cache_hit_rate <- mean(sapply(query_history, function(q) q$cache_hit), na.rm = TRUE)
  if (cache_hit_rate < 0.3) {
    recommendations <- c(recommendations, "Low cache hit rate - consider cache warming strategies")
  }
  
  if (length(recommendations) == 0) {
    recommendations <- "Query performance is optimal"
  }
  
  recommendations
}

# ============================================================================
# MODULE EXPORTS
# ============================================================================

intelligent_query_planner_exports <- list(
  # Main planner functions
  create_intelligent_query_planner = create_intelligent_query_planner,
  init_query_performance_tracker = init_query_performance_tracker,
  
  # Strategy evaluation
  evaluate_strategy = evaluate_strategy,
  calculate_optimal_batch_size = calculate_optimal_batch_size,
  
  # Performance analysis
  calculate_performance_grade = calculate_performance_grade,
  calculate_system_health = calculate_system_health,
  
  # Configuration
  QUERY_PLANNER_CONFIG = QUERY_PLANNER_CONFIG,
  SYSTEM_STATE_INDICATORS = SYSTEM_STATE_INDICATORS
)

cat("✅ Intelligent Query Planning System loaded successfully\n")
cat("   Strategies available:", length(QUERY_PLANNER_CONFIG$strategies), "\n")
cat("   Adaptive optimization:", QUERY_PLANNER_CONFIG$enable_adaptive_planning, "\n")
cat("   Target response time: <", QUERY_PLANNER_CONFIG$target_response_time_ms, "ms\n")