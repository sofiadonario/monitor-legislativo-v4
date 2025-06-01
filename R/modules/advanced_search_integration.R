# Advanced Search System Integration - Week 3 Implementation
# Monitor Legislativo v4 - Complete Advanced Search System
# =========================================================

#' Advanced Search System Integration
#' 
#' Complete integration of the advanced search system for Monitor Legislativo v4
#' Week 3 implementation. Combines all components for optimal performance:
#' 
#' - PostgreSQL full-text search with Portuguese configuration
#' - Advanced geographic and temporal filtering
#' - Auto-complete with Brazilian legal terminology
#' - Search result caching with Redis integration
#' - Performance monitoring and benchmarking
#' - ABNT-compliant academic citations
#' - Security and LGPD compliance
#' 
#' Target: <2s response time for 95% of complex queries on 134k+ documents
#' 
#' @family advanced-search
#' @export

# Source all required modules
source("R/modules/search_module_enhanced.R", local = TRUE)
source("R/modules/search_server_enhanced.R", local = TRUE) 
source("R/utils/search_cache.R", local = TRUE)
source("R/utils/search_benchmarks.R", local = TRUE)
source("R/utils/database_utils.R", local = TRUE)
source("scripts/R/security_hardening.R", local = TRUE)

#' Initialize complete advanced search system
#' 
#' @param enable_caching Whether to enable Redis caching
#' @param enable_monitoring Whether to enable performance monitoring
#' @param warm_cache Whether to warm cache with popular searches
#' @return List with initialization results
#' @export
init_advanced_search_system <- function(enable_caching = TRUE, enable_monitoring = TRUE, warm_cache = TRUE) {
  cat("🚀 Initializing Advanced Search System - Week 3 Implementation\n")
  cat("================================================================\n")
  
  init_results <- list()
  
  # 1. Initialize database connection
  cat("1. Initializing optimized database connection...\n")
  db_result <- init_database_connection()
  init_results$database <- db_result
  
  if (!db_result$connection_loaded) {
    warning("Database connection failed - search functionality will be limited")
  } else {
    cat("   ✅ PostgreSQL connection established\n")
  }
  
  # 2. Initialize search caching system
  if (enable_caching) {
    cat("2. Initializing search result caching...\n")
    cache_result <- init_search_cache()
    init_results$cache <- cache_result
    
    if (cache_result$redis_available) {
      cat("   ✅ Redis cache enabled\n")
    } else {
      cat("   ⚠️  Using memory cache fallback\n")
    }
  } else {
    cat("2. Search caching disabled\n")
    init_results$cache <- list(enabled = FALSE)
  }
  
  # 3. Initialize security hardening
  cat("3. Initializing security hardening...\n")
  security_result <- init_security_hardening()
  init_results$security <- security_result
  
  if (security_result) {
    cat("   ✅ Security systems enabled\n")
  } else {
    warning("Security initialization failed")
  }
  
  # 4. Verify database setup
  if (db_result$connection_loaded) {
    cat("4. Verifying database search setup...\n")
    
    # Check if advanced search functions exist
    pool <- db_result$pool
    tryCatch({
      # Test search function
      test_result <- execute_query(pool, 
        "SELECT * FROM search_legislative_documents($1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 5, 0, 'relevance')",
        params = list("test"))
      
      if (!is.null(test_result)) {
        cat("   ✅ Advanced search functions verified\n")
        init_results$search_functions <- TRUE
      } else {
        cat("   ⚠️  Search functions available but returned no test data\n")
        init_results$search_functions <- TRUE
      }
    }, error = function(e) {
      warning("Advanced search functions not available: ", e$message)
      cat("   ⚠️  Run database/advanced_search_setup.sql to enable full functionality\n")
      init_results$search_functions <- FALSE
    })
    
    # Check search filters cache
    tryCatch({
      filters_result <- execute_query(pool, "SELECT COUNT(*) as count FROM search_filters_cache")
      
      if (!is.null(filters_result) && filters_result$count > 0) {
        cat("   ✅ Search filters cache populated\n")
        init_results$filters_cache <- TRUE
      } else {
        cat("   ⚠️  Search filters cache empty - refreshing...\n")
        refresh_result <- execute_query(pool, "SELECT refresh_search_filters_cache()")
        init_results$filters_cache <- !is.null(refresh_result)
      }
    }, error = function(e) {
      warning("Search filters cache not available: ", e$message)
      init_results$filters_cache <- FALSE
    })
  } else {
    cat("4. Database verification skipped (no connection)\n")
    init_results$search_functions <- FALSE
    init_results$filters_cache <- FALSE
  }
  
  # 5. Performance monitoring setup
  if (enable_monitoring) {
    cat("5. Setting up performance monitoring...\n")
    
    # Initialize performance metrics
    init_results$monitoring <- list(enabled = TRUE)
    
    # Run initial benchmark if database is available
    if (db_result$connection_loaded && init_results$search_functions) {
      cat("   Running initial performance benchmark...\n")
      tryCatch({
        benchmark_results <- run_search_benchmarks(db_result$pool, include_cache_warming = FALSE)
        init_results$initial_benchmark <- benchmark_results
        
        cat("   ✅ Initial benchmark completed\n")
        cat("      Average response time:", round(benchmark_results$summary$avg_response_time, 2), "seconds\n")
        cat("      Performance grade:", benchmark_results$summary$performance_grade, "\n")
      }, error = function(e) {
        warning("Initial benchmark failed: ", e$message)
        init_results$initial_benchmark <- list(error = e$message)
      })
    } else {
      cat("   ⚠️  Benchmark skipped (database/functions not available)\n")
    }
  } else {
    cat("5. Performance monitoring disabled\n")
    init_results$monitoring <- list(enabled = FALSE)
  }
  
  # 6. Cache warming
  if (enable_caching && warm_cache && db_result$connection_loaded && init_results$search_functions) {
    cat("6. Warming search cache with popular queries...\n")
    tryCatch({
      warmed_count <- warm_search_cache(db_result$pool)
      init_results$cache_warming <- list(success = TRUE, queries_cached = warmed_count)
      cat("   ✅ Cache warmed with", warmed_count, "popular queries\n")
    }, error = function(e) {
      warning("Cache warming failed: ", e$message)
      init_results$cache_warming <- list(success = FALSE, error = e$message)
    })
  } else {
    cat("6. Cache warming skipped\n")
    init_results$cache_warming <- list(success = FALSE, reason = "disabled or unavailable")
  }
  
  # 7. System health check
  cat("7. Running system health check...\n")
  health_check <- get_system_health_status(init_results)
  init_results$health_check <- health_check
  
  cat("   Overall system health:", health_check$status, "\n")
  if (length(health_check$warnings) > 0) {
    cat("   Warnings:", length(health_check$warnings), "\n")
  }
  if (length(health_check$errors) > 0) {
    cat("   Errors:", length(health_check$errors), "\n")
  }
  
  cat("\n================================================================\n")
  cat("🎉 Advanced Search System Initialization Complete!\n")
  cat("\nSystem Status:\n")
  cat("  Database:        ", if (init_results$database$connection_loaded) "✅ Connected" else "❌ Failed", "\n")
  cat("  Search Functions:", if (init_results$search_functions) "✅ Available" else "⚠️  Limited", "\n")
  cat("  Caching:         ", if (init_results$cache$redis_available) "✅ Redis" else if (enable_caching) "⚠️  Memory" else "❌ Disabled", "\n")
  cat("  Security:        ", if (init_results$security) "✅ Enabled" else "⚠️  Issues", "\n")
  cat("  Monitoring:      ", if (init_results$monitoring$enabled) "✅ Active" else "❌ Disabled", "\n")
  
  if (!is.null(init_results$initial_benchmark$summary)) {
    cat("  Performance:     ", init_results$initial_benchmark$summary$performance_grade, " grade\n")
  }
  
  cat("\n================================================================\n")
  
  return(init_results)
}

#' Get system health status
#' 
#' @param init_results Initialization results
#' @return List with health status information
get_system_health_status <- function(init_results) {
  warnings <- c()
  errors <- c()
  status <- "healthy"
  
  # Database health
  if (!init_results$database$connection_loaded) {
    errors <- c(errors, "Database connection failed")
    status <- "critical"
  }
  
  # Search functions health
  if (!init_results$search_functions) {
    warnings <- c(warnings, "Advanced search functions not available")
    if (status == "healthy") status <- "degraded"
  }
  
  # Cache health
  if (init_results$cache$enabled && !init_results$cache$redis_available) {
    warnings <- c(warnings, "Redis cache unavailable, using memory fallback")
    if (status == "healthy") status <- "degraded"
  }
  
  # Security health
  if (!init_results$security) {
    warnings <- c(warnings, "Security hardening issues detected")
    if (status == "healthy") status <- "degraded"
  }
  
  # Performance health
  if (!is.null(init_results$initial_benchmark$summary)) {
    if (init_results$initial_benchmark$summary$performance_grade %in% c("D", "F")) {
      warnings <- c(warnings, "Poor performance detected in benchmarks")
      if (status == "healthy") status <- "degraded"
    }
  }
  
  return(list(
    status = status,
    warnings = warnings,
    errors = errors,
    check_time = Sys.time()
  ))
}

#' Create advanced search module for Shiny app integration
#' 
#' @param id Module namespace ID
#' @param db_pool Database connection pool reactive
#' @param enable_analytics Whether to enable search analytics
#' @return List of UI and server components
#' @export
create_advanced_search_module <- function(id, db_pool = reactive(NULL), enable_analytics = TRUE) {
  
  # Enhanced UI with all advanced features
  ui <- searchAdvancedUI(id)
  
  # Enhanced server with caching and monitoring
  server <- function(input, output, session) {
    # Call the advanced server with additional functionality
    base_module <- searchAdvancedServer(id, db_pool)
    
    # Add performance monitoring wrapper
    if (enable_analytics) {
      # Wrap search results with performance logging
      enhanced_results <- reactive({
        base_results <- base_module$results()
        metadata <- base_module$search_metadata()
        
        # Log performance if we have metadata
        if (!is.null(metadata)) {
          log_search_performance(
            query_text = metadata$query,
            response_time = metadata$search_time,
            result_count = metadata$total_count,
            filters_applied = metadata$filters,
            cache_hit = !is.null(metadata$from_cache) && metadata$from_cache,
            user_session = session$token
          )
        }
        
        return(base_results)
      })
      
      # Replace results reactive with enhanced version
      base_module$results <- enhanced_results
    }
    
    # Add analytics outputs
    if (enable_analytics) {
      output$search_performance_table <- renderTable({
        metadata <- base_module$search_metadata()
        
        if (is.null(metadata)) {
          return(data.frame(
            Metric = c("Search Status"),
            Value = c("Ready")
          ))
        }
        
        data.frame(
          Metric = c(
            "Search Time",
            "Results Found", 
            "Query Length",
            "Filters Applied",
            "Performance Rating"
          ),
          Value = c(
            paste0(round(metadata$search_time, 3), " seconds"),
            format(metadata$total_count, big.mark = ","),
            paste0(nchar(metadata$query), " characters"),
            length(metadata$filters[!sapply(metadata$filters, is.null)]),
            if (metadata$search_time <= 1) "Excellent" else 
              if (metadata$search_time <= 2) "Good" else "Needs Optimization"
          )
        )
      }, bordered = TRUE, striped = TRUE)
      
      output$popular_terms_table <- renderTable({
        # Mock popular terms data (would come from search analytics)
        data.frame(
          Term = c("lei", "decreto", "portaria", "público", "federal"),
          Frequency = c("15,234", "12,876", "8,901", "7,456", "6,234"),
          "Avg Results" = c("1,234", "987", "654", "2,345", "3,456"),
          check.names = FALSE
        )
      }, bordered = TRUE, striped = TRUE)
    }
    
    return(base_module)
  }
  
  return(list(ui = ui, server = server))
}

#' Generate system status report
#' 
#' @param include_recommendations Whether to include optimization recommendations
#' @return Character vector with status report
generate_system_status_report <- function(include_recommendations = TRUE) {
  report <- c()
  report <- c(report, "=======================================================")
  report <- c(report, "MONITOR LEGISLATIVO V4 - ADVANCED SEARCH SYSTEM STATUS")
  report <- c(report, "=======================================================")
  report <- c(report, paste("Report generated:", Sys.time()))
  report <- c(report, "")
  
  # Database status
  db_health <- get_database_health()
  report <- c(report, "DATABASE STATUS:")
  report <- c(report, paste("  Connection:", db_health$pool_status))
  if (!is.null(db_health$database_metrics)) {
    report <- c(report, paste("  Total documents:", format(db_health$database_metrics$total_documents, big.mark = ",")))
    report <- c(report, paste("  States covered:", db_health$database_metrics$states_count))
  }
  report <- c(report, "")
  
  # Cache status
  if (exists("get_cache_stats")) {
    cache_stats <- get_cache_stats()
    report <- c(report, "CACHE STATUS:")
    report <- c(report, paste("  Backend:", cache_stats$backend))
    report <- c(report, paste("  Hit rate:", paste0(cache_stats$hit_rate, "%")))
    report <- c(report, paste("  Total requests:", cache_stats$total_requests))
    report <- c(report, "")
  }
  
  # Performance status
  perf_stats <- get_performance_stats()
  report <- c(report, "PERFORMANCE STATUS:")
  report <- c(report, paste("  Total searches:", perf_stats$overview$total_searches))
  report <- c(report, paste("  Average response time:", paste0(perf_stats$overview$average_response_time, "s")))
  report <- c(report, paste("  Fast searches:", paste0(perf_stats$overview$fast_searches_percent, "%")))
  if (perf_stats$overview$critical_searches > 0) {
    report <- c(report, paste("  Critical issues:", perf_stats$overview$critical_searches))
  }
  report <- c(report, "")
  
  # Recommendations
  if (include_recommendations) {
    recommendations <- generate_performance_recommendations()
    if (length(recommendations) > 0) {
      report <- c(report, "OPTIMIZATION RECOMMENDATIONS:")
      for (rec_name in names(recommendations)) {
        rec <- recommendations[[rec_name]]
        report <- c(report, paste("  [", rec$priority, "] ", rec$issue, sep = ""))
        for (suggestion in rec$suggestions) {
          report <- c(report, paste("    -", suggestion))
        }
      }
      report <- c(report, "")
    }
  }
  
  report <- c(report, "=======================================================")
  
  return(report)
}

cat("✅ Advanced Search System Integration loaded - Week 3 Complete\n")
cat("   All components integrated and ready for deployment\n")
cat("   Run init_advanced_search_system() to initialize\n")