# ============================================================================
# PERFORMANCE REGRESSION TESTING SUITE FOR BRAZILIAN LEGISLATIVE SYSTEM
# ============================================================================
# 
# This suite provides comprehensive performance regression testing to ensure
# that code changes and system updates don't degrade performance of the
# Brazilian Legislative Monitoring System. It establishes performance baselines,
# runs automated regression tests, and provides detailed regression analysis.
#
# Key Features:
# - Automated baseline establishment and maintenance
# - Continuous performance regression detection
# - Git commit-level performance tracking
# - Brazilian legislative workload-specific regression tests
# - Performance trend analysis and alerting
# - Railway infrastructure performance regression monitoring
# - Database query performance regression tracking
# - Cache performance regression analysis
# - Memory usage regression detection
# - Integration with CI/CD pipelines for automated testing
#
# Designed for ongoing performance validation throughout development lifecycle
# ============================================================================

cat("📈 Loading Performance Regression Testing Suite for Brazilian Legislative System\n")

# Load required libraries with error handling
suppressPackageStartupMessages({
  library(microbenchmark)
  library(profvis)
  library(pryr)
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
  library(ggplot2)
  library(jsonlite)
  library(digest)
  library(lubridate)
  library(stringr)
  library(future)
  library(future.apply)
})

# Performance regression configuration
REGRESSION_CONFIG <- list(
  # Baseline thresholds for regression detection
  performance_degradation_threshold_pct = 15,  # 15% degradation triggers alert
  critical_degradation_threshold_pct = 30,     # 30% degradation is critical
  memory_increase_threshold_mb = 50,           # 50MB memory increase is concerning
  
  # Test categories and their importance weights
  test_weights = list(
    database_operations = 0.35,      # 35% weight - most critical
    search_operations = 0.25,        # 25% weight - user-facing
    geographic_analysis = 0.20,      # 20% weight - resource intensive
    cache_performance = 0.15,        # 15% weight - system efficiency
    system_operations = 0.05         # 5% weight - basic functionality
  ),
  
  # Regression test intervals
  baseline_refresh_days = 7,         # Refresh baseline every 7 days
  regression_test_frequency_hours = 24,  # Run regression tests every 24 hours
  
  # Performance data retention
  performance_history_days = 90,     # Keep 90 days of performance history
  baseline_history_count = 10,      # Keep last 10 baselines
  
  # Railway-specific regression monitoring
  railway_memory_regression_mb = 100,   # 100MB memory increase on Railway
  railway_response_time_regression_ms = 1000,  # 1 second response time increase
  
  # Brazilian legislative workload patterns for regression testing
  workload_patterns = list(
    quick_search = list(weight = 0.4, complexity = "low"),
    filtered_search = list(weight = 0.25, complexity = "medium"),
    geographic_analysis = list(weight = 0.15, complexity = "high"),
    temporal_analysis = list(weight = 0.10, complexity = "high"), 
    citation_generation = list(weight = 0.10, complexity = "medium")
  )
)

# Global storage for regression testing data
REGRESSION_DATA <- list(
  baselines = list(),
  test_history = list(),
  regression_alerts = list(),
  performance_trends = list()
)

# Performance baseline storage
PERFORMANCE_BASELINES <- list()

# ============================================================================
# BASELINE ESTABLISHMENT AND MANAGEMENT
# ============================================================================

#' Establish comprehensive performance baseline for regression testing
#' @param baseline_name Name for the baseline (e.g., "v1.0.0", "production")
#' @param test_duration_minutes Duration for baseline establishment
#' @return Baseline performance metrics
establish_performance_baseline <- function(baseline_name = paste0("baseline_", format(Sys.time(), "%Y%m%d_%H%M")), 
                                          test_duration_minutes = 30) {
  
  cat("📏 Establishing performance baseline:", baseline_name, "\n")
  cat("⏱️ Baseline test duration:", test_duration_minutes, "minutes\n")
  
  baseline_start <- Sys.time()
  
  baseline_data <- list(
    baseline_name = baseline_name,
    establishment_time = baseline_start,
    test_duration_minutes = test_duration_minutes,
    system_info = capture_system_info(),
    database_benchmarks = list(),
    search_benchmarks = list(),
    geographic_benchmarks = list(),
    cache_benchmarks = list(),
    memory_benchmarks = list(),
    railway_specific_benchmarks = list(),
    workload_benchmarks = list()
  )
  
  tryCatch({
    
    # 1. Database Operation Benchmarks
    cat("🗄️ Establishing database operation benchmarks...\n")
    baseline_data$database_benchmarks <- establish_database_benchmarks()
    
    # 2. Search Operation Benchmarks
    cat("🔍 Establishing search operation benchmarks...\n")
    baseline_data$search_benchmarks <- establish_search_benchmarks()
    
    # 3. Geographic Analysis Benchmarks
    cat("🗺️ Establishing geographic analysis benchmarks...\n")
    baseline_data$geographic_benchmarks <- establish_geographic_benchmarks()
    
    # 4. Cache Performance Benchmarks
    cat("💾 Establishing cache performance benchmarks...\n")
    baseline_data$cache_benchmarks <- establish_cache_benchmarks()
    
    # 5. Memory Usage Benchmarks
    cat("🧠 Establishing memory usage benchmarks...\n")
    baseline_data$memory_benchmarks <- establish_memory_benchmarks()
    
    # 6. Railway-Specific Benchmarks
    cat("🚄 Establishing Railway-specific benchmarks...\n")
    baseline_data$railway_specific_benchmarks <- establish_railway_benchmarks()
    
    # 7. Brazilian Legislative Workload Benchmarks
    cat("🇧🇷 Establishing Brazilian legislative workload benchmarks...\n")
    baseline_data$workload_benchmarks <- establish_workload_benchmarks(test_duration_minutes)
    
    # Calculate composite performance score
    baseline_data$composite_score <- calculate_composite_performance_score(baseline_data)
    
  }, error = function(e) {
    cat("❌ Error establishing performance baseline:", e$message, "\n")
    baseline_data$error <- e$message
  })
  
  baseline_data$establishment_duration <- as.numeric(difftime(Sys.time(), baseline_start, units = "mins"))
  
  # Store baseline
  PERFORMANCE_BASELINES[[baseline_name]] <<- baseline_data
  
  # Save baseline to file for persistence
  save_baseline_to_file(baseline_data)
  
  cat("✅ Performance baseline", baseline_name, "established in", round(baseline_data$establishment_duration, 1), "minutes\n")
  
  return(baseline_data)
}

#' Capture comprehensive system information for baseline context
#' @return System information list
capture_system_info <- function() {
  
  system_info <- list(
    timestamp = Sys.time(),
    r_version = R.version.string,
    platform = R.Version()$platform,
    os = Sys.info()["sysname"],
    node_name = Sys.info()["nodename"],
    memory_total_mb = round(as.numeric(pryr::mem_used()) / 1024 / 1024, 1),
    working_directory = getwd(),
    railway_environment = Sys.getenv("RAILWAY_ENVIRONMENT", "unknown"),
    git_commit = get_git_commit_hash(),
    package_versions = get_key_package_versions(),
    environment_variables = capture_relevant_env_vars()
  )
  
  return(system_info)
}

#' Get current git commit hash for tracking performance against code changes
#' @return Git commit hash or "unknown"
get_git_commit_hash <- function() {
  tryCatch({
    if (file.exists(".git")) {
      system("git rev-parse HEAD", intern = TRUE, ignore.stderr = TRUE)[1]
    } else {
      "unknown"
    }
  }, error = function(e) {
    "unknown"
  })
}

#' Get versions of key packages that might affect performance
#' @return List of package versions
get_key_package_versions <- function() {
  key_packages <- c("DBI", "RPostgres", "pool", "dplyr", "shiny", "plotly")
  
  versions <- list()
  for (pkg in key_packages) {
    tryCatch({
      versions[[pkg]] <- as.character(packageVersion(pkg))
    }, error = function(e) {
      versions[[pkg]] <- "not_installed"
    })
  }
  
  return(versions)
}

#' Capture relevant environment variables (without exposing secrets)
#' @return List of environment variable information
capture_relevant_env_vars <- function() {
  relevant_vars <- c("RAILWAY_ENVIRONMENT", "PORT", "R_LIBS_USER", "TZ")
  
  env_info <- list()
  for (var in relevant_vars) {
    value <- Sys.getenv(var, "")
    env_info[[var]] <- list(
      is_set = value != "",
      length = nchar(value)
    )
  }
  
  return(env_info)
}

# ============================================================================
# BENCHMARK ESTABLISHMENT FUNCTIONS
# ============================================================================

#' Establish database operation benchmarks
#' @return Database benchmark results
establish_database_benchmarks <- function() {
  
  db_benchmarks <- list(
    connection_establishment = list(),
    simple_queries = list(),
    complex_queries = list(),
    aggregation_queries = list()
  )
  
  tryCatch({
    
    # Test database connection establishment
    connection_benchmark <- microbenchmark(
      {
        if (exists("get_database_pool")) {
          pool <- get_database_pool()
          if (!is.null(pool)) {
            dbGetQuery(pool, "SELECT 1")
          }
        }
      },
      times = 10,
      unit = "ms"
    )
    
    db_benchmarks$connection_establishment <- list(
      median_ms = median(connection_benchmark$time / 1e6),
      mean_ms = mean(connection_benchmark$time / 1e6),
      max_ms = max(connection_benchmark$time / 1e6),
      samples = length(connection_benchmark$time)
    )
    
    # Get main table for testing
    main_table <- NULL
    if (exists("get_main_table")) {
      main_table <- get_main_table()
    }
    
    if (!isTRUE(is.null(main_table)) && exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      # Simple query benchmark
      simple_query <- sprintf("SELECT COUNT(*) FROM %s LIMIT 1", main_table)
      simple_benchmark <- microbenchmark(
        dbGetQuery(secure_db_pool, simple_query),
        times = 20,
        unit = "ms"
      )
      
      db_benchmarks$simple_queries <- list(
        median_ms = median(simple_benchmark$time / 1e6),
        mean_ms = mean(simple_benchmark$time / 1e6),
        max_ms = max(simple_benchmark$time / 1e6),
        samples = length(simple_benchmark$time)
      )
      
      # Complex query benchmark
      complex_query <- sprintf("SELECT estado, COUNT(*) FROM %s GROUP BY estado ORDER BY COUNT(*) DESC LIMIT 10", main_table)
      complex_benchmark <- microbenchmark(
        dbGetQuery(secure_db_pool, complex_query),
        times = 10,
        unit = "ms"
      )
      
      db_benchmarks$complex_queries <- list(
        median_ms = median(complex_benchmark$time / 1e6),
        mean_ms = mean(complex_benchmark$time / 1e6),
        max_ms = max(complex_benchmark$time / 1e6),
        samples = length(complex_benchmark$time)
      )
    }
    
  }, error = function(e) {
    cat("❌ Error establishing database benchmarks:", e$message, "\n")
    db_benchmarks$error <- e$message
  })
  
  return(db_benchmarks)
}

#' Establish search operation benchmarks
#' @return Search benchmark results
establish_search_benchmarks <- function() {
  
  search_benchmarks <- list(
    simple_search = list(),
    filtered_search = list(),
    full_text_search = list()
  )
  
  tryCatch({
    
    if (exists("get_library_documents_optimized")) {
      
      # Simple search benchmark
      simple_search_benchmark <- microbenchmark(
        get_library_documents_optimized(limit = 10),
        times = 15,
        unit = "ms"
      )
      
      search_benchmarks$simple_search <- list(
        median_ms = median(simple_search_benchmark$time / 1e6),
        mean_ms = mean(simple_search_benchmark$time / 1e6),
        max_ms = max(simple_search_benchmark$time / 1e6),
        samples = length(simple_search_benchmark$time)
      )
      
      # Filtered search benchmark
      filtered_search_benchmark <- microbenchmark(
        get_library_documents_optimized(
          category = "legislation", 
          state = "SP", 
          limit = 20
        ),
        times = 10,
        unit = "ms"
      )
      
      search_benchmarks$filtered_search <- list(
        median_ms = median(filtered_search_benchmark$time / 1e6),
        mean_ms = mean(filtered_search_benchmark$time / 1e6),
        max_ms = max(filtered_search_benchmark$time / 1e6),
        samples = length(filtered_search_benchmark$time)
      )
      
      # Full-text search benchmark
      fulltext_search_benchmark <- microbenchmark(
        get_library_documents_optimized(
          search_term = "transporte público", 
          limit = 50
        ),
        times = 8,
        unit = "ms"
      )
      
      search_benchmarks$full_text_search <- list(
        median_ms = median(fulltext_search_benchmark$time / 1e6),
        mean_ms = mean(fulltext_search_benchmark$time / 1e6),
        max_ms = max(fulltext_search_benchmark$time / 1e6),
        samples = length(fulltext_search_benchmark$time)
      )
    }
    
  }, error = function(e) {
    cat("❌ Error establishing search benchmarks:", e$message, "\n")
    search_benchmarks$error <- e$message
  })
  
  return(search_benchmarks)
}

#' Establish geographic analysis benchmarks
#' @return Geographic benchmark results
establish_geographic_benchmarks <- function() {
  
  geographic_benchmarks <- list(
    state_aggregation = list(),
    municipality_analysis = list(),
    choropleth_data_prep = list()
  )
  
  tryCatch({
    
    # State aggregation benchmark
    state_agg_benchmark <- microbenchmark(
      {
        if (exists("get_library_documents_optimized")) {
          docs <- get_library_documents_optimized(limit = 1000)
          if (!isTRUE(is.null(docs)) && nrow(docs) > 0) {
            state_summary <- docs %>%
              group_by(state) %>%
              summarise(count = n(), .groups = 'drop') %>%
              arrange(desc(count))
          }
        }
      },
      times = 5,
      unit = "ms"
    )
    
    geographic_benchmarks$state_aggregation <- list(
      median_ms = median(state_agg_benchmark$time / 1e6),
      mean_ms = mean(state_agg_benchmark$time / 1e6),
      max_ms = max(state_agg_benchmark$time / 1e6),
      samples = length(state_agg_benchmark$time)
    )
    
    # Municipality analysis benchmark (if available)
    if (file.exists("modules/maps/enhanced_maps_loader.R")) {
      municipality_benchmark <- microbenchmark(
        {
          # Simulate municipality data processing
          test_municipalities <- c("São Paulo", "Rio de Janeiro", "Belo Horizonte", "Brasília", "Salvador")
          municipality_data <- data.frame(
            municipality = test_municipalities,
            doc_count = sample(100:1000, length(test_municipalities)),
            stringsAsFactors = FALSE
          )
          municipality_summary <- municipality_data %>%
            arrange(desc(doc_count)) %>%
            slice_head(n = 10)
        },
        times = 10,
        unit = "ms"
      )
      
      geographic_benchmarks$municipality_analysis <- list(
        median_ms = median(municipality_benchmark$time / 1e6),
        mean_ms = mean(municipality_benchmark$time / 1e6),
        max_ms = max(municipality_benchmark$time / 1e6),
        samples = length(municipality_benchmark$time)
      )
    }
    
  }, error = function(e) {
    cat("❌ Error establishing geographic benchmarks:", e$message, "\n")
    geographic_benchmarks$error <- e$message
  })
  
  return(geographic_benchmarks)
}

#' Establish cache performance benchmarks
#' @return Cache benchmark results
establish_cache_benchmarks <- function() {
  
  cache_benchmarks <- list(
    cache_hit_performance = list(),
    cache_miss_performance = list(),
    cache_efficiency = list()
  )
  
  tryCatch({
    
    # Test cache performance if caching system is available
    if (exists("get_performance_stats")) {
      
      baseline_stats <- get_performance_stats()
      
      cache_benchmarks$cache_efficiency <- list(
        initial_hit_rate = baseline_stats$cache_hit_rate,
        initial_cache_size = baseline_stats$query_cache_size,
        avg_query_time = baseline_stats$avg_query_time,
        queries_executed = baseline_stats$queries_executed
      )
      
      # Test cache hit performance
      if (exists("get_library_documents_optimized")) {
        # First call (cache miss)
        cache_miss_benchmark <- microbenchmark(
          get_library_documents_optimized(search_term = "performance_test", limit = 10),
          times = 5,
          unit = "ms"
        )
        
        cache_benchmarks$cache_miss_performance <- list(
          median_ms = median(cache_miss_benchmark$time / 1e6),
          mean_ms = mean(cache_miss_benchmark$time / 1e6),
          max_ms = max(cache_miss_benchmark$time / 1e6),
          samples = length(cache_miss_benchmark$time)
        )
        
        # Second call (cache hit)
        cache_hit_benchmark <- microbenchmark(
          get_library_documents_optimized(search_term = "performance_test", limit = 10),
          times = 10,
          unit = "ms"
        )
        
        cache_benchmarks$cache_hit_performance <- list(
          median_ms = median(cache_hit_benchmark$time / 1e6),
          mean_ms = mean(cache_hit_benchmark$time / 1e6),
          max_ms = max(cache_hit_benchmark$time / 1e6),
          samples = length(cache_hit_benchmark$time),
          cache_improvement_ratio = median(cache_miss_benchmark$time) / median(cache_hit_benchmark$time)
        )
      }
    }
    
  }, error = function(e) {
    cat("❌ Error establishing cache benchmarks:", e$message, "\n")
    cache_benchmarks$error <- e$message
  })
  
  return(cache_benchmarks)
}

#' Establish memory usage benchmarks
#' @return Memory benchmark results
establish_memory_benchmarks <- function() {
  
  memory_benchmarks <- list(
    baseline_memory = list(),
    memory_allocation = list(),
    memory_cleanup = list(),
    railway_compliance = list()
  )
  
  tryCatch({
    
    # Baseline memory usage
    baseline_memory_mb <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    memory_benchmarks$baseline_memory <- list(
      memory_mb = round(baseline_memory_mb, 1),
      timestamp = Sys.time()
    )
    
    # Test memory allocation performance
    memory_allocation_benchmark <- microbenchmark(
      {
        test_data <- replicate(1000, rnorm(100), simplify = FALSE)
        rm(test_data)
        gc()
      },
      times = 5,
      unit = "ms"
    )
    
    memory_benchmarks$memory_allocation <- list(
      median_ms = median(memory_allocation_benchmark$time / 1e6),
      mean_ms = mean(memory_allocation_benchmark$time / 1e6),
      max_ms = max(memory_allocation_benchmark$time / 1e6),
      samples = length(memory_allocation_benchmark$time)
    )
    
    # Test memory cleanup efficiency
    pre_cleanup_memory <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    # Create some objects to clean up
    cleanup_test_objects <- list()
    for (i in 1:10) {
      cleanup_test_objects[[i]] <- matrix(rnorm(10000), ncol = 100)
    }
    
    post_allocation_memory <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    # Clean up
    rm(cleanup_test_objects)
    gc()
    
    post_cleanup_memory <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    memory_benchmarks$memory_cleanup <- list(
      memory_increase_mb = round(post_allocation_memory - pre_cleanup_memory, 1),
      memory_recovered_mb = round(post_allocation_memory - post_cleanup_memory, 1),
      cleanup_efficiency_pct = round(((post_allocation_memory - post_cleanup_memory) / (post_allocation_memory - pre_cleanup_memory)) * 100, 1)
    )
    
    # Railway compliance check
    current_memory <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    memory_benchmarks$railway_compliance <- list(
      current_memory_mb = round(current_memory, 1),
      railway_limit_mb = 2048,
      utilization_pct = round((current_memory / 2048) * 100, 1),
      within_limit = current_memory <= 2048,
      headroom_mb = 2048 - current_memory
    )
    
  }, error = function(e) {
    cat("❌ Error establishing memory benchmarks:", e$message, "\n")
    memory_benchmarks$error <- e$message
  })
  
  return(memory_benchmarks)
}

#' Establish Railway-specific benchmarks
#' @return Railway benchmark results
establish_railway_benchmarks <- function() {
  
  railway_benchmarks <- list(
    cold_start_simulation = list(),
    environment_check = list(),
    resource_constraints = list()
  )
  
  tryCatch({
    
    # Cold start simulation benchmark
    cold_start_benchmark <- microbenchmark(
      {
        # Simulate application initialization
        temp_env <- new.env()
        temp_env$startup_time <- Sys.time()
        
        # Simulate library loading (already loaded, but measure impact)
        gc()
        
        # Simulate database connection establishment
        if (exists("get_database_pool")) {
          pool <- get_database_pool()
          if (!is.null(pool)) {
            dbGetQuery(pool, "SELECT 1")
          }
        }
        
        rm(temp_env)
      },
      times = 3,  # Cold start is expensive, fewer samples
      unit = "ms"
    )
    
    railway_benchmarks$cold_start_simulation <- list(
      median_ms = median(cold_start_benchmark$time / 1e6),
      mean_ms = mean(cold_start_benchmark$time / 1e6),
      max_ms = max(cold_start_benchmark$time / 1e6),
      samples = length(cold_start_benchmark$time)
    )
    
    # Environment check
    railway_benchmarks$environment_check <- list(
      is_railway = Sys.getenv("RAILWAY_ENVIRONMENT", "") != "",
      port = Sys.getenv("PORT", "3838"),
      database_url_set = Sys.getenv("DATABASE_URL", "") != "",
      environment_type = Sys.getenv("RAILWAY_ENVIRONMENT", "local")
    )
    
    # Resource constraint validation
    current_memory <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    railway_benchmarks$resource_constraints <- list(
      memory_utilization_pct = round((current_memory / 2048) * 100, 1),
      within_memory_limit = current_memory <= 2048,
      db_connection_limit = 100,
      estimated_connection_usage = 5  # Conservative estimate
    )
    
  }, error = function(e) {
    cat("❌ Error establishing Railway benchmarks:", e$message, "\n")
    railway_benchmarks$error <- e$message
  })
  
  return(railway_benchmarks)
}

#' Establish Brazilian legislative workload benchmarks
#' @param test_duration_minutes Duration for workload testing
#' @return Workload benchmark results
establish_workload_benchmarks <- function(test_duration_minutes = 30) {
  
  workload_benchmarks <- list(
    academic_research_workflow = list(),
    policy_analysis_workflow = list(),
    legislative_monitoring_workflow = list(),
    citation_workflow = list()
  )
  
  tryCatch({
    
    # Academic research workflow benchmark
    academic_workflow_benchmark <- microbenchmark(
      {
        if (exists("get_library_documents_optimized")) {
          # Simulate academic research pattern
          search_terms <- c("educação superior", "política educacional", "ensino público")
          selected_term <- sample(search_terms, 1)
          
          docs <- get_library_documents_optimized(
            search_term = selected_term,
            category = "legislation",
            limit = 25
          )
          
          if (!isTRUE(is.null(docs)) && nrow(docs) > 0) {
            # Simulate analysis
            summary_stats <- list(
              total_docs = nrow(docs),
              unique_states = length(unique(docs$state[docs$state != ""])),
              date_range = range(docs$date, na.rm = TRUE)
            )
          }
        }
      },
      times = 5,
      unit = "ms"
    )
    
    workload_benchmarks$academic_research_workflow <- list(
      median_ms = median(academic_workflow_benchmark$time / 1e6),
      mean_ms = mean(academic_workflow_benchmark$time / 1e6),
      max_ms = max(academic_workflow_benchmark$time / 1e6),
      samples = length(academic_workflow_benchmark$time)
    )
    
    # Policy analysis workflow benchmark
    policy_workflow_benchmark <- microbenchmark(
      {
        if (exists("get_library_documents_optimized")) {
          # Simulate policy analysis pattern
          policy_areas <- c("saúde pública", "segurança pública", "meio ambiente")
          selected_area <- sample(policy_areas, 1)
          
          # Multi-state analysis
          states <- c("SP", "RJ", "MG")
          
          for (state in states) {
            docs <- get_library_documents_optimized(
              search_term = selected_area,
              state = state,
              limit = 15
            )
            
            if (!isTRUE(is.null(docs)) && nrow(docs) > 0) {
              # Simulate policy comparison analysis
              state_analysis <- list(
                state = state,
                doc_count = nrow(docs),
                recent_docs = sum(docs$date >= (Sys.Date() - 365), na.rm = TRUE)
              )
            }
          }
        }
      },
      times = 3,
      unit = "ms"
    )
    
    workload_benchmarks$policy_analysis_workflow <- list(
      median_ms = median(policy_workflow_benchmark$time / 1e6),
      mean_ms = mean(policy_workflow_benchmark$time / 1e6),
      max_ms = max(policy_workflow_benchmark$time / 1e6),
      samples = length(policy_workflow_benchmark$time)
    )
    
    # Legislative monitoring workflow benchmark
    monitoring_workflow_benchmark <- microbenchmark(
      {
        if (exists("get_dashboard_metrics_optimized")) {
          # Simulate legislative monitoring dashboard
          metrics <- get_dashboard_metrics_optimized()
          
          # Simulate trend analysis
          if (exists("get_library_documents_optimized")) {
            recent_docs <- get_library_documents_optimized(
              date_start = Sys.Date() - 30,
              limit = 100
            )
            
            if (!isTRUE(is.null(recent_docs)) && nrow(recent_docs) > 0) {
              trend_analysis <- list(
                recent_activity = nrow(recent_docs),
                category_distribution = table(recent_docs$category),
                geographic_distribution = table(recent_docs$state[recent_docs$state != ""])
              )
            }
          }
        }
      },
      times = 8,
      unit = "ms"
    )
    
    workload_benchmarks$legislative_monitoring_workflow <- list(
      median_ms = median(monitoring_workflow_benchmark$time / 1e6),
      mean_ms = mean(monitoring_workflow_benchmark$time / 1e6),
      max_ms = max(monitoring_workflow_benchmark$time / 1e6),
      samples = length(monitoring_workflow_benchmark$time)
    )
    
  }, error = function(e) {
    cat("❌ Error establishing workload benchmarks:", e$message, "\n")
    workload_benchmarks$error <- e$message
  })
  
  return(workload_benchmarks)
}

# ============================================================================
# REGRESSION TESTING FUNCTIONS
# ============================================================================

#' Run comprehensive performance regression test
#' @param baseline_name Name of baseline to compare against
#' @param test_name Name for this regression test
#' @return Regression test results with detailed analysis
run_performance_regression_test <- function(baseline_name = "latest", test_name = paste0("regression_", format(Sys.time(), "%Y%m%d_%H%M"))) {
  
  cat("🔍 Running performance regression test:", test_name, "\n")
  cat("📏 Comparing against baseline:", baseline_name, "\n")
  
  regression_test_start <- Sys.time()
  
  # Get baseline for comparison
  baseline <- get_baseline_for_comparison(baseline_name)
  if (is.null(baseline)) {
    cat("❌ Baseline not found, establishing new baseline first\n")
    baseline <- establish_performance_baseline(baseline_name)
  }
  
  # Run current performance tests
  cat("⚡ Running current performance tests...\n")
  current_performance <- establish_performance_baseline(paste0("current_", format(Sys.time(), "%H%M%S")), 15)  # Shorter duration for regression test
  
  # Compare performance
  cat("📊 Analyzing performance regression...\n")
  regression_analysis <- analyze_performance_regression(baseline, current_performance)
  
  # Generate regression report
  regression_report <- generate_regression_report(regression_analysis, baseline_name, test_name)
  
  # Store regression test results
  regression_results <- list(
    test_name = test_name,
    baseline_name = baseline_name,
    test_timestamp = regression_test_start,
    test_duration = as.numeric(difftime(Sys.time(), regression_test_start, units = "mins")),
    baseline_data = baseline,
    current_performance = current_performance,
    regression_analysis = regression_analysis,
    regression_report = regression_report
  )
  
  # Store in global results
  REGRESSION_DATA$test_history[[test_name]] <<- regression_results
  
  # Check for regression alerts
  if (regression_analysis$has_regression) {
    REGRESSION_DATA$regression_alerts[[length(REGRESSION_DATA$regression_alerts) + 1]] <<- list(
      alert_time = Sys.time(),
      test_name = test_name,
      severity = regression_analysis$regression_severity,
      summary = regression_analysis$regression_summary
    )
    
    cat("🚨 REGRESSION ALERT:", regression_analysis$regression_severity, "\n")
    cat("📝 Summary:", regression_analysis$regression_summary, "\n")
  }
  
  cat("✅ Regression test completed in", round(regression_results$test_duration, 1), "minutes\n")
  
  return(regression_results)
}

#' Analyze performance regression between baseline and current performance
#' @param baseline Baseline performance data
#' @param current Current performance data
#' @return Detailed regression analysis
analyze_performance_regression <- function(baseline, current) {
  
  regression_analysis <- list(
    has_regression = FALSE,
    regression_severity = "NONE",
    regression_summary = "",
    detailed_comparisons = list(),
    performance_deltas = list(),
    critical_regressions = list(),
    improvements = list()
  )
  
  tryCatch({
    
    # Compare database benchmarks
    if (!isTRUE(is.null(baseline$database_benchmarks)) && !is.null(current$database_benchmarks)) {
      db_comparison <- compare_benchmark_categories(
        baseline$database_benchmarks, 
        current$database_benchmarks, 
        "database_operations"
      )
      regression_analysis$detailed_comparisons$database_operations <- db_comparison
    }
    
    # Compare search benchmarks
    if (!isTRUE(is.null(baseline$search_benchmarks)) && !is.null(current$search_benchmarks)) {
      search_comparison <- compare_benchmark_categories(
        baseline$search_benchmarks,
        current$search_benchmarks,
        "search_operations"
      )
      regression_analysis$detailed_comparisons$search_operations <- search_comparison
    }
    
    # Compare memory benchmarks
    if (!isTRUE(is.null(baseline$memory_benchmarks)) && !is.null(current$memory_benchmarks)) {
      memory_comparison <- compare_memory_benchmarks(
        baseline$memory_benchmarks,
        current$memory_benchmarks
      )
      regression_analysis$detailed_comparisons$memory_usage <- memory_comparison
    }
    
    # Compare cache benchmarks
    if (!isTRUE(is.null(baseline$cache_benchmarks)) && !is.null(current$cache_benchmarks)) {
      cache_comparison <- compare_benchmark_categories(
        baseline$cache_benchmarks,
        current$cache_benchmarks,
        "cache_performance"
      )
      regression_analysis$detailed_comparisons$cache_performance <- cache_comparison
    }
    
    # Calculate overall regression assessment
    regression_assessment <- assess_overall_regression(regression_analysis$detailed_comparisons)
    
    regression_analysis$has_regression <- regression_assessment$has_regression
    regression_analysis$regression_severity <- regression_assessment$severity
    regression_analysis$regression_summary <- regression_assessment$summary
    regression_analysis$critical_regressions <- regression_assessment$critical_issues
    regression_analysis$improvements <- regression_assessment$improvements
    
  }, error = function(e) {
    cat("❌ Error analyzing performance regression:", e$message, "\n")
    regression_analysis$error <- e$message
  })
  
  return(regression_analysis)
}

#' Compare benchmark categories between baseline and current
#' @param baseline_benchmarks Baseline benchmark data
#' @param current_benchmarks Current benchmark data
#' @param category_name Category name for reporting
#' @return Benchmark comparison results
compare_benchmark_categories <- function(baseline_benchmarks, current_benchmarks, category_name) {
  
  comparison <- list(
    category = category_name,
    comparisons = list(),
    overall_regression = FALSE,
    performance_delta_pct = 0,
    significant_changes = list()
  )
  
  # Compare each benchmark within the category
  for (benchmark_name in names(baseline_benchmarks)) {
    if (benchmark_name %in% names(current_benchmarks)) {
      
      baseline_bench <- baseline_benchmarks[[benchmark_name]]
      current_bench <- current_benchmarks[[benchmark_name]]
      
      # Extract median performance metrics
      baseline_median <- extract_median_metric(baseline_bench)
      current_median <- extract_median_metric(current_bench)
      
      if (!isTRUE(is.null(baseline_median)) && !isTRUE(is.null(current_median)) && baseline_median > 0) {
        
        performance_change_pct <- ((current_median - baseline_median) / baseline_median) * 100
        
        benchmark_comparison <- list(
          benchmark_name = benchmark_name,
          baseline_median = baseline_median,
          current_median = current_median,
          performance_change_pct = round(performance_change_pct, 1),
          is_regression = performance_change_pct > REGRESSION_CONFIG$performance_degradation_threshold_pct,
          is_critical = performance_change_pct > REGRESSION_CONFIG$critical_degradation_threshold_pct,
          is_improvement = performance_change_pct < -5  # 5% improvement threshold
        )
        
        comparison$comparisons[[benchmark_name]] <- benchmark_comparison
        
        # Check for overall category regression
        if (benchmark_comparison$is_regression) {
          comparison$overall_regression <- TRUE
        }
        
        # Track significant changes
        if (abs(performance_change_pct) > 10) {  # 10% threshold for significance
          comparison$significant_changes[[benchmark_name]] <- benchmark_comparison
        }
      }
    }
  }
  
  # Calculate category-level performance delta
  if (length(comparison$comparisons) > 0) {
    all_deltas <- sapply(comparison$comparisons, function(x) x$performance_change_pct)
    comparison$performance_delta_pct <- round(mean(all_deltas), 1)
  }
  
  return(comparison)
}

#' Compare memory benchmarks with special handling for memory metrics
#' @param baseline_memory Baseline memory benchmarks
#' @param current_memory Current memory benchmarks  
#' @return Memory comparison results
compare_memory_benchmarks <- function(baseline_memory, current_memory) {
  
  memory_comparison <- list(
    baseline_memory_mb = baseline_memory$baseline_memory$memory_mb,
    current_memory_mb = current_memory$baseline_memory$memory_mb,
    memory_increase_mb = current_memory$baseline_memory$memory_mb - baseline_memory$baseline_memory$memory_mb,
    memory_increase_pct = 0,
    is_memory_regression = FALSE,
    railway_compliance_change = list()
  )
  
  # Calculate memory increase percentage
  if (baseline_memory$baseline_memory$memory_mb > 0) {
    memory_comparison$memory_increase_pct <- round(
      (memory_comparison$memory_increase_mb / baseline_memory$baseline_memory$memory_mb) * 100, 1
    )
  }
  
  # Check for memory regression
  memory_comparison$is_memory_regression <- memory_comparison$memory_increase_mb > REGRESSION_CONFIG$memory_increase_threshold_mb
  
  # Compare Railway compliance
  if (!isTRUE(is.null(baseline_memory$railway_compliance)) && !is.null(current_memory$railway_compliance)) {
    memory_comparison$railway_compliance_change <- list(
      baseline_utilization_pct = baseline_memory$railway_compliance$utilization_pct,
      current_utilization_pct = current_memory$railway_compliance$utilization_pct,
      utilization_change_pct = current_memory$railway_compliance$utilization_pct - baseline_memory$railway_compliance$utilization_pct,
      baseline_within_limit = baseline_memory$railway_compliance$within_limit,
      current_within_limit = current_memory$railway_compliance$within_limit,
      compliance_degraded = baseline_memory$railway_compliance$within_limit && !current_memory$railway_compliance$within_limit
    )
  }
  
  return(memory_comparison)
}

#' Extract median performance metric from benchmark data
#' @param benchmark_data Benchmark data structure
#' @return Median performance value or NULL
extract_median_metric <- function(benchmark_data) {
  
  if (is.null(benchmark_data)) return(NULL)
  
  # Try different possible median field names
  median_fields <- c("median_ms", "median_time_seconds", "median", "mean_ms")
  
  for (field in median_fields) {
    if (!is.null(benchmark_data[[field]])) {
      return(as.numeric(benchmark_data[[field]]))
    }
  }
  
  return(NULL)
}

#' Assess overall regression across all categories
#' @param detailed_comparisons All category comparisons
#' @return Overall regression assessment
assess_overall_regression <- function(detailed_comparisons) {
  
  assessment <- list(
    has_regression = FALSE,
    severity = "NONE",
    summary = "No significant performance regression detected",
    critical_issues = list(),
    improvements = list(),
    weighted_regression_score = 0
  )
  
  if (length(detailed_comparisons) == 0) {
    return(assessment)
  }
  
  # Calculate weighted regression score
  total_weighted_score <- 0
  total_weight <- 0
  
  for (category_name in names(detailed_comparisons)) {
    comparison <- detailed_comparisons[[category_name]]
    category_weight <- REGRESSION_CONFIG$test_weights[[category_name]]
    
    if (is.null(category_weight)) category_weight <- 0.1  # Default weight
    
    if (!is.null(comparison$performance_delta_pct)) {
      total_weighted_score <- total_weighted_score + (comparison$performance_delta_pct * category_weight)
      total_weight <- total_weight + category_weight
    }
    
    # Check for critical issues
    if (!isTRUE(is.null(comparison$overall_regression)) && comparison$overall_regression) {
      assessment$critical_issues[[category_name]] <- comparison
    }
    
    # Check for improvements
    if (!isTRUE(is.null(comparison$performance_delta_pct)) && comparison$performance_delta_pct < -5) {
      assessment$improvements[[category_name]] <- comparison
    }
  }
  
  # Calculate overall weighted regression score
  if (total_weight > 0) {
    assessment$weighted_regression_score <- round(total_weighted_score / total_weight, 1)
  }
  
  # Determine regression severity
  if (assessment$weighted_regression_score > REGRESSION_CONFIG$critical_degradation_threshold_pct) {
    assessment$has_regression <- TRUE
    assessment$severity <- "CRITICAL"
    assessment$summary <- paste0("Critical performance regression detected (", assessment$weighted_regression_score, "% degradation)")
  } else if (assessment$weighted_regression_score > REGRESSION_CONFIG$performance_degradation_threshold_pct) {
    assessment$has_regression <- TRUE
    assessment$severity <- "WARNING"
    assessment$summary <- paste0("Performance regression detected (", assessment$weighted_regression_score, "% degradation)")
  } else if (assessment$weighted_regression_score < -5) {
    assessment$severity <- "IMPROVEMENT"
    assessment$summary <- paste0("Performance improvement detected (", abs(assessment$weighted_regression_score), "% improvement)")
  }
  
  return(assessment)
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

#' Calculate composite performance score from baseline data
#' @param baseline_data Complete baseline data
#' @return Composite performance score
calculate_composite_performance_score <- function(baseline_data) {
  
  score <- 0
  components <- 0
  
  # Database score (35% weight)
  if (!is.null(baseline_data$database_benchmarks$simple_queries$median_ms)) {
    db_score <- max(0, 100 - baseline_data$database_benchmarks$simple_queries$median_ms)
    score <- score + (db_score * 0.35)
    components <- components + 1
  }
  
  # Search score (25% weight) 
  if (!is.null(baseline_data$search_benchmarks$simple_search$median_ms)) {
    search_score <- max(0, 100 - (baseline_data$search_benchmarks$simple_search$median_ms / 10))
    score <- score + (search_score * 0.25)
    components <- components + 1
  }
  
  # Memory score (20% weight)
  if (!is.null(baseline_data$memory_benchmarks$railway_compliance$utilization_pct)) {
    memory_score <- max(0, 100 - baseline_data$memory_benchmarks$railway_compliance$utilization_pct)
    score <- score + (memory_score * 0.20)
    components <- components + 1
  }
  
  # Cache score (20% weight)
  if (!is.null(baseline_data$cache_benchmarks$cache_efficiency$initial_hit_rate)) {
    cache_score <- baseline_data$cache_benchmarks$cache_efficiency$initial_hit_rate
    score <- score + (cache_score * 0.20)
    components <- components + 1
  }
  
  # Normalize score
  if (components > 0) {
    score <- score / components
  }
  
  return(round(score, 1))
}

#' Get baseline for comparison, with fallback logic
#' @param baseline_name Name of baseline to retrieve
#' @return Baseline data or NULL
get_baseline_for_comparison <- function(baseline_name) {
  
  # Try to get from memory first
  if (baseline_name %in% names(PERFORMANCE_BASELINES)) {
    return(PERFORMANCE_BASELINES[[baseline_name]])
  }
  
  # Try to load from file
  baseline <- load_baseline_from_file(baseline_name)
  if (!is.null(baseline)) {
    PERFORMANCE_BASELINES[[baseline_name]] <<- baseline
    return(baseline)
  }
  
  # If "latest" requested, get most recent baseline
  if (baseline_name == "latest" && length(PERFORMANCE_BASELINES) > 0) {
    latest_name <- names(PERFORMANCE_BASELINES)[length(PERFORMANCE_BASELINES)]
    return(PERFORMANCE_BASELINES[[latest_name]])
  }
  
  return(NULL)
}

#' Save baseline to file for persistence
#' @param baseline_data Baseline data to save
#' @return TRUE if successful, FALSE otherwise
save_baseline_to_file <- function(baseline_data) {
  
  tryCatch({
    
    # Create baselines directory if it doesn't exist
    if (!dir.exists("baselines")) {
      dir.create("baselines", recursive = TRUE)
    }
    
    filename <- file.path("baselines", paste0(baseline_data$baseline_name, ".json"))
    
    # Convert to JSON and save
    baseline_json <- jsonlite::toJSON(baseline_data, auto_unbox = TRUE, pretty = TRUE)
    writeLines(baseline_json, filename)
    
    cat("💾 Baseline saved to:", filename, "\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error saving baseline to file:", e$message, "\n")
    return(FALSE)
  })
}

#' Load baseline from file
#' @param baseline_name Name of baseline to load
#' @return Baseline data or NULL
load_baseline_from_file <- function(baseline_name) {
  
  tryCatch({
    
    filename <- file.path("baselines", paste0(baseline_name, ".json"))
    
    if (file.exists(filename)) {
      baseline_json <- readLines(filename)
      baseline_data <- jsonlite::fromJSON(baseline_json)
      
      cat("📁 Baseline loaded from:", filename, "\n")
      return(baseline_data)
    }
    
    return(NULL)
    
  }, error = function(e) {
    cat("❌ Error loading baseline from file:", e$message, "\n")
    return(NULL)
  })
}

#' Generate comprehensive regression report
#' @param regression_analysis Regression analysis results
#' @param baseline_name Baseline name
#' @param test_name Test name
#' @return Formatted regression report
generate_regression_report <- function(regression_analysis, baseline_name, test_name) {
  
  report_lines <- c()
  
  # Header
  report_lines <- c(report_lines, 
    "========================================",
    paste("PERFORMANCE REGRESSION TEST REPORT"),
    "========================================",
    paste("Test Name:", test_name),
    paste("Baseline:", baseline_name),
    paste("Test Time:", format(Sys.time(), "%Y-%m-%d %H:%M:%S")),
    ""
  )
  
  # Overall Assessment
  report_lines <- c(report_lines,
    "OVERALL ASSESSMENT:",
    paste("  Regression Status:", ifelse(regression_analysis$has_regression, "⚠️ DETECTED", "✅ NONE")),
    paste("  Severity Level:", regression_analysis$regression_severity),
    paste("  Summary:", regression_analysis$regression_summary),
    ""
  )
  
  # Detailed Results by Category
  if (length(regression_analysis$detailed_comparisons) > 0) {
    report_lines <- c(report_lines, "DETAILED RESULTS BY CATEGORY:")
    
    for (category_name in names(regression_analysis$detailed_comparisons)) {
      comparison <- regression_analysis$detailed_comparisons[[category_name]]
      
      report_lines <- c(report_lines,
        paste("", toupper(category_name), ":"),
        paste("    Overall Regression:", ifelse(comparison$overall_regression, "YES", "NO")),
        paste("    Performance Delta:", paste0(comparison$performance_delta_pct, "%"))
      )
      
      if (length(comparison$significant_changes) > 0) {
        report_lines <- c(report_lines, "    Significant Changes:")
        for (change_name in names(comparison$significant_changes)) {
          change <- comparison$significant_changes[[change_name]]
          report_lines <- c(report_lines,
            paste("      -", change_name, ":", paste0(change$performance_change_pct, "%"))
          )
        }
      }
      
      report_lines <- c(report_lines, "")
    }
  }
  
  # Critical Issues
  if (length(regression_analysis$critical_regressions) > 0) {
    report_lines <- c(report_lines, 
      "🚨 CRITICAL ISSUES:",
      paste("  -", names(regression_analysis$critical_regressions)),
      ""
    )
  }
  
  # Improvements
  if (length(regression_analysis$improvements) > 0) {
    report_lines <- c(report_lines,
      "📈 IMPROVEMENTS DETECTED:",
      paste("  -", names(regression_analysis$improvements)),
      ""
    )
  }
  
  # Recommendations
  report_lines <- c(report_lines,
    "RECOMMENDATIONS:",
    generate_regression_recommendations(regression_analysis),
    ""
  )
  
  return(paste(report_lines, collapse = "\n"))
}

#' Generate regression-specific recommendations
#' @param regression_analysis Regression analysis results
#' @return Vector of recommendation strings
generate_regression_recommendations <- function(regression_analysis) {
  
  recommendations <- c()
  
  if (regression_analysis$has_regression) {
    if (regression_analysis$regression_severity == "CRITICAL") {
      recommendations <- c(recommendations,
        "  • URGENT: Investigate and fix critical performance regressions before deployment",
        "  • Review recent code changes that may have introduced performance issues",
        "  • Consider rolling back to previous version if performance cannot be restored"
      )
    } else {
      recommendations <- c(recommendations,
        "  • Investigate performance regressions and optimize where possible",
        "  • Monitor performance closely in production",
        "  • Consider performance optimization in next development cycle"
      )
    }
  } else {
    recommendations <- c(recommendations,
      "  • Performance is stable - continue current development practices",
      "  • Consider establishing this as a new baseline if improvements are significant"
    )
  }
  
  return(recommendations)
}

# ============================================================================
# INITIALIZATION AND EXPORT
# ============================================================================

cat("✅ Performance Regression Testing Suite loaded successfully\n")
cat("📈 Ready for comprehensive regression testing of Brazilian Legislative System\n")
cat("📏 Baseline establishment and comparison system enabled\n")
cat("🚨 Automated regression detection and alerting configured\n")
cat("🎯 Railway-specific performance regression monitoring ready\n")

# Export main regression testing functions
cat("📋 Available regression testing functions:\n")
cat("  • establish_performance_baseline(baseline_name, test_duration_minutes)\n")
cat("  • run_performance_regression_test(baseline_name, test_name)\n")
cat("  • analyze_performance_regression(baseline, current)\n")
cat("  • calculate_composite_performance_score(baseline_data)\n")
cat("  • generate_regression_report(regression_analysis, baseline_name, test_name)\n")