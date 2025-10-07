# Arrow Performance Validation & Benchmarking
# Monitor Legislativo v4 - Railway Performance Testing
# ===================================================

#' Performance Validation and Benchmarking for Apache Arrow Implementation
#' 
#' This module provides comprehensive performance testing and validation
#' for the Brazilian Legislative Monitoring Platform's Arrow data pipeline.
#' 
#' Performance Targets:
#' - Memory usage: <1GB for 1M+ records
#' - Query performance: 0.2s for 40M record queries
#' - Aggregation performance: <1s for 134k document aggregations
#' - Railway deployment: 2GB memory constraint compatibility

# Load required libraries
required_packages <- c("arrow", "dplyr", "microbenchmark", "pryr", "tibble", "lubridate")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    warning(paste("Package", pkg, "not available. Installing..."))
    install.packages(pkg, dependencies = TRUE)
  }
  library(pkg, character.only = TRUE)
}

# Source Arrow pipeline functions
source("R/data/arrow_pipeline.R")
source("R/utils/parquet_conversion.R")

#' Comprehensive Arrow Performance Benchmark
#' 
#' Runs complete performance benchmarks against Arrow implementation
#' 
#' @param test_dataset_path Path to test Parquet dataset
#' @param iterations Number of benchmark iterations
#' @param memory_target_gb Memory usage target in GB
#' @return List with detailed benchmark results
#' @export
run_arrow_performance_benchmark <- function(test_dataset_path = NULL,
                                          iterations = 5,
                                          memory_target_gb = 1.0) {
  
  cat("🚀 Starting comprehensive Arrow performance benchmark...\n")
  cat("   Memory target:", memory_target_gb, "GB\n")
  cat("   Benchmark iterations:", iterations, "\n\n")
  
  benchmark_start <- Sys.time()
  results <- list()
  
  # Create test dataset if none provided
  if (is.null(test_dataset_path)) {
    test_dataset_path <- create_test_parquet_dataset()
  }
  
  # Initialize Arrow dataset
  cat("📊 Initializing Arrow dataset...\n")
  dataset <- init_arrow_dataset(test_dataset_path)
  
  if (is.null(dataset)) {
    stop("Failed to initialize test dataset")
  }
  
  # 1. Memory Usage Validation
  cat("🧠 Testing memory usage...\n")
  memory_results <- validate_memory_usage(dataset, memory_target_gb)
  results$memory_validation <- memory_results
  
  # 2. Query Performance Benchmark
  cat("⚡ Testing query performance...\n")
  query_results <- benchmark_query_performance(dataset, iterations)
  results$query_performance <- query_results
  
  # 3. Aggregation Performance Benchmark  
  cat("📈 Testing aggregation performance...\n")
  aggregation_results <- benchmark_aggregation_performance(dataset, iterations)
  results$aggregation_performance <- aggregation_results
  
  # 4. Search Performance Benchmark
  cat("🔍 Testing search performance...\n")
  search_results <- benchmark_search_performance(dataset, iterations)
  results$search_performance <- search_results
  
  # 5. Concurrent Load Testing
  cat("⚡ Testing concurrent load handling...\n")
  concurrent_results <- benchmark_concurrent_queries(dataset)
  results$concurrent_performance <- concurrent_results
  
  # 6. Railway Compatibility Testing
  cat("🚂 Testing Railway deployment compatibility...\n")
  railway_results <- validate_railway_compatibility(dataset)
  results$railway_compatibility <- railway_results
  
  total_benchmark_time <- as.numeric(difftime(Sys.time(), benchmark_start, units = "secs"))
  
  # Generate performance report
  report <- generate_performance_report(results, total_benchmark_time)
  results$performance_report <- report
  
  cat("✅ Arrow performance benchmark completed!\n")
  cat("   Total benchmark time:", round(total_benchmark_time, 2), "seconds\n\n")
  
  # Print summary
  print_benchmark_summary(results)
  
  return(results)
}

#' Validate Memory Usage Against Target
#' 
#' Tests memory consumption for various operation sizes
#' 
#' @param dataset Arrow dataset
#' @param memory_target_gb Memory target in GB
#' @return Memory validation results
validate_memory_usage <- function(dataset, memory_target_gb = 1.0) {
  
  memory_target_bytes <- memory_target_gb * 1024^3
  memory_tests <- list()
  
  # Test different query sizes
  test_sizes <- c(1000, 10000, 50000, 100000, 500000, 1000000)
  
  for (size in test_sizes) {
    gc()  # Clean memory before test
    initial_memory <- pryr::mem_used()
    
    tryCatch({
      # Execute query of specified size
      test_result <- dataset %>%
        head(size) %>%
        collect()
      
      peak_memory <- pryr::mem_used()
      memory_used <- as.numeric(peak_memory - initial_memory)
      
      memory_tests[[paste0("size_", size)]] <- list(
        records = size,
        memory_used_bytes = memory_used,
        memory_used_mb = round(memory_used / 1024^2, 2),
        memory_used_gb = round(memory_used / 1024^3, 3),
        target_met = memory_used < memory_target_bytes,
        result_rows = nrow(test_result)
      )
      
      # Clean up
      rm(test_result)
      gc()
      
    }, error = function(e) {
      memory_tests[[paste0("size_", size)]] <- list(
        records = size,
        error = e$message,
        target_met = FALSE
      )
    })
  }
  
  # Calculate overall memory validation
  successful_tests <- memory_tests[!sapply(memory_tests, function(x) "error" %in% names(x))]
  max_memory_test <- which.max(sapply(successful_tests, function(x) x$memory_used_bytes))
  
  if (length(max_memory_test) > 0) {
    max_memory_gb <- successful_tests[[max_memory_test]]$memory_used_gb
    memory_target_met <- max_memory_gb <= memory_target_gb
  } else {
    max_memory_gb <- NA
    memory_target_met <- FALSE
  }
  
  return(list(
    target_gb = memory_target_gb,
    max_memory_used_gb = max_memory_gb,
    target_met = memory_target_met,
    detailed_tests = memory_tests,
    successful_tests = length(successful_tests),
    failed_tests = length(memory_tests) - length(successful_tests)
  ))
}

#' Benchmark Query Performance
#' 
#' Tests query response times for different scenarios
#' 
#' @param dataset Arrow dataset
#' @param iterations Number of benchmark iterations
#' @return Query performance results
benchmark_query_performance <- function(dataset, iterations = 5) {
  
  # Define test scenarios
  test_scenarios <- list(
    simple_select = list(
      name = "Simple Select (1000 rows)",
      test_fn = function(ds) ds %>% head(1000) %>% collect()
    ),
    filtered_query = list(
      name = "Filtered Query",
      test_fn = function(ds) {
        ds %>%
          filter(year >= 2020) %>%
          head(5000) %>%
          collect()
      }
    ),
    complex_filter = list(
      name = "Complex Multi-Filter Query",
      test_fn = function(ds) {
        ds %>%
          filter(year >= 2018, !is.na(state)) %>%
          select(urn, title, state, year) %>%
          head(10000) %>%
          collect()
      }
    ),
    large_query = list(
      name = "Large Query (100k records)",
      test_fn = function(ds) {
        ds %>%
          filter(year >= 2015) %>%
          head(100000) %>%
          collect()
      }
    )
  )
  
  benchmark_results <- list()
  
  for (scenario_name in names(test_scenarios)) {
    scenario <- test_scenarios[[scenario_name]]
    
    cat("   Testing:", scenario$name, "\n")
    
    # Run microbenchmark
    bench_result <- microbenchmark(
      scenario$test_fn(dataset),
      times = iterations
    )
    
    # Extract timing statistics
    times_ms <- as.numeric(bench_result$time) / 1e6  # Convert to milliseconds
    
    benchmark_results[[scenario_name]] <- list(
      scenario = scenario$name,
      mean_time_ms = mean(times_ms),
      median_time_ms = median(times_ms),
      min_time_ms = min(times_ms),
      max_time_ms = max(times_ms),
      iterations = iterations,
      target_200ms_met = mean(times_ms) <= 200,  # 0.2s target
      all_results_ms = times_ms
    )
  }
  
  return(benchmark_results)
}

#' Benchmark Aggregation Performance
#' 
#' Tests aggregation query performance for dashboard metrics
#' 
#' @param dataset Arrow dataset
#' @param iterations Number of benchmark iterations
#' @return Aggregation performance results
benchmark_aggregation_performance <- function(dataset, iterations = 5) {
  
  aggregation_scenarios <- list(
    simple_count = list(
      name = "Simple Count",
      test_fn = function(ds) ds %>% summarise(total = n()) %>% collect()
    ),
    group_by_state = list(
      name = "Group by State",
      test_fn = function(ds) {
        ds %>%
          group_by(state) %>%
          summarise(count = n(), .groups = "drop") %>%
          collect()
      }
    ),
    complex_aggregation = list(
      name = "Complex Multi-Group Aggregation",
      test_fn = function(ds) {
        ds %>%
          filter(year >= 2018) %>%
          group_by(state, document_type_full) %>%
          summarise(
            count = n(),
            .groups = "drop"
          ) %>%
          arrange(desc(count)) %>%
          collect()
      }
    ),
    temporal_aggregation = list(
      name = "Temporal Aggregation by Year",
      test_fn = function(ds) {
        ds %>%
          group_by(year) %>%
          summarise(
            doc_count = n(),
            states_count = n_distinct(state),
            .groups = "drop"
          ) %>%
          arrange(desc(year)) %>%
          collect()
      }
    )
  )
  
  aggregation_results <- list()
  
  for (scenario_name in names(aggregation_scenarios)) {
    scenario <- aggregation_scenarios[[scenario_name]]
    
    cat("   Testing:", scenario$name, "\n")
    
    # Run microbenchmark
    bench_result <- microbenchmark(
      scenario$test_fn(dataset),
      times = iterations
    )
    
    times_ms <- as.numeric(bench_result$time) / 1e6
    
    aggregation_results[[scenario_name]] <- list(
      scenario = scenario$name,
      mean_time_ms = mean(times_ms),
      median_time_ms = median(times_ms),
      target_1000ms_met = mean(times_ms) <= 1000,  # 1s target for aggregations
      all_results_ms = times_ms
    )
  }
  
  return(aggregation_results)
}

#' Benchmark Search Performance
#' 
#' Tests text search capabilities and performance
#' 
#' @param dataset Arrow dataset
#' @param iterations Number of benchmark iterations
#' @return Search performance results
benchmark_search_performance <- function(dataset, iterations = 3) {
  
  search_terms <- c("transporte", "decreto", "lei", "brasil")
  search_results <- list()
  
  for (term in search_terms) {
    cat("   Testing search for:", term, "\n")
    
    bench_result <- microbenchmark(
      search_legislative_arrow(dataset, term, limit = 100),
      times = iterations
    )
    
    times_ms <- as.numeric(bench_result$time) / 1e6
    
    search_results[[paste0("search_", term)]] <- list(
      search_term = term,
      mean_time_ms = mean(times_ms),
      median_time_ms = median(times_ms),
      target_500ms_met = mean(times_ms) <= 500,  # 0.5s target for search
      iterations = iterations
    )
  }
  
  return(search_results)
}

#' Benchmark Concurrent Query Performance
#' 
#' Tests system behavior under concurrent load
#' 
#' @param dataset Arrow dataset
#' @return Concurrent performance results
benchmark_concurrent_queries <- function(dataset) {
  
  # Simple concurrent test (simulated)
  concurrent_start <- Sys.time()
  
  # Execute multiple queries in sequence (simulating concurrent load)
  query_results <- list()
  
  for (i in 1:5) {
    start_time <- Sys.time()
    
    result <- dataset %>%
      filter(year >= 2019) %>%
      head(1000) %>%
      collect()
    
    query_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    query_results[[i]] <- query_time
  }
  
  total_concurrent_time <- as.numeric(difftime(Sys.time(), concurrent_start, units = "secs"))
  avg_query_time <- mean(unlist(query_results))
  
  return(list(
    total_queries = 5,
    total_time_secs = total_concurrent_time,
    avg_query_time_secs = avg_query_time,
    queries_per_second = 5 / total_concurrent_time,
    individual_times = query_results
  ))
}

#' Validate Railway Deployment Compatibility
#' 
#' Tests compatibility with Railway platform constraints
#' 
#' @param dataset Arrow dataset
#' @return Railway compatibility results
validate_railway_compatibility <- function(dataset) {
  
  compatibility_tests <- list()
  
  # Test 1: Memory constraint simulation (2GB limit)
  tryCatch({
    large_query_start <- Sys.time()
    initial_memory <- pryr::mem_used()
    
    large_result <- dataset %>%
      head(200000) %>%  # Large query simulation
      collect()
    
    peak_memory <- pryr::mem_used()
    memory_used_gb <- as.numeric(peak_memory - initial_memory) / 1024^3
    query_time <- as.numeric(difftime(Sys.time(), large_query_start, units = "secs"))
    
    compatibility_tests$memory_constraint <- list(
      memory_used_gb = round(memory_used_gb, 3),
      railway_compatible = memory_used_gb < 1.5,  # Leave headroom for Railway
      query_time_secs = query_time,
      records_processed = nrow(large_result)
    )
    
    rm(large_result)
    gc()
    
  }, error = function(e) {
    compatibility_tests$memory_constraint <- list(
      error = e$message,
      railway_compatible = FALSE
    )
  })
  
  # Test 2: Cold start performance (important for Railway)
  tryCatch({
    # Clear cache to simulate cold start
    clear_arrow_cache()
    
    cold_start_time <- system.time({
      cold_dataset <- init_arrow_dataset(dirname(dataset$files[1]))
      cold_result <- cold_dataset %>% head(100) %>% collect()
    })
    
    compatibility_tests$cold_start <- list(
      cold_start_time_secs = as.numeric(cold_start_time[3]),
      acceptable_cold_start = cold_start_time[3] < 10,  # 10s cold start target
      records_retrieved = nrow(cold_result)
    )
    
  }, error = function(e) {
    compatibility_tests$cold_start <- list(
      error = e$message,
      acceptable_cold_start = FALSE
    )
  })
  
  return(compatibility_tests)
}

#' Create Test Parquet Dataset for Benchmarking
#' 
#' Creates a representative test dataset if none exists
#' 
#' @param output_dir Output directory for test dataset
#' @param num_records Number of test records to create
#' @return Path to created test dataset
create_test_parquet_dataset <- function(output_dir = tempfile("arrow_test_"), 
                                      num_records = 100000) {
  
  cat("📦 Creating test Parquet dataset...\n")
  
  # Create synthetic Brazilian legislative data
  set.seed(42)  # Reproducible test data
  
  brazilian_states <- c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Bahia", 
                       "Paraná", "Rio Grande do Sul", "Pernambuco", "Ceará")
  
  document_types <- c("Lei Municipal", "Decreto Federal", "Resolução", 
                     "Medida Provisória", "Lei Estadual", "Portaria")
  
  test_data <- tibble(
    urn = paste0("urn:lex:br:test:", 1:num_records),
    title = paste("Test Document", 1:num_records),
    state = sample(brazilian_states, num_records, replace = TRUE),
    municipality = paste("Município", sample(1:500, num_records, replace = TRUE)),
    document_type_full = sample(document_types, num_records, replace = TRUE),
    year = sample(2015:2024, num_records, replace = TRUE),
    promulgation_date = as.Date("2020-01-01") + sample(0:1460, num_records, replace = TRUE),
    document_description = paste("Test description for document", 1:num_records),
    processed_at = Sys.time(),
    data_source = "test_generation"
  )
  
  # Create output directory
  dir.create(output_dir, recursive = TRUE, showWarnings = FALSE)
  
  # Convert to Arrow table and write as partitioned Parquet
  arrow_table <- arrow::as_arrow_table(test_data)
  
  arrow::write_dataset(
    arrow_table,
    output_dir,
    format = "parquet",
    partitioning = c("year", "state"),
    compression = "snappy"
  )
  
  cat("   Created", num_records, "test records\n")
  cat("   Output:", output_dir, "\n")
  
  return(output_dir)
}

#' Generate Performance Report
#' 
#' Creates comprehensive performance analysis report
#' 
#' @param results Benchmark results
#' @param total_time Total benchmark time
#' @return Performance report
generate_performance_report <- function(results, total_time) {
  
  report <- list()
  
  # Memory validation summary
  if ("memory_validation" %in% names(results)) {
    memory_result <- results$memory_validation
    report$memory_summary <- list(
      target_met = memory_result$target_met,
      max_memory_gb = memory_result$max_memory_used_gb,
      target_gb = memory_result$target_gb,
      verdict = if (memory_result$target_met) "PASS" else "FAIL"
    )
  }
  
  # Query performance summary
  if ("query_performance" %in% names(results)) {
    query_results <- results$query_performance
    avg_query_times <- sapply(query_results, function(x) x$mean_time_ms)
    report$query_summary <- list(
      avg_query_time_ms = mean(avg_query_times),
      fastest_query_ms = min(avg_query_times),
      slowest_query_ms = max(avg_query_times),
      target_200ms_pass_rate = mean(sapply(query_results, function(x) x$target_200ms_met))
    )
  }
  
  # Overall assessment
  report$overall_assessment <- list(
    memory_compliant = results$memory_validation$target_met %||% FALSE,
    performance_acceptable = (report$query_summary$avg_query_time_ms %||% Inf) < 500,
    railway_compatible = results$railway_compatibility$memory_constraint$railway_compatible %||% FALSE,
    recommendation = "Production ready" # Will be updated based on criteria
  )
  
  # Update recommendation based on results
  if (!report$overall_assessment$memory_compliant) {
    report$overall_assessment$recommendation <- "Memory optimization needed"
  } else if (!report$overall_assessment$performance_acceptable) {
    report$overall_assessment$recommendation <- "Query optimization needed"
  } else if (!report$overall_assessment$railway_compatible) {
    report$overall_assessment$recommendation <- "Railway compatibility issues"
  }
  
  return(report)
}

#' Print Benchmark Summary
#' 
#' Prints formatted benchmark results
#' 
#' @param results Benchmark results
print_benchmark_summary <- function(results) {
  
  cat("\n" %R% "═" %R% 50 %R% "\n")
  cat("   ARROW PERFORMANCE BENCHMARK SUMMARY\n")
  cat("═" %R% 50 %R% "\n\n")
  
  # Memory Results
  if ("memory_validation" %in% names(results)) {
    mem_result <- results$memory_validation
    cat("🧠 MEMORY VALIDATION:\n")
    cat("   Target: <", mem_result$target_gb, "GB\n")
    cat("   Peak Usage:", round(mem_result$max_memory_used_gb, 3), "GB\n")
    cat("   Status:", if (mem_result$target_met) "✅ PASS" else "❌ FAIL", "\n\n")
  }
  
  # Query Performance Results
  if ("query_performance" %in% names(results)) {
    cat("⚡ QUERY PERFORMANCE:\n")
    for (test_name in names(results$query_performance)) {
      test_result <- results$query_performance[[test_name]]
      cat("   ", test_result$scenario, ":", round(test_result$mean_time_ms, 1), "ms",
          if (test_result$target_200ms_met) "✅" else "⚠️", "\n")
    }
    cat("\n")
  }
  
  # Aggregation Performance
  if ("aggregation_performance" %in% names(results)) {
    cat("📈 AGGREGATION PERFORMANCE:\n")
    for (test_name in names(results$aggregation_performance)) {
      test_result <- results$aggregation_performance[[test_name]]
      cat("   ", test_result$scenario, ":", round(test_result$mean_time_ms, 1), "ms",
          if (test_result$target_1000ms_met) "✅" else "⚠️", "\n")
    }
    cat("\n")
  }
  
  # Overall Assessment
  if ("performance_report" %in% names(results)) {
    overall <- results$performance_report$overall_assessment
    cat("🎯 OVERALL ASSESSMENT:\n")
    cat("   Memory Compliant:", if (overall$memory_compliant) "✅" else "❌", "\n")
    cat("   Performance Acceptable:", if (overall$performance_acceptable) "✅" else "❌", "\n")
    cat("   Railway Compatible:", if (overall$railway_compatible) "✅" else "❌", "\n")
    cat("   Recommendation:", overall$recommendation, "\n\n")
  }
  
  cat("═" %R% 50 %R% "\n")
}

# Helper function for string repetition
`%R%` <- function(x, n) paste(rep(x, n), collapse = "")

# Helper function for null-coalescing
`%||%` <- function(x, y) if (is.null(x)) y else x

cat("✅ Arrow performance validation module loaded successfully\n")
cat("   Comprehensive benchmarking for Railway deployment\n")
cat("   Memory and performance validation against PRD targets\n")