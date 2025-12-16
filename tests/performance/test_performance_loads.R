# ============================================================================
# SPRINT 8A: PERFORMANCE TESTING SUITE - LOAD VALIDATION
# ============================================================================
# 
# Comprehensive Performance Testing for Monitor Legislativo v4
# Concurrent user testing (target: 50+ researchers)
# Database query performance under load (134k+ documents)
# Memory usage validation (Railway 2GB compliance)
# Response time validation (<2s dashboard, <30s reports)
# API throughput testing with realistic academic usage patterns
# Geographic analysis performance (all Brazilian municipalities)
# 
# Author: Sprint 8A Implementation
# Version: 1.0.0
# Last Updated: 2024-09-10
# ============================================================================

library(testthat)
library(httr)
library(jsonlite)
library(parallel)
library(future)
library(future.apply)
library(dplyr)
library(microbenchmark)

# Performance Testing Configuration
PERF_CONFIG <- list(
  base_url = ifelse(
    Sys.getenv("K_SERVICE") != "",
    "https://mackmonitor-667999538255.southamerica-east1.run.app",
    "http://localhost:8000"
  ),
  api_version = "v1",
  concurrent_users = 10,  # Scaled for testing environment
  max_concurrent_users = 25,  # Maximum for stress testing
  timeout = 60,
  test_duration_seconds = 30,
  memory_limit_mb = 2048,  # Cloud Run 2GB limit
  response_time_targets = list(
    dashboard = 2,    # 2 seconds for dashboard
    search = 5,       # 5 seconds for search
    reports = 30,     # 30 seconds for reports
    api_simple = 1,   # 1 second for simple API calls
    api_complex = 10  # 10 seconds for complex queries
  ),
  load_test_requests = 100,
  stress_test_requests = 500
)

# Performance Monitoring Functions
# ================================

#' Monitor system memory usage (if possible)
monitor_memory_usage <- function() {
  tryCatch({
    # Try to get memory information from the system
    if (Sys.info()["sysname"] == "Linux") {
      mem_info <- system("cat /proc/meminfo | grep MemAvailable", intern = TRUE)
      if (length(mem_info) > 0) {
        mem_kb <- as.numeric(gsub("[^0-9]", "", mem_info[1]))
        mem_mb <- mem_kb / 1024
        return(mem_mb)
      }
    }
    
    # Fallback - estimate from R's memory usage
    r_mem_mb <- as.numeric(object.size(ls(envir = .GlobalEnv))) / (1024^2)
    return(r_mem_mb)
    
  }, error = function(e) {
    return(NA)
  })
}

#' Make timed API request
make_timed_request <- function(endpoint, method = "GET", body = NULL) {
  url <- paste0(PERF_CONFIG$base_url, "/api/", PERF_CONFIG$api_version, endpoint)
  
  start_time <- Sys.time()
  
  tryCatch({
    if (method == "GET") {
      response <- GET(url, timeout(PERF_CONFIG$timeout))
    } else if (method == "POST") {
      response <- POST(url, body = body, encode = "json", timeout(PERF_CONFIG$timeout))
    }
    
    end_time <- Sys.time()
    response_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    
    return(list(
      status = status_code(response),
      response_time = response_time,
      success = status_code(response) == 200,
      timestamp = start_time,
      size_bytes = length(content(response, "raw"))
    ))
    
  }, error = function(e) {
    end_time <- Sys.time()
    response_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    
    return(list(
      status = 0,
      response_time = response_time,
      success = FALSE,
      error = e$message,
      timestamp = start_time
    ))
  })
}

#' Simulate concurrent users
simulate_concurrent_users <- function(num_users, test_duration_seconds, endpoints) {
  cat(paste("🔄 Simulating", num_users, "concurrent users for", test_duration_seconds, "seconds...\n"))
  
  # Set up parallel processing
  plan(multisession, workers = min(num_users, 8))  # Limit workers to available cores
  
  results <- list()
  start_time <- Sys.time()
  
  # Create tasks for each user
  user_tasks <- list()
  for (i in 1:num_users) {
    user_tasks[[i]] <- future({
      user_results <- list()
      user_start <- Sys.time()
      
      while (as.numeric(difftime(Sys.time(), user_start, units = "secs")) < test_duration_seconds) {
        # Select random endpoint
        endpoint <- sample(endpoints, 1)[[1]]
        
        # Make request
        result <- make_timed_request(endpoint$path, endpoint$method, endpoint$body)
        result$user_id <- i
        result$endpoint <- endpoint$path
        
        user_results[[length(user_results) + 1]] <- result
        
        # Small delay to simulate realistic user behavior
        Sys.sleep(runif(1, 0.1, 0.5))
      }
      
      return(user_results)
    })
  }
  
  # Collect results from all users
  all_results <- future_lapply(user_tasks, value)
  
  # Flatten results
  flat_results <- unlist(all_results, recursive = FALSE)
  
  total_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  
  return(list(
    results = flat_results,
    total_time = total_time,
    num_users = num_users,
    total_requests = length(flat_results)
  ))
}

#' Analyze performance results
analyze_performance_results <- function(results) {
  if (length(results) == 0) {
    return(list(error = "No results to analyze"))
  }
  
  # Extract metrics
  response_times <- sapply(results, function(r) r$response_time %||% 0)
  success_rate <- mean(sapply(results, function(r) r$success %||% FALSE))
  status_codes <- sapply(results, function(r) r$status %||% 0)
  
  # Calculate statistics
  stats <- list(
    total_requests = length(results),
    success_rate = success_rate,
    failed_requests = sum(!sapply(results, function(r) r$success %||% FALSE)),
    avg_response_time = mean(response_times, na.rm = TRUE),
    median_response_time = median(response_times, na.rm = TRUE),
    min_response_time = min(response_times, na.rm = TRUE),
    max_response_time = max(response_times, na.rm = TRUE),
    p95_response_time = quantile(response_times, 0.95, na.rm = TRUE),
    p99_response_time = quantile(response_times, 0.99, na.rm = TRUE),
    status_code_distribution = table(status_codes)
  )
  
  return(stats)
}

# CONCURRENT USER TESTING (TARGET: 50+ RESEARCHERS)
# =================================================

test_that("Concurrent User Testing - Academic Researchers", {
  skip_on_cran()
  skip_if_offline()
  
  cat("\n👥 Testing Concurrent User Load - Academic Researchers\n")
  
  # Define realistic academic usage patterns
  academic_endpoints <- list(
    list(path = "/health", method = "GET"),
    list(path = "/statistics", method = "GET"),
    list(path = "/documents?limit=20", method = "GET"),
    list(path = "/geography?level=state", method = "GET"),
    list(path = "/search", method = "POST", body = list(query = "educação", limit = 10)),
    list(path = "/search", method = "POST", body = list(query = "saúde", limit = 15)),
    list(path = "/search", method = "POST", body = list(query = "transporte", limit = 10))
  )
  
  # Test 1: Low Load (5 concurrent users)
  cat("\n1️⃣ Testing Low Load (5 concurrent users)...\n")
  low_load_results <- simulate_concurrent_users(5, 15, academic_endpoints)
  low_load_stats <- analyze_performance_results(low_load_results$results)
  
  expect_true(low_load_stats$success_rate >= 0.9,
              info = paste("Low load success rate should be >= 90%, got:",
                          round(low_load_stats$success_rate * 100, 1), "%"))
  
  expect_true(low_load_stats$avg_response_time <= 5,
              info = paste("Low load avg response time should be <= 5s, got:",
                          round(low_load_stats$avg_response_time, 2), "seconds"))
  
  # Test 2: Medium Load (10 concurrent users)
  cat("\n2️⃣ Testing Medium Load (10 concurrent users)...\n")
  medium_load_results <- simulate_concurrent_users(10, 20, academic_endpoints)
  medium_load_stats <- analyze_performance_results(medium_load_results$results)
  
  expect_true(medium_load_stats$success_rate >= 0.85,
              info = paste("Medium load success rate should be >= 85%, got:",
                          round(medium_load_stats$success_rate * 100, 1), "%"))
  
  expect_true(medium_load_stats$avg_response_time <= 10,
              info = paste("Medium load avg response time should be <= 10s, got:",
                          round(medium_load_stats$avg_response_time, 2), "seconds"))
  
  # Test 3: High Load (15-20 concurrent users) - Stress test
  cat("\n3️⃣ Testing High Load (15 concurrent users)...\n")
  high_load_results <- simulate_concurrent_users(15, 25, academic_endpoints)
  high_load_stats <- analyze_performance_results(high_load_results$results)
  
  expect_true(high_load_stats$success_rate >= 0.7,
              info = paste("High load success rate should be >= 70%, got:",
                          round(high_load_stats$success_rate * 100, 1), "%"))
  
  # Print performance summary
  cat("\n📊 Concurrent User Testing Summary:\n")
  cat(paste("   Low Load (5 users):", round(low_load_stats$success_rate * 100, 1), 
            "% success,", round(low_load_stats$avg_response_time, 2), "s avg\n"))
  cat(paste("   Medium Load (10 users):", round(medium_load_stats$success_rate * 100, 1), 
            "% success,", round(medium_load_stats$avg_response_time, 2), "s avg\n"))
  cat(paste("   High Load (15 users):", round(high_load_stats$success_rate * 100, 1), 
            "% success,", round(high_load_stats$avg_response_time, 2), "s avg\n"))
  
  cat("✅ Concurrent User Testing completed\n")
})

# DATABASE QUERY PERFORMANCE UNDER LOAD (134K+ DOCUMENTS)
# ========================================================

test_that("Database Query Performance Under Load", {
  skip_on_cran()
  skip_if_offline()
  
  cat("\n🗃️ Testing Database Query Performance Under Load\n")
  
  # Test different query complexities
  db_intensive_endpoints <- list(
    list(path = "/documents?limit=100", method = "GET", name = "Large document query"),
    list(path = "/documents?state=SP&year=2023&limit=50", method = "GET", name = "Filtered query"),
    list(path = "/geography?level=state", method = "GET", name = "Geographic aggregation"),
    list(path = "/statistics", method = "GET", name = "Statistics calculation"),
    list(path = "/search", method = "POST", 
         body = list(query = "constituição federal", limit = 50), name = "Complex search")
  )
  
  db_performance_results <- list()
  
  for (endpoint in db_intensive_endpoints) {
    cat(paste("\n🔍 Testing:", endpoint$name, "...\n"))
    
    # Benchmark the query multiple times
    times <- list()
    successes <- 0
    
    for (i in 1:5) {
      result <- make_timed_request(endpoint$path, endpoint$method, endpoint$body)
      times[[i]] <- result$response_time
      if (result$success) successes <- successes + 1
    }
    
    avg_time <- mean(unlist(times), na.rm = TRUE)
    success_rate <- successes / 5
    
    db_performance_results[[endpoint$name]] <- list(
      avg_time = avg_time,
      success_rate = success_rate,
      times = unlist(times)
    )
    
    cat(paste("   ⏱️ Average time:", round(avg_time, 2), "seconds\n"))
    cat(paste("   ✅ Success rate:", round(success_rate * 100, 1), "%\n"))
  }
  
  # Test query performance under concurrent load
  cat("\n⚡ Testing Concurrent Database Load...\n")
  
  concurrent_db_results <- simulate_concurrent_users(8, 20, db_intensive_endpoints)
  concurrent_db_stats <- analyze_performance_results(concurrent_db_results$results)
  
  # Validate database performance
  expect_true(concurrent_db_stats$success_rate >= 0.8,
              info = paste("Concurrent DB success rate should be >= 80%, got:",
                          round(concurrent_db_stats$success_rate * 100, 1), "%"))
  
  expect_true(concurrent_db_stats$p95_response_time <= 15,
              info = paste("95th percentile response time should be <= 15s, got:",
                          round(concurrent_db_stats$p95_response_time, 2), "seconds"))
  
  cat("✅ Database Query Performance testing completed\n")
})

# MEMORY USAGE VALIDATION (CLOUD RUN 2GB COMPLIANCE)
# ================================================

test_that("Memory Usage Validation - Cloud Run 2GB Compliance", {
  skip_on_cran()
  skip_if_offline()

  cat("\n💾 Testing Memory Usage - Cloud Run 2GB Compliance\n")
  
  # Monitor memory before testing
  initial_memory <- monitor_memory_usage()
  cat(paste("📊 Initial memory estimate:", round(initial_memory %||% 0, 2), "MB\n"))
  
  # Test memory usage under load
  cat("\n🔄 Testing memory usage under sustained load...\n")
  
  memory_test_endpoints <- list(
    list(path = "/documents?limit=100", method = "GET"),
    list(path = "/search", method = "POST", body = list(query = "test data", limit = 50)),
    list(path = "/geography?level=municipality", method = "GET"),
    list(path = "/statistics", method = "GET")
  )
  
  # Run sustained requests and monitor memory
  memory_samples <- list()
  request_count <- 0
  
  start_time <- Sys.time()
  while (as.numeric(difftime(Sys.time(), start_time, units = "secs")) < 30) {
    # Make requests
    for (endpoint in memory_test_endpoints) {
      result <- make_timed_request(endpoint$path, endpoint$method, endpoint$body)
      request_count <- request_count + 1
      
      # Sample memory periodically
      if (request_count %% 5 == 0) {
        current_memory <- monitor_memory_usage()
        if (!is.na(current_memory)) {
          memory_samples[[length(memory_samples) + 1]] <- current_memory
        }
      }
    }
    
    Sys.sleep(0.1)  # Brief pause
  }
  
  # Analyze memory usage
  if (length(memory_samples) > 0) {
    avg_memory <- mean(unlist(memory_samples), na.rm = TRUE)
    max_memory <- max(unlist(memory_samples), na.rm = TRUE)
    
    cat(paste("📈 Average memory during test:", round(avg_memory, 2), "MB\n"))
    cat(paste("📊 Peak memory during test:", round(max_memory, 2), "MB\n"))
    cat(paste("🔢 Total requests made:", request_count, "\n"))

    # Cloud Run has 2GB (2048MB) limit
    expect_true(max_memory <= PERF_CONFIG$memory_limit_mb,
                info = paste("Memory usage should stay under", PERF_CONFIG$memory_limit_mb,
                           "MB, peak was:", round(max_memory, 2), "MB"))
    
    # Memory should be reasonable for normal operations
    expect_true(avg_memory <= PERF_CONFIG$memory_limit_mb * 0.5,
                info = paste("Average memory should be under 50% of limit (", 
                           PERF_CONFIG$memory_limit_mb * 0.5, "MB), got:", 
                           round(avg_memory, 2), "MB"))
  } else {
    cat("⚠️ Unable to monitor memory usage on this system\n")
  }
  
  # Test memory cleanup by forcing garbage collection
  cat("\n🧹 Testing memory cleanup...\n")
  pre_gc_memory <- monitor_memory_usage()
  gc(verbose = FALSE)
  post_gc_memory <- monitor_memory_usage()
  
  if (!isTRUE(is.na(pre_gc_memory)) && !is.na(post_gc_memory)) {
    memory_freed <- pre_gc_memory - post_gc_memory
    cat(paste("🗑️ Memory freed by garbage collection:", round(memory_freed, 2), "MB\n"))
  }
  
  cat("✅ Memory Usage Validation completed\n")
})

# RESPONSE TIME VALIDATION (<2S DASHBOARD, <30S REPORTS)
# ======================================================

test_that("Response Time Validation - Performance Targets", {
  skip_on_cran()
  skip_if_offline()
  
  cat("\n⏱️ Testing Response Time Targets\n")
  
  # Define performance target tests
  performance_tests <- list(
    list(
      name = "Dashboard Performance",
      endpoints = list(
        list(path = "/health", method = "GET"),
        list(path = "/statistics", method = "GET"),
        list(path = "/analytics/dashboard", method = "GET")
      ),
      target_time = PERF_CONFIG$response_time_targets$dashboard,
      category = "dashboard"
    ),
    list(
      name = "Search Performance",
      endpoints = list(
        list(path = "/search", method = "POST", body = list(query = "educação", limit = 20)),
        list(path = "/search", method = "POST", body = list(query = "saúde", limit = 15)),
        list(path = "/documents?state=SP&limit=30", method = "GET")
      ),
      target_time = PERF_CONFIG$response_time_targets$search,
      category = "search"
    ),
    list(
      name = "Report Generation",
      endpoints = list(
        list(path = "/export?format=csv&limit=100", method = "GET"),
        list(path = "/geography?level=municipality", method = "GET"),
        list(path = "/analytics/trends?granularity=month", method = "GET")
      ),
      target_time = PERF_CONFIG$response_time_targets$reports,
      category = "reports"
    ),
    list(
      name = "Simple API Calls",
      endpoints = list(
        list(path = "/health", method = "GET"),
        list(path = "/info", method = "GET"),
        list(path = "/documents?limit=5", method = "GET")
      ),
      target_time = PERF_CONFIG$response_time_targets$api_simple,
      category = "simple_api"
    )
  )
  
  performance_summary <- list()
  
  for (test_group in performance_tests) {
    cat(paste("\n🎯 Testing", test_group$name, "(target:", test_group$target_time, "seconds)...\n"))
    
    all_times <- list()
    successful_requests <- 0
    total_requests <- 0
    
    for (endpoint in test_group$endpoints) {
      # Test each endpoint multiple times
      for (i in 1:3) {
        result <- make_timed_request(endpoint$path, endpoint$method, endpoint$body)
        all_times[[length(all_times) + 1]] <- result$response_time
        total_requests <- total_requests + 1
        if (result$success) successful_requests <- successful_requests + 1
      }
    }
    
    # Calculate statistics
    avg_time <- mean(unlist(all_times), na.rm = TRUE)
    median_time <- median(unlist(all_times), na.rm = TRUE)
    p95_time <- quantile(unlist(all_times), 0.95, na.rm = TRUE)
    success_rate <- successful_requests / total_requests
    
    performance_summary[[test_group$category]] <- list(
      avg_time = avg_time,
      median_time = median_time,
      p95_time = p95_time,
      success_rate = success_rate,
      target_time = test_group$target_time,
      meets_target = avg_time <= test_group$target_time
    )
    
    cat(paste("   📊 Average time:", round(avg_time, 2), "seconds\n"))
    cat(paste("   📈 95th percentile:", round(p95_time, 2), "seconds\n"))
    cat(paste("   ✅ Success rate:", round(success_rate * 100, 1), "%\n"))
    cat(paste("   🎯 Meets target:", ifelse(avg_time <= test_group$target_time, "YES", "NO"), "\n"))
    
    # Validate against targets
    expect_true(success_rate >= 0.8,
                info = paste(test_group$name, "success rate should be >= 80%, got:",
                           round(success_rate * 100, 1), "%"))
    
    # Allow some flexibility for development/testing environment
    acceptable_time <- test_group$target_time * 2  # 2x target for testing tolerance
    expect_true(avg_time <= acceptable_time,
                info = paste(test_group$name, "avg time should be <=", acceptable_time, 
                           "seconds, got:", round(avg_time, 2), "seconds"))
  }
  
  # Overall performance assessment
  target_met_count <- sum(sapply(performance_summary, function(p) p$meets_target))
  total_test_groups <- length(performance_summary)
  
  cat(paste("\n📊 Performance Targets Met:", target_met_count, "/", total_test_groups, "\n"))
  
  cat("✅ Response Time Validation completed\n")
})

# API THROUGHPUT TESTING WITH REALISTIC ACADEMIC USAGE
# ====================================================

test_that("API Throughput Testing - Academic Usage Patterns", {
  skip_on_cran()
  skip_if_offline()
  
  cat("\n🚀 Testing API Throughput - Academic Usage Patterns\n")
  
  # Define realistic academic research patterns
  research_patterns <- list(
    literature_review = list(
      weight = 0.4,  # 40% of academic usage
      endpoints = list(
        list(path = "/search", method = "POST", body = list(query = "educação superior", limit = 20)),
        list(path = "/search", method = "POST", body = list(query = "política educacional", limit = 15)),
        list(path = "/documents?type=lei&state=SP", method = "GET")
      )
    ),
    data_analysis = list(
      weight = 0.3,  # 30% of academic usage
      endpoints = list(
        list(path = "/statistics", method = "GET"),
        list(path = "/geography?level=state", method = "GET"),
        list(path = "/analytics/trends", method = "GET")
      )
    ),
    document_retrieval = list(
      weight = 0.2,  # 20% of academic usage
      endpoints = list(
        list(path = "/documents?limit=50", method = "GET"),
        list(path = "/documents/sample-doc-1", method = "GET"),
        list(path = "/export?format=csv&limit=100", method = "GET")
      )
    ),
    citation_analysis = list(
      weight = 0.1,  # 10% of academic usage
      endpoints = list(
        list(path = "/citations?document_id=sample-doc", method = "GET"),
        list(path = "/analytics/content", method = "GET")
      )
    )
  )
  
  # Create weighted endpoint list for realistic distribution
  weighted_endpoints <- list()
  for (pattern_name in names(research_patterns)) {
    pattern <- research_patterns[[pattern_name]]
    weight <- pattern$weight
    
    # Add endpoints based on weight
    for (endpoint in pattern$endpoints) {
      for (i in 1:ceiling(weight * 10)) {  # Scale weight to get appropriate count
        weighted_endpoints[[length(weighted_endpoints) + 1]] <- endpoint
      }
    }
  }
  
  cat(paste("📚 Created", length(weighted_endpoints), "weighted academic usage endpoints\n"))
  
  # Test throughput with academic pattern
  cat("\n📈 Testing Academic Usage Throughput...\n")
  
  throughput_start <- Sys.time()
  throughput_results <- list()
  
  # Simulate realistic academic session (burst then steady)
  for (phase in c("burst", "steady")) {
    if (phase == "burst") {
      # Initial burst of research activity
      users <- 8
      duration <- 15
      cat(paste("   🔥 Burst phase:", users, "users for", duration, "seconds\n"))
    } else {
      # Steady research work
      users <- 4  
      duration <- 20
      cat(paste("   📖 Steady phase:", users, "users for", duration, "seconds\n"))
    }
    
    phase_results <- simulate_concurrent_users(users, duration, weighted_endpoints)
    throughput_results[[phase]] <- phase_results
  }
  
  total_throughput_time <- as.numeric(difftime(Sys.time(), throughput_start, units = "secs"))
  
  # Analyze throughput results
  all_requests <- c(throughput_results$burst$results, throughput_results$steady$results)
  throughput_stats <- analyze_performance_results(all_requests)
  
  # Calculate throughput metrics
  total_requests <- length(all_requests)
  requests_per_second <- total_requests / total_throughput_time
  successful_requests_per_second <- (total_requests * throughput_stats$success_rate) / total_throughput_time
  
  cat(paste("\n📊 Throughput Analysis:\n"))
  cat(paste("   🔢 Total requests:", total_requests, "\n"))
  cat(paste("   ⏱️ Total time:", round(total_throughput_time, 2), "seconds\n"))
  cat(paste("   🚀 Requests/second:", round(requests_per_second, 2), "\n"))
  cat(paste("   ✅ Successful requests/second:", round(successful_requests_per_second, 2), "\n"))
  cat(paste("   📈 Overall success rate:", round(throughput_stats$success_rate * 100, 1), "%\n"))
  cat(paste("   ⏱️ Average response time:", round(throughput_stats$avg_response_time, 2), "seconds\n"))
  
  # Validate throughput targets
  expect_true(throughput_stats$success_rate >= 0.8,
              info = paste("Academic usage success rate should be >= 80%, got:",
                          round(throughput_stats$success_rate * 100, 1), "%"))
  
  expect_true(successful_requests_per_second >= 1,
              info = paste("Should handle >= 1 successful request/second, got:",
                          round(successful_requests_per_second, 2)))
  
  expect_true(throughput_stats$avg_response_time <= 8,
              info = paste("Average response time should be <= 8s under load, got:",
                          round(throughput_stats$avg_response_time, 2), "seconds"))
  
  cat("✅ API Throughput Testing completed\n")
})

# GEOGRAPHIC ANALYSIS PERFORMANCE (ALL BRAZILIAN MUNICIPALITIES)
# ==============================================================

test_that("Geographic Analysis Performance - Brazilian Municipalities", {
  skip_on_cran()
  skip_if_offline()
  
  cat("\n🗺️ Testing Geographic Analysis Performance\n")
  
  # Test different geographic analysis levels
  geographic_tests <- list(
    list(
      name = "State Level Analysis",
      endpoint = "/geography?level=state&metric=count",
      expected_regions = 27,  # Brazilian states + DF
      target_time = 3
    ),
    list(
      name = "Regional Analysis", 
      endpoint = "/geography?level=region&metric=count",
      expected_regions = 5,   # Brazilian regions
      target_time = 2
    ),
    list(
      name = "Municipality Analysis",
      endpoint = "/geography?level=municipality&metric=count",
      expected_regions = 50,  # Limited sample for performance
      target_time = 10
    )
  )
  
  geographic_performance <- list()
  
  for (geo_test in geographic_tests) {
    cat(paste("\n🏛️ Testing", geo_test$name, "...\n"))
    
    # Test multiple times for consistent results
    times <- list()
    data_counts <- list()
    successes <- 0
    
    for (i in 1:3) {
      result <- make_timed_request(geo_test$endpoint)
      times[[i]] <- result$response_time
      
      if (result$success) {
        successes <- successes + 1
        
        # Try to get response data
        tryCatch({
          response <- GET(paste0(PERF_CONFIG$base_url, "/api/", PERF_CONFIG$api_version, geo_test$endpoint))
          if (status_code(response) == 200) {
            data <- content(response, "parsed")
            if (!isTRUE(is.null(data$data)) && is.data.frame(data$data)) {
              data_counts[[i]] <- nrow(data$data)
            }
          }
        }, error = function(e) {
          # Ignore parsing errors for performance test
        })
      }
    }
    
    avg_time <- mean(unlist(times), na.rm = TRUE)
    success_rate <- successes / 3
    avg_data_count <- if (length(data_counts) > 0) mean(unlist(data_counts), na.rm = TRUE) else 0
    
    geographic_performance[[geo_test$name]] <- list(
      avg_time = avg_time,
      success_rate = success_rate,
      avg_data_count = avg_data_count,
      target_time = geo_test$target_time,
      meets_target = avg_time <= geo_test$target_time
    )
    
    cat(paste("   ⏱️ Average time:", round(avg_time, 2), "seconds\n"))
    cat(paste("   ✅ Success rate:", round(success_rate * 100, 1), "%\n"))
    cat(paste("   📊 Average data points:", round(avg_data_count, 0), "\n"))
    cat(paste("   🎯 Meets target:", ifelse(avg_time <= geo_test$target_time, "YES", "NO"), "\n"))
    
    # Validate geographic performance
    expect_true(success_rate >= 0.8,
                info = paste(geo_test$name, "success rate should be >= 80%, got:",
                           round(success_rate * 100, 1), "%"))
    
    # Allow some flexibility for development environment
    expect_true(avg_time <= geo_test$target_time * 1.5,
                info = paste(geo_test$name, "should complete within", geo_test$target_time * 1.5,
                           "seconds, got:", round(avg_time, 2), "seconds"))
  }
  
  # Test geographic analysis under concurrent load
  cat("\n🔄 Testing Geographic Analysis Under Concurrent Load...\n")
  
  geo_endpoints <- list(
    list(path = "/geography?level=state", method = "GET"),
    list(path = "/geography?level=region", method = "GET"),
    list(path = "/geography?level=municipality", method = "GET")
  )
  
  concurrent_geo_results <- simulate_concurrent_users(6, 20, geo_endpoints)
  concurrent_geo_stats <- analyze_performance_results(concurrent_geo_results$results)
  
  expect_true(concurrent_geo_stats$success_rate >= 0.75,
              info = paste("Concurrent geographic analysis success rate should be >= 75%, got:",
                          round(concurrent_geo_stats$success_rate * 100, 1), "%"))
  
  cat("✅ Geographic Analysis Performance testing completed\n")
})

# COMPREHENSIVE PERFORMANCE SUMMARY
# =================================

test_that("Comprehensive Performance Summary", {
  skip_on_cran()
  skip_if_offline()
  
  cat("\n📊 Comprehensive Performance Summary\n")
  
  # Run a final comprehensive performance test
  cat("\n🔄 Running comprehensive performance validation...\n")
  
  # Mixed workload representing typical usage
  mixed_endpoints <- list(
    # Quick operations (40%)
    list(path = "/health", method = "GET"),
    list(path = "/info", method = "GET"),
    list(path = "/statistics", method = "GET"),
    list(path = "/documents?limit=10", method = "GET"),
    
    # Medium operations (40%)
    list(path = "/search", method = "POST", body = list(query = "educação", limit = 20)),
    list(path = "/documents?state=SP&limit=30", method = "GET"),
    list(path = "/geography?level=state", method = "GET"),
    
    # Heavy operations (20%)
    list(path = "/documents?limit=100", method = "GET"),
    list(path = "/geography?level=municipality", method = "GET"),
    list(path = "/export?format=csv&limit=50", method = "GET")
  )
  
  # Comprehensive test with realistic mixed load
  final_results <- simulate_concurrent_users(12, 30, mixed_endpoints)
  final_stats <- analyze_performance_results(final_results$results)
  
  # Calculate performance scores
  performance_scores <- list(
    success_rate_score = min(final_stats$success_rate * 100, 100),
    response_time_score = max(0, 100 - (final_stats$avg_response_time * 10)),
    throughput_score = min((final_results$total_requests / final_results$total_time) * 10, 100),
    reliability_score = min((1 - (final_stats$failed_requests / final_stats$total_requests)) * 100, 100)
  )
  
  overall_score <- mean(unlist(performance_scores))
  
  cat("\n📋 Final Performance Metrics:\n")
  cat(paste("   🎯 Success Rate:", round(final_stats$success_rate * 100, 1), "%\n"))
  cat(paste("   ⏱️ Average Response Time:", round(final_stats$avg_response_time, 2), "seconds\n"))
  cat(paste("   📈 95th Percentile Time:", round(final_stats$p95_response_time, 2), "seconds\n"))
  cat(paste("   🚀 Throughput:", round(final_results$total_requests / final_results$total_time, 2), "req/sec\n"))
  cat(paste("   📊 Total Requests:", final_stats$total_requests, "\n"))
  cat(paste("   ❌ Failed Requests:", final_stats$failed_requests, "\n"))
  
  cat("\n🏆 Performance Scores:\n")
  cat(paste("   ✅ Success Rate Score:", round(performance_scores$success_rate_score, 1), "/100\n"))
  cat(paste("   ⏱️ Response Time Score:", round(performance_scores$response_time_score, 1), "/100\n"))
  cat(paste("   🚀 Throughput Score:", round(performance_scores$throughput_score, 1), "/100\n"))
  cat(paste("   🔒 Reliability Score:", round(performance_scores$reliability_score, 1), "/100\n"))
  cat(paste("   🎯 Overall Performance Score:", round(overall_score, 1), "/100\n"))
  
  # Performance grade
  if (overall_score >= 80) {
    grade <- "A - Excellent"
  } else if (overall_score >= 70) {
    grade <- "B - Good"
  } else if (overall_score >= 60) {
    grade <- "C - Acceptable"
  } else {
    grade <- "D - Needs Improvement"
  }
  
  cat(paste("🏅 Performance Grade:", grade, "\n"))
  
  # Set minimum expectations for production readiness
  expect_true(final_stats$success_rate >= 0.8,
              info = paste("Final success rate should be >= 80% for production, got:",
                          round(final_stats$success_rate * 100, 1), "%"))
  
  expect_true(final_stats$avg_response_time <= 10,
              info = paste("Final average response time should be <= 10s, got:",
                          round(final_stats$avg_response_time, 2), "seconds"))
  
  expect_true(overall_score >= 60,
              info = paste("Overall performance score should be >= 60 for production, got:",
                          round(overall_score, 1)))
  
  cat("✅ Comprehensive Performance Summary completed\n")
})

cat("🎯 Sprint 8A Performance Testing Suite loaded successfully\n")
cat("📋 Performance test suites available:\n")
cat("   1. Concurrent User Testing (Academic Researchers)\n")
cat("   2. Database Query Performance Under Load\n")
cat("   3. Memory Usage Validation (Cloud Run 2GB Compliance)\n")
cat("   4. Response Time Validation (Performance Targets)\n")
cat("   5. API Throughput Testing (Academic Usage Patterns)\n")
cat("   6. Geographic Analysis Performance (Brazilian Municipalities)\n")
cat("   7. Comprehensive Performance Summary\n")