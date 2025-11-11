# MONITOR LEGISLATIVO V4 - PRODUCTION LOAD TESTING SUITE
# =======================================================
# Comprehensive load testing for Railway deployment
# Brazilian Legislative Monitoring System - Academic Institution Focus

library(httr2)
library(parallel)
library(dplyr)
library(lubridate)
library(jsonlite)

# =============================================================================
# LOAD TESTING CONFIGURATION
# =============================================================================

#' Load testing configuration for Brazilian academic context
LOAD_TEST_CONFIG <- list(
  # Base URL (Railway production or staging)
  base_url = Sys.getenv("LOAD_TEST_URL", "http://localhost:3838"),
  
  # Academic usage patterns (peak hours: 9-11 AM, 2-4 PM)
  concurrent_users = as.numeric(Sys.getenv("LOAD_TEST_USERS", "50")),
  test_duration_minutes = as.numeric(Sys.getenv("LOAD_TEST_DURATION", "10")),
  ramp_up_seconds = as.numeric(Sys.getenv("LOAD_TEST_RAMP_UP", "30")),
  
  # Brazilian academic scenarios
  scenarios = list(
    browse_dashboard = 0.4,      # 40% - Main dashboard viewing
    search_legislation = 0.3,    # 30% - Legislative search
    view_analytics = 0.15,       # 15% - Analytics viewing
    export_data = 0.1,           # 10% - Data export
    admin_functions = 0.05       # 5%  - Admin operations
  ),
  
  # Performance thresholds for Railway 3GB limit
  thresholds = list(
    max_response_time_ms = 3000,
    acceptable_error_rate = 0.05,  # 5%
    min_throughput_rps = 10,       # Requests per second
    max_memory_usage_mb = 2500     # Railway memory limit consideration
  )
)

# =============================================================================
# LOAD TESTING FUNCTIONS
# =============================================================================

#' Execute HTTP request with timing and error handling
#' @param url Request URL
#' @param method HTTP method (GET, POST, etc.)
#' @param headers Request headers
#' @param body Request body (for POST requests)
#' @return List with response details and timing
execute_request <- function(url, method = "GET", headers = list(), body = NULL) {
  start_time <- Sys.time()
  
  result <- list(
    url = url,
    method = method,
    timestamp = start_time,
    success = FALSE,
    status_code = 0,
    response_time_ms = 0,
    error = NULL,
    response_size = 0
  )
  
  tryCatch({
    request <- httr2::request(url) %>%
      httr2::req_method(method) %>%
      httr2::req_timeout(30)
    
    # Add headers
    if (length(headers) > 0) {
      request <- httr2::req_headers(request, !!!headers)
    }
    
    # Add body for POST requests
    if (!is.null(body)) {
      request <- httr2::req_body_json(request, body)
    }
    
    # Execute request
    response <- httr2::req_perform(request)
    
    # Calculate metrics
    end_time <- Sys.time()
    result$response_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
    result$status_code <- httr2::resp_status(response)
    result$success <- result$status_code >= 200 && result$status_code < 400
    result$response_size <- length(httr2::resp_body_raw(response))
    
  }, error = function(e) {
    end_time <- Sys.time()
    result$response_time_ms <<- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
    result$error <<- e$message
  })
  
  return(result)
}

#' Simulate user browsing dashboard
simulate_browse_dashboard <- function(user_id, base_url) {
  results <- list()
  
  # Main dashboard
  results[[1]] <- execute_request(paste0(base_url, "/"))
  
  # Health check
  results[[2]] <- execute_request(paste0(base_url, "/health"))
  
  # Dashboard refresh (simulate auto-refresh)
  Sys.sleep(runif(1, 2, 5))
  results[[3]] <- execute_request(paste0(base_url, "/"))
  
  return(results)
}

#' Simulate legislative search
simulate_search_legislation <- function(user_id, base_url) {
  results <- list()
  
  # Search terms relevant to Brazilian legislation
  search_terms <- c("lei", "decreto", "resolução", "portaria", "educação", "saúde")
  term <- sample(search_terms, 1)
  
  # Search request
  search_url <- paste0(base_url, "/search?q=", URLencode(term))
  results[[1]] <- execute_request(search_url)
  
  # View search results (simulate clicking through results)
  Sys.sleep(runif(1, 1, 3))
  results[[2]] <- execute_request(paste0(base_url, "/document/", sample(1:1000, 1)))
  
  return(results)
}

#' Simulate analytics viewing
simulate_view_analytics <- function(user_id, base_url) {
  results <- list()
  
  # Analytics dashboard
  results[[1]] <- execute_request(paste0(base_url, "/analytics"))
  
  # Geographic visualization (Brazilian states)
  results[[2]] <- execute_request(paste0(base_url, "/api/geographic/states"))
  
  # Temporal analysis
  results[[3]] <- execute_request(paste0(base_url, "/api/analytics/temporal"))
  
  return(results)
}

#' Simulate data export
simulate_export_data <- function(user_id, base_url) {
  results <- list()
  
  # Export request
  export_params <- list(
    format = sample(c("csv", "json"), 1),
    limit = sample(c(100, 500, 1000), 1)
  )
  
  export_url <- paste0(base_url, "/api/export?format=", export_params$format, 
                      "&limit=", export_params$limit)
  results[[1]] <- execute_request(export_url)
  
  return(results)
}

#' Simulate admin functions
simulate_admin_functions <- function(user_id, base_url) {
  results <- list()
  
  # System status
  results[[1]] <- execute_request(paste0(base_url, "/admin/status"))
  
  # Metrics endpoint
  results[[2]] <- execute_request(paste0(base_url, "/admin/metrics"))
  
  return(results)
}

#' Run load test scenario for single user
run_user_scenario <- function(user_id, test_duration_minutes, base_url) {
  user_results <- list()
  start_time <- Sys.time()
  end_time <- start_time + minutes(test_duration_minutes)
  
  cat("👤 User", user_id, "starting load test session\n")
  
  while (Sys.time() < end_time) {
    # Select scenario based on probability distribution
    scenario_prob <- runif(1)
    scenario_results <- list()
    
    if (scenario_prob <= LOAD_TEST_CONFIG$scenarios$browse_dashboard) {
      scenario_results <- simulate_browse_dashboard(user_id, base_url)
    } else if (scenario_prob <= sum(LOAD_TEST_CONFIG$scenarios$browse_dashboard, 
                                   LOAD_TEST_CONFIG$scenarios$search_legislation)) {
      scenario_results <- simulate_search_legislation(user_id, base_url)
    } else if (scenario_prob <= sum(LOAD_TEST_CONFIG$scenarios$browse_dashboard,
                                   LOAD_TEST_CONFIG$scenarios$search_legislation,
                                   LOAD_TEST_CONFIG$scenarios$view_analytics)) {
      scenario_results <- simulate_view_analytics(user_id, base_url)
    } else if (scenario_prob <= sum(LOAD_TEST_CONFIG$scenarios$browse_dashboard,
                                   LOAD_TEST_CONFIG$scenarios$search_legislation,
                                   LOAD_TEST_CONFIG$scenarios$view_analytics,
                                   LOAD_TEST_CONFIG$scenarios$export_data)) {
      scenario_results <- simulate_export_data(user_id, base_url)
    } else {
      scenario_results <- simulate_admin_functions(user_id, base_url)
    }
    
    # Add user ID to each result
    scenario_results <- lapply(scenario_results, function(r) {
      r$user_id <- user_id
      return(r)
    })
    
    user_results <- append(user_results, scenario_results)
    
    # Random think time between requests (1-10 seconds)
    think_time <- runif(1, 1, 10)
    Sys.sleep(think_time)
  }
  
  cat("✅ User", user_id, "completed", length(user_results), "requests\n")
  return(user_results)
}

# =============================================================================
# LOAD TEST EXECUTION
# =============================================================================

#' Execute comprehensive load test
#' @param config Load test configuration (uses LOAD_TEST_CONFIG if NULL)
#' @return List with test results and metrics
execute_load_test <- function(config = NULL) {
  if (is.null(config)) {
    config <- LOAD_TEST_CONFIG
  }
  
  cat("🚀 Starting load test for Monitor Legislativo v4\n")
  cat("📊 Configuration:\n")
  cat("   - URL:", config$base_url, "\n")
  cat("   - Users:", config$concurrent_users, "\n")
  cat("   - Duration:", config$test_duration_minutes, "minutes\n")
  cat("   - Ramp-up:", config$ramp_up_seconds, "seconds\n")
  
  # Test connectivity first
  cat("🔍 Testing connectivity...\n")
  health_check <- execute_request(paste0(config$base_url, "/health"))
  if (!health_check$success) {
    stop("❌ Application not accessible at ", config$base_url)
  }
  cat("✅ Application accessible\n")
  
  test_start_time <- Sys.time()
  
  # Create user processes with ramp-up
  cat("👥 Starting", config$concurrent_users, "concurrent users...\n")
  
  # Calculate ramp-up delay between users
  ramp_delay <- config$ramp_up_seconds / config$concurrent_users
  
  # Use parallel processing for concurrent users
  cl <- makeCluster(min(config$concurrent_users, detectCores()))
  clusterEvalQ(cl, {
    library(httr2)
    library(lubridate)
  })
  
  # Export functions and variables to cluster
  clusterExport(cl, c("run_user_scenario", "execute_request", 
                      "simulate_browse_dashboard", "simulate_search_legislation",
                      "simulate_view_analytics", "simulate_export_data",
                      "simulate_admin_functions", "LOAD_TEST_CONFIG"))
  
  # Start users with ramp-up
  all_results <- list()
  for (user_batch in split(1:config$concurrent_users, ceiling(1:config$concurrent_users / 10))) {
    # Start batch of users
    batch_results <- parLapply(cl, user_batch, function(user_id) {
      # Ramp-up delay
      Sys.sleep((user_id - 1) * ramp_delay)
      
      run_user_scenario(user_id, config$test_duration_minutes, config$base_url)
    })
    
    all_results <- append(all_results, batch_results)
    
    # Small delay between batches to avoid overwhelming the system
    Sys.sleep(5)
  }
  
  stopCluster(cl)
  
  test_end_time <- Sys.time()
  
  cat("⏱️ Load test completed in", 
      round(as.numeric(difftime(test_end_time, test_start_time, units = "minutes")), 2), 
      "minutes\n")
  
  # Flatten results
  flat_results <- unlist(all_results, recursive = FALSE)
  
  # Generate test report
  report <- generate_load_test_report(flat_results, config, test_start_time, test_end_time)
  
  return(list(
    results = flat_results,
    report = report,
    config = config
  ))
}

# =============================================================================
# REPORTING AND ANALYSIS
# =============================================================================

#' Generate comprehensive load test report
#' @param results List of all request results
#' @param config Load test configuration
#' @param start_time Test start time
#' @param end_time Test end time
#' @return Detailed test report
generate_load_test_report <- function(results, config, start_time, end_time) {
  cat("📊 Generating load test report...\n")
  
  # Convert results to data frame for analysis
  results_df <- do.call(rbind, lapply(results, function(r) {
    data.frame(
      user_id = r$user_id %||% 0,
      url = r$url %||% "",
      method = r$method %||% "GET",
      timestamp = as.POSIXct(r$timestamp %||% Sys.time()),
      success = r$success %||% FALSE,
      status_code = r$status_code %||% 0,
      response_time_ms = r$response_time_ms %||% 0,
      response_size = r$response_size %||% 0,
      error = r$error %||% "",
      stringsAsFactors = FALSE
    )
  }))
  
  # Calculate metrics
  total_requests <- nrow(results_df)
  successful_requests <- sum(results_df$success)
  failed_requests <- total_requests - successful_requests
  error_rate <- failed_requests / total_requests
  
  # Response time statistics
  response_times <- results_df$response_time_ms[results_df$success]
  avg_response_time <- mean(response_times, na.rm = TRUE)
  median_response_time <- median(response_times, na.rm = TRUE)
  p95_response_time <- quantile(response_times, 0.95, na.rm = TRUE)
  p99_response_time <- quantile(response_times, 0.99, na.rm = TRUE)
  
  # Throughput calculation
  test_duration_seconds <- as.numeric(difftime(end_time, start_time, units = "secs"))
  throughput_rps <- total_requests / test_duration_seconds
  
  # Performance assessment
  performance_assessment <- list(
    response_time_pass = avg_response_time <= config$thresholds$max_response_time_ms,
    error_rate_pass = error_rate <= config$thresholds$acceptable_error_rate,
    throughput_pass = throughput_rps >= config$thresholds$min_throughput_rps
  )
  
  overall_pass <- all(unlist(performance_assessment))
  
  # Create report
  report <- list(
    summary = list(
      test_duration_minutes = round(test_duration_seconds / 60, 2),
      concurrent_users = config$concurrent_users,
      total_requests = total_requests,
      successful_requests = successful_requests,
      failed_requests = failed_requests,
      error_rate_percent = round(error_rate * 100, 2),
      throughput_rps = round(throughput_rps, 2)
    ),
    
    response_times = list(
      average_ms = round(avg_response_time, 2),
      median_ms = round(median_response_time, 2),
      p95_ms = round(p95_response_time, 2),
      p99_ms = round(p99_response_time, 2)
    ),
    
    performance_assessment = performance_assessment,
    overall_pass = overall_pass,
    
    # Status code distribution
    status_codes = table(results_df$status_code),
    
    # Error analysis
    errors = if (failed_requests > 0) {
      table(results_df$error[results_df$error != ""])
    } else {
      "No errors"
    },
    
    # URL performance breakdown
    url_performance = results_df %>%
      group_by(url) %>%
      summarise(
        requests = n(),
        success_rate = mean(success),
        avg_response_time = mean(response_time_ms[success], na.rm = TRUE),
        .groups = "drop"
      ) %>%
      arrange(desc(requests)),
    
    # Recommendations
    recommendations = generate_recommendations(error_rate, avg_response_time, throughput_rps, config)
  )
  
  # Print summary
  cat("\n" %+% "="*50 %+% "\n")
  cat("📈 LOAD TEST REPORT SUMMARY\n")
  cat("="*50 %+% "\n")
  cat("🎯 Overall Result:", if (overall_pass) "✅ PASS" else "❌ FAIL", "\n")
  cat("📊 Total Requests:", total_requests, "\n")
  cat("✅ Successful:", successful_requests, "(", round((1-error_rate)*100, 1), "%)\n")
  cat("❌ Failed:", failed_requests, "(", round(error_rate*100, 1), "%)\n")
  cat("⚡ Throughput:", round(throughput_rps, 2), "RPS\n")
  cat("⏱️ Avg Response Time:", round(avg_response_time, 2), "ms\n")
  cat("🎯 95th Percentile:", round(p95_response_time, 2), "ms\n")
  cat("="*50 %+% "\n")
  
  return(report)
}

#' Generate recommendations based on test results
generate_recommendations <- function(error_rate, avg_response_time, throughput_rps, config) {
  recommendations <- list()
  
  if (error_rate > config$thresholds$acceptable_error_rate) {
    recommendations <- append(recommendations, 
      paste("❌ High error rate (", round(error_rate*100, 1), 
            "%) - Check application logs and database connectivity"))
  }
  
  if (avg_response_time > config$thresholds$max_response_time_ms) {
    recommendations <- append(recommendations,
      paste("⏱️ Slow response times (", round(avg_response_time), 
            "ms) - Consider optimizing queries and adding caching"))
  }
  
  if (throughput_rps < config$thresholds$min_throughput_rps) {
    recommendations <- append(recommendations,
      paste("📉 Low throughput (", round(throughput_rps, 2), 
            "RPS) - Consider scaling Railway resources or optimizing code"))
  }
  
  # Railway-specific recommendations
  recommendations <- append(recommendations, 
    "🚂 Railway Optimization: Monitor memory usage and consider upgrading if consistently > 80%")
  
  recommendations <- append(recommendations,
    "🔍 Brazilian Academic Context: Peak usage 9-11 AM and 2-4 PM - schedule maintenance outside these hours")
  
  if (length(recommendations) == 0) {
    recommendations <- append(recommendations, "✅ Performance within acceptable thresholds")
  }
  
  return(recommendations)
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# String concatenation operator
`%+%` <- function(x, y) paste0(x, y)

# Null coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x

# =============================================================================
# MAIN EXECUTION
# =============================================================================

#' Run complete load test suite
run_load_test_suite <- function() {
  cat("🎯 Monitor Legislativo v4 - Load Test Suite\n")
  cat("==========================================\n")
  
  # Run load test
  test_results <- execute_load_test()
  
  # Save results
  timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
  results_file <- paste0("tests/results/load_test_", timestamp, ".rds")
  
  dir.create(dirname(results_file), recursive = TRUE, showWarnings = FALSE)
  saveRDS(test_results, results_file)
  
  # Save JSON report for CI/CD
  json_report_file <- paste0("tests/results/load_test_report_", timestamp, ".json")
  writeLines(toJSON(test_results$report, auto_unbox = TRUE, pretty = TRUE), json_report_file)
  
  cat("💾 Results saved to:", results_file, "\n")
  cat("📄 JSON report saved to:", json_report_file, "\n")
  
  # Return overall pass/fail for CI/CD
  if (test_results$report$overall_pass) {
    cat("🎉 Load test PASSED!\n")
    return(0)
  } else {
    cat("💥 Load test FAILED!\n")
    return(1)
  }
}

# Execute if run directly
if (!interactive()) {
  quit(status = run_load_test_suite())
}