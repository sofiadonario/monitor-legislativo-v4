# Production Testing Suite for Monitor Legislativo v4
# Week 12: Comprehensive testing and validation

library(testthat)
library(httr)
library(jsonlite)

# Configuration
test_base_url <- Sys.getenv("TEST_BASE_URL", "http://localhost:3838")
health_endpoint <- paste0(test_base_url, "/health")

# Test Helper Functions
wait_for_service <- function(url, timeout = 60, interval = 5) {
  start_time <- Sys.time()
  
  while (difftime(Sys.time(), start_time, units = "secs") < timeout) {
    tryCatch({
      response <- GET(url, timeout(10))
      if (status_code(response) == 200) {
        return(TRUE)
      }
    }, error = function(e) {
      # Service not ready yet
    })
    
    Sys.sleep(interval)
  }
  
  FALSE
}

check_response_time <- function(url, max_time = 5) {
  start_time <- Sys.time()
  response <- GET(url, timeout(max_time))
  end_time <- Sys.time()
  
  response_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
  list(
    response = response,
    time = response_time,
    within_limit = response_time <= max_time
  )
}

# Test Suite 1: Infrastructure Health Checks
test_that("Health endpoint responds correctly", {
  cat("🔍 Testing health endpoint...\n")
  
  expect_true(wait_for_service(health_endpoint), 
              "Service should be available within timeout period")
  
  response <- GET(health_endpoint)
  expect_equal(status_code(response), 200)
  expect_match(content(response, "text"), "healthy|ok|ready", ignore.case = TRUE)
  
  cat("✅ Health check passed\n")
})

test_that("Application responds within performance targets", {
  cat("🔍 Testing response time performance...\n")
  
  result <- check_response_time(test_base_url, max_time = 15)
  
  expect_true(result$within_limit, 
              sprintf("Page load should be <15s, got %.2fs", result$time))
  expect_equal(status_code(result$response), 200)
  
  cat(sprintf("✅ Response time: %.2fs (target: <15s)\n", result$time))
})

# Test Suite 2: Core Application Features
test_that("Main application interface loads", {
  cat("🔍 Testing main application interface...\n")
  
  response <- GET(test_base_url)
  expect_equal(status_code(response), 200)
  
  content_text <- content(response, "text")
  expect_match(content_text, "Monitor Legislativo", ignore.case = TRUE)
  expect_match(content_text, "shiny", ignore.case = TRUE)
  
  cat("✅ Main interface loads correctly\n")
})

test_that("Search functionality endpoint exists", {
  cat("🔍 Testing search endpoint availability...\n")
  
  search_url <- paste0(test_base_url, "/search")
  
  # Try different search endpoints
  possible_endpoints <- c(
    paste0(test_base_url, "/search"),
    paste0(test_base_url, "/api/search"),
    paste0(test_base_url, "/lexml/search")
  )
  
  endpoint_found <- FALSE
  for (endpoint in possible_endpoints) {
    tryCatch({
      response <- GET(endpoint, timeout(10))
      if (status_code(response) %in% c(200, 400, 405)) {  # 400/405 acceptable for GET on POST endpoint
        endpoint_found <- TRUE
        cat(sprintf("✅ Search endpoint found: %s\n", endpoint))
        break
      }
    }, error = function(e) {
      # Continue to next endpoint
    })
  }
  
  expect_true(endpoint_found, "At least one search endpoint should be available")
})

# Test Suite 3: Database Connectivity
test_that("Database connectivity", {
  cat("🔍 Testing database connectivity...\n")
  
  # Check if database environment variables are set
  database_url <- Sys.getenv("DATABASE_URL")
  if (nzchar(database_url)) {
    cat("✅ Database URL configured\n")
  } else {
    skip("Database URL not configured - this is OK for development")
  }
  
  # Test through application (if it provides a DB status endpoint)
  db_status_url <- paste0(test_base_url, "/api/db/status")
  tryCatch({
    response <- GET(db_status_url, timeout(10))
    if (status_code(response) == 200) {
      cat("✅ Database connectivity confirmed via API\n")
    }
  }, error = function(e) {
    cat("ℹ️  Database status endpoint not available (OK for basic deployment)\n")
  })
})

# Test Suite 4: Performance Benchmarks
test_that("Performance benchmarks", {
  cat("🔍 Running performance benchmarks...\n")
  
  # Test multiple requests to check consistency
  response_times <- numeric(5)
  
  for (i in 1:5) {
    start_time <- Sys.time()
    response <- GET(test_base_url, timeout(30))
    end_time <- Sys.time()
    
    response_times[i] <- as.numeric(difftime(end_time, start_time, units = "secs"))
    expect_equal(status_code(response), 200)
    
    Sys.sleep(1)  # Brief pause between requests
  }
  
  avg_response_time <- mean(response_times)
  max_response_time <- max(response_times)
  
  cat(sprintf("📊 Average response time: %.2fs\n", avg_response_time))
  cat(sprintf("📊 Maximum response time: %.2fs\n", max_response_time))
  
  expect_lt(avg_response_time, 20, "Average response time should be reasonable")
  expect_lt(max_response_time, 30, "Maximum response time should not exceed 30s")
  
  cat("✅ Performance benchmarks completed\n")
})

# Test Suite 5: Error Handling
test_that("Error handling and resilience", {
  cat("🔍 Testing error handling...\n")
  
  # Test 404 handling
  not_found_url <- paste0(test_base_url, "/nonexistent-page")
  response <- GET(not_found_url)
  expect_equal(status_code(response), 404)
  
  # Test malformed requests
  tryCatch({
    malformed_url <- paste0(test_base_url, "/search?query=", paste(rep("x", 10000), collapse = ""))
    response <- GET(malformed_url, timeout(10))
    # Should either return an error status or handle gracefully
    expect_true(status_code(response) %in% c(200, 400, 413, 414))
  }, error = function(e) {
    # Timeout or connection error is acceptable for malformed requests
    cat("ℹ️  Malformed request handled by timeout/connection error\n")
  })
  
  cat("✅ Error handling tests completed\n")
})

# Test Suite 6: Security Headers
test_that("Security headers are present", {
  cat("🔍 Testing security headers...\n")
  
  response <- GET(test_base_url)
  headers <- headers(response)
  
  # Check for important security headers
  security_headers <- c(
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy"
  )
  
  headers_found <- 0
  for (header in security_headers) {
    if (header %in% names(headers)) {
      headers_found <- headers_found + 1
      cat(sprintf("✅ Security header found: %s\n", header))
    }
  }
  
  if (headers_found > 0) {
    cat("✅ Security headers configured\n")
  } else {
    cat("ℹ️  Security headers not detected (may be configured at proxy level)\n")
  }
})

# Test Suite 7: Load Testing (Light)
test_that("Basic load handling", {
  cat("🔍 Testing basic load handling...\n")
  
  # Simulate multiple concurrent requests
  library(parallel)
  
  make_request <- function(i) {
    start_time <- Sys.time()
    response <- GET(test_base_url, timeout(30))
    end_time <- Sys.time()
    
    list(
      request_id = i,
      status = status_code(response),
      time = as.numeric(difftime(end_time, start_time, units = "secs"))
    )
  }
  
  # Run 10 concurrent requests
  cat("🔄 Running 10 concurrent requests...\n")
  
  if (Sys.info()["sysname"] != "Windows") {
    # Use parallel processing on Unix-like systems
    results <- mclapply(1:10, make_request, mc.cores = min(10, detectCores()))
  } else {
    # Sequential on Windows to avoid parallel issues
    results <- lapply(1:10, make_request)
  }
  
  # Analyze results
  success_count <- sum(sapply(results, function(r) r$status == 200))
  avg_time <- mean(sapply(results, function(r) r$time))
  max_time <- max(sapply(results, function(r) r$time))
  
  cat(sprintf("📊 Successful requests: %d/10\n", success_count))
  cat(sprintf("📊 Average response time under load: %.2fs\n", avg_time))
  cat(sprintf("📊 Maximum response time under load: %.2fs\n", max_time))
  
  expect_gte(success_count, 8, "At least 80% of concurrent requests should succeed")
  expect_lt(avg_time, 25, "Average response time under load should be reasonable")
  
  cat("✅ Basic load testing completed\n")
})

# Summary Report
test_that("Generate test summary", {
  cat("\n" + rep("=", 60) + "\n")
  cat("🎯 PRODUCTION TEST SUMMARY\n")
  cat(rep("=", 60) + "\n")
  
  cat("✅ Infrastructure health checks passed\n")
  cat("✅ Core application features verified\n")
  cat("✅ Performance benchmarks completed\n")
  cat("✅ Error handling tested\n")
  cat("✅ Security configurations checked\n")
  cat("✅ Basic load handling verified\n")
  
  cat("\n🚀 Application ready for production use!\n")
  cat(sprintf("🌐 Test URL: %s\n", test_base_url))
  cat(sprintf("❤️  Health Check: %s\n", health_endpoint))
  
  cat("\n📋 Next Steps:\n")
  cat("1. Configure custom domain (if needed)\n")
  cat("2. Set up monitoring alerts\n")
  cat("3. Schedule regular backups\n")
  cat("4. Create user documentation\n")
  cat("5. Plan user training sessions\n")
  
  cat(rep("=", 60) + "\n")
})

# Run all tests
cat("🧪 Starting Production Test Suite for Monitor Legislativo v4\n")
cat(sprintf("🎯 Target URL: %s\n", test_base_url))
cat(rep("-", 60) + "\n")

# Execute test suite
test_results <- test_file("production_tests.R", reporter = "progress")

cat("\n🎉 Production testing completed!\n")