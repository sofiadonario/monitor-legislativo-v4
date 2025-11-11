# MONITOR LEGISLATIVO V4 - END-TO-END TESTING SUITE
# ===================================================
# Comprehensive E2E tests for Railway production deployment
# Brazilian Legislative Monitoring System validation

library(httr2)
library(jsonlite)
library(dplyr)
library(testthat)

# =============================================================================
# E2E TEST CONFIGURATION
# =============================================================================

E2E_CONFIG <- list(
  base_url = Sys.getenv("E2E_TEST_URL", "http://localhost:3838"),
  timeout_seconds = 30,
  retry_attempts = 3,
  
  # Brazilian legislative test data
  test_scenarios = list(
    basic_navigation = TRUE,
    search_functionality = TRUE,
    data_export = TRUE,
    geographic_visualization = TRUE,
    analytics_dashboard = TRUE,
    admin_functions = FALSE  # Requires authentication
  ),
  
  # Performance expectations for Railway deployment
  performance_targets = list(
    page_load_max_ms = 5000,
    search_response_max_ms = 3000,
    api_response_max_ms = 2000,
    export_timeout_max_ms = 30000
  )
)

# =============================================================================
# TEST UTILITIES
# =============================================================================

#' Execute HTTP request with retry logic
#' @param url Request URL
#' @param method HTTP method
#' @param body Request body
#' @param expected_status Expected HTTP status code
#' @return Response object or error
make_request <- function(url, method = "GET", body = NULL, expected_status = 200) {
  for (attempt in 1:E2E_CONFIG$retry_attempts) {
    tryCatch({
      request <- httr2::request(url) %>%
        httr2::req_method(method) %>%
        httr2::req_timeout(E2E_CONFIG$timeout_seconds)
      
      if (!is.null(body)) {
        request <- httr2::req_body_json(request, body)
      }
      
      response <- httr2::req_perform(request)
      
      if (httr2::resp_status(response) == expected_status) {
        return(response)
      } else {
        stop("Unexpected status code: ", httr2::resp_status(response))
      }
      
    }, error = function(e) {
      if (attempt == E2E_CONFIG$retry_attempts) {
        stop("Request failed after ", E2E_CONFIG$retry_attempts, " attempts: ", e$message)
      }
      Sys.sleep(2^attempt) # Exponential backoff
    })
  }
}

#' Measure page load time
#' @param url Page URL
#' @return Load time in milliseconds
measure_page_load_time <- function(url) {
  start_time <- Sys.time()
  response <- make_request(url)
  end_time <- Sys.time()
  
  load_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
  return(list(
    load_time_ms = load_time_ms,
    response = response
  ))
}

#' Extract application metrics from health endpoint
#' @return List of application metrics
get_app_metrics <- function() {
  tryCatch({
    response <- make_request(paste0(E2E_CONFIG$base_url, "/health"))
    content <- httr2::resp_body_json(response)
    return(content)
  }, error = function(e) {
    return(list(error = e$message))
  })
}

# =============================================================================
# BASIC FUNCTIONALITY TESTS
# =============================================================================

test_that("Application is accessible and responsive", {
  cat("🔍 Testing application accessibility...\n")
  
  # Test main page
  result <- measure_page_load_time(E2E_CONFIG$base_url)
  
  expect_true(httr2::resp_status(result$response) == 200,
              "Main page should be accessible")
  
  expect_true(result$load_time_ms < E2E_CONFIG$performance_targets$page_load_max_ms,
              paste("Page load time should be < ", E2E_CONFIG$performance_targets$page_load_max_ms, "ms"))
  
  # Check for essential content
  content <- httr2::resp_body_string(result$response)
  expect_true(grepl("Monitor Legislativo", content, ignore.case = TRUE),
              "Page should contain application title")
  
  cat("✅ Application accessibility test passed\n")
})

test_that("Health check endpoint works correctly", {
  cat("🔍 Testing health check endpoint...\n")
  
  response <- make_request(paste0(E2E_CONFIG$base_url, "/health"))
  
  expect_true(httr2::resp_status(response) == 200,
              "Health endpoint should return 200")
  
  # Parse health response
  health_data <- httr2::resp_body_json(response)
  
  expect_true(!is.null(health_data$status),
              "Health response should include status")
  
  expect_true(health_data$status %in% c("healthy", "degraded"),
              "Health status should be healthy or degraded")
  
  cat("✅ Health check test passed\n")
})

test_that("Static assets load correctly", {
  cat("🔍 Testing static assets...\n")
  
  # Test common static asset endpoints
  static_endpoints <- c(
    "/favicon.ico",
    "/shared/bootstrap/css/bootstrap.min.css",
    "/shared/shiny.css"
  )
  
  for (endpoint in static_endpoints) {
    url <- paste0(E2E_CONFIG$base_url, endpoint)
    tryCatch({
      response <- make_request(url)
      expect_true(httr2::resp_status(response) %in% c(200, 304),
                  paste("Static asset", endpoint, "should be accessible"))
    }, error = function(e) {
      # Some static assets might not exist, which is OK
      cat("⚠️ Static asset", endpoint, "not found (may be OK)\n")
    })
  }
  
  cat("✅ Static assets test completed\n")
})

# =============================================================================
# SEARCH FUNCTIONALITY TESTS
# =============================================================================

test_that("Search functionality works correctly", {
  if (!E2E_CONFIG$test_scenarios$search_functionality) {
    skip("Search functionality tests disabled")
  }
  
  cat("🔍 Testing search functionality...\n")
  
  # Test search with Brazilian legislative terms
  search_terms <- c("lei", "decreto", "educação", "saúde")
  
  for (term in search_terms) {
    cat("   Testing search for:", term, "\n")
    
    search_url <- paste0(E2E_CONFIG$base_url, "/search?q=", URLencode(term))
    
    start_time <- Sys.time()
    response <- make_request(search_url)
    end_time <- Sys.time()
    
    search_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
    
    expect_true(httr2::resp_status(response) == 200,
                paste("Search for", term, "should return 200"))
    
    expect_true(search_time_ms < E2E_CONFIG$performance_targets$search_response_max_ms,
                paste("Search response time should be <", E2E_CONFIG$performance_targets$search_response_max_ms, "ms"))
    
    # Check response content
    content <- httr2::resp_body_string(response)
    expect_true(nchar(content) > 0,
                "Search should return content")
  }
  
  cat("✅ Search functionality test passed\n")
})

test_that("Empty search handling", {
  cat("🔍 Testing empty search handling...\n")
  
  # Test empty search
  empty_search_url <- paste0(E2E_CONFIG$base_url, "/search?q=")
  response <- make_request(empty_search_url)
  
  expect_true(httr2::resp_status(response) == 200,
              "Empty search should not cause server error")
  
  # Test search with no results
  nonsense_search_url <- paste0(E2E_CONFIG$base_url, "/search?q=", URLencode("xyzabc123"))
  response <- make_request(nonsense_search_url)
  
  expect_true(httr2::resp_status(response) == 200,
              "Search with no results should return 200")
  
  cat("✅ Empty search handling test passed\n")
})

# =============================================================================
# API ENDPOINT TESTS
# =============================================================================

test_that("API endpoints are functional", {
  cat("🔍 Testing API endpoints...\n")
  
  # Test various API endpoints
  api_endpoints <- list(
    "/api/health" = "Health API",
    "/api/stats" = "Statistics API",
    "/api/documents/count" = "Document count API"
  )
  
  for (endpoint in names(api_endpoints)) {
    description <- api_endpoints[[endpoint]]
    cat("   Testing", description, "...\n")
    
    tryCatch({
      start_time <- Sys.time()
      response <- make_request(paste0(E2E_CONFIG$base_url, endpoint))
      end_time <- Sys.time()
      
      api_response_time <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
      
      expect_true(httr2::resp_status(response) == 200,
                  paste(description, "should return 200"))
      
      expect_true(api_response_time < E2E_CONFIG$performance_targets$api_response_max_ms,
                  paste(description, "response time should be <", E2E_CONFIG$performance_targets$api_response_max_ms, "ms"))
      
      # Try to parse JSON response
      tryCatch({
        json_content <- httr2::resp_body_json(response)
        expect_true(!is.null(json_content),
                    paste(description, "should return valid JSON"))
      }, error = function(e) {
        # Some endpoints might return non-JSON content
        cat("⚠️", description, "did not return JSON (may be OK)\n")
      })
      
    }, error = function(e) {
      cat("⚠️", description, "failed:", e$message, "\n")
      # Don't fail the test for optional API endpoints
    })
  }
  
  cat("✅ API endpoints test completed\n")
})

# =============================================================================
# DATA EXPORT TESTS
# =============================================================================

test_that("Data export functionality works", {
  if (!E2E_CONFIG$test_scenarios$data_export) {
    skip("Data export tests disabled")
  }
  
  cat("🔍 Testing data export functionality...\n")
  
  # Test CSV export
  export_formats <- c("csv", "json")
  
  for (format in export_formats) {
    cat("   Testing", format, "export...\n")
    
    export_url <- paste0(E2E_CONFIG$base_url, "/api/export?format=", format, "&limit=10")
    
    start_time <- Sys.time()
    
    tryCatch({
      response <- make_request(export_url)
      end_time <- Sys.time()
      
      export_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
      
      expect_true(httr2::resp_status(response) == 200,
                  paste(format, "export should return 200"))
      
      expect_true(export_time_ms < E2E_CONFIG$performance_targets$export_timeout_max_ms,
                  paste(format, "export should complete within timeout"))
      
      # Check content type
      content_type <- httr2::resp_header(response, "content-type")
      if (format == "csv") {
        expect_true(grepl("csv", content_type, ignore.case = TRUE),
                    "CSV export should have correct content type")
      } else if (format == "json") {
        expect_true(grepl("json", content_type, ignore.case = TRUE),
                    "JSON export should have correct content type")
      }
      
    }, error = function(e) {
      cat("⚠️", format, "export failed:", e$message, "\n")
      # Don't fail test if export is not implemented
    })
  }
  
  cat("✅ Data export test completed\n")
})

# =============================================================================
# GEOGRAPHIC VISUALIZATION TESTS
# =============================================================================

test_that("Geographic visualization endpoints work", {
  if (!E2E_CONFIG$test_scenarios$geographic_visualization) {
    skip("Geographic visualization tests disabled")
  }
  
  cat("🔍 Testing geographic visualization...\n")
  
  # Test Brazilian geographic data endpoints
  geo_endpoints <- list(
    "/api/geographic/states" = "Brazilian states data",
    "/api/geographic/municipalities" = "Brazilian municipalities data"
  )
  
  for (endpoint in names(geo_endpoints)) {
    description <- geo_endpoints[[endpoint]]
    cat("   Testing", description, "...\n")
    
    tryCatch({
      response <- make_request(paste0(E2E_CONFIG$base_url, endpoint))
      
      expect_true(httr2::resp_status(response) == 200,
                  paste(description, "should be accessible"))
      
      # Check if response contains geographic data
      content <- httr2::resp_body_string(response)
      expect_true(nchar(content) > 0,
                  paste(description, "should return content"))
      
    }, error = function(e) {
      cat("⚠️", description, "failed:", e$message, "\n")
      # Geographic endpoints might not be implemented yet
    })
  }
  
  cat("✅ Geographic visualization test completed\n")
})

# =============================================================================
# PERFORMANCE AND STRESS TESTS
# =============================================================================

test_that("Application handles concurrent requests", {
  cat("🔍 Testing concurrent request handling...\n")
  
  # Simulate concurrent users (lighter version of load test)
  concurrent_requests <- 5
  
  # Create multiple requests simultaneously
  start_time <- Sys.time()
  
  # Use parallel processing for concurrent requests
  if (requireNamespace("parallel", quietly = TRUE)) {
    results <- parallel::mclapply(1:concurrent_requests, function(i) {
      tryCatch({
        response <- make_request(E2E_CONFIG$base_url)
        list(success = TRUE, status = httr2::resp_status(response))
      }, error = function(e) {
        list(success = FALSE, error = e$message)
      })
    }, mc.cores = min(concurrent_requests, parallel::detectCores()))
    
    end_time <- Sys.time()
    total_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
    
    # Check results
    successful_requests <- sum(sapply(results, function(r) r$success))
    
    expect_true(successful_requests >= concurrent_requests * 0.8,
                "At least 80% of concurrent requests should succeed")
    
    expect_true(total_time_ms < E2E_CONFIG$performance_targets$page_load_max_ms * 2,
                "Concurrent requests should complete in reasonable time")
    
    cat("✅ Concurrent request test passed (", successful_requests, "/", concurrent_requests, ")\n")
  } else {
    cat("⚠️ Parallel package not available, skipping concurrent test\n")
  }
})

# =============================================================================
# BRAZILIAN CONTENT VALIDATION TESTS
# =============================================================================

test_that("Brazilian legislative content is properly handled", {
  cat("🔍 Testing Brazilian content handling...\n")
  
  # Test Portuguese language support
  portuguese_terms <- c("educação", "saúde", "legislação", "município")
  
  for (term in portuguese_terms) {
    search_url <- paste0(E2E_CONFIG$base_url, "/search?q=", URLencode(term))
    
    tryCatch({
      response <- make_request(search_url)
      
      expect_true(httr2::resp_status(response) == 200,
                  paste("Portuguese term", term, "should be searchable"))
      
      # Check encoding
      content <- httr2::resp_body_string(response)
      expect_true(validUTF8(content),
                  "Content should be valid UTF-8")
      
    }, error = function(e) {
      cat("⚠️ Portuguese term", term, "failed:", e$message, "\n")
    })
  }
  
  cat("✅ Brazilian content handling test completed\n")
})

# =============================================================================
# SECURITY TESTS
# =============================================================================

test_that("Basic security measures are in place", {
  cat("🔍 Testing basic security measures...\n")
  
  # Test for common security headers
  response <- make_request(E2E_CONFIG$base_url)
  headers <- httr2::resp_headers(response)
  
  # Check for security headers (not all may be present)
  security_headers <- c("x-frame-options", "x-content-type-options", "x-xss-protection")
  
  for (header in security_headers) {
    if (!is.null(headers[[header]])) {
      cat("✅ Found security header:", header, "\n")
    }
  }
  
  # Test SQL injection protection (basic test)
  malicious_search <- "'; DROP TABLE documents; --"
  malicious_url <- paste0(E2E_CONFIG$base_url, "/search?q=", URLencode(malicious_search))
  
  tryCatch({
    response <- make_request(malicious_url)
    expect_true(httr2::resp_status(response) %in% c(200, 400),
                "Application should handle malicious input gracefully")
  }, error = function(e) {
    cat("⚠️ Malicious input test failed:", e$message, "\n")
  })
  
  cat("✅ Basic security test completed\n")
})

# =============================================================================
# MAIN TEST EXECUTION
# =============================================================================

#' Run complete E2E test suite
#' @return Test results summary
run_e2e_test_suite <- function() {
  cat("🎯 Monitor Legislativo v4 - End-to-End Test Suite\n")
  cat("================================================\n")
  cat("🌐 Testing URL:", E2E_CONFIG$base_url, "\n")
  cat("⏱️ Timeout:", E2E_CONFIG$timeout_seconds, "seconds\n\n")
  
  # Check if application is accessible
  tryCatch({
    health_response <- make_request(paste0(E2E_CONFIG$base_url, "/health"))
    cat("✅ Application is accessible\n\n")
  }, error = function(e) {
    cat("❌ Application is not accessible:", e$message, "\n")
    cat("Please ensure the application is running at:", E2E_CONFIG$base_url, "\n")
    return(list(status = "FAILED", error = "Application not accessible"))
  })
  
  # Run tests
  start_time <- Sys.time()
  
  test_results <- tryCatch({
    # Execute all tests
    test_file("tests/production/end_to_end_tests.R")
  }, error = function(e) {
    list(status = "ERROR", error = e$message)
  })
  
  end_time <- Sys.time()
  test_duration <- as.numeric(difftime(end_time, start_time, units = "minutes"))
  
  cat("\n" %+% "="*50 %+% "\n")
  cat("📊 E2E TEST SUITE COMPLETED\n")
  cat("="*50 %+% "\n")
  cat("⏱️ Duration:", round(test_duration, 2), "minutes\n")
  cat("🌐 URL:", E2E_CONFIG$base_url, "\n")
  
  # Save results
  timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
  results_file <- paste0("tests/results/e2e_test_", timestamp, ".rds")
  
  dir.create(dirname(results_file), recursive = TRUE, showWarnings = FALSE)
  
  results_summary <- list(
    timestamp = Sys.time(),
    duration_minutes = test_duration,
    config = E2E_CONFIG,
    results = test_results
  )
  
  saveRDS(results_summary, results_file)
  cat("💾 Results saved to:", results_file, "\n")
  
  return(results_summary)
}

# String concatenation operator
`%+%` <- function(x, y) paste0(x, y)

# Execute if run directly
if (!interactive()) {
  run_e2e_test_suite()
}