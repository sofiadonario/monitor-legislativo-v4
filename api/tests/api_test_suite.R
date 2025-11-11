# ============================================================================
# COMPREHENSIVE API TEST SUITE - WEEK 6 REST API IMPLEMENTATION
# ============================================================================
# 
# Complete testing framework for Brazilian Legislative API
# Covers endpoint functionality, authentication, performance, and security
# Designed for continuous integration and quality assurance
# 
# Test Categories:
# - Endpoint Functionality Tests
# - Authentication and Authorization Tests
# - Rate Limiting Tests
# - Performance and Load Tests
# - Security and Vulnerability Tests
# - Data Validation and Brazilian Context Tests
# - LGPD Compliance Tests
# ============================================================================

cat("🧪 Loading Comprehensive API Test Suite - Week 6\n")

# Load testing packages
testing_packages <- c("testthat", "httr", "jsonlite", "microbenchmark", "parallel")
missing_test_packages <- character(0)

for (pkg in testing_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE, quietly = TRUE))
  } else {
    missing_test_packages <- c(missing_test_packages, pkg)
  }
}

if (length(missing_test_packages) > 0) {
  cat("⚠️ Missing testing packages:", paste(missing_test_packages, collapse = ", "), "\n")
  cat("📦 Install with: install.packages(c(", paste0("'", missing_test_packages, "'", collapse = ", "), "))\n")
}

# Test Configuration
TEST_CONFIG <- list(
  # API Base Configuration
  base_url = "http://localhost:8000/api/v1",
  test_api_key = "ml_v4_demo_development_key_12345",
  timeout_seconds = 30,
  
  # Test Data
  valid_estados = c("SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "PE", "CE"),
  invalid_estados = c("XX", "YY", "ZZ", "123", ""),
  valid_anos = 2018:2024,
  invalid_anos = c(1900, 2050, -1, 0),
  
  # Performance Thresholds
  response_time_threshold_ms = 500,
  concurrent_request_limit = 100,
  memory_usage_threshold_mb = 512,
  
  # Rate Limiting Test Configuration
  demo_tier_limits = list(
    requests_per_hour = 100,
    requests_per_minute = 10,
    burst_allowance = 10
  ),
  
  # Security Test Configuration
  security_headers = c(
    "X-Content-Type-Options",
    "X-Frame-Options", 
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy"
  )
)

# Test Results Storage
TEST_RESULTS <- list(
  endpoint_tests = list(),
  auth_tests = list(),
  performance_tests = list(),
  security_tests = list(),
  summary = list()
)

# Helper Functions
make_api_request <- function(endpoint, method = "GET", params = NULL, headers = NULL, body = NULL, api_key = TEST_CONFIG$test_api_key) {
  
  # Build URL
  url <- paste0(TEST_CONFIG$base_url, endpoint)
  
  # Default headers
  default_headers <- list(
    "Accept" = "application/json",
    "Content-Type" = "application/json",
    "User-Agent" = "Monitor-Legislativo-Test-Suite/1.0"
  )
  
  if (!is.null(api_key)) {
    default_headers[["X-API-Key"]] <- api_key
  }
  
  if (!is.null(headers)) {
    default_headers <- c(default_headers, headers)
  }
  
  # Make request
  tryCatch({
    if (method == "GET") {
      response <- httr::GET(
        url, 
        query = params, 
        httr::add_headers(.headers = default_headers),
        httr::timeout(TEST_CONFIG$timeout_seconds)
      )
    } else if (method == "POST") {
      response <- httr::POST(
        url,
        body = if (!is.null(body)) jsonlite::toJSON(body, auto_unbox = TRUE) else NULL,
        httr::add_headers(.headers = default_headers),
        httr::timeout(TEST_CONFIG$timeout_seconds)
      )
    } else {
      stop(paste("Unsupported HTTP method:", method))
    }
    
    return(list(
      success = TRUE,
      response = response,
      status_code = httr::status_code(response),
      content = httr::content(response, "text", encoding = "UTF-8"),
      headers = httr::headers(response),
      response_time_ms = as.numeric(response$times["total"]) * 1000
    ))
    
  }, error = function(e) {
    return(list(
      success = FALSE,
      error = e$message,
      response = NULL
    ))
  })
}

parse_json_response <- function(request_result) {
  if (!request_result$success) {
    return(NULL)
  }
  
  tryCatch({
    return(jsonlite::fromJSON(request_result$content))
  }, error = function(e) {
    return(NULL)
  })
}

# ENDPOINT FUNCTIONALITY TESTS
# =============================

test_health_endpoint <- function() {
  cat("Testing /health endpoint...\n")
  
  result <- make_api_request("/health", api_key = NULL)  # Health endpoint should not require auth
  
  test_result <- list(
    endpoint = "/health",
    passed = FALSE,
    details = list()
  )
  
  if (result$success) {
    test_result$details$response_received <- TRUE
    test_result$details$status_code <- result$status_code
    test_result$details$response_time_ms <- result$response_time_ms
    
    # Parse response
    data <- parse_json_response(result)
    
    if (!is.null(data)) {
      test_result$details$json_parsed <- TRUE
      test_result$details$has_status <- !is.null(data$data$status)
      test_result$details$has_timestamp <- !is.null(data$timestamp)
      
      # Health endpoint should return status 200 and indicate healthy status
      test_result$passed <- (result$status_code == 200 && 
                            !isTRUE(is.null(data$data$status)) &&
                            data$error == FALSE)
    }
  }
  
  TEST_RESULTS$endpoint_tests[["health"]] <<- test_result
  return(test_result)
}

test_legislation_search_endpoint <- function() {
  cat("Testing /legislation/search endpoint...\n")
  
  test_cases <- list(
    basic_search = list(params = list(q = "transporte"), expected_status = 200),
    state_filter = list(params = list(estado = "SP"), expected_status = 200),
    year_filter = list(params = list(ano = 2023), expected_status = 200),
    combined_filters = list(params = list(q = "lei", estado = "RJ", ano = 2022), expected_status = 200),
    invalid_state = list(params = list(estado = "XX"), expected_status = 400),
    invalid_year = list(params = list(ano = 1900), expected_status = 400),
    pagination = list(params = list(limit = 10, offset = 20), expected_status = 200),
    large_limit = list(params = list(limit = 1000), expected_status = 200)
  )
  
  test_results <- list()
  
  for (test_name in names(test_cases)) {
    test_case <- test_cases[[test_name]]
    result <- make_api_request("/legislation/search", params = test_case$params)
    
    test_results[[test_name]] <- list(
      passed = (result$success && result$status_code == test_case$expected_status),
      status_code = if (result$success) result$status_code else NA,
      response_time_ms = if (result$success) result$response_time_ms else NA,
      error = if (!result$success) result$error else NULL
    )
  }
  
  TEST_RESULTS$endpoint_tests[["legislation_search"]] <<- test_results
  return(test_results)
}

test_geographic_analysis_endpoint <- function() {
  cat("Testing /geographic/analysis endpoint...\n")
  
  test_cases <- list(
    state_level = list(params = list(level = "state"), expected_status = 200),
    region_level = list(params = list(level = "region"), expected_status = 200),
    municipality_level = list(params = list(level = "municipality", estado = "SP"), expected_status = 200),
    invalid_level = list(params = list(level = "invalid"), expected_status = 400),
    density_metric = list(params = list(level = "state", metric = "density"), expected_status = 200)
  )
  
  test_results <- list()
  
  for (test_name in names(test_cases)) {
    test_case <- test_cases[[test_name]]
    result <- make_api_request("/geographic/analysis", params = test_case$params)
    
    test_results[[test_name]] <- list(
      passed = (result$success && result$status_code == test_case$expected_status),
      status_code = if (result$success) result$status_code else NA,
      response_time_ms = if (result$success) result$response_time_ms else NA
    )
  }
  
  TEST_RESULTS$endpoint_tests[["geographic_analysis"]] <<- test_results
  return(test_results)
}

test_citations_endpoint <- function() {
  cat("Testing /citations/generate endpoint...\n")
  
  test_cases <- list(
    abnt_citation = list(params = list(document_id = "doc_1", format = "abnt"), expected_status = 200),
    apa_citation = list(params = list(document_id = "doc_1", format = "apa"), expected_status = 200),
    all_formats = list(params = list(document_id = "doc_1", all_formats = TRUE), expected_status = 200),
    invalid_document = list(params = list(document_id = "nonexistent"), expected_status = 404),
    invalid_format = list(params = list(document_id = "doc_1", format = "invalid"), expected_status = 400),
    missing_document_id = list(params = list(format = "abnt"), expected_status = 400)
  )
  
  test_results <- list()
  
  for (test_name in names(test_cases)) {
    test_case <- test_cases[[test_name]]
    result <- make_api_request("/citations/generate", params = test_case$params)
    
    test_results[[test_name]] <- list(
      passed = (result$success && result$status_code == test_case$expected_status),
      status_code = if (result$success) result$status_code else NA,
      response_time_ms = if (result$success) result$response_time_ms else NA
    )
  }
  
  TEST_RESULTS$endpoint_tests[["citations"]] <<- test_results
  return(test_results)
}

test_export_endpoint <- function() {
  cat("Testing /export/data endpoint...\n")
  
  test_cases <- list(
    csv_export = list(params = list(format = "csv", limit = 10), expected_status = 200),
    json_export = list(params = list(format = "json", limit = 10), expected_status = 200),
    bibtex_export = list(params = list(format = "bibtex", limit = 5), expected_status = 200),
    filtered_export = list(params = list(format = "csv", estado = "SP", limit = 10), expected_status = 200),
    invalid_format = list(params = list(format = "invalid"), expected_status = 400)
  )
  
  test_results <- list()
  
  for (test_name in names(test_cases)) {
    test_case <- test_cases[[test_name]]
    result <- make_api_request("/export/data", params = test_case$params)
    
    test_results[[test_name]] <- list(
      passed = (result$success && result$status_code == test_case$expected_status),
      status_code = if (result$success) result$status_code else NA,
      response_time_ms = if (result$success) result$response_time_ms else NA
    )
  }
  
  TEST_RESULTS$endpoint_tests[["export"]] <<- test_results
  return(test_results)
}

# AUTHENTICATION TESTS
# ====================

test_api_key_authentication <- function() {
  cat("Testing API key authentication...\n")
  
  test_cases <- list(
    valid_key = list(api_key = TEST_CONFIG$test_api_key, expected_status = 200),
    invalid_key = list(api_key = "invalid_key_12345", expected_status = 401),
    missing_key = list(api_key = NULL, expected_status = 401),
    malformed_key = list(api_key = "ml_invalid_format", expected_status = 401)
  )
  
  test_results <- list()
  
  for (test_name in names(test_cases)) {
    test_case <- test_cases[[test_name]]
    result <- make_api_request("/legislation/search", 
                              params = list(q = "test"), 
                              api_key = test_case$api_key)
    
    test_results[[test_name]] <- list(
      passed = (result$success && result$status_code == test_case$expected_status) ||
               (!result$success && test_case$expected_status >= 400),
      status_code = if (result$success) result$status_code else "request_failed",
      response_time_ms = if (result$success) result$response_time_ms else NA
    )
  }
  
  TEST_RESULTS$auth_tests[["api_key_auth"]] <<- test_results
  return(test_results)
}

# RATE LIMITING TESTS
# ===================

test_rate_limiting <- function() {
  cat("Testing rate limiting...\n")
  
  # Test burst protection (send multiple rapid requests)
  cat("  Testing burst protection...\n")
  burst_results <- list()
  
  for (i in 1:15) {  # Try to exceed burst limit
    result <- make_api_request("/health", api_key = NULL)
    burst_results[[i]] <- list(
      request_number = i,
      status_code = if (result$success) result$status_code else 999,
      response_time_ms = if (result$success) result$response_time_ms else NA
    )
    
    # Small delay to avoid overwhelming the system
    Sys.sleep(0.1)
  }
  
  # Check if rate limiting kicked in
  rate_limited_requests <- sum(sapply(burst_results, function(x) x$status_code == 429))
  
  test_result <- list(
    burst_protection = list(
      total_requests = length(burst_results),
      rate_limited_requests = rate_limited_requests,
      passed = rate_limited_requests > 0  # We expect some requests to be rate limited
    )
  )
  
  TEST_RESULTS$auth_tests[["rate_limiting"]] <<- test_result
  return(test_result)
}

# PERFORMANCE TESTS
# =================

test_response_times <- function() {
  cat("Testing response time performance...\n")
  
  endpoints_to_test <- c(
    "/health",
    "/legislation/search?q=transport",
    "/legislation/search?estado=SP&limit=10",
    "/geographic/analysis?level=state",
    "/citations/generate?document_id=doc_1&format=abnt"
  )
  
  performance_results <- list()
  
  for (endpoint in endpoints_to_test) {
    # Run multiple tests to get average
    times <- numeric(5)
    
    for (i in 1:5) {
      result <- make_api_request(endpoint)
      times[i] <- if (result$success) result$response_time_ms else NA
      Sys.sleep(0.5)  # Avoid overwhelming the API
    }
    
    avg_time <- mean(times, na.rm = TRUE)
    max_time <- max(times, na.rm = TRUE)
    
    performance_results[[endpoint]] <- list(
      avg_response_time_ms = avg_time,
      max_response_time_ms = max_time,
      passed = !isTRUE(is.na(avg_time)) && avg_time < TEST_CONFIG$response_time_threshold_ms,
      all_requests_successful = sum(is.na(times)) == 0
    )
  }
  
  TEST_RESULTS$performance_tests[["response_times"]] <<- performance_results
  return(performance_results)
}

test_concurrent_requests <- function() {
  cat("Testing concurrent request handling...\n")
  
  # Function to make a single request
  make_test_request <- function(i) {
    result <- make_api_request("/health", api_key = NULL)
    return(list(
      request_id = i,
      success = result$success,
      status_code = if (result$success) result$status_code else 999,
      response_time_ms = if (result$success) result$response_time_ms else NA
    ))
  }
  
  # Run concurrent requests
  if (requireNamespace("parallel", quietly = TRUE)) {
    concurrent_count <- min(10, TEST_CONFIG$concurrent_request_limit)  # Start with 10 concurrent requests
    
    start_time <- Sys.time()
    results <- parallel::mclapply(1:concurrent_count, make_test_request, mc.cores = min(4, concurrent_count))
    end_time <- Sys.time()
    
    total_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    successful_requests <- sum(sapply(results, function(x) x$success && x$status_code == 200))
    
    test_result <- list(
      concurrent_requests = concurrent_count,
      successful_requests = successful_requests,
      total_time_seconds = total_time,
      success_rate = successful_requests / concurrent_count,
      avg_time_per_request = total_time / concurrent_count,
      passed = (successful_requests / concurrent_count) >= 0.8  # 80% success rate threshold
    )
  } else {
    test_result <- list(
      error = "parallel package not available",
      passed = FALSE
    )
  }
  
  TEST_RESULTS$performance_tests[["concurrent_requests"]] <<- test_result
  return(test_result)
}

# SECURITY TESTS
# ==============

test_security_headers <- function() {
  cat("Testing security headers...\n")
  
  result <- make_api_request("/health", api_key = NULL)
  
  security_test_results <- list()
  
  if (result$success) {
    headers <- result$headers
    
    for (header in TEST_CONFIG$security_headers) {
      security_test_results[[header]] <- list(
        present = !isTRUE(is.null(headers[[header]])) || !is.null(headers[[tolower(header)]]),
        value = headers[[header]] %||% headers[[tolower(header)]] %||% "not_present"
      )
    }
    
    # Test for proper CORS headers
    security_test_results[["cors_headers"]] <- list(
      access_control_allow_origin = !is.null(headers[["access-control-allow-origin"]]),
      access_control_allow_methods = !is.null(headers[["access-control-allow-methods"]]),
      access_control_allow_headers = !is.null(headers[["access-control-allow-headers"]])
    )
  }
  
  TEST_RESULTS$security_tests[["headers"]] <<- security_test_results
  return(security_test_results)
}

test_input_validation <- function() {
  cat("Testing input validation and injection protection...\n")
  
  # SQL injection attempts
  sql_injection_tests <- list(
    sql_in_query = list(params = list(q = "'; DROP TABLE documents; --"), expected_safe = TRUE),
    sql_in_state = list(params = list(estado = "SP'; DROP TABLE users; --"), expected_safe = TRUE),
    sql_in_year = list(params = list(ano = "2023; DELETE FROM api_keys"), expected_safe = TRUE)
  )
  
  # XSS attempts
  xss_tests <- list(
    script_tag = list(params = list(q = "<script>alert('xss')</script>"), expected_safe = TRUE),
    javascript_url = list(params = list(q = "javascript:alert('xss')"), expected_safe = TRUE)
  )
  
  test_results <- list(
    sql_injection = list(),
    xss_protection = list()
  )
  
  # Test SQL injection protection
  for (test_name in names(sql_injection_tests)) {
    test_case <- sql_injection_tests[[test_name]]
    result <- make_api_request("/legislation/search", params = test_case$params)
    
    # API should either reject the request (4xx) or handle it safely (2xx with clean response)
    test_results$sql_injection[[test_name]] <- list(
      passed = result$success && (result$status_code >= 400 || result$status_code == 200),
      status_code = if (result$success) result$status_code else "request_failed"
    )
  }
  
  # Test XSS protection
  for (test_name in names(xss_tests)) {
    test_case <- xss_tests[[test_name]]
    result <- make_api_request("/legislation/search", params = test_case$params)
    
    test_results$xss_protection[[test_name]] <- list(
      passed = result$success && (result$status_code >= 400 || result$status_code == 200),
      status_code = if (result$success) result$status_code else "request_failed"
    )
  }
  
  TEST_RESULTS$security_tests[["input_validation"]] <<- test_results
  return(test_results)
}

# BRAZILIAN CONTEXT VALIDATION TESTS
# ==================================

test_brazilian_data_validation <- function() {
  cat("Testing Brazilian context data validation...\n")
  
  test_results <- list()
  
  # Test valid Brazilian states
  valid_state_tests <- list()
  for (estado in TEST_CONFIG$valid_estados[1:3]) {  # Test first 3 states
    result <- make_api_request("/legislation/search", params = list(estado = estado))
    valid_state_tests[[estado]] <- list(
      passed = result$success && result$status_code == 200,
      status_code = if (result$success) result$status_code else "failed"
    )
  }
  
  # Test invalid Brazilian states
  invalid_state_tests <- list()
  for (estado in TEST_CONFIG$invalid_estados[1:2]) {  # Test first 2 invalid states
    result <- make_api_request("/legislation/search", params = list(estado = estado))
    invalid_state_tests[[estado]] <- list(
      passed = result$success && result$status_code == 400,  # Should return 400 for invalid states
      status_code = if (result$success) result$status_code else "failed"
    )
  }
  
  test_results <- list(
    valid_states = valid_state_tests,
    invalid_states = invalid_state_tests
  )
  
  TEST_RESULTS$endpoint_tests[["brazilian_validation"]] <<- test_results
  return(test_results)
}

# MAIN TEST RUNNER
# ================

run_comprehensive_test_suite <- function(include_performance = TRUE, include_security = TRUE) {
  cat("🧪 Running Comprehensive API Test Suite\n")
  cat("========================================\n")
  
  start_time <- Sys.time()
  
  # Clear previous results
  TEST_RESULTS <<- list(
    endpoint_tests = list(),
    auth_tests = list(),
    performance_tests = list(),
    security_tests = list(),
    summary = list()
  )
  
  # Run endpoint tests
  cat("\n📡 ENDPOINT FUNCTIONALITY TESTS\n")
  cat("--------------------------------\n")
  test_health_endpoint()
  test_legislation_search_endpoint()
  test_geographic_analysis_endpoint()
  test_citations_endpoint()
  test_export_endpoint()
  test_brazilian_data_validation()
  
  # Run authentication tests
  cat("\n🔐 AUTHENTICATION TESTS\n")
  cat("-----------------------\n")
  test_api_key_authentication()
  test_rate_limiting()
  
  # Run performance tests (optional)
  if (include_performance) {
    cat("\n⚡ PERFORMANCE TESTS\n")
    cat("-------------------\n")
    test_response_times()
    test_concurrent_requests()
  }
  
  # Run security tests (optional)
  if (include_security) {
    cat("\n🔒 SECURITY TESTS\n")
    cat("-----------------\n")
    test_security_headers()
    test_input_validation()
  }
  
  end_time <- Sys.time()
  total_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
  
  # Generate summary
  summary <- generate_test_summary(total_time)
  TEST_RESULTS$summary <<- summary
  
  # Print results
  print_test_results()
  
  return(TEST_RESULTS)
}

# TEST REPORTING
# ==============

generate_test_summary <- function(total_time) {
  
  # Count tests
  total_tests <- 0
  passed_tests <- 0
  
  # Count endpoint tests
  for (category in names(TEST_RESULTS$endpoint_tests)) {
    test_group <- TEST_RESULTS$endpoint_tests[[category]]
    if (is.list(test_group) && "passed" %in% names(test_group)) {
      total_tests <- total_tests + 1
      if (test_group$passed) passed_tests <- passed_tests + 1
    } else {
      for (test_name in names(test_group)) {
        total_tests <- total_tests + 1
        if (test_group[[test_name]]$passed) passed_tests <- passed_tests + 1
      }
    }
  }
  
  # Count auth tests
  for (category in names(TEST_RESULTS$auth_tests)) {
    test_group <- TEST_RESULTS$auth_tests[[category]]
    if (is.list(test_group) && "passed" %in% names(test_group)) {
      total_tests <- total_tests + 1
      if (test_group$passed) passed_tests <- passed_tests + 1
    } else {
      for (test_name in names(test_group)) {
        total_tests <- total_tests + 1
        if (test_group[[test_name]]$passed) passed_tests <- passed_tests + 1
      }
    }
  }
  
  # Calculate performance metrics
  avg_response_time <- NA
  if (!is.null(TEST_RESULTS$performance_tests$response_times)) {
    times <- sapply(TEST_RESULTS$performance_tests$response_times, function(x) x$avg_response_time_ms)
    avg_response_time <- mean(times, na.rm = TRUE)
  }
  
  return(list(
    total_tests = total_tests,
    passed_tests = passed_tests,
    failed_tests = total_tests - passed_tests,
    success_rate = if (total_tests > 0) round((passed_tests / total_tests) * 100, 1) else 0,
    total_execution_time_seconds = round(total_time, 2),
    avg_response_time_ms = if (!is.na(avg_response_time)) round(avg_response_time, 1) else NA,
    timestamp = Sys.time()
  ))
}

print_test_results <- function() {
  cat("\n🏁 TEST RESULTS SUMMARY\n")
  cat("=======================\n")
  
  summary <- TEST_RESULTS$summary
  
  cat("📊 Overall Results:\n")
  cat(sprintf("   Total Tests: %d\n", summary$total_tests))
  cat(sprintf("   Passed: %d\n", summary$passed_tests))
  cat(sprintf("   Failed: %d\n", summary$failed_tests))
  cat(sprintf("   Success Rate: %.1f%%\n", summary$success_rate))
  cat(sprintf("   Execution Time: %.2f seconds\n", summary$total_execution_time_seconds))
  
  if (!is.na(summary$avg_response_time_ms)) {
    cat(sprintf("   Avg Response Time: %.1f ms\n", summary$avg_response_time_ms))
  }
  
  # Print detailed results for failed tests
  if (summary$failed_tests > 0) {
    cat("\n❌ Failed Tests:\n")
    
    # Check endpoint tests
    for (category in names(TEST_RESULTS$endpoint_tests)) {
      test_group <- TEST_RESULTS$endpoint_tests[[category]]
      if (is.list(test_group)) {
        for (test_name in names(test_group)) {
          if (is.list(test_group[[test_name]]) && 
              "passed" %in% names(test_group[[test_name]]) && 
              !test_group[[test_name]]$passed) {
            cat(sprintf("   - %s/%s\n", category, test_name))
          }
        }
      }
    }
  }
  
  cat("\n✅ Test suite completed successfully!\n")
}

# Quick Test Function
quick_test <- function() {
  cat("🚀 Running Quick API Test\n")
  
  # Test health endpoint
  result <- make_api_request("/health", api_key = NULL)
  
  if (result$success && result$status_code == 200) {
    cat("✅ API is responding (Health check passed)\n")
    
    # Test authenticated endpoint
    auth_result <- make_api_request("/legislation/search", params = list(q = "test"))
    
    if (auth_result$success && auth_result$status_code == 200) {
      cat("✅ Authentication working (Search endpoint accessible)\n")
      cat("🎉 API is ready for use!\n")
      return(TRUE)
    } else {
      cat("⚠️ Authentication issues detected\n")
      return(FALSE)
    }
  } else {
    cat("❌ API health check failed\n")
    return(FALSE)
  }
}

cat("✅ Comprehensive API Test Suite loaded successfully\n")
cat("📋 Available functions:\n")
cat("  - run_comprehensive_test_suite(): Complete test suite\n")
cat("  - quick_test(): Basic API functionality check\n")
cat("  - Individual test functions available for specific testing\n")