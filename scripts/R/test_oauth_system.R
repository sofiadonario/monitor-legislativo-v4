# OAuth2 Authentication System - Test Suite
# Comprehensive testing for LGPD compliance and security features
# Monitor Legislativo v4

library(testthat)
library(DBI)
library(RPostgres)
library(pool)
library(httr)
library(jsonlite)

# Load authentication modules for testing
source("auth_system.R")
source("lgpd_compliance.R")
source("security_hardening.R")
source("database.R")

# Test configuration
TEST_CONFIG <- list(
  test_email = "test.researcher@usp.br",
  test_full_name = "Dr. João Silva",
  test_oauth_subject_id = "test_google_123456",
  test_provider = "google",
  test_domain = "usp.br"
)

cat("🧪 Starting OAuth2 Authentication System Tests\n")
cat("=" %R% 50, "\n")

#' Test Database Schema
test_database_schema <- function() {
  cat("📊 Testing Database Schema...\n")
  
  if (is.null(.db_pool)) {
    cat("❌ Database not connected - skipping schema tests\n")
    return(FALSE)
  }
  
  tryCatch({
    # Test user management tables exist
    required_tables <- c("users", "user_roles", "user_role_assignments", 
                        "user_sessions", "data_access_log", "data_subject_requests",
                        "trusted_domains")
    
    existing_tables <- dbGetQuery(.db_pool,
      "SELECT table_name FROM information_schema.tables 
       WHERE table_schema = 'public' AND table_name = ANY($1)",
      params = list(required_tables)
    )$table_name
    
    missing_tables <- setdiff(required_tables, existing_tables)
    
    if (length(missing_tables) > 0) {
      cat("❌ Missing tables:", paste(missing_tables, collapse = ", "), "\n")
      return(FALSE)
    }
    
    # Test default roles exist
    roles_count <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM user_roles")$count[1]
    if (roles_count < 4) {
      cat("❌ Default roles not properly inserted\n")
      return(FALSE)
    }
    
    # Test trusted domains exist
    domains_count <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM trusted_domains")$count[1]
    if (domains_count < 5) {
      cat("❌ Trusted domains not properly inserted\n")
      return(FALSE)
    }
    
    cat("✅ Database schema validation passed\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Database schema test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Test OAuth2 Configuration
test_oauth_config <- function() {
  cat("🔐 Testing OAuth2 Configuration...\n")
  
  tryCatch({
    # Test Google configuration
    google_config <- get_oauth_config("google")
    
    if (isTRUE(is.null(google_config$client_id)) || nchar(google_config$client_id) == 0) {
      cat("⚠️ Google OAuth not configured (missing client_id)\n")
    } else {
      cat("✅ Google OAuth configuration found\n")
    }
    
    # Test Microsoft configuration  
    microsoft_config <- get_oauth_config("microsoft")
    
    if (isTRUE(is.null(microsoft_config$client_id)) || nchar(microsoft_config$client_id) == 0) {
      cat("⚠️ Microsoft OAuth not configured (missing client_id)\n")
    } else {
      cat("✅ Microsoft OAuth configuration found\n")
    }
    
    # Test OAuth URL generation
    test_state <- "test_state_123"
    google_url <- generate_auth_url("google", test_state)
    
    if (grepl("accounts.google.com", google_url) && grepl(test_state, google_url)) {
      cat("✅ OAuth URL generation working\n")
    } else {
      cat("❌ OAuth URL generation failed\n")
      return(FALSE)
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ OAuth configuration test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Test User Creation and Role Assignment
test_user_management <- function() {
  cat("👤 Testing User Management...\n")
  
  if (is.null(.db_pool)) {
    cat("❌ Database not connected - skipping user tests\n")
    return(FALSE)
  }
  
  tryCatch({
    # Test user creation
    test_user_info <- list(
      email = TEST_CONFIG$test_email,
      full_name = TEST_CONFIG$test_full_name,
      oauth_subject_id = TEST_CONFIG$test_oauth_subject_id,
      email_verified = TRUE,
      avatar_url = NULL
    )
    
    # Clean up any existing test user
    dbExecute(.db_pool,
      "DELETE FROM users WHERE email = $1",
      params = list(TEST_CONFIG$test_email)
    )
    
    # Create test user
    user_record <- create_or_update_user(test_user_info, TEST_CONFIG$test_provider)
    
    if (isTRUE(is.null(user_record)) || nrow(user_record) == 0) {
      cat("❌ User creation failed\n")
      return(FALSE)
    }
    
    cat("✅ User creation successful\n")
    
    # Test role assignment (should be automatic for @usp.br domain)
    user_roles <- strsplit(user_record$roles[1], ",")[[1]]
    
    if ("researcher" %in% user_roles) {
      cat("✅ Automatic role assignment working\n")
    } else {
      cat("⚠️ Automatic role assignment may not be working (got:", 
          paste(user_roles, collapse = ", "), ")\n")
    }
    
    # Test user update
    updated_user <- create_or_update_user(test_user_info, TEST_CONFIG$test_provider)
    
    if (!isTRUE(is.null(updated_user)) && updated_user$id[1] == user_record$id[1]) {
      cat("✅ User update working\n")
    } else {
      cat("❌ User update failed\n")
      return(FALSE)
    }
    
    # Store test user ID for cleanup
    TEST_CONFIG$test_user_id <- user_record$id[1]
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ User management test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Test Session Management
test_session_management <- function() {
  cat("🔒 Testing Session Management...\n")
  
  if (isTRUE(is.null(.db_pool)) || isTRUE(is.null(TEST_CONFIG$test_user_id))) {
    cat("❌ Prerequisites not met - skipping session tests\n")
    return(FALSE)
  }
  
  tryCatch({
    # Mock user record
    mock_user <- data.frame(
      id = TEST_CONFIG$test_user_id,
      email = TEST_CONFIG$test_email,
      stringsAsFactors = FALSE
    )
    
    # Mock token data
    mock_token <- list(
      access_token = "test_access_token_123",
      refresh_token = "test_refresh_token_456"
    )
    
    # Mock request info
    mock_request <- list(
      ip_address = "127.0.0.1",
      user_agent = "Test User Agent"
    )
    
    # Test session creation
    session_info <- create_user_session(mock_user, mock_token, mock_request)
    
    if (isTRUE(is.null(session_info)) || isTRUE(is.null(session_info$session_id))) {
      cat("❌ Session creation failed\n")
      return(FALSE)
    }
    
    cat("✅ Session creation successful\n")
    
    # Test session validation
    validated_session <- validate_session(session_info$session_id, session_info$csrf_token)
    
    if (is.null(validated_session)) {
      cat("❌ Session validation failed\n")
      return(FALSE)
    }
    
    cat("✅ Session validation working\n")
    
    # Test session timeout check
    is_expired <- check_session_timeout(session_info$session_id)
    
    if (is_expired) {
      cat("❌ Session incorrectly marked as expired\n")
      return(FALSE)
    }
    
    cat("✅ Session timeout check working\n")
    
    # Test session revocation
    revoke_result <- revoke_session(session_info$session_id, "test_logout")
    
    if (!revoke_result) {
      cat("❌ Session revocation failed\n")
      return(FALSE)
    }
    
    # Verify session is revoked
    revoked_session <- validate_session(session_info$session_id)
    
    if (!is.null(revoked_session)) {
      cat("❌ Session still valid after revocation\n")
      return(FALSE)
    }
    
    cat("✅ Session revocation working\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Session management test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Test LGPD Compliance Features
test_lgpd_compliance <- function() {
  cat("🇧🇷 Testing LGPD Compliance...\n")
  
  if (isTRUE(is.null(.db_pool)) || isTRUE(is.null(TEST_CONFIG$test_user_id))) {
    cat("❌ Prerequisites not met - skipping LGPD tests\n")
    return(FALSE)
  }
  
  tryCatch({
    # Test consent recording
    consent_result <- record_lgpd_consent(
      TEST_CONFIG$test_user_id,
      "data_processing",
      TRUE
    )
    
    if (!consent_result) {
      cat("❌ LGPD consent recording failed\n")
      return(FALSE)
    }
    
    cat("✅ LGPD consent recording working\n")
    
    # Test data access logging
    log_result <- log_data_access(
      TEST_CONFIG$test_user_id,
      "test_session_123",
      "search",
      "legislative_documents",
      c("doc_1", "doc_2"),
      "transporte sustentável"
    )
    
    if (!log_result) {
      cat("❌ Data access logging failed\n")
      return(FALSE)
    }
    
    cat("✅ Data access logging working\n")
    
    # Test access history retrieval
    access_history <- get_user_access_history(TEST_CONFIG$test_user_id)
    
    if (nrow(access_history) == 0) {
      cat("⚠️ Access history retrieval returned no results\n")
    } else {
      cat("✅ Access history retrieval working\n")
    }
    
    # Test data subject request creation
    request_id <- create_data_subject_request(
      TEST_CONFIG$test_user_id,
      "access",
      "Test data access request"
    )
    
    if (is.null(request_id)) {
      cat("❌ Data subject request creation failed\n")
      return(FALSE)
    }
    
    cat("✅ Data subject request creation working\n")
    
    # Test data export functionality
    export_path <- export_user_data(TEST_CONFIG$test_user_id)
    
    if (isTRUE(is.null(export_path)) || !file.exists(export_path)) {
      cat("❌ User data export failed\n")
      return(FALSE)
    } else {
      # Clean up test export file
      unlink(export_path)
      cat("✅ User data export working\n")
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ LGPD compliance test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Test Security Features
test_security_features <- function() {
  cat("🛡️ Testing Security Features...\n")
  
  tryCatch({
    # Test CSRF token generation
    csrf_token1 <- generate_csrf_token("test_session_1")
    csrf_token2 <- generate_csrf_token("test_session_2")
    
    if (nchar(csrf_token1) != 32 || nchar(csrf_token2) != 32) {
      cat("❌ CSRF token generation failed\n")
      return(FALSE)
    }
    
    if (csrf_token1 == csrf_token2) {
      cat("❌ CSRF tokens are not unique\n")
      return(FALSE)
    }
    
    cat("✅ CSRF token generation working\n")
    
    # Test CSRF token validation
    valid_check <- validate_csrf_token(csrf_token1, csrf_token1)
    invalid_check <- validate_csrf_token(csrf_token1, csrf_token2)
    
    if (!valid_check || invalid_check) {
      cat("❌ CSRF token validation failed\n")
      return(FALSE)
    }
    
    cat("✅ CSRF token validation working\n")
    
    # Test input sanitization
    dangerous_input <- "<script>alert('xss')</script>test@example.com"
    sanitized_input <- sanitize_input(dangerous_input)
    
    if (grepl("<script>", sanitized_input)) {
      cat("❌ Input sanitization failed\n")
      return(FALSE)
    }
    
    cat("✅ Input sanitization working\n")
    
    # Test email validation
    valid_email_check <- validate_email("valid@usp.br")
    invalid_email_check <- validate_email("invalid-email")
    
    if (!valid_email_check || invalid_email_check) {
      cat("❌ Email validation failed\n")
      return(FALSE)
    }
    
    cat("✅ Email validation working\n")
    
    # Test institutional domain validation
    domain_check <- validate_institutional_domain("researcher@usp.br")
    
    if (!domain_check$valid) {
      cat("⚠️ Institutional domain validation may not be working properly\n")
    } else {
      cat("✅ Institutional domain validation working\n")
    }
    
    # Test rate limiting
    rate_check1 <- check_rate_limit("test_user_123", "test_action")
    rate_check2 <- check_rate_limit("test_user_123", "test_action")
    
    if (!rate_check1$allowed || !rate_check2$allowed) {
      cat("❌ Rate limiting too restrictive\n")
      return(FALSE)
    }
    
    if (rate_check2$requests_made <= rate_check1$requests_made) {
      cat("❌ Rate limiting not counting requests\n")
      return(FALSE)
    }
    
    cat("✅ Rate limiting working\n")
    
    # Test search parameter validation
    valid_params <- list(
      search_text = "transporte sustentável",
      date_from = as.Date("2020-01-01"),
      date_to = as.Date("2023-12-31"),
      document_types = c("legislacao", "jurisprudencia"),
      states = c("SP", "RJ"),
      limit = 100
    )
    
    validation_result <- validate_search_parameters(valid_params)
    
    if (!validation_result$valid) {
      cat("❌ Search parameter validation failed for valid input\n")
      cat("Errors:", paste(validation_result$errors, collapse = ", "), "\n")
      return(FALSE)
    }
    
    cat("✅ Search parameter validation working\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Security features test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Test Permission System
test_permission_system <- function() {
  cat("🔐 Testing Permission System...\n")
  
  tryCatch({
    # Mock user sessions with different roles
    admin_user <- list(
      roles = c("admin"),
      permissions = list(list(
        manage_users = TRUE,
        manage_system = TRUE,
        export_unlimited = TRUE
      ))
    )
    
    researcher_user <- list(
      roles = c("researcher"),
      permissions = list(list(
        advanced_search = TRUE,
        export_data = TRUE,
        view_analytics = TRUE
      ))
    )
    
    citizen_user <- list(
      roles = c("citizen"),
      permissions = list(list(
        basic_search = TRUE,
        view_documents = TRUE,
        limited_export = TRUE
      ))
    )
    
    # Test admin permissions
    if (!has_permission(admin_user, "manage_users")) {
      cat("❌ Admin permissions not working\n")
      return(FALSE)
    }
    
    # Test researcher permissions
    if (!has_permission(researcher_user, "advanced_search")) {
      cat("❌ Researcher permissions not working\n")
      return(FALSE)
    }
    
    # Test citizen permissions (should NOT have admin access)
    if (has_permission(citizen_user, "manage_users")) {
      cat("❌ Permission system allowing unauthorized access\n")
      return(FALSE)
    }
    
    cat("✅ Permission system working correctly\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Permission system test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Clean up test data
cleanup_test_data <- function() {
  cat("🧹 Cleaning up test data...\n")
  
  if (is.null(.db_pool)) {
    return()
  }
  
  tryCatch({
    # Remove test user and related data
    if (!is.null(TEST_CONFIG$test_user_id)) {
      dbExecute(.db_pool,
        "DELETE FROM data_access_log WHERE user_id = $1",
        params = list(TEST_CONFIG$test_user_id)
      )
      
      dbExecute(.db_pool,
        "DELETE FROM data_subject_requests WHERE user_id = $1",
        params = list(TEST_CONFIG$test_user_id)
      )
      
      dbExecute(.db_pool,
        "DELETE FROM user_sessions WHERE user_id = $1",
        params = list(TEST_CONFIG$test_user_id)
      )
      
      dbExecute(.db_pool,
        "DELETE FROM user_role_assignments WHERE user_id = $1",
        params = list(TEST_CONFIG$test_user_id)
      )
      
      dbExecute(.db_pool,
        "DELETE FROM users WHERE id = $1",
        params = list(TEST_CONFIG$test_user_id)
      )
    }
    
    # Clean up rate limiting test data
    cleanup_rate_limiting()
    
    cat("✅ Test data cleanup completed\n")
    
  }, error = function(e) {
    cat("⚠️ Test cleanup error:", e$message, "\n")
  })
}

#' Run all tests
run_oauth_tests <- function() {
  cat("\n🚀 OAuth2 Authentication System Test Suite\n")
  cat("==========================================\n\n")
  
  # Initialize database connection for testing
  db_connected <- init_database()
  
  if (!db_connected) {
    cat("⚠️ Database not connected - some tests will be skipped\n\n")
  }
  
  test_results <- list()
  
  # Run tests
  test_results$schema <- test_database_schema()
  test_results$oauth_config <- test_oauth_config()
  test_results$user_management <- test_user_management()
  test_results$session_management <- test_session_management()
  test_results$lgpd_compliance <- test_lgpd_compliance()
  test_results$security_features <- test_security_features()
  test_results$permission_system <- test_permission_system()
  
  # Clean up
  cleanup_test_data()
  
  # Summary
  cat("\n📊 Test Results Summary\n")
  cat("======================\n")
  
  passed_tests <- sum(unlist(test_results))
  total_tests <- length(test_results)
  
  for (test_name in names(test_results)) {
    status <- if (test_results[[test_name]]) "✅ PASS" else "❌ FAIL"
    cat(sprintf("%-20s: %s\n", test_name, status))
  }
  
  cat(sprintf("\nOverall: %d/%d tests passed (%.1f%%)\n", 
              passed_tests, total_tests, (passed_tests/total_tests)*100))
  
  if (passed_tests == total_tests) {
    cat("\n🎉 All tests passed! OAuth2 system is ready for deployment.\n")
  } else {
    cat("\n⚠️  Some tests failed. Review the output above before deployment.\n")
  }
  
  # Close database connection
  if (!is.null(.db_pool)) {
    close_database()
  }
  
  return(test_results)
}

# Helper function for string repetition
`%R%` <- function(str, times) {
  paste(rep(str, times), collapse = "")
}

# Run tests if script is executed directly
if (!interactive()) {
  run_oauth_tests()
}