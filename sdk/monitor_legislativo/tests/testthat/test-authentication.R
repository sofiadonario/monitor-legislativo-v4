# Test suite for authentication functions
# Author: Monitor Legislativo Research Team

context("Authentication Functions")

# Setup test environment
setup({
  # Clear any existing configuration
  ml_clear_config()
})

teardown({
  # Clean up after tests
  ml_clear_config()
})

# Test API key configuration
test_that("ml_set_api_key handles invalid inputs correctly", {
  # Test empty API key
  expect_false(ml_set_api_key(""))
  expect_false(ml_set_api_key(NULL))
  expect_false(ml_set_api_key("   "))
  
  # Test invalid format
  expect_false(ml_set_api_key("invalid"))
  expect_false(ml_set_api_key("123"))
  expect_false(ml_set_api_key("short_key"))
})

test_that("ml_set_api_key accepts valid format keys", {
  # Test valid format (even if not real)
  valid_key <- "test_api_key_1234567890_abcdef"
  
  # Mock the API validation to avoid real API calls
  mockery::stub(ml_set_api_key, "ml_validate_api_key", TRUE)
  
  expect_true(ml_set_api_key(valid_key))
})

test_that("ml_get_config returns expected structure", {
  config <- ml_get_config()
  
  expect_is(config, "list")
  expect_true("base_url" %in% names(config))
  expect_true("api_key_configured" %in% names(config))
  expect_true("timeout" %in% names(config))
  expect_true("package_version" %in% names(config))
  
  # Check default values
  expect_equal(config$api_key_configured, FALSE)
  expect_equal(config$package_version, "1.0.0")
})

test_that("ml_set_base_url validates URLs correctly", {
  # Test invalid URLs
  expect_false(ml_set_base_url("not_a_url"))
  expect_false(ml_set_base_url("ftp://invalid.com"))
  
  # Test valid URLs
  expect_true(ml_set_base_url("http://localhost:3838"))
  expect_true(ml_set_base_url("https://api.example.com"))
  
  # Check URL is set correctly
  config <- ml_get_config()
  expect_equal(config$base_url, "https://api.example.com/api/v4")
})

test_that("ml_set_options configures settings correctly", {
  # Test timeout setting
  expect_true(ml_set_options(timeout = 60))
  config <- ml_get_config()
  expect_equal(config$timeout, 60)
  
  # Test invalid timeout
  expect_false(ml_set_options(timeout = -1))
  expect_false(ml_set_options(timeout = "invalid"))
  
  # Test cache setting
  expect_true(ml_set_options(cache_enabled = FALSE))
  config <- ml_get_config()
  expect_equal(config$cache_enabled, FALSE)
  
  # Test verbose setting
  expect_true(ml_set_options(verbose = TRUE))
  config <- ml_get_config()
  expect_equal(config$verbose, TRUE)
})

test_that("ml_clear_config resets configuration", {
  # Set some configuration
  ml_set_base_url("https://test.com")
  ml_set_options(timeout = 120, verbose = TRUE)
  
  # Clear configuration
  expect_true(ml_clear_config())
  
  # Check configuration is reset
  config <- ml_get_config()
  expect_equal(config$api_key_configured, FALSE)
  expect_equal(config$timeout, 30) # Should reset to default
})

# Test error handling
test_that("authentication functions handle errors gracefully", {
  # Test API validation without key
  expect_false(ml_validate_api_key())
  
  # Test authentication without key
  expect_null(ml_authenticate())
})

# Test edge cases
test_that("authentication functions handle edge cases", {
  # Test setting options with mixed valid/invalid values
  result <- ml_set_options(
    timeout = 45,      # valid
    cache_enabled = "invalid",  # invalid but should convert
    verbose = NULL     # should be ignored
  )
  
  expect_true(result)
  
  config <- ml_get_config()
  expect_equal(config$timeout, 45)
  expect_equal(config$cache_enabled, TRUE)  # converted from "invalid"
})