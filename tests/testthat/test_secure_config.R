# test_secure_config.R - Tests for secure configuration
# ============================================================================

library(testthat)
source(test_path("..", "..", "R", "config", "secure_config.R"))

test_that("get_config loads environment variables correctly", {
  # Set a test environment variable
  Sys.setenv(TEST_CONFIG_VAR = "test_value")

  value <- get_config("TEST_CONFIG_VAR")
  expect_equal(value, "test_value")

  # Clean up
  Sys.unsetenv("TEST_CONFIG_VAR")
})

test_that("get_config uses default when env var not set", {
  value <- get_config("NONEXISTENT_VAR", default = "default_value")
  expect_equal(value, "default_value")
})

test_that("get_config errors on required missing variable", {
  expect_error(
    get_config("NONEXISTENT_REQUIRED_VAR", required = TRUE),
    "Required configuration"
  )
})

test_that("mask_sensitive masks passwords correctly", {
  # Test PostgreSQL password masking
  text <- "postgresql://user:password=MySecret123@host:5432/db"
  masked <- mask_sensitive(text)
  expect_false(grepl("MySecret123", masked))
  expect_true(grepl("\\*\\*\\*MASKED\\*\\*\\*", masked))

  # Test API key masking
  text2 <- "api_key: 'secret_key_12345'"
  masked2 <- mask_sensitive(text2)
  expect_false(grepl("secret_key_12345", masked2))

  # Test Bearer token masking
  text3 <- "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
  masked3 <- mask_sensitive(text3)
  expect_false(grepl("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", masked3))
})

test_that("get_db_config returns proper structure", {
  # Set test environment variables
  Sys.setenv(DB_HOST = "test_host")
  Sys.setenv(DB_PORT = "1234")
  Sys.setenv(DB_NAME = "test_db")
  Sys.setenv(DB_USER = "test_user")
  Sys.setenv(DB_PASSWORD = "test_pass")

  config <- get_db_config()

  expect_type(config, "list")
  expect_equal(config$host, "test_host")
  expect_equal(config$port, 1234)
  expect_equal(config$dbname, "test_db")
  expect_equal(config$user, "test_user")
  expect_equal(config$password, "test_pass")

  # Clean up
  Sys.unsetenv(c("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"))
})

test_that("get_auth_credentials returns hashed passwords", {
  # Set test credentials
  Sys.setenv(AUTH_ADMIN_PASSWORD = "admin_test_pass")

  credentials <- get_auth_credentials()

  expect_type(credentials, "list")
  expect_true("admin" %in% names(credentials))

  # Check password is hashed, not plain text
  expect_false(credentials$admin$password_hash == "admin_test_pass")
  expect_equal(
    credentials$admin$password_hash,
    digest("admin_test_pass", algo = "sha256")
  )

  # Clean up
  Sys.unsetenv("AUTH_ADMIN_PASSWORD")
})

test_that("get_api_keys parses environment format correctly", {
  # Set test API keys in the expected format
  Sys.setenv(API_KEYS = "key1:Test Key:demo:100:1000:read,key2:Test Key 2:premium:200:2000:read;write")

  keys <- get_api_keys()

  expect_type(keys, "list")
  expect_true("key1" %in% names(keys))
  expect_true("key2" %in% names(keys))

  expect_equal(keys$key1$name, "Test Key")
  expect_equal(keys$key1$tier, "demo")
  expect_equal(keys$key1$rate_limit_per_minute, 100)
  expect_equal(keys$key1$quota_per_day, 1000)
  expect_equal(keys$key1$permissions, "read")

  expect_equal(keys$key2$permissions, c("read", "write"))

  # Clean up
  Sys.unsetenv("API_KEYS")
})

test_that("get_api_keys returns demo key when none configured", {
  # Ensure no API keys are set
  Sys.unsetenv("API_KEYS")
  Sys.unsetenv("API_KEYS_FILE")

  suppressWarnings({
    keys <- get_api_keys()
  })

  expect_type(keys, "list")
  expect_true(length(keys) > 0)
  expect_true("demo_development_only" %in% names(keys))
})

test_that("validate_config checks required configurations", {
  # Test with missing required configs
  Sys.unsetenv("DB_PASSWORD")
  Sys.unsetenv("AUTH_ADMIN_PASSWORD")

  result <- suppressWarnings(validate_config())
  expect_false(result)

  # Set required configs
  Sys.setenv(DB_PASSWORD = "test_pass")
  Sys.setenv(AUTH_ADMIN_PASSWORD = "admin_pass")

  result <- validate_config()
  expect_true(result)

  # Clean up
  Sys.unsetenv(c("DB_PASSWORD", "AUTH_ADMIN_PASSWORD"))
})
