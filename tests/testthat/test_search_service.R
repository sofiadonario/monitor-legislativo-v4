# test_search_service.R - Tests for SearchService
# ============================================================================

library(testthat)
library(R6)
source(test_path("..", "..", "R", "services", "search_service.R"))

get_private_env <- function(service) {
  service$.__enclos_env__$private
}

test_that("SearchService initializes correctly", {
  service <- SearchService$new()

  expect_s3_class(service, "SearchService")
  expect_equal(service$default_limit, 50)
  expect_equal(service$max_limit, 1000)
  expect_false(service$cache_enabled)
})

test_that("SearchService respects pagination limits", {
  service <- SearchService$new()
  private_env <- get_private_env(service)

  # Test default limit
  expect_equal(private_env$validate_limit(NULL), 50)

  # Test max limit enforcement
  expect_equal(private_env$validate_limit(9999), 1000)

  # Test minimum limit
  expect_equal(private_env$validate_limit(0), 1)
  expect_equal(private_env$validate_limit(-5), 1)
})

test_that("Search term sanitization works correctly", {
  service <- SearchService$new()
  private_env <- get_private_env(service)

  # Test dangerous character removal
  expect_equal(
    private_env$sanitize_search_term("<script>alert('xss')</script>"),
    "scriptalert('xss')/script"
  )

  # Test SQL injection prevention
  expect_equal(
    private_env$sanitize_search_term("'; DROP TABLE documents; --"),
    " DROP TABLE documents --"
  )

  # Test trimming
  expect_equal(
    private_env$sanitize_search_term("  test  "),
    "test"
  )

  # Test empty string handling
  expect_equal(private_env$sanitize_search_term(""), "")
  expect_equal(private_env$sanitize_search_term(NULL), "")
})

test_that("Cache key generation is consistent", {
  service <- SearchService$new()
  private_env <- get_private_env(service)

  key1 <- private_env$build_cache_key("cat1", "search", "state", NULL, NULL, "date_desc", 50, 0, FALSE)
  key2 <- private_env$build_cache_key("cat1", "search", "state", NULL, NULL, "date_desc", 50, 0, FALSE)

  expect_equal(key1, key2)

  # Different parameters should generate different keys
  key3 <- private_env$build_cache_key("cat2", "search", "state", NULL, NULL, "date_desc", 50, 0, FALSE)
  expect_false(key1 == key3)
})

test_that("Empty results are handled correctly", {
  service <- SearchService$new()

  # Test with no data source
  results <- service$search_documents(
    category = "nonexistent",
    search_term = "impossible_search_12345"
  )

  expect_s3_class(results, "data.frame")
  expect_equal(nrow(results), 0)
})

test_that("CSV fallback loading works", {
  service <- SearchService$new()
  private_env <- get_private_env(service)

  # Create a temporary CSV for testing
  test_data <- data.frame(
    titulo = c("Test Document 1", "Test Document 2"),
    resumo = c("Summary 1", "Summary 2"),
    categoria = c("cat1", "cat2"),
    estado = c("SP", "RJ"),
    data = c("2025-01-01", "2025-01-02"),
    stringsAsFactors = FALSE
  )

  temp_csv <- tempfile(fileext = ".csv")
  write.csv(test_data, temp_csv, row.names = FALSE)

  # Inject test data into private CSV cache
  private_env$csv_data <- read.csv(temp_csv, stringsAsFactors = FALSE)

  # Test search
  results <- service$search_documents(category = "cat1")

  # Clean up
  unlink(temp_csv)

  expect_equal(nrow(results), 1)
  expect_equal(results$titulo[1], "Test Document 1")
})

test_that("Count function works correctly", {
  service <- SearchService$new()

  # Test with empty data
  count <- service$count_documents()
  expect_type(count, "integer")
  expect_gte(count, 0)
})

test_that("Cache operations work correctly", {
  service <- SearchService$new(cache_enabled = TRUE)
  private_env <- get_private_env(service)

  # Test cache save and retrieve
  test_data <- data.frame(test = "data")
  key <- "test_key"

  private_env$save_to_cache(key, test_data)
  cached <- private_env$get_from_cache(key)

  expect_equal(cached, test_data)

  # Test cache clear
  service$clear_cache()
  cached_after_clear <- private_env$get_from_cache(key)

  expect_null(cached_after_clear)
})
