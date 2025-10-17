#' Test Suite for Safety Library (R/safety.R)
#'
#' Comprehensive tests for defensive programming utilities
#' Created: 2025-01-16

context("Safety Library - Scalar Extraction")

test_that("as_scalar handles NULL and empty vectors", {
  # NULL input with allow_na=TRUE
  expect_equal(as_scalar(NULL, "test", allow_na = TRUE), NA)

  # Empty vector with allow_na=TRUE
  expect_equal(as_scalar(character(0), "test", allow_na = TRUE), NA)

  # NULL input with allow_na=FALSE should error
  expect_error(
    as_scalar(NULL, "test", allow_na = FALSE),
    "Missing required value: test"
  )

  # Empty string vector
  expect_equal(as_scalar("", "test", allow_na = TRUE), NA)
  expect_equal(as_scalar(c("  ", "\t"), "test", allow_na = TRUE), NA)
})

test_that("as_scalar extracts first element from vectors", {
  # Single element
  expect_equal(as_scalar(42, "test"), 42)
  expect_equal(as_scalar("hello", "test"), "hello")

  # Multiple elements - should take first
  expect_warning(
    result <- as_scalar(c(1, 2, 3), "test"),
    "Multiple values where scalar expected"
  )
  expect_equal(result, 1)

  # Character vector
  expect_warning(
    result <- as_scalar(c("a", "b", "c"), "test"),
    "Multiple values where scalar expected"
  )
  expect_equal(result, "a")
})

test_that("as_scalar_chr converts to character", {
  expect_equal(as_scalar_chr(42, "test"), "42")
  expect_equal(as_scalar_chr("hello", "test"), "hello")
  expect_equal(as_scalar_chr(NULL, "test", allow_na = TRUE), NA_character_)
})

test_that("as_scalar_num converts to numeric", {
  expect_equal(as_scalar_num("42", "test"), 42)
  expect_equal(as_scalar_num(42, "test"), 42)
  expect_equal(as_scalar_num(NULL, "test", allow_na = TRUE), NA_real_)
})

test_that("as_scalar_int converts to integer", {
  expect_equal(as_scalar_int("42", "test"), 42L)
  expect_equal(as_scalar_int(42.7, "test"), 42L)
  expect_equal(as_scalar_int(NULL, "test", allow_na = TRUE), NA_integer_)
})

context("Safety Library - Data Frame Validation")

test_that("nz_rows handles empty data frames", {
  # NULL input
  expect_null(nz_rows(NULL, "test"))

  # Empty data frame
  empty_df <- data.frame()
  expect_null(nz_rows(empty_df, "test"))

  # Data frame with 0 rows but columns
  zero_row_df <- data.frame(a = integer(0), b = character(0))
  expect_null(nz_rows(zero_row_df, "test"))
})

test_that("nz_rows returns valid data frames", {
  # Valid data frame
  df <- data.frame(a = 1:3, b = letters[1:3])
  result <- nz_rows(df, "test")
  expect_equal(result, df)
  expect_equal(nrow(result), 3)
})

test_that("nz_rows rejects non-data.frame objects", {
  # Vector
  expect_null(nz_rows(c(1, 2, 3), "test"))

  # List
  expect_null(nz_rows(list(a = 1, b = 2), "test"))

  # Matrix (not a data.frame)
  expect_null(nz_rows(matrix(1:9, nrow = 3), "test"))
})

context("Safety Library - Vector Validation")

test_that("nz_length handles empty vectors", {
  expect_null(nz_length(NULL, "test"))
  expect_null(nz_length(character(0), "test"))
  expect_null(nz_length(numeric(0), "test"))
})

test_that("nz_length returns valid vectors", {
  expect_equal(nz_length(c(1, 2, 3), "test"), c(1, 2, 3))
  expect_equal(nz_length("hello", "test"), "hello")
})

context("Safety Library - Safe Conversions")

test_that("safe_as_numeric handles invalid inputs", {
  # NULL
  expect_equal(safe_as_numeric(NULL), NA_real_)
  expect_equal(safe_as_numeric(NULL, default = 0), 0)

  # Empty string
  expect_equal(safe_as_numeric(""), NA_real_)
  expect_equal(safe_as_numeric("", default = 0), 0)

  # Invalid string
  expect_equal(safe_as_numeric("not a number"), NA_real_)
  expect_equal(safe_as_numeric("not a number", default = 0), 0)
})

test_that("safe_as_numeric converts valid inputs", {
  expect_equal(safe_as_numeric("42"), 42)
  expect_equal(safe_as_numeric(42), 42)
  expect_equal(safe_as_numeric("3.14"), 3.14)
})

test_that("safe_as_date handles invalid inputs", {
  # NULL
  expect_equal(safe_as_date(NULL), NA)
  expect_equal(safe_as_date(NULL, default = as.Date("2020-01-01")), as.Date("2020-01-01"))

  # Empty string
  expect_equal(safe_as_date(""), NA)

  # Invalid date string
  expect_equal(safe_as_date("not a date"), NA)
})

test_that("safe_as_date converts valid inputs", {
  expect_equal(safe_as_date("2023-01-15"), as.Date("2023-01-15"))
  expect_equal(safe_as_date(as.Date("2023-01-15")), as.Date("2023-01-15"))
})

context("Safety Library - Logging")

test_that("logging functions don't error", {
  expect_silent(log_info("test message"))
  expect_silent(log_warn("warning message"))
  expect_silent(log_error("error message"))

  # Debug only logs when DEBUG_SAFETY=TRUE
  options(DEBUG_SAFETY = FALSE)
  expect_silent(log_debug("debug message"))

  options(DEBUG_SAFETY = TRUE)
  expect_output(log_debug("debug message"), "DEBUG.*debug message")
  options(DEBUG_SAFETY = FALSE)
})

context("Safety Library - UI Components")

test_that("empty_card creates HTML div", {
  card <- empty_card("Test message")
  expect_true(inherits(card, "shiny.tag"))
  expect_true(grepl("alert alert-info", as.character(card)))
  expect_true(grepl("Test message", as.character(card)))
})

test_that("error_card creates HTML div", {
  card <- error_card("Error message")
  expect_true(inherits(card, "shiny.tag"))
  expect_true(grepl("alert alert-danger", as.character(card)))
  expect_true(grepl("Error message", as.character(card)))
})

test_that("loading_card creates HTML div", {
  card <- loading_card("Loading...")
  expect_true(inherits(card, "shiny.tag"))
  expect_true(grepl("alert alert-secondary", as.character(card)))
  expect_true(grepl("Loading", as.character(card)))
})

context("Safety Library - Safe Render")

test_that("safe_render handles NULL results", {
  result <- safe_render(NULL, empty_msg = "No data")
  expect_true(inherits(result, "shiny.tag"))
  expect_true(grepl("No data", as.character(result)))
})

test_that("safe_render handles empty data frames", {
  result <- safe_render(data.frame(), empty_msg = "No rows")
  expect_true(inherits(result, "shiny.tag"))
  expect_true(grepl("No rows", as.character(result)))
})

test_that("safe_render catches errors", {
  result <- safe_render(stop("Test error"), error_msg = "Failed to render")
  expect_true(inherits(result, "shiny.tag"))
  expect_true(grepl("Failed to render", as.character(result)))
})

test_that("safe_render returns valid results", {
  df <- data.frame(a = 1:3, b = letters[1:3])
  result <- safe_render(df)
  expect_equal(result, df)
})

context("Safety Library - Integration Tests")

test_that("safety library handles empty data workflow", {
  # Simulate empty query result
  query_result <- NULL

  # Check with nz_rows
  df <- nz_rows(query_result, "query")
  expect_null(df)

  # Extract scalar from empty result
  count <- as_scalar(df$count, "count", allow_na = TRUE)
  expect_true(is.na(count))
})

test_that("safety library handles valid data workflow", {
  # Simulate valid query result
  query_result <- data.frame(
    state = c("SP", "RJ", "MG"),
    count = c(100, 200, 150)
  )

  # Check with nz_rows
  df <- nz_rows(query_result, "query")
  expect_equal(nrow(df), 3)

  # Extract scalar safely
  first_state <- as_scalar(df$state, "state")
  expect_equal(first_state, "SP")

  # Convert count safely
  total <- sum(safe_as_numeric(df$count), na.rm = TRUE)
  expect_equal(total, 450)
})

test_that("init_safety configures options", {
  init_safety(debug = TRUE)
  expect_true(getOption("DEBUG_SAFETY"))

  init_safety(debug = FALSE)
  expect_false(getOption("DEBUG_SAFETY"))
})
