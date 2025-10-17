#' Test Suite for Consolidated Safety Utilities
#'
#' Tests for R/utils/scalar_utils.R and R/utils/ui_utils.R
#' Created: 2025-01-16

# Load utilities
source("R/utils/scalar_utils.R")

context("Scalar Safety - Basic Extraction")

test_that("scalar functions handle NULL and empty", {
  expect_equal(scalar(NULL, default = NA), NA)
  expect_equal(scalar_chr(NULL), "—")
  expect_equal(scalar_num(NULL), 0)
  expect_equal(scalar_int(NULL), 0L)
  expect_equal(scalar_lgl(NULL), FALSE)
})

test_that("scalar functions extract first element", {
  expect_equal(scalar(c(1, 2, 3)), 1)
  expect_equal(scalar_chr(c("a", "b")), "a")
  expect_equal(scalar_num(c(10, 20)), 10)
  expect_equal(scalar_int(c(5L, 10L)), 5L)
})

test_that("scalar_chr handles empty strings", {
  expect_equal(scalar_chr(""), "—")
  expect_equal(scalar_chr("  "), "—")
  expect_equal(scalar_chr(NA_character_), "—")
})

context("Safe Calculations")

test_that("safe calculation functions work", {
  df <- data.frame(a = 1:3)
  expect_equal(safe_nrow(df), 3)
  expect_equal(safe_nrow(NULL), 0)

  expect_equal(safe_length(c(1, 2, 3)), 3)
  expect_equal(safe_length(NULL), 0)

  expect_equal(safe_mean(c(1, 2, 3)), 2)
  expect_equal(safe_mean(NULL), 0)

  expect_equal(safe_sum(c(1, 2, 3)), 6)
  expect_equal(safe_sum(numeric(0)), 0)
})

context("Safe Conversions")

test_that("safe_as_numeric works", {
  expect_equal(safe_as_numeric("42"), 42)
  expect_equal(safe_as_numeric(NULL), NA_real_)
  expect_equal(safe_as_numeric(""), NA_real_)
  expect_equal(safe_as_numeric("not a number"), NA_real_)
  expect_equal(safe_as_numeric(NULL, default = 0), 0)
})

test_that("safe_as_date works", {
  expect_equal(safe_as_date("2023-01-15"), as.Date("2023-01-15"))
  expect_true(is.na(safe_as_date(NULL)))
  expect_true(is.na(safe_as_date("")))
  expect_true(is.na(safe_as_date("not a date")))
})

context("Existence Checks")

test_that("nz_rows works", {
  df <- data.frame(a = 1:3)
  expect_true(nz_rows(df))
  expect_false(nz_rows(data.frame()))
  expect_false(nz_rows(NULL))
})

test_that("nz_len works", {
  expect_true(nz_len(c(1, 2, 3)))
  expect_false(nz_len(NULL))
  expect_false(nz_len(character(0)))
})

context("UI Helpers")

test_that("value_box_scalar works", {
  expect_equal(value_box_scalar(42), "42")
  expect_equal(value_box_scalar(NULL), "—")
  expect_equal(value_box_scalar(c(1, 2, 3)), "1")
})

test_that("text_scalar works", {
  expect_equal(text_scalar(42), "42")
  expect_equal(text_scalar(NULL), "—")
  expect_equal(text_scalar(42, prefix = "$"), "$42")
})

context("Logging")

test_that("logging functions don't error", {
  expect_silent(log_info("test"))
  expect_silent(log_warn("warning"))
  expect_silent(log_error("error"))
})

context("Integration Tests")

test_that("full workflow with empty data", {
  df <- NULL

  # Check with nz_rows
  expect_false(nz_rows(df))

  # Safe scalar extraction
  count <- scalar_num(if (nz_rows(df)) nrow(df) else NULL)
  expect_equal(count, 0)

  # Value box display
  display <- value_box_scalar(count)
  expect_equal(display, "0")
})

test_that("full workflow with valid data", {
  df <- data.frame(state = c("SP", "RJ"), count = c(100, 200))

  # Check
  expect_true(nz_rows(df))

  # Extract
  first_state <- scalar_chr(df$state)
  expect_equal(first_state, "SP")

  # Calculate
  total <- safe_sum(df$count)
  expect_equal(total, 300)

  # Display
  display <- value_box_scalar(total, format_fn = function(x) format(x, big.mark = ","))
  expect_equal(display, "300")
})
