# Test Suite for Scalar Safety Functions
# Tests to ensure all scalar guards prevent vector leaks

library(testthat)
source("../../R/utils/scalar_utils.R")
source("../../R/utils/ui_utils.R")

test_that("scalar_chr handles vectors correctly", {
  expect_equal(scalar_chr(c("a", "b", "c")), "a")
  expect_equal(scalar_chr(character(0)), "—")
  expect_equal(scalar_chr(NULL), "—")
  expect_equal(scalar_chr(NA), "—")
  expect_equal(scalar_chr(c(NA, "test")), "—")
})

test_that("scalar_num handles vectors correctly", {
  expect_equal(scalar_num(c(1, 2, 3)), 1)
  expect_equal(scalar_num(numeric(0)), 0)
  expect_equal(scalar_num(NULL), 0)
  expect_equal(scalar_num(NA), 0)
  expect_equal(scalar_num(c(NA, 5)), 0)
})

test_that("scalar_int handles vectors correctly", {
  expect_equal(scalar_int(c(1L, 2L, 3L)), 1L)
  expect_equal(scalar_int(integer(0)), 0L)
  expect_equal(scalar_int(NULL), 0L)
  expect_equal(scalar_int(NA), 0L)
})

test_that("safe_valueBox always returns scalar values", {
  # Test with various vector inputs
  result1 <- safe_valueBox(c(1, 2, 3), "Test", icon = NULL)
  expect_true("shiny.tag" %in% class(result1))

  result2 <- safe_valueBox(numeric(0), "Empty", icon = NULL)
  expect_true("shiny.tag" %in% class(result2))

  result3 <- safe_valueBox(c("a", "b"), "Multiple", icon = NULL)
  expect_true("shiny.tag" %in% class(result3))
})

test_that("value_box_scalar wrapper prevents scalar errors", {
  expect_equal(value_box_scalar(c(1, 2, 3)), "1")
  expect_equal(value_box_scalar(c("a", "b")), "a")
  expect_equal(value_box_scalar(NULL), "—")
  expect_equal(value_box_scalar(numeric(0)), "0")  # Empty numeric returns numeric default
})

test_that("text_scalar prevents scalar errors in renderText", {
  expect_equal(text_scalar(c(1, 2, 3)), "1")
  expect_equal(text_scalar(c("test", "multiple")), "test")
  expect_equal(text_scalar(NULL), "—")
  expect_equal(text_scalar(numeric(0), prefix = "Value: "), "Value: 0")  # Empty numeric returns numeric default
})

test_that("safe calculation helpers return scalars", {
  df <- data.frame(x = 1:10, y = 11:20)

  expect_equal(length(safe_nrow(df)), 1)
  expect_equal(length(safe_length(c(1, 2, 3))), 1)
  expect_equal(length(safe_n_distinct(c(1, 1, 2, 3))), 1)
  expect_equal(length(safe_mean(1:100)), 1)
  expect_equal(length(safe_sum(1:100)), 1)
  expect_equal(length(safe_max(1:100)), 1)
  expect_equal(length(safe_min(1:100)), 1)
})

test_that("scalar formatting functions return scalars", {
  expect_equal(length(scalar_pct(c(0.5, 0.8))), 1)
  expect_equal(length(scalar_decimal(c(3.14, 2.71))), 1)
  expect_equal(length(scalar_int_formatted(c(1000, 2000))), 1)
})

test_that("vector leak logging detects and records leaks", {
  # Clear any previous logs
  clear_vector_leak_log()

  # Create some vector leaks
  log_vector_leak(c(1, 2, 3), context = "test_1")
  log_vector_leak(c("a", "b"), context = "test_2")

  # Check that leaks were recorded
  report <- get_vector_leak_report()
  expect_equal(report$total_leaks, 2)
  expect_equal(length(report$recent_leaks), 2)

  # Verify leak details
  expect_equal(report$recent_leaks[[1]]$length, 3)
  expect_equal(report$recent_leaks[[1]]$context, "test_1")
  expect_equal(report$recent_leaks[[2]]$length, 2)
  expect_equal(report$recent_leaks[[2]]$context, "test_2")

  # Clean up
  clear_vector_leak_log()
})

test_that("logged scalar functions detect leaks", {
  clear_vector_leak_log()

  # These should trigger leak logging
  result1 <- scalar_chr_logged(c("a", "b", "c"), context = "chr_test")
  result2 <- scalar_num_logged(c(1, 2, 3), context = "num_test")
  result3 <- scalar_int_logged(c(1L, 2L), context = "int_test")

  # Verify results are still scalar
  expect_equal(result1, "a")
  expect_equal(result2, 1)
  expect_equal(result3, 1L)

  # Verify leaks were logged
  report <- get_vector_leak_report()
  expect_equal(report$total_leaks, 3)

  clear_vector_leak_log()
})

# Integration test: Simulate valueBox render with vector data
test_that("valueBox renders correctly with vector data inputs", {
  # Simulate various data provider outputs that might be vectors
  mock_metrics <- list(
    active_sessions = c(5, 10),  # Accidentally returns vector
    queries_per_hour = 100,
    response_time = c(0.5, 0.6, 0.7)  # Vector instead of scalar
  )

  # These should all work without errors
  expect_silent({
    box1 <- safe_valueBox(
      value = scalar_num(mock_metrics$active_sessions, default = 0),
      subtitle = "Active Sessions"
    )

    box2 <- safe_valueBox(
      value = scalar_num(mock_metrics$queries_per_hour, default = 0),
      subtitle = "Queries/Hour"
    )

    box3 <- safe_valueBox(
      value = scalar_num(mock_metrics$response_time, default = 0),
      subtitle = "Response Time"
    )
  })
})
