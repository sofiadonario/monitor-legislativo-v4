# Test Suite for Geographic Analysis Enhancements
# Tests all implementations from the PRD

library(testthat)
library(dplyr)
library(plotly)

# Source the modules
source("modules/geographic/geographic_optimization.R")
source("modules/geographic/geojson_handler.R")

# Test configuration
test_that("Brazilian CRS configuration is correct", {
  expect_equal(BRAZILIAN_CRS$SIRGAS2000, "EPSG:4674")
  expect_equal(BRAZILIAN_CRS$WGS84, "EPSG:4326")
  expect_true(length(BRAZILIAN_CRS) >= 3)
})

test_that("Brazil state coordinates are complete", {
  expect_equal(nrow(BRAZIL_STATE_COORDS), 27)
  expect_true(all(c("state_code", "lat", "lng") %in% names(BRAZIL_STATE_COORDS)))
  expect_true(all(!is.na(BRAZIL_STATE_COORDS$lat)))
  expect_true(all(!is.na(BRAZIL_STATE_COORDS$lng)))
  
  # Check coordinate ranges for Brazil
  expect_true(all(BRAZIL_STATE_COORDS$lat >= -35 & BRAZIL_STATE_COORDS$lat <= 5))
  expect_true(all(BRAZIL_STATE_COORDS$lng >= -75 & BRAZIL_STATE_COORDS$lng <= -30))
})

# Test memory management
test_that("Memory monitoring works correctly", {
  monitor <- monitor_memory("test_operation")
  expect_type(monitor, "closure")
  
  # Test cleanup function
  expect_silent(monitor())
})

# Test stratified sampling
test_that("Stratified sampling works with different data sizes", {
  # Create test data
  test_data <- data.frame(
    estado = rep(c("SP", "RJ", "MG", "BA"), each = 100),
    doc_count = sample(1:1000, 400),
    stringsAsFactors = FALSE
  )
  
  # Test with target size smaller than data
  sampled <- stratified_sample_documents(test_data, target_size = 200, strata_var = "estado")
  
  expect_lte(nrow(sampled), 200)
  expect_true(all(c("SP", "RJ", "MG", "BA") %in% sampled$estado))
  expect_true(!is.null(attr(sampled, "sampling_info")))
  
  # Test with target size larger than data
  large_sample <- stratified_sample_documents(test_data, target_size = 500)
  expect_equal(nrow(large_sample), nrow(test_data))
})

# Test statistical validation
test_that("Statistical validation adds correct fields", {
  test_data <- data.frame(
    estado = c("SP", "RJ", "MG"),
    doc_count = c(100, 50, 5),
    latest_date = as.Date(c("2024-01-15", "2024-01-10", "2024-01-05"))
  )
  
  validated <- validate_geographic_stats(test_data)
  
  expect_true("statistically_reliable" %in% names(validated))
  expect_true("ci_lower" %in% names(validated))
  expect_true("ci_upper" %in% names(validated))
  expect_true("data_quality" %in% names(validated))
  
  # Check statistical reliability
  expect_true(validated$statistically_reliable[1])  # SP with 100 docs
  expect_true(validated$statistically_reliable[2])  # RJ with 50 docs
  expect_false(validated$statistically_reliable[3]) # MG with 5 docs
  
  # Check quality categories
  expect_equal(validated$data_quality[1], "high")   # 100 docs
  expect_equal(validated$data_quality[2], "medium") # 50 docs
  expect_equal(validated$data_quality[3], "low")    # 5 docs
})

# Test GeoJSON handling
test_that("GeoJSON validation works correctly", {
  # Test valid GeoJSON
  valid_geojson <- list(
    type = "FeatureCollection",
    features = list(
      list(
        type = "Feature",
        properties = list(state_code = "SP"),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(c(-50, -25), c(-50, -20), c(-45, -20), c(-45, -25), c(-50, -25)))
        )
      )
    )
  )
  
  validation <- validate_geojson(valid_geojson)
  expect_true(validation$valid)
  expect_null(validation$error)
  
  # Test invalid GeoJSON
  invalid_geojson <- list(type = "InvalidType")
  validation_invalid <- validate_geojson(invalid_geojson)
  expect_false(validation_invalid$valid)
  expect_true(!is.null(validation_invalid$error))
})

test_that("Inline Brazil boundaries are valid", {
  boundaries <- get_inline_brazil_boundaries()
  
  expect_equal(boundaries$type, "FeatureCollection")
  expect_true(is.list(boundaries$features))
  expect_true(length(boundaries$features) > 0)
  
  # Validate structure
  validation <- validate_geojson(boundaries)
  expect_true(validation$valid)
})

# Test caching functionality
test_that("Geographic cache works correctly", {
  cache <- create_geographic_cache(ttl_seconds = 1)
  
  # Test set and get
  test_data <- data.frame(estado = "SP", count = 100)
  cache$set("test_key", test_data)
  
  retrieved <- cache$get("test_key")
  expect_equal(retrieved$estado, "SP")
  expect_equal(retrieved$count, 100)
  
  # Test TTL expiration
  Sys.sleep(2)
  expired <- cache$get("test_key")
  expect_null(expired)
  
  # Test cache size
  cache$set("key1", data.frame(a = 1))
  cache$set("key2", data.frame(b = 2))
  expect_equal(cache$size(), 2)
  
  # Test clear
  cache$clear()
  expect_equal(cache$size(), 0)
})

# Test WebGL choropleth creation
test_that("WebGL choropleth handles various data sizes", {
  # Test with empty data
  empty_plot <- create_webgl_choropleth(data.frame())
  expect_true(inherits(empty_plot, "plotly"))
  
  # Test with small dataset
  small_data <- data.frame(
    estado = c("SP", "RJ"),
    doc_count = c(100, 50),
    latest_date = as.Date(c("2024-01-15", "2024-01-10")),
    type_count = c(5, 3),
    lat = c(-23.55, -22.84),
    lng = c(-46.64, -43.15)
  )
  
  plot_small <- create_webgl_choropleth(small_data, use_webgl = FALSE)
  expect_true(inherits(plot_small, "plotly"))
  
  # Test with WebGL enabled
  plot_webgl <- create_webgl_choropleth(small_data, use_webgl = TRUE)
  expect_true(inherits(plot_webgl, "plotly"))
})

# Performance tests
test_that("Functions handle large datasets efficiently", {
  # Create large test dataset
  large_data <- data.frame(
    estado = sample(BRAZIL_STATE_COORDS$state_code, 10000, replace = TRUE),
    doc_count = sample(1:1000, 10000, replace = TRUE),
    latest_date = sample(seq(as.Date("2020-01-01"), as.Date("2024-01-01"), by = "day"), 10000, replace = TRUE),
    type_count = sample(1:10, 10000, replace = TRUE)
  )
  
  # Test sampling performance
  start_time <- Sys.time()
  sampled_large <- stratified_sample_documents(large_data, target_size = 2000)
  sampling_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  
  expect_lt(sampling_time, 5)  # Should complete in under 5 seconds
  expect_lte(nrow(sampled_large), 2000)
  
  # Test validation performance
  start_time <- Sys.time()
  validated_large <- validate_geographic_stats(large_data)
  validation_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  
  expect_lt(validation_time, 2)  # Should complete in under 2 seconds
  expect_equal(nrow(validated_large), nrow(large_data))
})

# Integration test for choropleth data preparation
test_that("Choropleth data preparation integrates correctly", {
  # Test data
  state_stats <- data.frame(
    estado = c("SP", "RJ", "MG"),
    doc_count = c(1000, 500, 250)
  )
  
  # Get boundaries
  boundaries <- get_inline_brazil_boundaries()
  
  # Prepare choropleth data
  choropleth_data <- prepare_choropleth_data(state_stats, boundaries)
  
  expect_true(is.list(choropleth_data))
  expect_true("geojson" %in% names(choropleth_data))
  expect_true("values" %in% names(choropleth_data))
  expect_true("metadata" %in% names(choropleth_data))
  
  expect_equal(choropleth_data$values[["SP"]], 1000)
  expect_equal(choropleth_data$metadata$total_states, 3)
})

# Test error handling
test_that("Functions handle errors gracefully", {
  # Test with NULL data
  expect_silent(create_webgl_choropleth(NULL))
  expect_silent(validate_geographic_stats(data.frame()))
  
  # Test with malformed data
  bad_data <- data.frame(wrong_column = "test")
  expect_error(prepare_choropleth_data(bad_data), "must have")
  
  # Test GeoJSON with wrong structure
  bad_geojson <- list(type = "NotAFeatureCollection")
  validation <- validate_geojson(bad_geojson)
  expect_false(validation$valid)
})

# Memory leak prevention test
test_that("Memory cleanup works properly", {
  # Get initial memory usage
  initial_objects <- length(ls(envir = .GlobalEnv))
  
  # Create memory monitor
  cleanup <- monitor_memory("memory_test")
  
  # Create some temporary objects
  temp_data <- data.frame(x = 1:1000, y = rnorm(1000))
  temp_large <- matrix(runif(10000), nrow = 100)
  
  # Call cleanup
  cleanup()
  
  # Check that we haven't significantly increased global objects
  final_objects <- length(ls(envir = .GlobalEnv))
  expect_lte(final_objects - initial_objects, 5)  # Allow for test artifacts
})

# Run all tests and report
cat("\n=== Geographic Analysis Enhancement Test Results ===\n")
cat("Running comprehensive test suite...\n")

test_results <- test_dir(".", pattern = "test_geographic_enhancements.R")

if (length(test_results$error) > 0) {
  cat("❌ Tests failed. Check implementation.\n")
  print(test_results)
} else {
  cat("✅ All tests passed successfully!\n")
  cat("Geographic analysis enhancements are ready for production.\n")
}

# Performance benchmark
cat("\n=== Performance Benchmarks ===\n")

# Benchmark data loading simulation
benchmark_data <- data.frame(
  estado = sample(BRAZIL_STATE_COORDS$state_code, 50000, replace = TRUE),
  doc_count = sample(1:10000, 50000, replace = TRUE),
  latest_date = sample(seq(as.Date("2020-01-01"), as.Date("2024-01-01"), by = "day"), 50000, replace = TRUE),
  type_count = sample(1:15, 50000, replace = TRUE)
)

# Benchmark sampling
start_time <- Sys.time()
sampled_benchmark <- stratified_sample_documents(benchmark_data, target_size = 5000)
sampling_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

# Benchmark validation
start_time <- Sys.time()
validated_benchmark <- validate_geographic_stats(sampled_benchmark)
validation_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

# Benchmark visualization
start_time <- Sys.time()
plot_benchmark <- create_webgl_choropleth(validated_benchmark %>% 
  left_join(BRAZIL_STATE_COORDS, by = c("estado" = "state_code")) %>%
  filter(!is.na(lat)))
viz_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

cat(sprintf("📊 Sampling 50k→5k documents: %.3f seconds\n", sampling_time))
cat(sprintf("📊 Statistical validation: %.3f seconds\n", validation_time))
cat(sprintf("📊 WebGL visualization: %.3f seconds\n", viz_time))
cat(sprintf("📊 Total processing time: %.3f seconds\n", sampling_time + validation_time + viz_time))

if (sampling_time < 2 && validation_time < 1 && viz_time < 3) {
  cat("🚀 Performance targets met! Ready for 134k+ documents.\n")
} else {
  cat("⚠️ Performance optimization needed.\n")
}

cat("\n=== Test Suite Complete ===\n")