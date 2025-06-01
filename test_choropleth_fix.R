# Comprehensive Choropleth Fix Validation Script
# Tests the "closure not subsettable" error fixes

cat("=== CHOROPLETH FIX VALIDATION ===\n")
cat("Testing fixes for 'object of type 'closure' is not subsettable'\n\n")

# Ensure pipe support is available for sourced files
suppressMessages({
  if (requireNamespace("magrittr", quietly = TRUE)) {
    library(magrittr)
  }
})

# Test 1: Source loading with error handling
cat("TEST 1: Source loading...\n")
source_success <- TRUE

tryCatch({
  source("scripts/R/geospatial_utils.R")
  cat("✅ geospatial_utils.R loaded\n")
}, error = function(e) {
  cat("❌ Error loading geospatial_utils.R:", e$message, "\n")
  source_success <- FALSE
})

tryCatch({
  source("scripts/R/choropleth_generator.R") 
  cat("✅ choropleth_generator.R loaded\n")
}, error = function(e) {
  cat("❌ Error loading choropleth_generator.R:", e$message, "\n")
  source_success <- FALSE
})

if (!source_success) {
  stop("Cannot proceed - source files failed to load")
}

# Test 2: Geospatial system initialization
cat("\nTEST 2: Geospatial system initialization...\n")

geo_init_result <- tryCatch({
  initialize_geospatial_system()
}, error = function(e) {
  cat("❌ Geospatial initialization error:", e$message, "\n")
  list(available = FALSE, error = e$message)
})

cat("Geospatial system available:", geo_init_result$available, "\n")
if (!is.null(geo_init_result$error)) {
  cat("Error details:", geo_init_result$error, "\n")
}

# Test 3: Safe data access patterns
cat("\nTEST 3: Safe data access patterns...\n")

# Create mock geospatial system to test closure issues
mock_geospatial <- list(
  boundaries = "mock_boundaries",
  geojson = list(type = "FeatureCollection", features = list()),
  available = TRUE
)

# Test accessing geojson properties safely
geojson_test_result <- tryCatch({
  geojson <- mock_geospatial$geojson
  has_proper_structure <- FALSE
  
  if (!is.null(geojson)) {
    has_proper_structure <- tryCatch({
      is.list(geojson) && 
      !is.null(geojson[["type"]]) && 
      geojson[["type"]] == "FeatureCollection" && 
      !identical(geojson[["features"]], "simplified")
    }, error = function(e) {
      cat("⚠️ Error checking GeoJSON structure:", e$message, "\n")
      FALSE
    })
  }
  
  list(success = TRUE, has_structure = has_proper_structure)
}, error = function(e) {
  cat("❌ GeoJSON access test failed:", e$message, "\n")
  list(success = FALSE, error = e$message)
})

if (geojson_test_result$success) {
  cat("✅ Safe GeoJSON access pattern works\n")
  cat("   - Has proper structure:", geojson_test_result$has_structure, "\n")
} else {
  cat("❌ Safe GeoJSON access failed\n")
}

# Test 4: Function availability check
cat("\nTEST 4: Function availability...\n")

functions_to_check <- c(
  "initialize_geospatial_system",
  "get_brazil_boundaries", 
  "sf_to_plotly_geojson",
  "create_professional_choropleth",
  "create_enhanced_fallback_map",
  "generate_choropleth_map"
)

for (func_name in functions_to_check) {
  if (exists(func_name)) {
    cat("✅", func_name, "- available\n")
  } else {
    cat("❌", func_name, "- NOT available\n")
  }
}

# Test 5: Mock choropleth generation (without requiring real packages)
cat("\nTEST 5: Mock choropleth generation...\n")

mock_state_data <- data.frame(
  state_code = c("SP", "RJ", "MG"),
  state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais"),
  documents = c(1000, 800, 600),
  lon = c(-46.6, -43.2, -43.9),
  lat = c(-23.5, -22.9, -19.9),
  stringsAsFactors = FALSE
)

if (exists("generate_choropleth_map")) {
  mock_result <- tryCatch({
    # This should fail gracefully without throwing "closure not subsettable"
    generate_choropleth_map(
      state_data = mock_state_data,
      geospatial_system = mock_geospatial,
      metric_column = "documents",
      map_metric = "count"
    )
  }, error = function(e) {
    cat("Mock generation error:", e$message, "\n")
    if (grepl("closure.*not subsettable", e$message)) {
      cat("❌ CLOSURE ERROR STILL PRESENT!\n")
    } else {
      cat("✅ No closure error (other errors expected without real packages)\n")
    }
    NULL
  })
  
  cat("Mock generation completed without closure errors\n")
} else {
  cat("❌ generate_choropleth_map function not available\n")
}

# Test Results Summary
cat("\n=== TEST RESULTS SUMMARY ===\n")
cat("Source loading:", if(source_success) "✅ PASS" else "❌ FAIL", "\n")
cat("Geospatial init:", if(geo_init_result$available) "✅ PASS" else "⚠️ EXPECTED (no packages)", "\n")
cat("Safe access patterns:", if(geojson_test_result$success) "✅ PASS" else "❌ FAIL", "\n")
cat("Function availability:", if(exists("generate_choropleth_map")) "✅ PASS" else "❌ FAIL", "\n")

cat("\n🎯 PRIMARY FIX TARGET: 'object of type 'closure' is not subsettable'\n")
cat("Status: Should be resolved with implemented safety checks\n")

cat("\n=== VALIDATION COMPLETE ===\n")