# Diagnostic script for choropleth map issues
# This will help identify why filled regions aren't showing

library(plotly)
library(dplyr)

cat("============================================\n")
cat("CHOROPLETH DIAGNOSTIC TEST\n")
cat("============================================\n\n")

# Step 1: Check required packages
cat("1. CHECKING REQUIRED PACKAGES:\n")
packages <- c("geobr", "sf", "geojsonio", "jsonlite", "plotly")
for (pkg in packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("  ✓", pkg, "is installed\n")
  } else {
    cat("  ✗", pkg, "is NOT installed\n")
  }
}

# Step 2: Test geospatial system initialization
cat("\n2. TESTING GEOSPATIAL SYSTEM:\n")
source("scripts/R/geospatial_utils.R")
geo_system <- initialize_geospatial_system()

if (!isTRUE(is.null(geo_system)) && geo_system$available) {
  cat("  ✓ Geospatial system initialized successfully\n")
  cat("  - States loaded:", geo_system$state_count, "\n")
  cat("  - Cache directory:", geo_system$cache_dir, "\n")
} else {
  cat("  ✗ Geospatial system failed to initialize\n")
  stop("Cannot proceed without geospatial system")
}

# Step 3: Check GeoJSON structure
cat("\n3. CHECKING GEOJSON STRUCTURE:\n")
if (!is.null(geo_system$geojson)) {
  if (is.character(geo_system$geojson)) {
    cat("  - GeoJSON is a character string (JSON text)\n")
    # Try to parse it
    tryCatch({
      json_obj <- jsonlite::fromJSON(geo_system$geojson)
      cat("  ✓ GeoJSON parsed successfully\n")
      cat("  - Type:", json_obj$type, "\n")
      cat("  - Features:", length(json_obj$features), "\n")
      
      # Check first feature structure
      if (length(json_obj$features) > 0) {
        first_feature <- json_obj$features[[1]]
        cat("  - First feature properties:\n")
        cat("    - State code:", first_feature$properties$abbrev_state, "\n")
        cat("    - State name:", first_feature$properties$name_state, "\n")
      }
    }, error = function(e) {
      cat("  ✗ Failed to parse GeoJSON:", e$message, "\n")
    })
  } else if (is.list(geo_system$geojson)) {
    cat("  - GeoJSON is already a list object\n")
    cat("  - Type:", geo_system$geojson$type, "\n")
    if (geo_system$geojson$features == "simplified") {
      cat("  ⚠ GeoJSON is in simplified mode (no actual geometry)\n")
    }
  }
} else {
  cat("  ✗ No GeoJSON available\n")
}

# Step 4: Test with sample data
cat("\n4. TESTING CHOROPLETH WITH SAMPLE DATA:\n")

# Create sample state data
sample_data <- data.frame(
  state_code = c("SP", "RJ", "MG", "RS", "PR"),
  state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", "Paraná"),
  documents = c(4500, 2800, 1500, 800, 600),
  stringsAsFactors = FALSE
)

cat("  Sample data created with", nrow(sample_data), "states\n")

# Step 5: Try creating a choropleth
cat("\n5. ATTEMPTING CHOROPLETH CREATION:\n")

if (!is.null(geo_system$geojson)) {
  tryCatch({
    # Parse GeoJSON if it's a string
    if (is.character(geo_system$geojson)) {
      geojson_obj <- jsonlite::fromJSON(geo_system$geojson)
    } else {
      geojson_obj <- geo_system$geojson
    }
    
    # Check if we have proper geometry
    if (!isTRUE(is.null(geojson_obj$features)) && geojson_obj$features != "simplified") {
      cat("  Creating choropleth with proper GeoJSON...\n")
      
      # Create choropleth
      fig <- plot_ly(
        type = "choroplethmapbox",
        geojson = geojson_obj,
        locations = sample_data$state_code,
        z = sample_data$documents,
        featureidkey = "properties.abbrev_state",
        colorscale = "Viridis",
        marker = list(
          line = list(color = "white", width = 1),
          opacity = 0.85
        ),
        colorbar = list(
          title = "Documents",
          thickness = 20,
          len = 0.8
        )
      ) %>%
      layout(
        mapbox = list(
          style = "carto-positron",
          zoom = 3,
          center = list(lat = -14, lon = -53)
        ),
        margin = list(l = 0, r = 0, t = 0, b = 0)
      )
      
      cat("  ✓ Choropleth created successfully\n")
      
      # Save to HTML for inspection
      htmlwidgets::saveWidget(fig, "test_choropleth.html", selfcontained = TRUE)
      cat("  ✓ Saved test map to test_choropleth.html\n")
      
    } else {
      cat("  ⚠ GeoJSON is simplified - cannot create true choropleth\n")
      cat("  Falling back to scatter map...\n")
    }
    
  }, error = function(e) {
    cat("  ✗ Choropleth creation failed:", e$message, "\n")
    cat("\n  ERROR DETAILS:\n")
    print(e)
  })
}

# Step 6: Check cache files
cat("\n6. CHECKING CACHE FILES:\n")
cache_dir <- geo_system$cache_dir
if (dir.exists(cache_dir)) {
  files <- list.files(cache_dir, full.names = FALSE)
  cat("  Cache directory contents:\n")
  for (f in files) {
    info <- file.info(file.path(cache_dir, f))
    cat("  -", f, "(", round(info$size/1024, 2), "KB)\n")
  }
  
  # Check GeoJSON cache specifically
  geojson_cache <- file.path(cache_dir, "brazil_states_geojson.json")
  if (file.exists(geojson_cache)) {
    content <- readLines(geojson_cache, n = 1)
    if (content == "BOUNDARIES_ONLY") {
      cat("\n  ⚠ ISSUE FOUND: GeoJSON cache contains 'BOUNDARIES_ONLY' marker\n")
      cat("  This means geojsonio failed to convert boundaries previously.\n")
      cat("  SOLUTION: Delete cache and reinitialize\n")
    }
  }
}

cat("\n============================================\n")
cat("DIAGNOSIS COMPLETE\n")
cat("============================================\n")