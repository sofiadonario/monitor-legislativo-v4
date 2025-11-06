#!/usr/bin/env Rscript

# ==============================================================================
# DOWNLOAD GEOGRAPHIC DATA FOR MONITOR LEGISLATIVO V4
# ==============================================================================
# This script downloads the Brazil states GeoJSON file for offline use
# Run this to ensure maps work even without internet connection
# ==============================================================================

cat("==============================================================================\n")
cat("Geographic Data Download Script\n")
cat("==============================================================================\n\n")

# Create data directory if it doesn't exist
if (!dir.exists("data")) {
  dir.create("data", showWarnings = FALSE)
  cat("✅ Created data/ directory\n")
}

if (!dir.exists("data/geo")) {
  dir.create("data/geo", showWarnings = FALSE)
  cat("✅ Created data/geo/ directory\n")
}

# URL for Brazil states GeoJSON
url <- "https://raw.githubusercontent.com/codeforamerica/click_that_hood/master/public/data/brazil-states.geojson"

# Download locations
locations <- c(
  "data/brazil_states.geojson",
  "data/geo/brazil_states.geojson"
)

cat("\nDownloading Brazil states GeoJSON from:\n")
cat(url, "\n\n")

# Download to both locations
for (filepath in locations) {
  cat("Downloading to:", filepath, "... ")
  
  tryCatch({
    download.file(
      url = url,
      destfile = filepath,
      method = "auto",
      quiet = TRUE
    )
    
    # Verify the file
    if (file.exists(filepath)) {
      size_mb <- round(file.info(filepath)$size / 1024 / 1024, 2)
      cat("✅ Success (", size_mb, "MB)\n", sep = "")
    } else {
      cat("❌ Failed\n")
    }
  }, error = function(e) {
    cat("❌ Error:", e$message, "\n")
  })
}

# Test if sf can read the file
cat("\nTesting geographic data...\n")
if (requireNamespace("sf", quietly = TRUE)) {
  test_file <- locations[1]
  if (file.exists(test_file)) {
    tryCatch({
      shp <- sf::st_read(test_file, quiet = TRUE)
      cat("✅ Successfully loaded", nrow(shp), "states\n")
      cat("   Available fields:", paste(names(shp), collapse = ", "), "\n")
      
      # Check for important fields
      if ("sigla" %in% names(shp)) {
        cat("   ✅ 'sigla' field found (state abbreviations)\n")
      } else if ("abbreviation" %in% names(shp)) {
        cat("   ⚠️  'abbreviation' field found (will be mapped to 'sigla')\n")
      } else {
        cat("   ⚠️  No state abbreviation field found - may cause issues with data merge\n")
      }
    }, error = function(e) {
      cat("❌ Failed to load GeoJSON:", e$message, "\n")
    })
  }
} else {
  cat("⚠️  sf package not installed - cannot test file\n")
  cat("   Install with: install.packages('sf')\n")
}

cat("\n==============================================================================\n")
cat("Download complete!\n")
cat("The application will now use local geographic data for better performance.\n")
cat("==============================================================================\n")
