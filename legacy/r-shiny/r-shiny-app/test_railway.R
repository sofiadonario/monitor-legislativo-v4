#!/usr/bin/env Rscript

# Test script for Railway deployment
cat("Testing R Shiny app for Railway deployment...\n")

# Test 1: Check R version
cat("\n1. R Version:\n")
print(R.version.string)

# Test 2: Check required packages
cat("\n2. Checking required packages:\n")
required_packages <- c("shiny", "shinydashboard", "DT", "httr", "jsonlite", "futile.logger")
for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat(paste("✓", pkg, "is installed\n"))
  } else {
    cat(paste("✗", pkg, "is NOT installed\n"))
  }
}

# Test 3: Try to load the app
cat("\n3. Testing app load:\n")
tryCatch({
  source("app.R", local = TRUE)
  cat("✓ App loads successfully\n")
}, error = function(e) {
  cat("✗ Error loading app:", e$message, "\n")
})

# Test 4: Check directories
cat("\n4. Checking required directories:\n")
dirs <- c("data", "data/cache", "data/geographic", "www", "logs", "exports", "R")
for (dir in dirs) {
  if (dir.exists(dir)) {
    cat(paste("✓", dir, "exists\n"))
  } else {
    cat(paste("✗", dir, "does NOT exist\n"))
  }
}

cat("\nTest complete!\n")