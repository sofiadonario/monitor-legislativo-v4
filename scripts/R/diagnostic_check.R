# Diagnostic script to check Railway deployment environment

cat("=== RAILWAY DEPLOYMENT DIAGNOSTIC ===\n")
cat("Current working directory:", getwd(), "\n")
cat("R version:", R.version.string, "\n")
cat("\n")

# List all files in current directory
cat("Files in current directory:\n")
files <- list.files(".", all.files = TRUE, recursive = FALSE)
for (f in files) {
  info <- file.info(f)
  cat(sprintf("  %s (size: %d bytes)\n", f, info$size))
}
cat("\n")

# Check for database.R specifically
if (file.exists("database.R")) {
  cat("✓ database.R EXISTS\n")
  cat("  File size:", file.info("database.R")$size, "bytes\n")
  cat("  Can read:", file.access("database.R", 4) == 0, "\n")
} else {
  cat("✗ database.R NOT FOUND\n")
}
cat("\n")

# Check for app.R
if (file.exists("app.R")) {
  cat("✓ app.R EXISTS\n")
  cat("  File size:", file.info("app.R")$size, "bytes\n")
} else {
  cat("✗ app.R NOT FOUND\n")
}
cat("\n")

# Environment variables
cat("Environment variables:\n")
cat("  PORT:", Sys.getenv("PORT", "not set"), "\n")
cat("  R_CONFIG_ACTIVE:", Sys.getenv("R_CONFIG_ACTIVE", "not set"), "\n")
cat("  DATABASE_URL:", if(nchar(Sys.getenv("DATABASE_URL")) > 0) "***SET***" else "not set", "\n")
cat("\n")

# Try to source database.R
cat("Attempting to source database.R...\n")
tryCatch({
  source("../../database.R")
  cat("✓ Successfully sourced database.R\n")
}, error = function(e) {
  cat("✗ Error sourcing database.R:\n")
  cat("  ", e$message, "\n")
})

# Check R package installation
cat("\nChecking R package installation:\n")
required_packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', 
                       'plotly', 'ggplot2', 'leaflet', 'stringr', 'markdown',
                       'DBI', 'RPostgres', 'pool', 'config', 'digest')

for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat(sprintf("  ✓ %s - AVAILABLE\n", pkg))
  } else {
    cat(sprintf("  ✗ %s - MISSING\n", pkg))
  }
}

# Check library paths
cat("\nR Library paths:\n")
lib_paths <- .libPaths()
for (i in seq_along(lib_paths)) {
  cat(sprintf("  [%d] %s\n", i, lib_paths[i]))
  if (dir.exists(lib_paths[i])) {
    pkg_count <- length(list.dirs(lib_paths[i], recursive = FALSE))
    cat(sprintf("      Contains %d packages\n", pkg_count))
  } else {
    cat("      Path does not exist!\n")
  }
}

# Test loading shiny specifically
cat("\nTesting shiny package load:\n")
tryCatch({
  library(shiny, quietly = TRUE)
  cat("  ✓ shiny loaded successfully\n")
  cat("  Version:", as.character(packageVersion("shiny")), "\n")
}, error = function(e) {
  cat("  ✗ Error loading shiny:", e$message, "\n")
})

cat("\n=== END DIAGNOSTIC ===\n") 