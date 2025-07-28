# Railway R Package Debugging Script
# This script helps diagnose and fix R package loading issues on Railway

cat("=== RAILWAY R PACKAGE DEBUG SCRIPT ===\n")
cat("Timestamp:", Sys.time(), "\n")
cat("R version:", R.version.string, "\n")
cat("Platform:", R.version$platform, "\n\n")

# 1. Check system information
cat("=== SYSTEM INFORMATION ===\n")
cat("Working directory:", getwd(), "\n")
cat("User:", Sys.getenv("USER", "unknown"), "\n")
cat("Home:", Sys.getenv("HOME", "unknown"), "\n")
cat("R_HOME:", R.home(), "\n")
cat("R_LIBS:", Sys.getenv("R_LIBS", "not set"), "\n")
cat("R_LIBS_USER:", Sys.getenv("R_LIBS_USER", "not set"), "\n")
cat("R_LIBS_SITE:", Sys.getenv("R_LIBS_SITE", "not set"), "\n\n")

# 2. Check library paths
cat("=== LIBRARY PATHS ===\n")
lib_paths <- .libPaths()
for (i in seq_along(lib_paths)) {
  path <- lib_paths[i]
  exists <- dir.exists(path)
  readable <- exists && file.access(path, 4) == 0
  pkg_count <- if (exists) length(list.dirs(path, recursive = FALSE)) else 0
  
  cat(sprintf("[%d] %s\n", i, path))
  cat(sprintf("    Exists: %s | Readable: %s | Packages: %d\n", exists, readable, pkg_count))
  
  if (exists && readable) {
    # List first few packages
    pkgs <- basename(list.dirs(path, recursive = FALSE))
    if (length(pkgs) > 0) {
      sample_pkgs <- head(pkgs, 5)
      cat(sprintf("    Sample packages: %s\n", paste(sample_pkgs, collapse = ", ")))
    }
  }
}

# 3. Try to find packages in alternative locations
cat("\n=== SEARCHING FOR PACKAGES ===\n")
search_paths <- c(
  "/usr/local/lib/R/site-library",
  "/usr/lib/R/site-library", 
  "/usr/lib/R/library",
  "/usr/local/lib/R/library",
  file.path(R.home(), "library"),
  file.path(R.home(), "site-library")
)

for (search_path in search_paths) {
  if (dir.exists(search_path)) {
    pkgs <- basename(list.dirs(search_path, recursive = FALSE))
    shiny_found <- "shiny" %in% pkgs
    cat(sprintf("Found %d packages in %s (shiny: %s)\n", length(pkgs), search_path, shiny_found))
    if (shiny_found) {
      cat(sprintf("  SHINY FOUND at: %s\n", search_path))
    }
  }
}

# 4. Test package installation and loading
cat("\n=== PACKAGE INSTALLATION TEST ===\n")
required_packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', 
                       'plotly', 'ggplot2', 'leaflet', 'stringr', 'markdown',
                       'DBI', 'RPostgres', 'pool', 'config', 'digest')

# Test if packages are installed
for (pkg in required_packages) {
  installed <- nzchar(system.file(package = pkg))
  namespace_ok <- requireNamespace(pkg, quietly = TRUE)
  
  cat(sprintf("%-15s: installed=%s, namespace=%s", pkg, installed, namespace_ok))
  
  if (installed && namespace_ok) {
    tryCatch({
      library(pkg, character.only = TRUE, quietly = TRUE)
      version <- as.character(packageVersion(pkg))
      cat(sprintf(" [v%s] ✓\n", version))
    }, error = function(e) {
      cat(sprintf(" ERROR: %s\n", e$message))
    })
  } else {
    cat(" ✗\n")
  }
}

# 5. Attempt automatic fix
cat("\n=== ATTEMPTING AUTOMATIC FIX ===\n")

# Try to add missing library paths
for (search_path in search_paths) {
  if (dir.exists(search_path) && !search_path %in% .libPaths()) {
    cat(sprintf("Adding %s to library paths\n", search_path))
    .libPaths(c(search_path, .libPaths()))
  }
}

# Test shiny loading specifically after path fixes
cat("\n=== TESTING SHINY AFTER FIXES ===\n")
tryCatch({
  library(shiny, quietly = TRUE)
  cat("✓ SUCCESS: Shiny loaded successfully!\n")
  cat("Shiny version:", as.character(packageVersion("shiny")), "\n")
  cat("Shiny path:", system.file(package = "shiny"), "\n")
}, error = function(e) {
  cat("✗ FAILURE: Still cannot load shiny\n")
  cat("Error:", e$message, "\n")
  
  # Last resort: try to reinstall shiny
  cat("\nAttempting emergency shiny reinstall...\n")
  tryCatch({
    install.packages("shiny", repos = "https://cloud.r-project.org/", quiet = TRUE)
    library(shiny, quietly = TRUE)
    cat("✓ Emergency reinstall successful!\n")
  }, error = function(e2) {
    cat("✗ Emergency reinstall failed:", e2$message, "\n")
  })
})

cat("\n=== DEBUG COMPLETE ===\n")