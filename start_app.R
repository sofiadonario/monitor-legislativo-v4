# Startup script for Railway deployment
# This handles the database.R loading issue gracefully

cat("=== RAILWAY STARTUP SCRIPT - V3 DEBUG ===\n")
cat("Working directory:", getwd(), "\n") 
cat("Files present:\n")
print(list.files())

# IMMEDIATE DEBUG - Source the force rebuild debug
cat("🔥 SOURCING FORCE_REBUILD_DEBUG.R IMMEDIATELY\n")
tryCatch({
  source("FORCE_REBUILD_DEBUG.R")
}, error = function(e) {
  cat("🔥 Failed to source FORCE_REBUILD_DEBUG.R:", e$message, "\n")
})

# Set R_CONFIG_ACTIVE to production if not set
if (Sys.getenv("R_CONFIG_ACTIVE") == "") {
  Sys.setenv(R_CONFIG_ACTIVE = "production")
  cat("✓ Set R_CONFIG_ACTIVE to production\n")
}

# CRITICAL: Verify R packages are available at runtime
cat("\n=== RUNTIME PACKAGE VERIFICATION ===\n")
required_packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', 
                       'plotly', 'ggplot2', 'leaflet', 'stringr', 'markdown',
                       'DBI', 'RPostgres', 'pool', 'config', 'digest')

all_available <- TRUE
for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat(sprintf("✓ %s - OK\n", pkg))
  } else {
    cat(sprintf("✗ %s - MISSING\n", pkg))
    all_available <- FALSE
  }
}

if (!all_available) {
  cat("ERROR: Some required packages are missing at runtime!\n")
  cat("Library paths:\n")
  print(.libPaths())
  quit(status = 1)
} else {
  cat("✓ All required packages verified at runtime\n")
}

# Test shiny package load specifically 
tryCatch({
  library(shiny, quietly = TRUE)
  cat("✓ Shiny loaded successfully at runtime\n")
  cat("Shiny version:", as.character(packageVersion("shiny")), "\n")
}, error = function(e) {
  cat("ERROR loading shiny at runtime:", e$message, "\n")
  cat("Running comprehensive debug script...\n")
  tryCatch({
    source("railway_debug.R")
  }, error = function(debug_error) {
    cat("Debug script failed:", debug_error$message, "\n")
  })
  quit(status = 1)
})
cat("=== END RUNTIME VERIFICATION ===\n\n")

# First source utils.R which contains required utility functions
tryCatch({
  source("utils.R")
  cat("✓ Successfully loaded utils.R\n")
}, error = function(e) {
  cat("✗ Could not load utils.R:", e$message, "\n")
})

# Try to source database.R, but if it fails, embed the functions directly
tryCatch({
  source("database.R")
  cat("✓ Successfully loaded database.R\n")
  
  # Load missing functions after database.R
  tryCatch({
    source("missing_functions.R")
    cat("✓ Successfully loaded missing_functions.R\n")
  }, error = function(e) {
    cat("⚠️ Error loading missing_functions.R:", e$message, "\n")
  })
  
}, error = function(e) {
  cat("✗ Could not load database.R:", e$message, "\n")
  cat("  Embedding database functions directly...\n")
  
  # Embed critical database functions here
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
  library(config)
  
  # Global connection pool
  .db_pool <- NULL
  .redis_connection <- NULL
  
  # Minimal init_database function
  init_database <- function() {
    cat("Using embedded init_database function\n")
    return(FALSE)  # Return false to use mock data
  }
  
  # Minimal close_database function
  close_database <- function() {
    cat("Using embedded close_database function\n")
  }
  
  # Stub functions to prevent errors
  load_legislative_data <- function(...) NULL
  get_database_stats <- function(...) NULL
  get_document_types <- function(...) character(0)
  get_states <- function(...) character(0)
  
  cat("✓ Embedded minimal database functions\n")
})

# Test the functions before loading the app
cat("🔍 TESTING DATA FUNCTIONS\n")
if (exists("load_legislative_data")) {
  cat("🔍 Testing load_legislative_data function\n")
  test_data <- load_legislative_data(limit = 5)
  if (!is.null(test_data)) {
    cat("🔍 SUCCESS: Got", nrow(test_data), "rows from load_legislative_data\n")
    cat("🔍 Sample titles:", paste(head(test_data$titulo, 2), collapse = ", "), "\n")
  } else {
    cat("🔍 ERROR: load_legislative_data returned NULL\n")
  }
} else {
  cat("🔍 ERROR: load_legislative_data function not found\n")
}

if (exists("get_documents")) {
  cat("🔍 Testing get_documents function\n")
  test_docs <- get_documents(limit = 3)
  if (!is.null(test_docs)) {
    cat("🔍 SUCCESS: get_documents returned", nrow(test_docs), "rows\n")
  } else {
    cat("🔍 ERROR: get_documents returned NULL\n")
  }
} else {
  cat("🔍 ERROR: get_documents function not found\n")
}

# Set database_connected variable for app.R to check
database_connected <- exists("load_legislative_data") && exists(".db_pool")
cat("📊 Database connection status for app.R:", database_connected, "\n")

# Now source the main app
cat("Loading main app.R...\n")
source("app.R")
cat("✓ App loaded successfully\n")