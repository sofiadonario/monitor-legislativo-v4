# Startup script for Railway deployment
# This handles the database.R loading issue gracefully

cat("=== RAILWAY STARTUP SCRIPT ===\n")
cat("Working directory:", getwd(), "\n")
cat("Files present:\n")
print(list.files())

# Try to source database.R, but if it fails, embed the functions directly
tryCatch({
  source("database.R")
  cat("✓ Successfully loaded database.R\n")
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

# Now source the main app
cat("Loading main app.R...\n")
source("app.R")
cat("✓ App loaded successfully\n")