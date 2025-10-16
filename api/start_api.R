#!/usr/bin/env Rscript
# ============================================================================
# START MONITOR LEGISLATIVO API SERVER
# ============================================================================
# Starts the Plumber API server with proper configuration
# For Railway deployment and local development

cat("================================================================================\n")
cat("STARTING MONITOR LEGISLATIVO API SERVER\n")
cat("================================================================================\n\n")

# Load required packages
required_packages <- c("plumber", "DBI", "RPostgres", "jsonlite")
missing_packages <- c()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  } else {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
}

if (length(missing_packages) > 0) {
  cat("❌ Missing required packages:", paste(missing_packages, collapse = ", "), "\n")
  cat("📦 Install with: install.packages(c('", paste(missing_packages, collapse = "', '"), "'))\n")
  quit(status = 1)
}

# Get configuration from environment
API_HOST <- Sys.getenv("API_HOST", "0.0.0.0")
API_PORT <- as.integer(Sys.getenv("API_PORT", Sys.getenv("PORT", "8000")))

cat(sprintf("📋 Configuration:\n"))
cat(sprintf("   Host: %s\n", API_HOST))
cat(sprintf("   Port: %d\n\n", API_PORT))

# Check database configuration
PGDATABASE <- Sys.getenv("PGDATABASE", "")
PGHOST <- Sys.getenv("PGHOST", "")

if (PGDATABASE != "" && PGHOST != "") {
  cat("✅ PostgreSQL environment variables configured\n")
  cat(sprintf("   Database: %s\n", PGDATABASE))
  cat(sprintf("   Host: %s\n", PGHOST))
} else {
  cat("⚠️  PostgreSQL environment variables not fully configured\n")
  cat("   Using defaults from plumber.R\n")
}

# Check Redis
REDIS_URL <- Sys.getenv("REDIS_URL", "")
if (REDIS_URL != "") {
  cat("✅ REDIS_URL configured - caching enabled\n")
} else {
  cat("ℹ️  No REDIS_URL - caching disabled\n")
}

cat("\n")

# Create and run the API
tryCatch(
  {
    cat("🚀 Starting API server...\n\n")

    cat("================================================================================\n")
    cat("API SERVER STARTING\n")
    cat("================================================================================\n")
    cat(sprintf("   URL: http://%s:%d\n", if (API_HOST == "0.0.0.0") "localhost" else API_HOST, API_PORT))
    cat(sprintf("   Docs: http://%s:%d/__docs__/\n", if (API_HOST == "0.0.0.0") "localhost" else API_HOST, API_PORT))
    cat("================================================================================\n\n")

    # Source the plumber.R file which will start the server
    source("api/plumber.R")
  },
  error = function(e) {
    cat("❌ Failed to start API server:", e$message, "\n")
    quit(status = 1)
  }
)
