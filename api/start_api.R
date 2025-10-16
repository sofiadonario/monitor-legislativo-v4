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
API_WORKERS <- as.integer(Sys.getenv("API_WORKERS", "1"))

cat(sprintf("📋 Configuration:\n"))
cat(sprintf("   Host: %s\n", API_HOST))
cat(sprintf("   Port: %d\n", API_PORT))
cat(sprintf("   Workers: %d\n\n", API_WORKERS))

# Check database connection
DATABASE_URL <- Sys.getenv("DATABASE_URL", "")
if (DATABASE_URL != "") {
  cat("✅ DATABASE_URL configured\n")
} else {
  cat("⚠️  No DATABASE_URL - API will run with fallback data\n")
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
    cat("🚀 Loading API routes...\n")

    # Load the main plumber file
    pr <- plumber::plumb("api/plumber.R")

    cat("✅ API routes loaded\n\n")

    cat("================================================================================\n")
    cat("API SERVER STARTING\n")
    cat("================================================================================\n")
    cat(sprintf("   URL: http://%s:%d\n", if (API_HOST == "0.0.0.0") "localhost" else API_HOST, API_PORT))
    cat(sprintf("   Docs: http://%s:%d/__docs__/\n", if (API_HOST == "0.0.0.0") "localhost" else API_HOST, API_PORT))
    cat("================================================================================\n\n")

    # Run the API
    pr$run(
      host = API_HOST,
      port = API_PORT,
      swagger = TRUE,
      debug = Sys.getenv("API_DEBUG", "false") == "true"
    )
  },
  error = function(e) {
    cat("❌ Failed to start API server:", e$message, "\n")
    quit(status = 1)
  }
)
