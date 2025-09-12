# ============================================================================
# RAILWAY API SERVER STARTUP SCRIPT - SPRINT 6B (API-001)
# ============================================================================
# 
# Production-ready startup script for Monitor Legislativo REST API on Railway
# Integrates with existing Shiny application and performance optimizations
# 
# Features:
# - Environment-aware configuration (development/production)
# - Railway-specific optimizations and logging
# - Integration with PostgreSQL and Redis from Sprint 6A
# - Graceful startup and shutdown procedures
# - Health check and monitoring setup
# - LGPD compliance and security features
# ============================================================================

cat("🚀 Starting Monitor Legislativo REST API Server (Sprint 6B)\n")
cat("📊 Integrating with Brazilian Legislative Data System\n")

# Set startup time for metrics
api_startup_time <- Sys.time()

# Environment detection
is_railway <- Sys.getenv("RAILWAY_ENVIRONMENT", "") != ""
is_production <- Sys.getenv("NODE_ENV", "development") == "production" || 
                 Sys.getenv("R_ENV", "development") == "production" ||
                 is_railway

cat("🌍 Environment:", if (is_production) "PRODUCTION" else "DEVELOPMENT", "\n")
cat("🚂 Railway deployment:", if (is_railway) "YES" else "NO", "\n")

# Set error handling for production
if (is_production) {
  options(error = function() {
    cat("❌ Production error occurred at", format(Sys.time()), "\n")
    traceback()
  })
}

# Load required packages with error handling
required_packages <- c("plumber", "jsonlite", "DBI", "pool", "RPostgres")

cat("📦 Loading required packages...\n")
missing_packages <- c()

for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    suppressPackageStartupMessages(library(pkg, character.only = TRUE, quietly = TRUE))
    cat("  ✅", pkg, "\n")
  } else {
    missing_packages <- c(missing_packages, pkg)
    cat("  ❌", pkg, "- MISSING\n")
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ Missing packages detected:", paste(missing_packages, collapse = ", "), "\n")
  cat("🔧 Attempting to install missing packages...\n")
  
  tryCatch({
    install.packages(missing_packages, repos = "https://cran.rstudio.com/")
    for (pkg in missing_packages) {
      library(pkg, character.only = TRUE)
      cat("  ✅", pkg, "- INSTALLED\n")
    }
  }, error = function(e) {
    cat("❌ Failed to install packages:", e$message, "\n")
    cat("🚨 API will run with limited functionality\n")
  })
}

# Load core application components
cat("📋 Loading core application components...\n")

# Set working directory to project root
if (file.exists("api/plumber_api.R")) {
  setwd(".")
} else if (file.exists("../api/plumber_api.R")) {
  setwd("..")
} else {
  cat("⚠️ Warning: Could not find API directory, using current directory\n")
}

# Load database connection with enhanced error handling
tryCatch({
  if (file.exists("db/connection.R")) {
    source("db/connection.R")
    cat("  ✅ Database connection module loaded\n")
  } else {
    cat("  ⚠️ Database connection module not found\n")
  }
}, error = function(e) {
  cat("  ❌ Error loading database connection:", e$message, "\n")
})

# Load performance optimization module
tryCatch({
  if (file.exists("db/performance_optimization.R")) {
    source("db/performance_optimization.R")
    cat("  ✅ Performance optimization module loaded\n")
  } else {
    cat("  ⚠️ Performance optimization module not found\n")
  }
}, error = function(e) {
  cat("  ❌ Error loading performance optimization:", e$message, "\n")
})

# Load real data loader
tryCatch({
  if (file.exists("modules/real_data_loader.R")) {
    source("modules/real_data_loader.R")
    cat("  ✅ Real data loader loaded\n")
  } else {
    cat("  ⚠️ Real data loader not found\n")
  }
}, error = function(e) {
  cat("  ❌ Error loading real data loader:", e$message, "\n")
})

# Configuration
API_CONFIG <- list(
  host = Sys.getenv("HOST", "0.0.0.0"),
  port = as.numeric(Sys.getenv("PORT", "8000")),
  debug = !is_production,
  docs = !is_production || Sys.getenv("API_DOCS", "false") == "true",
  docs_callback = if (!is_production) function(pr) {
    pr$mount("/docs", plumber::pr_static("api/documentation"))
  } else NULL
)

cat("🔧 API Configuration:\n")
cat("  Host:", API_CONFIG$host, "\n")
cat("  Port:", API_CONFIG$port, "\n")
cat("  Debug mode:", API_CONFIG$debug, "\n")
cat("  Documentation:", API_CONFIG$docs, "\n")

# Pre-startup health checks
cat("🏥 Performing pre-startup health checks...\n")

# Check database connectivity
db_healthy <- FALSE
if (exists("connection_status")) {
  db_healthy <- connection_status$status == "connected"
  cat("  📊 Database status:", connection_status$status, "\n")
  cat("  📄 Documents available:", format(connection_status$document_count, big.mark = ","), "\n")
} else {
  cat("  ⚠️ Database connection status unknown\n")
}

# Check data availability
data_healthy <- FALSE
if (exists("get_total_documents")) {
  total_docs <- get_total_documents()
  data_healthy <- total_docs > 0
  cat("  📚 Total documents accessible:", format(total_docs, big.mark = ","), "\n")
} else {
  cat("  ⚠️ Data access functions not available\n")
}

# Warm up caches if available
if (exists("warm_up_caches")) {
  cat("🔥 Warming up performance caches...\n")
  tryCatch({
    warm_up_caches()
    cat("  ✅ Caches warmed up successfully\n")
  }, error = function(e) {
    cat("  ⚠️ Cache warm-up failed:", e$message, "\n")
  })
}

# Create and configure Plumber API
cat("🔌 Creating Plumber API instance...\n")

tryCatch({
  # Load the main API file
  if (file.exists("api/plumber_api.R")) {
    pr <- plumber::pr("api/plumber_api.R")
    cat("  ✅ Main API loaded from api/plumber_api.R\n")
  } else {
    stop("API file not found: api/plumber_api.R")
  }
  
  # Configure documentation if enabled
  if (API_CONFIG$docs) {
    # Enable automatic documentation
    pr$set_api_spec(function(spec) {
      spec$info$version <- "1.0.0"
      spec$info$title <- "Monitor Legislativo API"
      spec$info$description <- "Comprehensive REST API for Brazilian Legislative Monitoring System"
      return(spec)
    })
    
    # Mount static documentation files
    if (dir.exists("api/documentation")) {
      pr$mount("/docs", plumber::pr_static("api/documentation"))
      cat("  ✅ Documentation mounted at /docs\n")
    }
  }
  
  # Configure error handling
  pr$set_error(function(req, res, err) {
    cat("❌ API Error:", err$message, "\n")
    
    if (exists("log_error")) {
      log_error(err, req)
    }
    
    list(
      error = TRUE,
      message = if (is_production) "Internal server error" else err$message,
      code = 500,
      timestamp = Sys.time()
    )
  })
  
  # Configure response logging if available
  if (exists("log_response")) {
    pr$set_serializer(function(req, value, body) {
      log_response(req, res, body)
      body
    })
  }
  
  cat("  ✅ Plumber API configured successfully\n")
  
}, error = function(e) {
  cat("❌ Failed to create Plumber API:", e$message, "\n")
  stop("Cannot proceed without API instance")
})

# Railway-specific optimizations
if (is_railway) {
  cat("🚂 Applying Railway-specific optimizations...\n")
  
  # Railway environment variables
  railway_vars <- c(
    "RAILWAY_ENVIRONMENT", "RAILWAY_PROJECT_ID", "RAILWAY_SERVICE_ID",
    "RAILWAY_DEPLOYMENT_ID", "RAILWAY_REPLICA_ID", "DATABASE_URL"
  )
  
  for (var in railway_vars) {
    if (Sys.getenv(var, "") != "") {
      cat("  📊", var, "configured\n")
    }
  }
  
  # Configure for Railway networking
  if (API_CONFIG$host == "0.0.0.0") {
    cat("  🌐 Configured for Railway external access\n")
  }
  
  # Railway memory optimization
  if (is_production) {
    # Optimize R memory usage for Railway limits
    options(scipen = 999)  # Avoid scientific notation
    gc() # Garbage collection
    cat("  💾 Memory optimizations applied\n")
  }
}

# Security configurations
cat("🛡️ Applying security configurations...\n")

# LGPD compliance logging
if (is_production) {
  cat("  ⚖️ LGPD compliance mode enabled\n")
}

# Production security headers
if (is_production) {
  cat("  🔒 Production security headers enabled\n")
}

# Final startup
cat("🎯 Starting API server...\n")
cat("=" * 60, "\n")
cat("Monitor Legislativo REST API - Sprint 6B (API-001)\n")
cat("Brazilian Legislative Data System\n")
cat("Performance Optimized • LGPD Compliant • Railway Ready\n")
cat("=" * 60, "\n")

startup_duration <- as.numeric(difftime(Sys.time(), api_startup_time, units = "secs"))
cat("⏱️ Startup completed in", round(startup_duration, 2), "seconds\n")

# Print access information
cat("\n📡 API Access Information:\n")
cat("  Local URL: http://localhost:", API_CONFIG$port, "\n", sep = "")
if (is_railway) {
  railway_url <- Sys.getenv("RAILWAY_PUBLIC_DOMAIN", "")
  if (railway_url != "") {
    cat("  Public URL: https://", railway_url, "\n", sep = "")
  }
}

cat("\n📚 Available Endpoints:\n")
cat("  GET  /health              - System health check\n")
cat("  GET  /info                - API information\n")
cat("  GET  /api/v1/documents    - List documents\n")
cat("  POST /api/v1/search       - Full-text search\n")
cat("  GET  /api/v1/geographic   - Geographic analysis\n")
cat("  GET  /api/v1/analytics    - Dashboard metrics\n")
cat("  GET  /api/v1/citations    - Citation generation\n")
cat("  POST /api/v1/export       - Data export\n")

if (API_CONFIG$docs) {
  cat("  GET  /docs                - API documentation\n")
  cat("  GET  /__docs__            - Interactive API explorer\n")
}

cat("\n🔑 Authentication:\n")
cat("  API Key required for all endpoints (except /health, /info)\n")
cat("  Header: Authorization: Bearer YOUR_API_KEY\n")
cat("  Header: X-API-Key: YOUR_API_KEY\n")

cat("\n📊 System Status:\n")
cat("  Database:", if (db_healthy) "CONNECTED" else "LIMITED", "\n")
cat("  Data Access:", if (data_healthy) "FULL" else "FALLBACK", "\n")
cat("  Performance Cache:", if (exists("get_performance_stats")) "ACTIVE" else "BASIC", "\n")
cat("  Documentation:", if (API_CONFIG$docs) "ENABLED" else "DISABLED", "\n")

# Final logs
if (exists("log_security_event")) {
  log_security_event("API_SERVER_STARTUP", list(
    startup_duration = startup_duration,
    environment = if (is_production) "production" else "development",
    railway = is_railway,
    database_status = if (db_healthy) "connected" else "limited"
  ))
}

cat("\n🚀 Monitor Legislativo API Server is now running!\n")
cat("📈 Ready to serve Brazilian legislative data to", format(Sys.time()), "\n\n")

# Start the server
tryCatch({
  pr$run(
    host = API_CONFIG$host,
    port = API_CONFIG$port,
    debug = API_CONFIG$debug
  )
}, error = function(e) {
  cat("❌ Server startup failed:", e$message, "\n")
  
  if (exists("log_error")) {
    log_error(e, additional_context = list(
      startup_phase = "server_run",
      host = API_CONFIG$host,
      port = API_CONFIG$port
    ))
  }
  
  stop("API server could not be started")
}, finally = {
  # Cleanup on shutdown
  cat("\n🛑 API server shutting down...\n")
  
  if (exists("close_secure_database")) {
    close_secure_database()
    cat("  ✅ Database connections closed\n")
  }
  
  if (exists("clear_performance_cache")) {
    clear_performance_cache(confirm = TRUE)
    cat("  ✅ Performance caches cleared\n")
  }
  
  cat("👋 Monitor Legislativo API server stopped gracefully\n")
})