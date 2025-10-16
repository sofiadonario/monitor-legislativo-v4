# ============================================================================
# MONITOR LEGISLATIVO R API (PLUMBER)
# ============================================================================
# Main entry point for the Legislative Monitor REST API
# Integrates with high-performance PostgreSQL schema from database/migrations
#
# Features:
# - Full-text search with Portuguese support
# - Geographic aggregations
# - Document retrieval
# - Caching with Redis and HTTP ETags
# - Rate limiting
# - CORS support
# ============================================================================

library(plumber)
library(DBI)
library(jsonlite)

cat("🚀 Starting Monitor Legislativo API\n")

# Load shared utilities
source("api/lib/validators.R")
source("api/lib/redis.R")
source("api/lib/cache.R")
source("api/lib/http_cache.R")

# Load database connection
if (file.exists("db/connection.R")) {
  source("db/connection.R")
  cat("✅ Database connection loaded\n")
}

# Initialize database connection pool
if (!exists("con_pg")) {
  tryCatch({
    DATABASE_URL <- Sys.getenv("DATABASE_URL")
    if (DATABASE_URL != "") {
      con_pg <- dbConnect(
        RPostgres::Postgres(),
        dbname = DATABASE_URL
      )
      cat("✅ PostgreSQL connected\n")
    } else {
      con_pg <- NULL
      cat("⚠️  No DATABASE_URL - API will use fallback data\n")
    }
  }, error = function(e) {
    con_pg <- NULL
    cat("⚠️  Database connection failed:", e$message, "\n")
  })
}

# Load route handlers
source("api/routes_search.R")
source("api/routes_doc.R")
source("api/routes_agg.R")
source("api/routes_map.R")

cat("✅ All route handlers loaded\n")

# Global error handler
#* @filter error-handler
function(req, res) {
  tryCatch(
    {
      plumber::forward()
    },
    api_error = function(e) {
      res$status <- 400
      list(
        error = e$error,
        message = e$message,
        timestamp = Sys.time()
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "internal_error",
        message = "An unexpected error occurred",
        timestamp = Sys.time()
      )
    }
  )
}

# CORS filter
#* @filter cors
function(req, res) {
  res$setHeader("Access-Control-Allow-Origin", "*")
  res$setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  )
  res$setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-API-Key"
  )

  if (req$REQUEST_METHOD == "OPTIONS") {
    res$status <- 200
    return(list())
  }

  plumber::forward()
}

# Request logging filter
#* @filter logger
function(req, res) {
  cat(sprintf(
    "[%s] %s %s\n",
    format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
    req$REQUEST_METHOD,
    req$PATH_INFO
  ))
  plumber::forward()
}

#* @apiTitle Monitor Legislativo API
#* @apiDescription Brazilian Legislative Monitoring System REST API
#* @apiVersion 1.0.0
#* @apiTag Search Full-text and fuzzy search endpoints
#* @apiTag Documents Individual document operations
#* @apiTag Aggregations Dashboard statistics and aggregations
#* @apiTag Geographic Map and geographic data
#* @apiTag System Health and system information

#* Get API information
#* @get /
#* @serializer json
function() {
  list(
    service = "Monitor Legislativo API",
    version = "1.0.0",
    database_schema = "high-performance PostgreSQL with full-text search",
    endpoints = list(
      search = list(
        "/search" = "Full-text search across documents",
        "/search/fuzzy" = "Fuzzy matching with typo tolerance",
        "/search/suggest" = "Search query suggestions"
      ),
      documents = list(
        "/document/<id>" = "Get document by ID",
        "/documents/recent" = "Recently published documents",
        "/documents/related/<id>" = "Find related documents",
        "/documents/count" = "Document count with filters",
        "/documents/status/<status>" = "Documents by status"
      ),
      aggregations = list(
        "/aggregations/by-year" = "Documents by year and jurisdiction",
        "/aggregations/by-state" = "Documents by state",
        "/aggregations/by-topic" = "Transportation topic aggregations",
        "/aggregations/stats" = "Overall statistics",
        "/aggregations/refresh" = "Refresh materialized views (POST)"
      ),
      geographic = list(
        "/map/states" = "State-level map data",
        "/map/municipalities/<state>" = "Municipality data for state",
        "/map/heatmap" = "Geographic heatmap data",
        "/map/geojson/states" = "States as GeoJSON"
      ),
      cache = list(
        "/cache/stats" = "Cache statistics",
        "/cache/clear" = "Clear cache (POST)"
      )
    ),
    features = list(
      full_text_search = TRUE,
      fuzzy_matching = TRUE,
      redis_cache = redis_is_connected(),
      materialized_views = TRUE,
      geographic_analysis = TRUE
    ),
    timestamp = Sys.time()
  )
}

#* Health check
#* @get /health
#* @serializer json
function() {
  db_status <- if (!is.null(con_pg)) {
    tryCatch(
      {
        dbGetQuery(con_pg, "SELECT 1")
        "connected"
      },
      error = function(e) "error"
    )
  } else {
    "unavailable"
  }

  redis_status <- if (redis_is_connected()) "connected" else "unavailable"

  list(
    status = "healthy",
    database = db_status,
    redis = redis_status,
    uptime_seconds = as.numeric(Sys.time() - .GlobalEnv$.start_time),
    timestamp = Sys.time()
  )
}

#* Get cache statistics
#* @get /cache/stats
#* @serializer json
cache_stats_handler

#* Clear cache
#* @post /cache/clear
#* @serializer json
cache_clear_handler

# Store start time
if (!exists(".start_time", envir = .GlobalEnv)) {
  assign(".start_time", Sys.time(), envir = .GlobalEnv)
}

cat("✅ API ready to serve requests\n")
cat("📚 Visit /swagger for interactive documentation\n")
