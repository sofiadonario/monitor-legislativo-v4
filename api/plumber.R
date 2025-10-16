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

#* @apiTitle Monitor Legislativo API
#* @apiDescription Brazilian Legislative Monitoring System REST API
#* @apiVersion 1.0.0
#* @apiTag Search Full-text and fuzzy search endpoints
#* @apiTag Documents Individual document operations
#* @apiTag Aggregations Dashboard statistics and aggregations
#* @apiTag Geographic Map and geographic data
#* @apiTag System Health and system information

library(plumber)
library(DBI)
library(RPostgres)

# Load shared utilities
source("api/lib/validators.R")
source("api/lib/redis.R")
source("api/lib/cache.R")
source("api/lib/http_cache.R")

# Initialize database connection
con_pg <- dbConnect(
  RPostgres::Postgres(),
  dbname   = Sys.getenv("PGDATABASE", "legis"),
  host     = Sys.getenv("PGHOST", "127.0.0.1"),
  user     = Sys.getenv("PGUSER", "postgres"),
  password = Sys.getenv("PGPASSWORD", ""),
  port     = as.integer(Sys.getenv("PGPORT", "5432"))
)

cat("✅ PostgreSQL connected\n")

# Create plumber API object
pr <- pr() %>%
  pr_set_error(function(req, res, err) {
    status <- if (inherits(err, "api_error")) 422 else 500
    res$status <- status
    list(
      error = if (status == 422) "invalid_request" else "server_error",
      message = conditionMessage(err) %||% "Unexpected error",
      request_id = req$HEADERS[["x-request-id"]] %||% ""
    )
  }) %>%
  pr_hooks(list(
    preroute = function(req) {
      req$start <- Sys.time()
    },
    postserialize = function(req, res, val) {
      dur <- as.numeric(difftime(Sys.time(), req$start, units = "secs"))
      res$setHeader("X-Response-Time", sprintf("%.3fs", dur))
    }
  ))

cat("✅ API hooks configured\n")

# Register route handlers
source("api/routes_search.R", local = TRUE)
source("api/routes_doc.R", local = TRUE)
source("api/routes_agg.R", local = TRUE)
source("api/routes_map.R", local = TRUE)

cat("✅ All route handlers loaded\n")

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
  db_status <- tryCatch(
    {
      dbGetQuery(con_pg, "SELECT 1")
      "connected"
    },
    error = function(e) "error"
  )

  redis_status <- if (redis_is_connected()) "connected" else "unavailable"

  list(
    status = "healthy",
    database = db_status,
    redis = redis_status,
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

cat("✅ API ready to serve requests\n")
cat("📚 Visit /__docs__/ for interactive documentation\n")

# Run the API
pr$run(host = "0.0.0.0", port = 8000)
