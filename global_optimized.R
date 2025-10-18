# ==============================================================================
# MONITOR LEGISLATIVO V4 - OPTIMIZED GLOBAL.R
# ==============================================================================
# Production-Ready Architecture | Railway Optimized | Brazilian Legal Context
#
# KEY OPTIMIZATIONS:
# 1. Preload heavy data ONCE (shared across all sessions)
# 2. Create DB pool globally (reused by all sessions)
# 3. Cache expensive computations with memoise
# 4. Simplify geometries BEFORE app starts
# 5. Fail gracefully - app starts even if some components unavailable
# ==============================================================================

cat("========================================\n")
cat("🚀 MONITOR LEGISLATIVO V4 - OPTIMIZED\n")
cat("========================================\n")

# ESSENTIAL PACKAGES
# ==================
suppressPackageStartupMessages({
  library(shiny)
  library(shinydashboard)
  library(DT)
  library(plotly)
  library(dplyr)
  library(data.table)
  library(RColorBrewer)
  library(DBI)
  library(RPostgres)
  library(pool)
  library(readr)
  library(stringr)
  library(lubridate)
  library(httr)
  library(jsonlite)
  library(htmltools)
  library(memoise)  # For caching
  library(future)   # For async operations
})

cat("✅ Core packages loaded\n")

# OPTIONAL PACKAGES (graceful degradation)
# ========================================
quietly_load <- function(pkg) {
  suppressPackageStartupMessages(
    requireNamespace(pkg, quietly = TRUE)
  )
}

LEAFLET_AVAILABLE <- quietly_load("leaflet")
SF_AVAILABLE <- quietly_load("sf")
GEOBR_AVAILABLE <- quietly_load("geobr")
RMAPSHAPER_AVAILABLE <- quietly_load("rmapshaper")

cat(sprintf("📦 Spatial packages: leaflet=%s sf=%s geobr=%s\n",
            LEAFLET_AVAILABLE, SF_AVAILABLE, GEOBR_AVAILABLE))

# CONFIGURATION
# =============
app_config <- list(
  app_title = "Monitor Legislativo v4",
  app_version = "4.0.0",
  environment = Sys.getenv("RAILWAY_ENVIRONMENT", "production"),
  cache_ttl = 300,  # 5 minutes
  max_db_connections = 5
)

# UTILITY HELPERS
# ===============
`%||%` <- function(x, y) if (is.null(x) || length(x) == 0L) y else x

scalar_int <- function(x, default = 0L) {
  if (is.null(x) || length(x) == 0L || all(is.na(x))) return(default)
  as.integer(x[[1L]])
}

scalar_chr <- function(x, default = "") {
  if (is.null(x) || length(x) == 0L || all(is.na(x))) return(default)
  as.character(x[[1L]])
}

scalar_num <- function(x, default = 0) {
  if (is.null(x) || length(x) == 0L || all(is.na(x))) return(default)
  as.numeric(x[[1L]])
}

# SAFE RENDER WRAPPERS
# ====================
safe_renderText <- function(expr, default = "—") {
  renderText({
    tryCatch({
      result <- expr
      scalar_chr(result, default = default)
    }, error = function(e) default)
  })
}

safe_valueBox <- function(value, subtitle = "", icon = NULL, color = "aqua") {
  tryCatch({
    valueBox(
      value = scalar_chr(value, "—"),
      subtitle = subtitle,
      icon = icon,
      color = color
    )
  }, error = function(e) {
    valueBox("—", subtitle, icon = icon("exclamation-triangle"), color = "yellow")
  })
}

cat("✅ Helper functions defined\n")

# DATABASE POOL (GLOBAL - SHARED BY ALL SESSIONS)
# ===============================================
db_pool <- NULL

init_db_pool <- function() {
  tryCatch({
    db_pool <<- pool::dbPool(
      drv = RPostgres::Postgres(),
      host = Sys.getenv("PGHOST", "localhost"),
      port = as.integer(Sys.getenv("PGPORT", "5432")),
      dbname = Sys.getenv("PGDATABASE", "railway"),
      user = Sys.getenv("PGUSER", "postgres"),
      password = Sys.getenv("PGPASSWORD", ""),
      sslmode = Sys.getenv("PGSSLMODE", "require"),
      minSize = 1,
      maxSize = app_config$max_db_connections,
      idleTimeout = 30000
    )

    # Verify connection
    test_query <- dbGetQuery(db_pool, "SELECT 1 as test")
    if (!is.null(test_query) && nrow(test_query) == 1) {
      cat("✅ Database pool created and verified\n")
      return(TRUE)
    } else {
      cat("⚠️  Database pool created but verification failed\n")
      return(FALSE)
    }
  }, error = function(e) {
    cat("❌ Database connection failed:", conditionMessage(e), "\n")
    cat("   App will run with demo data\n")
    db_pool <<- NULL
    return(FALSE)
  })
}

# Initialize immediately
DB_AVAILABLE <- init_db_pool()

# Cleanup on exit
onStop(function() {
  if (!is.null(db_pool)) {
    tryCatch(poolClose(db_pool), error = function(e) NULL)
    cat("✅ Database pool closed\n")
  }
})

# PRELOAD & CACHE HEAVY DATA
# ===========================

# 1. IBGE Geography (load once, simplify, cache)
# -----------------------------------------------
brazil_states_sf <- NULL
brazil_municipalities_sf <- NULL

load_brazil_geography <- function() {
  if (!SF_AVAILABLE || !GEOBR_AVAILABLE) {
    cat("⚠️  Spatial packages unavailable - maps will be basic\n")
    return(list(states = NULL, municipalities = NULL))
  }

  tryCatch({
    cat("📍 Loading Brazilian geography...\n")

    # Load states (27 polygons - fast)
    states_raw <- geobr::read_state(year = 2020, showProgress = FALSE)

    # Simplify to ~10% for web display (faster rendering, smaller JSON)
    if (RMAPSHAPER_AVAILABLE) {
      states_simplified <- rmapshaper::ms_simplify(states_raw, keep = 0.1, keep_shapes = TRUE)
    } else {
      states_simplified <- sf::st_simplify(states_raw, dTolerance = 0.01)
    }

    cat("  ✓ States loaded and simplified\n")

    # Load municipalities (5570 polygons - heavier, so more aggressive simplification)
    muni_raw <- geobr::read_municipality(year = 2020, showProgress = FALSE)

    if (RMAPSHAPER_AVAILABLE) {
      muni_simplified <- rmapshaper::ms_simplify(muni_raw, keep = 0.05, keep_shapes = TRUE)
    } else {
      muni_simplified <- sf::st_simplify(muni_raw, dTolerance = 0.02)
    }

    cat("  ✓ Municipalities loaded and simplified\n")

    list(
      states = states_simplified,
      municipalities = muni_simplified
    )

  }, error = function(e) {
    cat("❌ Failed to load geography:", conditionMessage(e), "\n")
    list(states = NULL, municipalities = NULL)
  })
}

# Load immediately during startup
brazil_geo <- load_brazil_geography()
brazil_states_sf <- brazil_geo$states
brazil_municipalities_sf <- brazil_geo$municipalities

# 2. Create memoized (cached) data retrieval functions
# -----------------------------------------------------

# Raw function to get documents from DB
.get_documents_raw <- function(filters = list(), limit = 100) {
  if (is.null(db_pool)) return(data.frame())

  tryCatch({
    # Build query
    query <- "SELECT * FROM legis_docs WHERE 1=1"
    params <- list()

    if (!is.null(filters$state) && filters$state != "all") {
      query <- paste(query, "AND state = $1")
      params <- c(params, filters$state)
    }

    query <- paste(query, "LIMIT", limit)

    # Execute
    if (length(params) > 0) {
      dbGetQuery(db_pool, query, params = params)
    } else {
      dbGetQuery(db_pool, query)
    }

  }, error = function(e) {
    cat("⚠️  Query failed:", conditionMessage(e), "\n")
    data.frame()
  })
}

# Cached version (5 minute TTL)
get_documents <- memoise::memoise(.get_documents_raw, ~memoise::timeout(app_config$cache_ttl))

# 3. Dashboard metrics (cached)
# ------------------------------
.get_dashboard_metrics_raw <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_documents = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      last_updated = Sys.time()
    ))
  }

  tryCatch({
    total_docs <- dbGetQuery(db_pool, "SELECT COUNT(*) as n FROM legis_docs")$n
    states_count <- dbGetQuery(db_pool, "SELECT COUNT(DISTINCT state) as n FROM legis_docs WHERE state IS NOT NULL")$n
    muni_count <- dbGetQuery(db_pool, "SELECT COUNT(DISTINCT municipality) as n FROM legis_docs WHERE municipality IS NOT NULL")$n

    list(
      total_documents = scalar_int(total_docs, 0),
      states_with_docs = scalar_int(states_count, 0),
      municipalities_with_docs = scalar_int(muni_count, 0),
      last_updated = Sys.time()
    )
  }, error = function(e) {
    cat("⚠️  Metrics query failed:", conditionMessage(e), "\n")
    list(
      total_documents = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      last_updated = Sys.time()
    )
  })
}

get_dashboard_metrics <- memoise::memoise(.get_dashboard_metrics_raw, ~memoise::timeout(app_config$cache_ttl))

# 4. Chart data preparation (cached)
# -----------------------------------
prepare_state_chart_data <- memoise::memoise(function() {
  if (is.null(db_pool)) return(data.frame(state = character(), count = integer()))

  tryCatch({
    dbGetQuery(db_pool, "
      SELECT state, COUNT(*) as count
      FROM legis_docs
      WHERE state IS NOT NULL
      GROUP BY state
      ORDER BY count DESC
      LIMIT 15
    ")
  }, error = function(e) {
    data.frame(state = character(), count = integer())
  })
}, ~memoise::timeout(app_config$cache_ttl))

prepare_category_chart_data <- memoise::memoise(function() {
  if (is.null(db_pool)) return(data.frame(category = character(), count = integer()))

  tryCatch({
    dbGetQuery(db_pool, "
      SELECT category, COUNT(*) as count
      FROM legis_docs
      WHERE category IS NOT NULL
      GROUP BY category
      ORDER BY count DESC
      LIMIT 10
    ")
  }, error = function(e) {
    data.frame(category = character(), count = integer())
  })
}, ~memoise::timeout(app_config$cache_ttl))

cat("✅ Cached data functions created\n")

# ASYNC SETUP (for long-running operations)
# ==========================================
future::plan(future::multisession, workers = 2)
cat("✅ Async execution configured (2 workers)\n")

# MODULE SYSTEM
# =============
# Define namespace for modules to keep things organized

# Service layer - wraps data access with caching/async
svc_lexml_search <- function(query) {
  # Stub - replace with actual LexML API call
  # Use httr with timeout
  tryCatch({
    response <- httr::GET(
      "https://api.lexml.gov.br/search",
      query = list(q = query),
      timeout(10)
    )
    httr::content(response)
  }, error = function(e) {
    cat("⚠️  LexML API error:", conditionMessage(e), "\n")
    list()
  })
}

# Memoize API calls (cache for 10 minutes)
svc_lexml_search <- memoise::memoise(svc_lexml_search, ~memoise::timeout(600))

cat("✅ Service layer created\n")

# STARTUP DIAGNOSTICS
# ===================
cat("\n========================================\n")
cat("📊 STARTUP STATUS:\n")
cat(sprintf("  Database:       %s\n", if (DB_AVAILABLE) "✅ Connected" else "❌ Unavailable"))
cat(sprintf("  Spatial Data:   %s\n", if (!is.null(brazil_states_sf)) "✅ Loaded" else "❌ Unavailable"))
cat(sprintf("  Cache:          ✅ Enabled (TTL: %ds)\n", app_config$cache_ttl))
cat(sprintf("  Async Workers:  ✅ 2 workers\n"))
cat("========================================\n\n")

cat("✅ Global configuration complete - app ready to launch\n")
