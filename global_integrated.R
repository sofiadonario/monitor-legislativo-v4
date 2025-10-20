# ==============================================================================
# MONITOR LEGISLATIVO V4 - INTEGRATED GLOBAL.R
# ==============================================================================
# Combines your existing modules with optimization patterns
# Production-Ready Architecture | Railway Optimized
# ==============================================================================

cat("========================================\n")
cat("🚀 MONITOR LEGISLATIVO V4 - INTEGRATED\n")
cat("========================================\n\n")

# ESSENTIAL PACKAGES
# ==================
suppressPackageStartupMessages({
  library(shiny)
  library(jsonlite)     # Load BEFORE shinydashboard to avoid masking conflicts
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
  library(htmltools)
  library(memoise)
  library(future)
})

cat("✅ Core packages loaded\n")

# OPTIONAL PACKAGES
# =================
LEAFLET_AVAILABLE <- suppressPackageStartupMessages(requireNamespace("leaflet", quietly = TRUE))
SF_AVAILABLE <- suppressPackageStartupMessages(requireNamespace("sf", quietly = TRUE))
GEOBR_AVAILABLE <- suppressPackageStartupMessages(requireNamespace("geobr", quietly = TRUE))
RMAPSHAPER_AVAILABLE <- suppressPackageStartupMessages(requireNamespace("rmapshaper", quietly = TRUE))
DT_AVAILABLE <- suppressPackageStartupMessages(requireNamespace("DT", quietly = TRUE))

cat(sprintf("📦 Spatial: leaflet=%s sf=%s geobr=%s\n",
            LEAFLET_AVAILABLE, SF_AVAILABLE, GEOBR_AVAILABLE))

# CONFIGURATION
# =============
app_config <- list(
  app_title = "Monitor Legislativo v4",
  app_version = "4.0.0",
  environment = Sys.getenv("RAILWAY_ENVIRONMENT", "production"),
  cache_ttl = 300,
  max_db_connections = 5,
  use_demo_data = FALSE
)

# UTILITY HELPERS (from your existing code)
# ==========================================
`%||%` <- function(x, y) if (is.null(x) || length(x) == 0L) y else x

# Your existing scalar utilities - keep them!
source("R/utils/scalar_utils.R", local = TRUE)
cat("✅ Scalar utilities loaded\n")

# SAFE RENDER WRAPPERS (from your existing code)
# ===============================================
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

safe_renderText <- function(expr, default = "—") {
  renderText({
    tryCatch({
      result <- expr
      scalar_chr(result, default = default)
    }, error = function(e) default)
  })
}

cat("✅ Safe wrappers defined\n")

# DATABASE POOL (GLOBAL - YOUR EXISTING CODE, OPTIMIZED)
# =======================================================
db_pool <- NULL
db_connection_pool <- NULL  # Alias for compatibility

# Your existing database utilities
source("R/utils/database_utils.R", local = TRUE)
cat("✅ Database utilities loaded\n")

# Initialize DB pool immediately
DB_AVAILABLE <- FALSE
tryCatch({
  db_pool <- create_db_pool()
  db_connection_pool <- db_pool  # Alias

  if (!is.null(db_pool)) {
    # Verify connection
    test_result <- pool::dbGetQuery(db_pool, "SELECT 1 as test")
    if (!is.null(test_result) && nrow(test_result) == 1) {
      DB_AVAILABLE <- TRUE
      cat("✅ Database pool created and verified\n")

      # Try to get document count from your actual table
      doc_count <- tryCatch({
        # Try common table names from your schema
        tables_to_try <- c("legis_docs", "documents", "legislative_documents",
                          "brazilian_legislative_complete", "lexml_parsed_enhanced")

        for (tbl in tables_to_try) {
          count <- tryCatch({
            result <- pool::dbGetQuery(db_pool, sprintf("SELECT COUNT(*) as n FROM %s", tbl))
            scalar_int(result$n, 0)
          }, error = function(e) 0)

          if (count > 0) {
            cat(sprintf("   Found %s documents in table '%s'\n",
                       format(count, big.mark = "."), tbl))
            return(count)
          }
        }
        0
      }, error = function(e) 0)
    }
  }
}, error = function(e) {
  cat("❌ Database connection failed:", conditionMessage(e), "\n")
  cat("   App will run with demo data\n")
  DB_AVAILABLE <- FALSE
})

# Cleanup on exit
onStop(function() {
  if (!is.null(db_pool)) {
    tryCatch(pool::poolClose(db_pool), error = function(e) NULL)
    cat("✅ Database pool closed\n")
  }
})

# LOAD YOUR DATA SERVICE MODULE
# ==============================
cat("📦 Loading data service module...\n")
data_service_result <- tryCatch({
  source("modules/data_service.R", local = TRUE)
}, error = function(e) {
  cat("⚠️  Data service module failed to load:", conditionMessage(e), "\n")
  NULL
})

# Export data service functions (memoized versions)
if (!is.null(data_service_result) && is.list(data_service_result)) {
  get_documents_raw <- data_service_result$get_documents
  get_analytics_data_raw <- data_service_result$get_analytics_data
  prepare_chart_data <- data_service_result$prepare_chart_data

  # Wrap with memoise for caching (5 minute TTL)
  get_documents <- memoise::memoise(get_documents_raw, ~memoise::timeout(app_config$cache_ttl))
  get_analytics_data <- memoise::memoise(get_analytics_data_raw, ~memoise::timeout(app_config$cache_ttl))

  cat("✅ Data service functions loaded and cached\n")
} else {
  # Fallback implementations
  cat("⚠️  Using fallback data functions\n")

  get_documents <- function(filters = list(), limit = 100, offset = NULL) {
    if (is.null(db_pool)) return(data.frame())

    tryCatch({
      query <- "SELECT * FROM legis_docs WHERE 1=1"

      if (!is.null(filters$state) && filters$state != "all") {
        query <- paste(query, "AND state = $1")
        params <- list(filters$state)
      } else {
        params <- list()
      }

      query <- paste(query, "LIMIT", limit)

      if (length(params) > 0) {
        pool::dbGetQuery(db_pool, query, params = params)
      } else {
        pool::dbGetQuery(db_pool, query)
      }
    }, error = function(e) {
      cat("⚠️  Query failed:", conditionMessage(e), "\n")
      data.frame()
    })
  }

  get_analytics_data <- get_documents
  prepare_chart_data <- function(data, type = "bar") {
    if (is.null(data) || nrow(data) == 0) return(data.frame())
    data
  }
}

# DASHBOARD METRICS (CACHED, YOUR LOGIC)
# =======================================
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
    # Try different table names
    table_candidates <- c("legis_docs", "documents", "legislative_documents")
    found_table <- NULL

    for (tbl in table_candidates) {
      exists_check <- tryCatch({
        pool::dbGetQuery(db_pool, sprintf("SELECT 1 FROM %s LIMIT 1", tbl))
      }, error = function(e) NULL)

      if (!is.null(exists_check)) {
        found_table <- tbl
        break
      }
    }

    if (is.null(found_table)) {
      return(list(
        total_documents = 0,
        states_with_docs = 0,
        municipalities_with_docs = 0,
        last_updated = Sys.time()
      ))
    }

    total_docs <- pool::dbGetQuery(db_pool, sprintf("SELECT COUNT(*) as n FROM %s", found_table))$n
    states_count <- pool::dbGetQuery(db_pool,
      sprintf("SELECT COUNT(DISTINCT state) as n FROM %s WHERE state IS NOT NULL", found_table))$n
    muni_count <- pool::dbGetQuery(db_pool,
      sprintf("SELECT COUNT(DISTINCT municipality) as n FROM %s WHERE municipality IS NOT NULL", found_table))$n

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

get_dashboard_metrics <- memoise::memoise(.get_dashboard_metrics_raw,
                                         ~memoise::timeout(app_config$cache_ttl))

# Alias for compatibility with your code
get_lexml_dashboard_metrics <- get_dashboard_metrics

cat("✅ Dashboard metrics function created\n")

# CHART DATA (CACHED)
# ===================
prepare_state_chart_data <- memoise::memoise(function() {
  if (is.null(db_pool)) return(data.frame(state = character(), count = integer()))

  tryCatch({
    # Try different table names
    for (tbl in c("legis_docs", "documents", "legislative_documents")) {
      result <- tryCatch({
        pool::dbGetQuery(db_pool, sprintf("
          SELECT state, COUNT(*) as count
          FROM %s
          WHERE state IS NOT NULL
          GROUP BY state
          ORDER BY count DESC
          LIMIT 15
        ", tbl))
      }, error = function(e) NULL)

      if (!is.null(result) && nrow(result) > 0) {
        return(result)
      }
    }
    data.frame(state = character(), count = integer())
  }, error = function(e) {
    data.frame(state = character(), count = integer())
  })
}, ~memoise::timeout(app_config$cache_ttl))

prepare_category_chart_data <- memoise::memoise(function() {
  if (is.null(db_pool)) return(data.frame(category = character(), count = integer()))

  tryCatch({
    for (tbl in c("legis_docs", "documents", "legislative_documents")) {
      result <- tryCatch({
        pool::dbGetQuery(db_pool, sprintf("
          SELECT category, COUNT(*) as count
          FROM %s
          WHERE category IS NOT NULL
          GROUP BY category
          ORDER BY count DESC
          LIMIT 10
        ", tbl))
      }, error = function(e) NULL)

      if (!is.null(result) && nrow(result) > 0) {
        return(result)
      }
    }
    data.frame(category = character(), count = integer())
  }, error = function(e) {
    data.frame(category = character(), count = integer())
  })
}, ~memoise::timeout(app_config$cache_ttl))

cat("✅ Chart data functions created\n")

# LOAD GEOGRAPHY DATA (PRELOADED, SIMPLIFIED)
# ============================================
brazil_states_sf <- NULL
brazil_municipalities_sf <- NULL

# Skip geography loading on Cloud Run to speed up startup
# Geography will be loaded lazily when needed
IS_CLOUD_RUN <- !is.na(Sys.getenv("K_SERVICE", NA))

if (SF_AVAILABLE && GEOBR_AVAILABLE && !IS_CLOUD_RUN) {
  cat("📍 Loading Brazilian geography...\n")

  tryCatch({
    # Load states (fast)
    states_raw <- geobr::read_state(year = 2020, showProgress = FALSE)

    # Simplify for web (10% of vertices)
    if (RMAPSHAPER_AVAILABLE) {
      brazil_states_sf <- rmapshaper::ms_simplify(states_raw, keep = 0.1, keep_shapes = TRUE)
    } else {
      brazil_states_sf <- sf::st_simplify(states_raw, dTolerance = 0.01)
    }

    cat("  ✓ States loaded and simplified\n")

    # Municipalities (optional - heavy)
    if (FALSE) {  # Disable for now - can enable later
      muni_raw <- geobr::read_municipality(year = 2020, showProgress = FALSE)
      if (RMAPSHAPER_AVAILABLE) {
        brazil_municipalities_sf <- rmapshaper::ms_simplify(muni_raw, keep = 0.05)
      } else {
        brazil_municipalities_sf <- sf::st_simplify(muni_raw, dTolerance = 0.02)
      }
      cat("  ✓ Municipalities loaded and simplified\n")
    }

  }, error = function(e) {
    cat("❌ Geography load failed:", conditionMessage(e), "\n")
  })
} else if (IS_CLOUD_RUN) {
  cat("⚡ Skipping geography preload on Cloud Run (will load lazily)\n")
}

# ASYNC SETUP
# ===========
future::plan(future::multisession, workers = 2)
cat("✅ Async configured (2 workers)\n")

# LOAD YOUR EXISTING MODULES
# ===========================
cat("\n📦 Loading application modules...\n")

# Load table compatibility layer
if (file.exists("R/table_compat.R")) {
  source("R/table_compat.R", local = TRUE)
  cat("  ✓ Table compatibility\n")
}

# Load render safety guards
if (file.exists("R/render_safety.R")) {
  source("R/render_safety.R", local = TRUE)
  cat("  ✓ Render safety\n")
}

# Load UI utilities
if (file.exists("R/utils/ui_utils.R")) {
  source("R/utils/ui_utils.R", local = TRUE)
  cat("  ✓ UI utilities\n")
}

# Export for modules to use
options(app_db_pool = db_pool)

# STARTUP DIAGNOSTICS
# ===================
cat("\n========================================\n")
cat("📊 STARTUP STATUS:\n")
cat(sprintf("  Database:       %s\n", if (DB_AVAILABLE) "✅ Connected" else "❌ Unavailable"))
cat(sprintf("  Spatial Data:   %s\n", if (!is.null(brazil_states_sf)) "✅ Loaded" else "❌ Unavailable"))
cat(sprintf("  Cache:          ✅ Enabled (TTL: %ds)\n", app_config$cache_ttl))
cat(sprintf("  Async Workers:  ✅ 2 workers\n"))
cat(sprintf("  Data Service:   %s\n", if (exists("get_documents")) "✅ Available" else "❌ Unavailable"))
cat("========================================\n\n")

# Export configuration
assign("app_config", app_config, envir = .GlobalEnv)
assign("DB_AVAILABLE", DB_AVAILABLE, envir = .GlobalEnv)
assign("LEAFLET_AVAILABLE", LEAFLET_AVAILABLE, envir = .GlobalEnv)
assign("SF_AVAILABLE", SF_AVAILABLE, envir = .GlobalEnv)

cat("✅ Global configuration complete - app ready to launch\n\n")
