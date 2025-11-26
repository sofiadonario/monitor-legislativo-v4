# ==============================================================================
# KPI CALCULATIONS USING MATERIALIZED VIEWS
# ==============================================================================
# Fast KPI computation using Week 1 materialized views
# - mv_executive_kpis: Overall system KPIs
# - mv_state_summary: State-level breakdowns
# - mv_monthly_trends: Temporal trends
#
# Author: Monitor Legislativo Team
# Date: 2025-11-26
# Version: 1.0
# ==============================================================================

library(DBI)
library(RPostgres)

#' Get executive KPIs from materialized view
#'
#' @param pool Database connection pool
#' @return List with KPI metrics
#' @export
get_executive_kpis <- function(pool = NULL) {
  tryCatch({
    if (is.null(pool)) {
      # Get connection from environment
      pool <- get_db_pool()
    }

    # Query materialized view (< 40ms response time)
    query <- "
      SELECT
        total_documents,
        states_covered,
        docs_last_30_days,
        docs_last_7_days,
        latest_document_date,
        oldest_document_date
      FROM mv_executive_kpis
      LIMIT 1
    "

    result <- dbGetQuery(pool, query)

    if (nrow(result) == 0) {
      return(list(
        total_documents = 0,
        states_covered = 0,
        docs_last_30_days = 0,
        docs_last_7_days = 0,
        latest_document_date = NA,
        oldest_document_date = NA,
        error = "No data available"
      ))
    }

    # Calculate derived metrics
    monthly_avg <- if (!is.na(result$docs_last_30_days[1])) {
      result$docs_last_30_days[1]
    } else {
      0
    }

    weekly_avg <- if (!is.na(result$docs_last_7_days[1])) {
      result$docs_last_7_days[1]
    } else {
      0
    }

    # Calculate growth rate (comparing weekly vs monthly average)
    growth_rate <- if (monthly_avg > 0 && weekly_avg > 0) {
      ((weekly_avg / 7) / (monthly_avg / 30) - 1) * 100
    } else {
      0
    }

    list(
      total_documents = result$total_documents[1],
      states_covered = result$states_covered[1],
      docs_last_30_days = result$docs_last_30_days[1],
      docs_last_7_days = result$docs_last_7_days[1],
      latest_document_date = result$latest_document_date[1],
      oldest_document_date = result$oldest_document_date[1],
      monthly_avg = monthly_avg,
      weekly_avg = weekly_avg,
      growth_rate = growth_rate
    )

  }, error = function(e) {
    cat("❌ Error fetching executive KPIs:", e$message, "\n")
    list(
      total_documents = 0,
      states_covered = 0,
      docs_last_30_days = 0,
      docs_last_7_days = 0,
      error = e$message
    )
  })
}

#' Get state summary data from materialized view
#'
#' @param pool Database connection pool
#' @param top_n Number of top states to return (default 10)
#' @return Data frame with state-level metrics
#' @export
get_state_summary <- function(pool = NULL, top_n = 10) {
  tryCatch({
    if (is.null(pool)) {
      pool <- get_db_pool()
    }

    query <- sprintf("
      SELECT
        state,
        document_count,
        recent_count,
        latest_document,
        ROUND(100.0 * recent_count / NULLIF(document_count, 0), 1) as recent_pct
      FROM mv_state_summary
      ORDER BY document_count DESC
      LIMIT %d
    ", top_n)

    result <- dbGetQuery(pool, query)

    if (nrow(result) == 0) {
      return(data.frame(
        state = character(0),
        document_count = numeric(0),
        recent_count = numeric(0),
        latest_document = character(0),
        recent_pct = numeric(0)
      ))
    }

    result

  }, error = function(e) {
    cat("❌ Error fetching state summary:", e$message, "\n")
    data.frame(
      state = character(0),
      document_count = numeric(0),
      error = e$message
    )
  })
}

#' Get monthly trends from materialized view
#'
#' @param pool Database connection pool
#' @param months Number of months to return (default 12)
#' @return Data frame with monthly trend data
#' @export
get_monthly_trends <- function(pool = NULL, months = 12) {
  tryCatch({
    if (is.null(pool)) {
      pool <- get_db_pool()
    }

    query <- sprintf("
      SELECT
        month,
        document_count
      FROM mv_monthly_trends
      ORDER BY month DESC
      LIMIT %d
    ", months)

    result <- dbGetQuery(pool, query)

    if (nrow(result) == 0) {
      return(data.frame(
        month = character(0),
        document_count = numeric(0)
      ))
    }

    # Reverse order to show oldest to newest
    result <- result[nrow(result):1, ]

    result

  }, error = function(e) {
    cat("❌ Error fetching monthly trends:", e$message, "\n")
    data.frame(
      month = character(0),
      document_count = numeric(0),
      error = e$message
    )
  })
}

#' Get database connection pool from environment
#'
#' @return Database connection pool
get_db_pool <- function() {
  # Check if pool already exists
  if (exists("db_pool", envir = .GlobalEnv)) {
    return(get("db_pool", envir = .GlobalEnv))
  }

  # Create new pool
  pool <- dbPool(
    drv = RPostgres::Postgres(),
    host = Sys.getenv("PGHOST", "34.39.228.246"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "monitor_legislativo"),
    user = Sys.getenv("PGUSER", "monitor_user"),
    password = Sys.getenv("PGPASSWORD", ""),
    minSize = 1,
    maxSize = 5
  )

  assign("db_pool", pool, envir = .GlobalEnv)
  pool
}

#' Refresh all materialized views (admin function)
#'
#' @param pool Database connection pool
#' @return TRUE if successful, FALSE otherwise
#' @export
refresh_materialized_views <- function(pool = NULL) {
  tryCatch({
    if (is.null(pool)) {
      pool <- get_db_pool()
    }

    cat("🔄 Refreshing materialized views...\n")

    # Refresh concurrently (requires unique indexes)
    dbExecute(pool, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_executive_kpis")
    dbExecute(pool, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_state_summary")
    dbExecute(pool, "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_monthly_trends")

    cat("✅ Materialized views refreshed successfully\n")
    TRUE

  }, error = function(e) {
    cat("❌ Error refreshing materialized views:", e$message, "\n")
    FALSE
  })
}

cat("✅ KPI Calculations module loaded (using materialized views)\n")
