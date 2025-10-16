# ============================================================================
# AGGREGATION API ROUTES
# ============================================================================
# Dashboard statistics and aggregations using materialized views

source("api/lib/validators.R")
source("api/lib/http_cache.R")

#' @get /aggregations/by-year
#' @serializer json
#' @tag Aggregations
#' @description Get document counts by year and jurisdiction
#' @param year_start:int Start year (optional)
#' @param year_end:int End year (optional)
#' @param jurisdiction:[federal|state|municipal|all] Filter by jurisdiction
get_docs_by_year <- with_http_cache(function(req, res) {
  year_start <- if (!is.null(req$args$year_start)) {
    safe_int(req$args$year_start, "year_start", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  year_end <- if (!is.null(req$args$year_end)) {
    safe_int(req$args$year_end, "year_end", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  jurisdiction <- validate_jurisdiction(req$args$jurisdiction %||% "all")

  con <- get("con_pg", envir = .GlobalEnv)

  # Use materialized view for fast aggregation
  sql_base <- "
    SELECT
      jurisdiction,
      year,
      n_docs
    FROM mv_docs_year_juris
    WHERE 1=1
  "

  params <- list()
  param_count <- 0

  if (!is.na(year_start)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year >= $%d", param_count))
    params <- c(params, list(year_start))
  }

  if (!is.na(year_end)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year <= $%d", param_count))
    params <- c(params, list(year_end))
  }

  if (jurisdiction != "all") {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND jurisdiction = $%d", param_count))
    params <- c(params, list(jurisdiction))
  }

  sql_base <- paste(sql_base, "ORDER BY year DESC, jurisdiction")

  tryCatch(
    {
      results <- dbGetQuery(con, sql_base, params = params)

      list(
        filters = list(
          year_start = if (!is.na(year_start)) year_start else NULL,
          year_end = if (!is.na(year_end)) year_end else NULL,
          jurisdiction = jurisdiction
        ),
        count = nrow(results),
        data = results,
        meta = list(
          source = "mv_docs_year_juris",
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Aggregation failed: %s", e$message)
      )
    }
  )
}, ttl = 600)

#' @get /aggregations/by-state
#' @serializer json
#' @tag Aggregations
#' @description Get document counts by state and year
#' @param year:int Filter by year (optional)
#' @param state:character Brazilian state code (optional)
get_docs_by_state <- with_http_cache(function(req, res) {
  year <- if (!is.null(req$args$year)) {
    safe_int(req$args$year, "year", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  state <- validate_state(req$args$state %||% "all")

  con <- get("con_pg", envir = .GlobalEnv)

  # Use materialized view
  sql_base <- "
    SELECT
      state,
      year,
      n_docs
    FROM mv_docs_state_year
    WHERE state IS NOT NULL
  "

  params <- list()
  param_count <- 0

  if (!is.na(year)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year = $%d", param_count))
    params <- c(params, list(year))
  }

  if (state != "all") {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND state = $%d", param_count))
    params <- c(params, list(state))
  }

  sql_base <- paste(sql_base, "ORDER BY year DESC, n_docs DESC")

  tryCatch(
    {
      results <- dbGetQuery(con, sql_base, params = params)

      list(
        filters = list(
          year = if (!is.na(year)) year else NULL,
          state = state
        ),
        count = nrow(results),
        data = results,
        meta = list(
          source = "mv_docs_state_year",
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Aggregation failed: %s", e$message)
      )
    }
  )
}, ttl = 600)

#' @get /aggregations/by-topic
#' @serializer json
#' @tag Aggregations
#' @description Get transportation-related document counts
#' @param year_start:int Start year (optional)
#' @param year_end:int End year (optional)
get_docs_by_topic <- with_http_cache(function(req, res) {
  year_start <- if (!is.null(req$args$year_start)) {
    safe_int(req$args$year_start, "year_start", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  year_end <- if (!is.null(req$args$year_end)) {
    safe_int(req$args$year_end, "year_end", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  con <- get("con_pg", envir = .GlobalEnv)

  # Use materialized view for transportation topics
  sql_base <- "
    SELECT
      year,
      jurisdiction,
      n_docs
    FROM mv_docs_transport_topic
    WHERE 1=1
  "

  params <- list()
  param_count <- 0

  if (!is.na(year_start)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year >= $%d", param_count))
    params <- c(params, list(year_start))
  }

  if (!is.na(year_end)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year <= $%d", param_count))
    params <- c(params, list(year_end))
  }

  sql_base <- paste(sql_base, "ORDER BY year DESC, n_docs DESC")

  tryCatch(
    {
      results <- dbGetQuery(con, sql_base, params = params)

      list(
        topic = "transportation",
        filters = list(
          year_start = if (!is.na(year_start)) year_start else NULL,
          year_end = if (!is.na(year_end)) year_end else NULL
        ),
        count = nrow(results),
        data = results,
        meta = list(
          source = "mv_docs_transport_topic",
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Aggregation failed: %s", e$message)
      )
    }
  )
}, ttl = 600)

#' @get /aggregations/stats
#' @serializer json
#' @tag Aggregations
#' @description Get overall statistics
get_overall_stats <- with_http_cache(function(req, res) {
  con <- get("con_pg", envir = .GlobalEnv)

  tryCatch(
    {
      # Total documents
      total <- dbGetQuery(con, "SELECT COUNT(*) as total FROM legis_docs")$total

      # By jurisdiction
      by_jurisdiction <- dbGetQuery(con, "
        SELECT jurisdiction, COUNT(*) as count
        FROM legis_docs
        GROUP BY jurisdiction
        ORDER BY count DESC
      ")

      # By year (last 10 years)
      by_year <- dbGetQuery(con, "
        SELECT year, COUNT(*) as count
        FROM legis_docs
        WHERE year >= EXTRACT(YEAR FROM CURRENT_DATE) - 10
        GROUP BY year
        ORDER BY year DESC
      ")

      # Recent activity (last 30 days)
      recent <- dbGetQuery(con, "
        SELECT COUNT(*) as count
        FROM legis_docs
        WHERE date >= CURRENT_DATE - INTERVAL '30 days'
      ")$count

      list(
        total_documents = total,
        by_jurisdiction = by_jurisdiction,
        by_year = by_year,
        recent_30_days = recent,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to retrieve stats: %s", e$message)
      )
    }
  )
}, ttl = 300)

#' @post /aggregations/refresh
#' @serializer json
#' @tag Aggregations
#' @description Refresh materialized views (admin only)
#' @response 200 Refresh successful
#' @response 500 Refresh failed
refresh_materialized_views <- with_no_cache(function(req, res) {
  # TODO: Add authentication check here
  # For now, allow without auth (add auth middleware later)

  con <- get("con_pg", envir = .GlobalEnv)

  views <- c(
    "mv_docs_year_juris",
    "mv_docs_state_year",
    "mv_docs_transport_topic"
  )

  results <- list()

  for (view in views) {
    result <- tryCatch(
      {
        dbExecute(con, sprintf("REFRESH MATERIALIZED VIEW CONCURRENTLY %s", view))
        list(view = view, status = "success")
      },
      error = function(e) {
        list(view = view, status = "failed", error = e$message)
      }
    )
    results[[view]] <- result
  }

  # Reset cache after refresh
  reset_ingest_cache()

  # Check if any failed
  any_failed <- any(sapply(results, function(r) r$status == "failed"))

  if (any_failed) {
    res$status <- 500
  }

  list(
    message = "Materialized view refresh complete",
    results = results,
    timestamp = Sys.time()
  )
})
