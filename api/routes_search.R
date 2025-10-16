# ============================================================================
# SEARCH API ROUTES
# ============================================================================
# Full-text search and fuzzy matching endpoints for Legislative Monitor

source("api/lib/validators.R")
source("api/lib/http_cache.R")

#' @get /search
#' @serializer json
#' @tag Search
#' @description Full-text search across legislative documents
#' @param q:character Search query (required)
#' @param jurisdiction:[federal|state|municipal|all] Filter by jurisdiction
#' @param state:character Brazilian state code (e.g., SP, RJ)
#' @param date_start:character Start date (YYYY-MM-DD)
#' @param date_end:character End date (YYYY-MM-DD)
#' @param page:int Page number (default: 1)
#' @param limit:int Results per page (default: 20, max: 100)
#' @response 200 Search results with pagination
#' @response 400 Invalid request parameters
search_documents <- with_http_cache(function(req, res) {
  # Validate and extract parameters
  query <- sanitize_search(as_scalar(req$args$q, "q"))
  jurisdiction <- validate_jurisdiction(req$args$jurisdiction %||% "all")
  state <- validate_state(req$args$state %||% "all")

  # Validate dates
  dates <- validate_date_range(req$args$date_start, req$args$date_end)

  # Validate pagination
  pagination <- validate_pagination(
    req$args$page,
    req$args$limit %||% 20,
    max_limit = 100
  )

  # Get database connection
  con <- get("con_pg", envir = .GlobalEnv)

  # Build SQL query with parameterized inputs
  sql_base <- "
    SELECT
      id,
      title,
      summary,
      jurisdiction,
      state,
      municipality,
      date,
      document_type,
      ts_rank(search_vector, query) AS relevance
    FROM legis_docs,
         to_tsquery('portuguese', $1) query
    WHERE search_vector @@ query
  "

  # Add filters
  params <- list(query)
  param_count <- 1

  if (jurisdiction != "all") {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND jurisdiction = $%d", param_count))
    params <- c(params, list(jurisdiction))
  }

  if (state != "all") {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND state = $%d", param_count))
    params <- c(params, list(state))
  }

  if (!is.na(dates$start)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND date >= $%d", param_count))
    params <- c(params, list(dates$start))
  }

  if (!is.na(dates$end)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND date <= $%d", param_count))
    params <- c(params, list(dates$end))
  }

  # Add ordering and pagination
  sql_base <- paste(sql_base, "ORDER BY relevance DESC, date DESC")

  param_count <- param_count + 1
  sql_base <- paste(sql_base, sprintf("LIMIT $%d", param_count))
  params <- c(params, list(pagination$limit))

  param_count <- param_count + 1
  sql_base <- paste(sql_base, sprintf("OFFSET $%d", param_count))
  params <- c(params, list(pagination$offset))

  # Get total count
  sql_count <- "
    SELECT COUNT(*) as total
    FROM legis_docs,
         to_tsquery('portuguese', $1) query
    WHERE search_vector @@ query
  "

  count_params <- list(query)
  count_param_idx <- 1

  if (jurisdiction != "all") {
    count_param_idx <- count_param_idx + 1
    sql_count <- paste(sql_count, sprintf("AND jurisdiction = $%d", count_param_idx))
    count_params <- c(count_params, list(jurisdiction))
  }

  if (state != "all") {
    count_param_idx <- count_param_idx + 1
    sql_count <- paste(sql_count, sprintf("AND state = $%d", count_param_idx))
    count_params <- c(count_params, list(state))
  }

  if (!is.na(dates$start)) {
    count_param_idx <- count_param_idx + 1
    sql_count <- paste(sql_count, sprintf("AND date >= $%d", count_param_idx))
    count_params <- c(count_params, list(dates$start))
  }

  if (!is.na(dates$end)) {
    count_param_idx <- count_param_idx + 1
    sql_count <- paste(sql_count, sprintf("AND date <= $%d", count_param_idx))
    count_params <- c(count_params, list(dates$end))
  }

  # Execute queries
  tryCatch(
    {
      results <- dbGetQuery(con, sql_base, params = params)
      total <- dbGetQuery(con, sql_count, params = count_params)$total

      list(
        query = query,
        filters = list(
          jurisdiction = jurisdiction,
          state = state,
          date_start = if (!is.na(dates$start)) as.character(dates$start) else NULL,
          date_end = if (!is.na(dates$end)) as.character(dates$end) else NULL
        ),
        pagination = list(
          page = pagination$page,
          limit = pagination$limit,
          total = total,
          total_pages = ceiling(total / pagination$limit)
        ),
        results = results,
        meta = list(
          execution_time_ms = as.numeric(Sys.time()) * 1000,
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "search_error",
        message = sprintf("Search failed: %s", e$message)
      )
    }
  )
}, ttl = 300)

#' @get /search/fuzzy
#' @serializer json
#' @tag Search
#' @description Fuzzy search using trigram matching for typo tolerance
#' @param q:character Search query (required)
#' @param threshold:numeric Similarity threshold (0-1, default: 0.3)
#' @param limit:int Maximum results (default: 20, max: 50)
fuzzy_search <- with_http_cache(function(req, res) {
  query <- sanitize_search(as_scalar(req$args$q, "q"))
  threshold <- as.numeric(req$args$threshold %||% 0.3)
  limit <- safe_int(req$args$limit %||% 20, "limit", min_val = 1, max_val = 50)

  # Validate threshold
  if (threshold < 0 || threshold > 1) {
    res$status <- 400
    return(list(
      error = "invalid_request",
      message = "threshold must be between 0 and 1"
    ))
  }

  con <- get("con_pg", envir = .GlobalEnv)

  sql <- "
    SELECT
      id,
      title,
      jurisdiction,
      state,
      date,
      similarity(unaccent(title), unaccent($1)) AS similarity_score
    FROM legis_docs
    WHERE unaccent(title) % unaccent($1)
      AND similarity(unaccent(title), unaccent($1)) >= $2
    ORDER BY similarity_score DESC, date DESC
    LIMIT $3
  "

  tryCatch(
    {
      results <- dbGetQuery(con, sql, params = list(query, threshold, limit))

      list(
        query = query,
        threshold = threshold,
        results_count = nrow(results),
        results = results,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "search_error",
        message = sprintf("Fuzzy search failed: %s", e$message)
      )
    }
  )
}, ttl = 300)

#' @get /search/suggest
#' @serializer json
#' @tag Search
#' @description Get search query suggestions based on popular terms
#' @param q:character Partial query (required)
#' @param limit:int Maximum suggestions (default: 10)
search_suggestions <- with_http_cache(function(req, res) {
  query <- sanitize_search(as_scalar(req$args$q, "q", allow_empty = TRUE))
  limit <- safe_int(req$args$limit %||% 10, "limit", min_val = 1, max_val = 20)

  if (nchar(query) < 2) {
    return(list(
      query = query,
      suggestions = list(),
      message = "Query too short (minimum 2 characters)"
    ))
  }

  con <- get("con_pg", envir = .GlobalEnv)

  # Find common terms from document titles
  sql <- "
    SELECT DISTINCT
      title,
      COUNT(*) OVER (PARTITION BY title) as frequency
    FROM legis_docs
    WHERE unaccent(title) ILIKE unaccent($1)
    ORDER BY frequency DESC
    LIMIT $2
  "

  tryCatch(
    {
      results <- dbGetQuery(con, sql, params = list(paste0("%", query, "%"), limit))

      list(
        query = query,
        suggestions = if (nrow(results) > 0) results$title else list(),
        count = nrow(results)
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "suggestion_error",
        message = sprintf("Suggestion query failed: %s", e$message)
      )
    }
  )
}, ttl = 600)
