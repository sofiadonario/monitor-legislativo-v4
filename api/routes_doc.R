# ============================================================================
# DOCUMENT API ROUTES
# ============================================================================
# Individual document retrieval and metadata endpoints

source("api/lib/validators.R")
source("api/lib/http_cache.R")

#' @get /document/<id>
#' @serializer json
#' @tag Documents
#' @description Get a single document by ID
#' @param id:character Document ID (required)
#' @response 200 Document details
#' @response 404 Document not found
get_document <- with_http_cache(function(req, res, id) {
  # Validate ID
  id <- as_scalar(id, "id")

  con <- get("con_pg", envir = .GlobalEnv)

  sql <- "
    SELECT
      id,
      title,
      full_text,
      summary,
      jurisdiction,
      state,
      municipality,
      date,
      year,
      status,
      document_type,
      author,
      subjects,
      url,
      urn
    FROM legis_docs
    WHERE id = $1
  "

  tryCatch(
    {
      result <- dbGetQuery(con, sql, params = list(id))

      if (nrow(result) == 0) {
        res$status <- 404
        return(list(
          error = "not_found",
          message = sprintf("Document with ID '%s' not found", id)
        ))
      }

      # Convert to list for JSON serialization
      doc <- as.list(result[1, ])

      list(
        document = doc,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to retrieve document: %s", e$message)
      )
    }
  )
}, ttl = 3600)

#' @get /documents/recent
#' @serializer json
#' @tag Documents
#' @description Get recently published documents
#' @param jurisdiction:[federal|state|municipal|all] Filter by jurisdiction
#' @param state:character Brazilian state code
#' @param days:int Number of days to look back (default: 30, max: 365)
#' @param limit:int Maximum results (default: 50, max: 200)
get_recent_documents <- with_http_cache(function(req, res) {
  jurisdiction <- validate_jurisdiction(req$args$jurisdiction %||% "all")
  state <- validate_state(req$args$state %||% "all")
  days <- safe_int(req$args$days %||% 30, "days", min_val = 1, max_val = 365)
  limit <- safe_int(req$args$limit %||% 50, "limit", min_val = 1, max_val = 200)

  con <- get("con_pg", envir = .GlobalEnv)

  sql_base <- "
    SELECT
      id,
      title,
      summary,
      jurisdiction,
      state,
      date,
      document_type
    FROM legis_docs
    WHERE date >= CURRENT_DATE - INTERVAL '$1 days'
      AND status = 'published'
  "

  params <- list(days)
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

  sql_base <- paste(sql_base, "ORDER BY date DESC")

  param_count <- param_count + 1
  sql_base <- paste(sql_base, sprintf("LIMIT $%d", param_count))
  params <- c(params, list(limit))

  tryCatch(
    {
      results <- dbGetQuery(con, sql_base, params = params)

      list(
        filters = list(
          jurisdiction = jurisdiction,
          state = state,
          days = days
        ),
        count = nrow(results),
        documents = results,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to retrieve recent documents: %s", e$message)
      )
    }
  )
}, ttl = 300)

#' @get /documents/related/<id>
#' @serializer json
#' @tag Documents
#' @description Find documents related to a given document using full-text similarity
#' @param id:character Document ID (required)
#' @param limit:int Maximum results (default: 10, max: 50)
get_related_documents <- with_http_cache(function(req, res, id) {
  id <- as_scalar(id, "id")
  limit <- safe_int(req$args$limit %||% 10, "limit", min_val = 1, max_val = 50)

  con <- get("con_pg", envir = .GlobalEnv)

  # First, check if document exists
  check_sql <- "SELECT title, search_vector FROM legis_docs WHERE id = $1"
  doc <- tryCatch(
    dbGetQuery(con, check_sql, params = list(id)),
    error = function(e) NULL
  )

  if (is.null(doc) || nrow(doc) == 0) {
    res$status <- 404
    return(list(
      error = "not_found",
      message = sprintf("Document with ID '%s' not found", id)
    ))
  }

  # Find similar documents using tsvector similarity
  sql <- "
    WITH source AS (
      SELECT search_vector FROM legis_docs WHERE id = $1
    )
    SELECT
      d.id,
      d.title,
      d.summary,
      d.jurisdiction,
      d.state,
      d.date,
      ts_rank(d.search_vector, (SELECT search_vector FROM source)) AS similarity
    FROM legis_docs d, source
    WHERE d.id != $1
      AND d.search_vector @@ (SELECT search_vector FROM source)
    ORDER BY similarity DESC
    LIMIT $2
  "

  tryCatch(
    {
      results <- dbGetQuery(con, sql, params = list(id, limit))

      list(
        source_document = list(
          id = id,
          title = doc$title[1]
        ),
        count = nrow(results),
        related_documents = results,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to find related documents: %s", e$message)
      )
    }
  )
}, ttl = 1800)

#' @get /documents/count
#' @serializer json
#' @tag Documents
#' @description Get document count with optional filters
#' @param jurisdiction:[federal|state|municipal|all] Filter by jurisdiction
#' @param state:character Brazilian state code
#' @param year:int Filter by year
get_document_count <- with_http_cache(function(req, res) {
  jurisdiction <- validate_jurisdiction(req$args$jurisdiction %||% "all")
  state <- validate_state(req$args$state %||% "all")
  year <- if (!is.null(req$args$year)) {
    safe_int(req$args$year, "year", min_val = 1900, max_val = 2100)
  } else {
    NA_integer_
  }

  con <- get("con_pg", envir = .GlobalEnv)

  sql_base <- "SELECT COUNT(*) as total FROM legis_docs WHERE 1=1"
  params <- list()
  param_count <- 0

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

  if (!is.na(year)) {
    param_count <- param_count + 1
    sql_base <- paste(sql_base, sprintf("AND year = $%d", param_count))
    params <- c(params, list(year))
  }

  tryCatch(
    {
      result <- dbGetQuery(con, sql_base, params = params)

      list(
        filters = list(
          jurisdiction = jurisdiction,
          state = state,
          year = if (!is.na(year)) year else NULL
        ),
        total = result$total[1],
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to count documents: %s", e$message)
      )
    }
  )
}, ttl = 600)

#' @get /documents/status/<status>
#' @serializer json
#' @tag Documents
#' @description Get documents by status
#' @param status:[draft|published|revoked|amended] Document status (required)
#' @param limit:int Maximum results (default: 50, max: 200)
get_documents_by_status <- with_http_cache(function(req, res, status) {
  status <- as_enum(
    status,
    "status",
    c("draft", "published", "revoked", "amended")
  )

  limit <- safe_int(req$args$limit %||% 50, "limit", min_val = 1, max_val = 200)

  con <- get("con_pg", envir = .GlobalEnv)

  sql <- "
    SELECT
      id,
      title,
      summary,
      jurisdiction,
      state,
      date,
      status,
      document_type
    FROM legis_docs
    WHERE status = $1
    ORDER BY date DESC
    LIMIT $2
  "

  tryCatch(
    {
      results <- dbGetQuery(con, sql, params = list(status, limit))

      list(
        status = status,
        count = nrow(results),
        documents = results,
        meta = list(
          timestamp = Sys.time()
        )
      )
    },
    error = function(e) {
      res$status <- 500
      list(
        error = "database_error",
        message = sprintf("Failed to retrieve documents by status: %s", e$message)
      )
    }
  )
}, ttl = 300)
