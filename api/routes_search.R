# ============================================================================
# SEARCH API ROUTES
# ============================================================================
# Full-text search endpoints using PostgreSQL full-text search

library(glue)

# Search implementation with full-text search and filters
search_impl <- function(q, scope, date_from, date_to, page, page_size, sort) {
  where <- c("to_tsvector('portuguese', unaccent(full_text)) @@ plainto_tsquery('portuguese', unaccent($1))")
  params <- list(q)
  i <- 2L

  if (!is.null(scope)) {
    where <- c(where, sprintf("jurisdiction = $%d", i))
    params[[i]] <- scope
    i <- i + 1
  }

  if (!is.na(date_from)) {
    where <- c(where, sprintf("date >= $%d", i))
    params[[i]] <- date_from
    i <- i + 1
  }

  if (!is.na(date_to)) {
    where <- c(where, sprintf("date <= $%d", i))
    params[[i]] <- date_to
    i <- i + 1
  }

  order <- if (sort == "recency") {
    "ORDER BY date DESC"
  } else {
    "ORDER BY ts_rank(to_tsvector('portuguese', unaccent(full_text)), plainto_tsquery('portuguese', unaccent($1))) DESC"
  }

  offset <- (page - 1L) * page_size

  sql_items <- sprintf("
    WITH base AS (
      SELECT id, title, jurisdiction, date,
             ts_headline('portuguese', unaccent(full_text), plainto_tsquery('portuguese', unaccent($1))) AS snippet,
             ts_rank(to_tsvector('portuguese', unaccent(full_text)), plainto_tsquery('portuguese', unaccent($1))) AS score
      FROM legis_docs
      WHERE %s
    )
    SELECT * FROM base %s LIMIT %d OFFSET %d;",
    paste(where, collapse = " AND "),
    order,
    page_size,
    offset
  )

  sql_count <- sprintf(
    "SELECT COUNT(*) AS total FROM legis_docs WHERE %s;",
    paste(where, collapse = " AND ")
  )

  total <- dbGetQuery(con_pg, sql_count, params = params)$total[[1]]
  items <- dbGetQuery(con_pg, sql_items, params = params)

  list(
    meta = list(page = page, page_size = page_size, total = total),
    items = items
  )
}

#' @get /api/v1/search
#' @serializer json
#' @tag Search
#' @description Full-text search across legislative documents
#' @param q:character Search query (required)
#' @param scope:[federal|state|municipal] Filter by jurisdiction (optional)
#' @param date_from:character Start date YYYY-MM-DD (optional)
#' @param date_to:character End date YYYY-MM-DD (optional)
#' @param page:int Page number (default: 1)
#' @param page_size:int Results per page (default: 25, max: 100)
#' @param sort:[relevance|recency] Sort order (default: relevance)
pr$get("/api/v1/search", with_http_cache(function(req, res) {
  q         <- as_scalar(req$args$q, "q")
  scope     <- if (!is.null(req$args$scope)) {
    as_enum(req$args$scope, "scope", c("federal", "state", "municipal"))
  } else {
    NULL
  }
  date_from <- safe_date(req$args$date_from, "date_from")
  date_to   <- safe_date(req$args$date_to, "date_to")
  page      <- max(1L, as.integer(req$args$page %||% 1))
  page_size <- min(100L, max(1L, as.integer(req$args$page_size %||% 25)))
  sort      <- match.arg((req$args$sort %||% "relevance"), c("relevance", "recency"))

  search_impl(q, scope, date_from, date_to, page, page_size, sort)
}, ttl = 90))
