# search_wrapper.R - Wrapper for backward compatibility with SearchService
# ============================================================================
# Purpose: Provides backward-compatible get_library_documents function
# Created: 2025
# ============================================================================

# Load search service
source("R/services/search_service.R")

# Initialize global search service instance
.search_service <- NULL

#' Initialize search service with database connection
#'
#' @param db_connection Database connection (optional)
init_search_service <- function(db_connection = NULL) {
  .search_service <<- SearchService$new(
    db_connection = db_connection,
    cache_enabled = TRUE,
    default_limit = 50
  )
}

#' Backward-compatible wrapper for get_library_documents
#'
#' @param category Document category filter
#' @param search_term Search query
#' @param state State filter
#' @param date_start Start date filter
#' @param date_end End date filter
#' @param sort_by Sort order
#' @param limit Page size (default 50, max 1000)
#' @param offset Page offset
#' @param use_semantic_search Enable semantic search
#' @return Data frame of documents
get_library_documents <- function(category = "all",
                                search_term = "",
                                state = "all",
                                date_start = NULL,
                                date_end = NULL,
                                sort_by = "date_desc",
                                limit = 50,
                                offset = 0,
                                use_semantic_search = TRUE) {

  # Initialize service if not already done
  if (is.null(.search_service)) {
    # Try to get database connection from global environment
    db_conn <- NULL
    if (exists("db") && !is.null(db)) {
      db_conn <- db
    } else if (exists("connection") && !is.null(connection)) {
      db_conn <- connection
    }
    init_search_service(db_conn)
  }

  # Handle legacy unlimited limit (999999)
  if (!isTRUE(is.null(limit)) && limit > 1000) {
    warning(paste("Large limit requested:", limit, "- using paginated approach"))

    # For very large requests, use pagination
    all_results <- list()
    current_offset <- offset
    page_size <- 1000
    total_fetched <- 0
    max_to_fetch <- min(limit, 10000) # Cap at 10000 for memory safety

    while (total_fetched < max_to_fetch) {
      page <- .search_service$search_documents(
        category = category,
        search_term = search_term,
        state = state,
        date_start = date_start,
        date_end = date_end,
        sort_by = sort_by,
        limit = page_size,
        offset = current_offset,
        use_semantic_search = use_semantic_search
      )

      if (isTRUE(is.null(page)) || nrow(page) == 0) {
        break
      }

      all_results[[length(all_results) + 1]] <- page
      total_fetched <- total_fetched + nrow(page)
      current_offset <- current_offset + page_size

      # Break if we got less than a full page
      if (nrow(page) < page_size) {
        break
      }
    }

    if (length(all_results) > 0) {
      return(do.call(rbind, all_results))
    } else {
      return(data.frame())
    }
  }

  # Normal paginated search
  return(.search_service$search_documents(
    category = category,
    search_term = search_term,
    state = state,
    date_start = date_start,
    date_end = date_end,
    sort_by = sort_by,
    limit = limit,
    offset = offset,
    use_semantic_search = use_semantic_search
  ))
}

#' Get total count of matching documents
#'
#' @param ... Same parameters as get_library_documents
#' @return Integer count
count_library_documents <- function(category = "all",
                                  search_term = "",
                                  state = "all",
                                  date_start = NULL,
                                  date_end = NULL) {

  if (is.null(.search_service)) {
    init_search_service()
  }

  return(.search_service$count_documents(
    category = category,
    search_term = search_term,
    state = state,
    date_start = date_start,
    date_end = date_end
  ))
}

#' Clear search cache
clear_search_cache <- function() {
  if (!is.null(.search_service)) {
    .search_service$clear_cache()
  }
}