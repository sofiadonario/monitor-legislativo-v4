# =============================================================================
# Pagination Utility Functions
# =============================================================================
# Phase 2: Performance Optimization - Task 2.3
# Server-side pagination to handle large datasets efficiently
# =============================================================================

#' Generate paginated SQL query
#'
#' @param base_query Character string with base SQL query (SELECT statement)
#' @param page Integer, current page number (1-indexed)
#' @param page_size Integer, number of rows per page (default 50)
#' @return Character string with paginated SQL query including total row count
#'
#' @examples
#' query <- "SELECT * FROM documents WHERE tipo = 'Lei'"
#' paginate_query(query, page = 1, page_size = 50)
paginate_query <- function(base_query, page = 1, page_size = 50) {
  if (page < 1) {
    stop("Page must be >= 1")
  }

  if (page_size < 1 || page_size > 500) {
    stop("Page size must be between 1 and 500")
  }

  offset <- (page - 1) * page_size

  # Add COUNT(*) OVER() for total row count (window function)
  # This allows us to get total count in a single query
  query_with_count <- gsub(
    "SELECT",
    "SELECT COUNT(*) OVER() as total_rows,",
    base_query,
    ignore.case = TRUE,
    fixed = FALSE
  )

  # Handle case where SELECT is already modified
  if (!grepl("total_rows", query_with_count, ignore.case = TRUE)) {
    query_with_count <- sub(
      "^\\s*SELECT\\s+",
      "SELECT COUNT(*) OVER() as total_rows, ",
      query_with_count,
      ignore.case = TRUE
    )
  }

  # Add LIMIT and OFFSET
  paginated_query <- paste(
    query_with_count,
    "LIMIT", page_size,
    "OFFSET", offset
  )

  paginated_query
}

#' Calculate pagination metadata
#'
#' @param total_rows Integer, total number of rows in dataset
#' @param page Integer, current page number
#' @param page_size Integer, rows per page
#' @return List with pagination metadata
#'
#' @examples
#' get_pagination_info(total_rows = 1000, page = 1, page_size = 50)
get_pagination_info <- function(total_rows, page, page_size) {
  total_pages <- ceiling(total_rows / page_size)

  list(
    current_page = page,
    total_pages = total_pages,
    page_size = page_size,
    total_rows = total_rows,
    has_previous = page > 1,
    has_next = page < total_pages,
    start_row = ((page - 1) * page_size) + 1,
    end_row = min(page * page_size, total_rows)
  )
}

#' Validate pagination parameters
#'
#' @param page Integer, page number
#' @param page_size Integer, rows per page
#' @param max_page_size Integer, maximum allowed page size (default 500)
#' @return List with validated parameters or error message
validate_pagination <- function(page, page_size, max_page_size = 500) {
  errors <- character(0)

  if (!is.numeric(page) || page < 1) {
    errors <- c(errors, "Page must be a positive integer")
  }

  if (!is.numeric(page_size) || page_size < 1) {
    errors <- c(errors, "Page size must be a positive integer")
  }

  if (page_size > max_page_size) {
    errors <- c(errors, sprintf("Page size cannot exceed %d", max_page_size))
  }

  if (length(errors) > 0) {
    return(list(
      valid = FALSE,
      errors = errors
    ))
  }

  list(
    valid = TRUE,
    page = as.integer(page),
    page_size = as.integer(page_size)
  )
}

#' Extract total rows from paginated query result
#'
#' @param result Data frame returned from paginated query
#' @return List with data and total_rows
#'
#' @examples
#' result <- data.frame(total_rows = c(1000, 1000), id = 1:2, name = c("A", "B"))
#' extract_pagination_data(result)
extract_pagination_data <- function(result) {
  if (is.null(result) || nrow(result) == 0) {
    return(list(
      data = data.frame(),
      total_rows = 0
    ))
  }

  # Extract total from first row
  total_rows <- if ("total_rows" %in% names(result)) {
    result$total_rows[1]
  } else {
    nrow(result)
  }

  # Remove total_rows column from data
  data <- result
  if ("total_rows" %in% names(data)) {
    data$total_rows <- NULL
  }

  list(
    data = data,
    total_rows = total_rows
  )
}

#' Create page range for pagination UI
#'
#' @param current_page Integer, current page
#' @param total_pages Integer, total pages
#' @param max_visible Integer, maximum pages to show (default 5)
#' @return Integer vector of page numbers to display
#'
#' @examples
#' get_page_range(current_page = 10, total_pages = 20, max_visible = 5)
get_page_range <- function(current_page, total_pages, max_visible = 5) {
  if (total_pages <= max_visible) {
    return(1:total_pages)
  }

  # Calculate start and end of range
  half_visible <- floor(max_visible / 2)

  start_page <- max(1, current_page - half_visible)
  end_page <- min(total_pages, start_page + max_visible - 1)

  # Adjust if we're at the end
  if (end_page - start_page + 1 < max_visible) {
    start_page <- max(1, end_page - max_visible + 1)
  }

  start_page:end_page
}
