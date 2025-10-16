# ============================================================================
# API VALIDATORS AND UTILITIES
# ============================================================================
# Input validation and sanitization for Legislative Monitor API
# Ensures data integrity and provides clear error messages

# Scalar validation
as_scalar <- function(x, name, allow_empty = FALSE) {
  if (is.null(x) || length(x) == 0 || (is.character(x) && trimws(x) == "")) {
    if (allow_empty) return(NA_character_)
    stop(structure(
      list(
        error = "invalid_request",
        message = sprintf("%s is required", name)
      ),
      class = "api_error"
    ))
  }
  if (length(x) > 1) {
    stop(structure(
      list(
        error = "invalid_request",
        message = sprintf("%s must be scalar", name)
      ),
      class = "api_error"
    ))
  }
  x[1]
}

# Enum validation
as_enum <- function(x, name, choices) {
  x <- as_scalar(x, name)
  if (!x %in% choices) {
    stop(structure(
      list(
        error = "invalid_request",
        message = sprintf("%s must be one of: %s", name, paste(choices, collapse = ", "))
      ),
      class = "api_error"
    ))
  }
  x
}

# Date validation
safe_date <- function(x, name) {
  if (is.null(x) || x == "") return(NA)
  d <- tryCatch(
    as.Date(x),
    error = function(e) NA
  )
  if (is.na(d)) {
    stop(structure(
      list(
        error = "invalid_request",
        message = sprintf("%s must be in YYYY-MM-DD format", name)
      ),
      class = "api_error"
    ))
  }
  d
}

# Integer validation
safe_int <- function(x, name, min_val = NULL, max_val = NULL) {
  if (is.null(x) || x == "") return(NA_integer_)
  val <- suppressWarnings(as.integer(x))
  if (is.na(val)) {
    stop(structure(
      list(
        error = "invalid_request",
        message = sprintf("%s must be an integer", name)
      ),
      class = "api_error"
    ))
  }
  if (!is.null(min_val) && val < min_val) {
    stop(structure(
      list(
        error = "invalid_request",
        message = sprintf("%s must be >= %d", name, min_val)
      ),
      class = "api_error"
    ))
  }
  if (!is.null(max_val) && val > max_val) {
    stop(structure(
      list(
        error = "invalid_request",
        message = sprintf("%s must be <= %d", name, max_val)
      ),
      class = "api_error"
    ))
  }
  val
}

# Coalesce operator
`%||%` <- function(a, b) {
  if (is.null(a) || (is.character(a) && a == "")) b else a
}

# Sanitize search query
sanitize_search <- function(query) {
  if (is.null(query) || query == "") return("")
  # Remove SQL injection attempts
  query <- gsub("[';\"\\\\]", "", query)
  # Limit length
  query <- substr(query, 1, 500)
  trimws(query)
}

# Validate pagination parameters
validate_pagination <- function(page, limit, max_limit = 1000) {
  page <- safe_int(page %||% 1, "page", min_val = 1)
  limit <- safe_int(limit %||% 100, "limit", min_val = 1, max_val = max_limit)

  list(
    page = page,
    limit = limit,
    offset = (page - 1) * limit
  )
}

# Validate jurisdiction
validate_jurisdiction <- function(jurisdiction) {
  if (is.null(jurisdiction) || jurisdiction == "") return("all")
  as_enum(
    jurisdiction,
    "jurisdiction",
    c("all", "federal", "state", "municipal")
  )
}

# Validate Brazilian state code
validate_state <- function(state) {
  if (is.null(state) || state == "") return("all")

  valid_states <- c(
    "all", "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO",
    "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ",
    "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"
  )

  as_enum(toupper(state), "state", valid_states)
}

# Validate date range
validate_date_range <- function(date_start, date_end) {
  start <- safe_date(date_start, "date_start")
  end <- safe_date(date_end, "date_end")

  if (!is.na(start) && !is.na(end) && start > end) {
    stop(structure(
      list(
        error = "invalid_request",
        message = "date_start must be before date_end"
      ),
      class = "api_error"
    ))
  }

  list(start = start, end = end)
}
