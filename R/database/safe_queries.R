# =============================================================================
# Safe Query Execution - SQL Injection Prevention
# =============================================================================
# Provides parameterized query execution to prevent SQL injection attacks
# Uses DBI parameterization instead of string concatenation
# =============================================================================

#' Execute a Safe Parameterized Query
#'
#' Executes a SQL query with parameterized inputs to prevent SQL injection.
#' This function should be used for ALL user-input-based queries.
#'
#' @param pool Database connection pool from pool package
#' @param query SQL query string with ? or $1, $2 placeholders
#' @param params Named list of parameters to bind to query
#' @param log_query Logical, whether to log the query execution (default: TRUE)
#'
#' @return Query results as data frame, or NULL on error
#'
#' @examples
#' \dontrun{
#' # Using ? placeholders (positional)
#' results <- execute_safe_query(
#'   pool = db_pool,
#'   query = "SELECT * FROM documents WHERE id = ? AND status = ?",
#'   params = list(123, "active")
#' )
#'
#' # Using named placeholders (PostgreSQL)
#' results <- execute_safe_query(
#'   pool = db_pool,
#'   query = "SELECT * FROM documents WHERE id = $1 AND status = $2",
#'   params = list(123, "active")
#' )
#' }
#'
#' @export
execute_safe_query <- function(pool, query, params = list(), log_query = TRUE) {
  # Validate inputs
  if (!inherits(pool, "Pool")) {
    stop("Parameter 'pool' must be a Pool object from the pool package")
  }

  if (!is.character(query) || length(query) != 1) {
    stop("Parameter 'query' must be a single character string")
  }

  if (!is.list(params)) {
    stop("Parameter 'params' must be a list")
  }

  # Log query execution (sanitized - no actual parameter values)
  if (log_query) {
    param_count <- length(params)
    message(sprintf(
      "[SAFE QUERY] Executing query with %d parameter(s) | Query: %s",
      param_count,
      substr(gsub("\\s+", " ", query), 1, 100)  # Truncate to 100 chars
    ))
  }

  # Execute query with error handling
  tryCatch({
    # Checkout connection from pool
    conn <- pool::poolCheckout(pool)

    # Ensure connection is returned even on error
    on.exit({
      pool::poolReturn(conn)
    }, add = TRUE)

    # Execute parameterized query
    result <- if (length(params) > 0) {
      # With parameters - use DBI parameterization
      DBI::dbGetQuery(conn, query, params = params)
    } else {
      # No parameters - direct execution
      DBI::dbGetQuery(conn, query)
    }

    if (log_query) {
      message(sprintf("[SAFE QUERY] Success - returned %d rows", nrow(result)))
    }

    return(result)

  }, error = function(e) {
    # Log error (but don't expose parameter values)
    message(sprintf(
      "[SAFE QUERY ERROR] Query failed | Error: %s | Query: %s",
      e$message,
      substr(query, 1, 100)
    ))

    # Re-throw error for calling code to handle
    stop(sprintf("Database query failed: %s", e$message))
  })
}


#' Execute a Safe Parameterized Update/Insert/Delete
#'
#' Executes a DML statement (INSERT/UPDATE/DELETE) with parameterized inputs.
#' Returns the number of rows affected.
#'
#' @param pool Database connection pool from pool package
#' @param statement SQL DML statement with ? or $1, $2 placeholders
#' @param params Named list of parameters to bind to statement
#' @param log_query Logical, whether to log the statement execution (default: TRUE)
#'
#' @return Number of rows affected
#'
#' @examples
#' \dontrun{
#' # Update with parameters
#' rows_affected <- execute_safe_dml(
#'   pool = db_pool,
#'   statement = "UPDATE documents SET status = $1 WHERE id = $2",
#'   params = list("archived", 123)
#' )
#' }
#'
#' @export
execute_safe_dml <- function(pool, statement, params = list(), log_query = TRUE) {
  # Validate inputs
  if (!inherits(pool, "Pool")) {
    stop("Parameter 'pool' must be a Pool object from the pool package")
  }

  if (!is.character(statement) || length(statement) != 1) {
    stop("Parameter 'statement' must be a single character string")
  }

  if (!is.list(params)) {
    stop("Parameter 'params' must be a list")
  }

  # Log statement execution (sanitized)
  if (log_query) {
    param_count <- length(params)
    message(sprintf(
      "[SAFE DML] Executing statement with %d parameter(s) | Statement: %s",
      param_count,
      substr(gsub("\\s+", " ", statement), 1, 100)
    ))
  }

  # Execute statement with error handling
  tryCatch({
    # Checkout connection from pool
    conn <- pool::poolCheckout(pool)

    # Ensure connection is returned even on error
    on.exit({
      pool::poolReturn(conn)
    }, add = TRUE)

    # Execute parameterized statement
    rows_affected <- if (length(params) > 0) {
      # With parameters - use DBI parameterization
      DBI::dbExecute(conn, statement, params = params)
    } else {
      # No parameters - direct execution
      DBI::dbExecute(conn, statement)
    }

    if (log_query) {
      message(sprintf("[SAFE DML] Success - %d row(s) affected", rows_affected))
    }

    return(rows_affected)

  }, error = function(e) {
    # Log error (but don't expose parameter values)
    message(sprintf(
      "[SAFE DML ERROR] Statement failed | Error: %s | Statement: %s",
      e$message,
      substr(statement, 1, 100)
    ))

    # Re-throw error for calling code to handle
    stop(sprintf("Database DML failed: %s", e$message))
  })
}


#' Validate and Sanitize Search Terms
#'
#' Validates search input and prepares it for safe use in queries.
#' Prevents common SQL injection patterns in search terms.
#'
#' @param search_term User-provided search term
#' @param max_length Maximum allowed length (default: 500)
#' @param allow_wildcards Allow SQL wildcards % and _ (default: TRUE)
#'
#' @return Sanitized search term, or NULL if invalid
#'
#' @examples
#' \dontrun{
#' safe_term <- validate_search_term("transportation policy", max_length = 100)
#' }
#'
#' @export
validate_search_term <- function(search_term, max_length = 500, allow_wildcards = TRUE) {
  # Check for NULL or empty
  if (is.null(search_term) || nchar(trimws(search_term)) == 0) {
    return(NULL)
  }

  # Convert to character
  search_term <- as.character(search_term)

  # Trim whitespace
  search_term <- trimws(search_term)

  # Check length
  if (nchar(search_term) > max_length) {
    warning(sprintf("Search term exceeds maximum length (%d), truncating", max_length))
    search_term <- substr(search_term, 1, max_length)
  }

  # Block obvious SQL injection patterns
  dangerous_patterns <- c(
    "';",           # Statement terminator
    "--",           # SQL comment
    "/\\*",         # Block comment start
    "\\*/",         # Block comment end
    "xp_",          # SQL Server extended procedures
    "sp_",          # SQL Server stored procedures
    "exec\\s",      # Execute command
    "execute\\s",   # Execute command
    "drop\\s",      # Drop command
    "delete\\s",    # Delete command (within search context)
    "insert\\s",    # Insert command
    "update\\s"     # Update command
  )

  for (pattern in dangerous_patterns) {
    if (grepl(pattern, search_term, ignore.case = TRUE)) {
      warning(sprintf("Search term contains potentially dangerous pattern: %s", pattern))
      return(NULL)
    }
  }

  # If wildcards not allowed, escape them
  if (!allow_wildcards) {
    search_term <- gsub("%", "\\%", search_term, fixed = TRUE)
    search_term <- gsub("_", "\\_", search_term, fixed = TRUE)
  }

  return(search_term)
}


#' Build Safe LIKE Pattern
#'
#' Builds a safe LIKE pattern for text search queries.
#' Properly escapes special characters and adds wildcards.
#'
#' @param term Search term to convert to LIKE pattern
#' @param match_type Type of match: "contains", "starts_with", "ends_with", "exact"
#'
#' @return Safe LIKE pattern string
#'
#' @examples
#' \dontrun{
#' pattern <- build_safe_like_pattern("transport", match_type = "contains")
#' # Returns: "%transport%"
#' }
#'
#' @export
build_safe_like_pattern <- function(term, match_type = "contains") {
  # Validate term
  term <- validate_search_term(term, allow_wildcards = FALSE)

  if (is.null(term)) {
    return(NULL)
  }

  # Escape existing wildcards in the term
  term <- gsub("%", "\\%", term, fixed = TRUE)
  term <- gsub("_", "\\_", term, fixed = TRUE)

  # Add wildcards based on match type
  pattern <- switch(
    match_type,
    "contains" = paste0("%", term, "%"),
    "starts_with" = paste0(term, "%"),
    "ends_with" = paste0("%", term),
    "exact" = term,
    stop("Invalid match_type. Must be: contains, starts_with, ends_with, or exact")
  )

  return(pattern)
}
