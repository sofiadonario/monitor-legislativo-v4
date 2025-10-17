#' Safety Library for Shiny App
#'
#' Defensive utilities to prevent scalar/empty data crashes
#' Created: 2025-01-16

#' Extract scalar value with validation
#'
#' @param x Vector to extract from
#' @param name Parameter name for error messages
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Scalar value or NA
#' @export
as_scalar <- function(x, name, allow_na = TRUE) {
  if (is.null(x) || length(x) == 0 || (is.character(x) && all(trimws(x) == ""))) {
    if (allow_na) return(NA)
    stop(sprintf("Missing required value: %s (length 0)", name), call. = FALSE)
  }
  if (length(x) > 1) {
    warning(sprintf("Multiple values where scalar expected: %s (taking first)", name))
  }
  x[1]
}

#' Safe scalar character extraction
#'
#' @param x Vector to extract from
#' @param name Parameter name for error messages
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Character scalar or NA
#' @export
as_scalar_chr <- function(x, name, allow_na = TRUE) {
  val <- as_scalar(x, name, allow_na)
  if (is.na(val) && allow_na) return(NA_character_)
  as.character(val)
}

#' Safe scalar numeric extraction
#'
#' @param x Vector to extract from
#' @param name Parameter name for error messages
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Numeric scalar or NA
#' @export
as_scalar_num <- function(x, name, allow_na = TRUE) {
  val <- as_scalar(x, name, allow_na)
  if (is.na(val) && allow_na) return(NA_real_)
  as.numeric(val)
}

#' Safe scalar integer extraction
#'
#' @param x Vector to extract from
#' @param name Parameter name for error messages
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Integer scalar or NA
#' @export
as_scalar_int <- function(x, name, allow_na = TRUE) {
  val <- as_scalar(x, name, allow_na)
  if (is.na(val) && allow_na) return(NA_integer_)
  as.integer(val)
}

#' Check for non-zero rows in data frame
#'
#' @param df Data frame to check
#' @param name Name for logging/error messages
#' @return Data frame if valid, NULL otherwise
#' @export
nz_rows <- function(df, name = "data") {
  if (is.null(df) || !is.data.frame(df) || nrow(df) == 0) {
    log_debug(sprintf("%s: empty or NULL data frame", name))
    return(NULL)
  }
  df
}

#' Check for non-empty vector
#'
#' @param x Vector to check
#' @param name Name for error messages
#' @return Vector if valid, NULL otherwise
#' @export
nz_length <- function(x, name = "vector") {
  if (is.null(x) || length(x) == 0) {
    log_debug(sprintf("%s: empty or NULL vector", name))
    return(NULL)
  }
  x
}

#' Safe database query wrapper
#'
#' @param pool Database pool or connection
#' @param query SQL query string
#' @param params Query parameters (list)
#' @param query_name Name for logging
#' @return Data frame or NULL
#' @export
safe_query <- function(pool, query, params = list(), query_name = "query") {
  tryCatch({
    log_debug(sprintf("Executing %s with %d params", query_name, length(params)))

    df <- DBI::dbGetQuery(pool, query, params = params)

    if (is.null(df) || nrow(df) == 0) {
      log_debug(sprintf("%s returned 0 rows", query_name))
      return(NULL)
    }

    log_debug(sprintf("%s returned %d rows", query_name, nrow(df)))
    df

  }, error = function(e) {
    log_error(sprintf("%s failed: %s", query_name, conditionMessage(e)))
    NULL
  })
}

#' Safe numeric conversion
#'
#' @param x Value to convert
#' @param default Default value if conversion fails
#' @return Numeric value or default
#' @export
safe_as_numeric <- function(x, default = NA_real_) {
  if (is.null(x) || length(x) == 0) return(default)
  if (is.character(x) && trimws(x) == "") return(default)

  result <- suppressWarnings(as.numeric(x))
  if (is.na(result) && !is.na(x)) return(default)
  result
}

#' Safe date conversion
#'
#' @param x Value to convert
#' @param default Default value if conversion fails
#' @return Date value or default
#' @export
safe_as_date <- function(x, default = NA) {
  if (is.null(x) || length(x) == 0) return(default)
  if (is.character(x) && trimws(x) == "") return(default)

  tryCatch({
    as.Date(x)
  }, error = function(e) {
    default
  })
}

#' Structured debug logging
#'
#' @param ... Messages to log
#' @export
log_debug <- function(...) {
  if (getOption("DEBUG_SAFETY", FALSE)) {
    cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| DEBUG |", paste(..., collapse = " "), "\n")
  }
}

#' Structured info logging
#'
#' @param ... Messages to log
#' @export
log_info <- function(...) {
  cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| INFO  |", paste(..., collapse = " "), "\n")
}

#' Structured warning logging
#'
#' @param ... Messages to log
#' @export
log_warn <- function(...) {
  cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| WARN  |", paste(..., collapse = " "), "\n")
}

#' Structured error logging
#'
#' @param ... Messages to log
#' @export
log_error <- function(...) {
  cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| ERROR |", paste(..., collapse = " "), "\n")
}

#' Create empty state UI card
#'
#' @param msg Message to display
#' @param icon Icon name (default: info-circle)
#' @return HTML div
#' @export
empty_card <- function(msg = "Sem resultados. Ajuste os filtros.", icon = "info-circle") {
  shiny::div(
    class = "alert alert-info",
    style = "margin: 20px; padding: 15px; text-align: center;",
    shiny::icon(icon),
    " ",
    msg
  )
}

#' Create error state UI card
#'
#' @param msg Error message to display
#' @return HTML div
#' @export
error_card <- function(msg = "Erro ao carregar dados. Tente novamente.") {
  shiny::div(
    class = "alert alert-danger",
    style = "margin: 20px; padding: 15px; text-align: center;",
    shiny::icon("exclamation-triangle"),
    " ",
    msg
  )
}

#' Create loading state UI card
#'
#' @param msg Loading message to display
#' @return HTML div
#' @export
loading_card <- function(msg = "Carregando...") {
  shiny::div(
    class = "alert alert-secondary",
    style = "margin: 20px; padding: 15px; text-align: center;",
    shiny::icon("spinner", class = "fa-spin"),
    " ",
    msg
  )
}

#' Safe render wrapper with error handling
#'
#' @param expr Expression to render
#' @param error_msg Error message to show users
#' @param empty_msg Message for empty results
#' @return Render function result or error UI
#' @export
safe_render <- function(expr, error_msg = "Erro ao renderizar componente.", empty_msg = NULL) {
  tryCatch({
    result <- expr

    # Check for NULL/empty results
    if (is.null(result)) {
      if (!is.null(empty_msg)) {
        return(empty_card(empty_msg))
      }
      return(NULL)
    }

    # Check for empty data frames
    if (is.data.frame(result) && nrow(result) == 0) {
      if (!is.null(empty_msg)) {
        return(empty_card(empty_msg))
      }
      return(NULL)
    }

    result

  }, error = function(e) {
    log_error(sprintf("Render error: %s", conditionMessage(e)))
    error_card(error_msg)
  })
}

#' Validate input selection exists
#'
#' @param input_value Input value to check
#' @param input_name Name for error message
#' @return TRUE if valid, stops execution otherwise
#' @export
validate_selection <- function(input_value, input_name = "selection") {
  shiny::validate(
    shiny::need(
      !is.null(input_value) && length(input_value) > 0,
      sprintf("Selecione pelo menos um %s.", input_name)
    )
  )
}

#' Validate data frame has rows
#'
#' @param df Data frame to check
#' @param msg Message to show if empty
#' @return TRUE if valid, stops execution otherwise
#' @export
validate_data <- function(df, msg = "Sem dados disponíveis. Ajuste os filtros.") {
  shiny::validate(
    shiny::need(!is.null(df) && is.data.frame(df) && nrow(df) > 0, msg)
  )
}

#' Validate numeric range
#'
#' @param range Numeric vector of length 2
#' @param name Name for error message
#' @return TRUE if valid, stops execution otherwise
#' @export
validate_range <- function(range, name = "range") {
  shiny::validate(
    shiny::need(
      !is.null(range) && length(range) == 2 && !any(is.na(range)),
      sprintf("Selecione um intervalo válido para %s.", name)
    )
  )
}

#' Initialize safety library
#'
#' @param debug Enable debug logging
#' @export
init_safety <- function(debug = FALSE) {
  options(DEBUG_SAFETY = debug)
  log_info("Safety library initialized (debug =", debug, ")")
}
