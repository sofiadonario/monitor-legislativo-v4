# R/utils/scalar_utils.R
# SINGLE SOURCE OF TRUTH FOR SCALAR SAFETY
# All modules must use these functions to avoid "Expecting a single value" errors

# ---- Core null/empty coalescing ----
# FIX v49: Safe %||% operator that prevents extent=0 error
`%||%` <- function(x, y) {
  if (isTRUE(is.null(x))) return(y)
  if (isTRUE(length(x) == 0L)) return(y)
  return(x)
}

# ---- Generic scalar extractors with consistent defaults ----
# FIX v50: ALL safe with isTRUE()
scalar <- function(x, default = NA) {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0L)) return(default)
  x[[1L]]
}

scalar_chr <- function(x, default = "—") {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0L) || isTRUE(all(is.na(x)))) return(default)
  val <- as.character(x[[1L]])
  if (isTRUE(is.na(val)) || isTRUE(!nzchar(val))) default else val
}

scalar_num <- function(x, default = 0) {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0L) || isTRUE(all(is.na(x)))) return(default)
  val <- suppressWarnings(as.numeric(x[[1L]]))
  if (isTRUE(is.na(val))) default else val
}

scalar_int <- function(x, default = 0L) {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0L) || isTRUE(all(is.na(x)))) return(default)
  val <- suppressWarnings(as.integer(x[[1L]]))
  if (isTRUE(is.na(val))) default else val
}

scalar_lgl <- function(x, default = FALSE) {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0L) || isTRUE(all(is.na(x)))) return(default)
  as.logical(x[[1L]]) %||% default
}

# ---- Safe calculation helpers (prevent vector leaks) ----
safe_nrow <- function(x, default = 0) {
  scalar_int(if (is.data.frame(x)) nrow(x) else if (is.atomic(x)) length(x) else NULL, default = default)
}

safe_length <- function(x, default = 0) {
  scalar_int(length(x), default = default)
}

# FIX v50: ALL safe with isTRUE()
safe_n_distinct <- function(x, default = 0) {
  scalar_int(if (isTRUE(!is.null(x)) && isTRUE(length(x) > 0L)) length(unique(x)) else NULL, default = default)
}

safe_mean <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (isTRUE(!is.null(x)) && isTRUE(length(x) > 0L)) mean(x, na.rm = na.rm) else NULL, default = default)
}

safe_sum <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (isTRUE(!is.null(x)) && isTRUE(length(x) > 0L)) sum(x, na.rm = na.rm) else NULL, default = default)
}

safe_max <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (isTRUE(!is.null(x)) && isTRUE(length(x) > 0L)) max(x, na.rm = na.rm) else NULL, default = default)
}

safe_min <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (isTRUE(!is.null(x)) && isTRUE(length(x) > 0L)) min(x, na.rm = na.rm) else NULL, default = default)
}

# ---- Safe existence/length checks ----
# FIX v50: ALL safe with isTRUE()
nz_rows <- function(df) isTRUE(is.data.frame(df)) && isTRUE(nrow(df) > 0L)
nz_len  <- function(x)  isTRUE(!is.null(x)) && isTRUE(length(x) > 0L)
has_rows <- function(x) isTRUE(is.data.frame(x)) && isTRUE(nrow(x) > 0L)

# ---- String collapse with safety ----
collapse1 <- function(x, sep = ", ", default = "—") {
  if (!nz_len(x)) return(default)
  paste0(x, collapse = sep)
}

# ---- UI-specific scalar wrappers ----
# These guarantee single values for valueBox() and renderText()

value_box_scalar <- function(x, default = "—", format_fn = NULL) {
  # Safely extract scalar and optionally format
  val <- if (is.numeric(x)) {
    scalar_num(x, default = 0)
  } else if (is.character(x)) {
    scalar_chr(x, default = default)
  } else {
    scalar(x, default = default)
  }

  if (!isTRUE(is.null(format_fn)) && is.function(format_fn)) {
    tryCatch(format_fn(val), error = function(e) as.character(val))
  } else {
    as.character(val)
  }
}

text_scalar <- function(x, default = "—", prefix = "", suffix = "") {
  # Safe scalar for renderText outputs
  val <- if (is.numeric(x)) {
    scalar_num(x, default = 0)
  } else {
    scalar_chr(x, default = default)
  }
  paste0(prefix, val, suffix)
}

# ---- Formatted scalar helpers ----
scalar_pct <- function(x, digits = 1, default = "0%") {
  val <- scalar_num(x, default = NA)
  if (is.na(val)) return(default)
  paste0(round(val * 100, digits), "%")
}

scalar_decimal <- function(x, digits = 2, default = "0.00") {
  val <- scalar_num(x, default = NA)
  if (is.na(val)) return(default)
  format(round(val, digits), nsmall = digits)
}

scalar_int_formatted <- function(x, big.mark = ".", default = "0") {
  val <- scalar_int(x, default = NA)
  if (is.na(val)) return(default)
  format(val, big.mark = big.mark, scientific = FALSE)
}

# ---- Vector leak detection and logging ----
.scalar_log_env <- new.env(parent = emptyenv())
.scalar_log_env$leak_count <- 0
.scalar_log_env$leaks <- list()

log_vector_leak <- function(x, context = "", call_info = NULL) {
  # Detect if x is a vector with length > 1
  if (!isTRUE(is.null(x)) && length(x) > 1) {
    leak_entry <- list(
      timestamp = Sys.time(),
      context = context,
      length = length(x),
      type = class(x)[1],
      preview = if (length(x) <= 10) x else c(head(x, 5), "...", tail(x, 5)),
      call = if (!is.null(call_info)) call_info else as.character(sys.call(-1))[1]
    )

    .scalar_log_env$leak_count <- .scalar_log_env$leak_count + 1
    .scalar_log_env$leaks[[.scalar_log_env$leak_count]] <- leak_entry

    # Log to console if in debug mode
    if (identical(Sys.getenv("DEBUG_SCALARS", "0"), "1")) {
      cat(sprintf("[VECTOR LEAK] %s: length=%d type=%s context=%s\n",
                  format(leak_entry$timestamp, "%H:%M:%S"),
                  leak_entry$length,
                  leak_entry$type,
                  leak_entry$context),
          file = stderr())
    }
  }
}

get_vector_leak_report <- function() {
  list(
    total_leaks = .scalar_log_env$leak_count,
    recent_leaks = tail(.scalar_log_env$leaks, 20)
  )
}

clear_vector_leak_log <- function() {
  .scalar_log_env$leak_count <- 0
  .scalar_log_env$leaks <- list()
}

# ---- Enhanced scalar functions with leak detection ----
scalar_chr_logged <- function(x, default = "—", context = "") {
  if (!isTRUE(is.null(x)) && length(x) > 1) {
    log_vector_leak(x, context = paste0("scalar_chr: ", context))
  }
  scalar_chr(x, default = default)
}

scalar_num_logged <- function(x, default = 0, context = "") {
  if (!isTRUE(is.null(x)) && length(x) > 1) {
    log_vector_leak(x, context = paste0("scalar_num: ", context))
  }
  scalar_num(x, default = default)
}

scalar_int_logged <- function(x, default = 0L, context = "") {
  if (!isTRUE(is.null(x)) && length(x) > 1) {
    log_vector_leak(x, context = paste0("scalar_int: ", context))
  }
  scalar_int(x, default = default)
}

# ============================================================================
# PRODUCTION-GRADE SCALAR EXTRACTORS (Added 2025-01-16)
# ============================================================================
# These are impossible-to-crash versions for production Railway deployment

#' Extract scalar with strict validation
#' @param x Vector to extract from
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Scalar value or NA/error
# FIX v50: Safe with isTRUE()
scalar1 <- function(x, allow_na = TRUE) {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0)) {
    if (isTRUE(allow_na)) return(NA)
    stop("Missing scalar value (length 0)")
  }
  if (isTRUE(length(x) > 1)) return(x[[1]])
  x
}

#' Safe numeric scalar extraction
#' @param x Vector to extract from
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Numeric scalar or NA
# FIX v50: Safe with isTRUE()
num1 <- function(x, allow_na = TRUE) {
  x <- scalar1(x, allow_na = allow_na)
  if (isTRUE(is.na(x))) return(NA_real_)
  suppressWarnings(as.numeric(x))
}

#' Safe character scalar extraction
#' @param x Vector to extract from
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Character scalar or NA
# FIX v50: Safe with isTRUE()
chr1 <- function(x, allow_na = TRUE) {
  x <- scalar1(x, allow_na = allow_na)
  if (isTRUE(is.na(x))) return(NA_character_)
  as.character(x)
}

#' Safe integer scalar extraction
#' @param x Vector to extract from
#' @param allow_na Whether to return NA for empty/NULL inputs
#' @return Integer scalar or NA
# FIX v50: Safe with isTRUE()
int1 <- function(x, allow_na = TRUE) {
  x <- scalar1(x, allow_na = allow_na)
  if (isTRUE(is.na(x))) return(NA_integer_)
  suppressWarnings(as.integer(x))
}

# ---- Safe glue that tolerates length-0 inputs ----
safe_glue <- function(..., .na = "", .sep = "", .collapse = NULL) {
  if (!requireNamespace("glue", quietly = TRUE)) {
    # Fallback if glue not available
    parts <- list(...)
    parts <- lapply(parts, function(p) if (length(p) == 0) .na else as.character(p))
    return(paste(unlist(parts), collapse = .sep))
  }

  parts <- list(...)
  parts <- lapply(parts, function(p) if (length(p) == 0) .na else p)
  do.call(glue::glue, c(parts, list(.na = .na, .sep = .sep, .collapse = .collapse)))
}

# ---- Friendly formatters that handle NA/zero-length ----
# FIX v50: Safe with isTRUE()
fmt_int <- function(x) {
  x <- num1(x, allow_na = TRUE)
  ifelse(isTRUE(is.na(x)), "–", formatC(as.integer(x), big.mark = ".", format = "d"))
}

fmt_pct <- function(x, digits = 1) {
  x <- num1(x, allow_na = TRUE)
  ifelse(isTRUE(is.na(x)), "–", paste0(formatC(100 * x, format = "f", digits = digits), "%"))
}

fmt_num <- function(x, digits = 1) {
  x <- num1(x, allow_na = TRUE)
  ifelse(isTRUE(is.na(x)), "–", formatC(x, big.mark = ".", decimal.mark = ",", digits = digits, format = "f"))
}

# ---- Safe ratio calculation ----
# FIX v50: Safe with isTRUE()
safe_ratio <- function(num, den) {
  num <- num1(num, allow_na = TRUE)
  den <- num1(den, allow_na = TRUE)
  if (isTRUE(is.na(num)) || isTRUE(is.na(den)) || isTRUE(den == 0)) return(NA_real_)
  num / den
}

# ============================================================================
# ADDITIONAL SAFETY UTILITIES (Added 2025-01-16)
# ============================================================================

# ---- Structured Logging ----
log_debug <- function(...) {
  if (identical(Sys.getenv("DEBUG_SAFETY", "0"), "1")) {
    cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| DEBUG |", paste(..., collapse = " "), "\n")
  }
}

log_info <- function(...) {
  cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| INFO  |", paste(..., collapse = " "), "\n")
}

log_warn <- function(...) {
  cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| WARN  |", paste(..., collapse = " "), "\n", file = stderr())
}

log_error <- function(...) {
  cat(format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "| ERROR |", paste(..., collapse = " "), "\n", file = stderr())
}

# ---- Safe Conversions ----
# FIX v50: Safe with isTRUE()
safe_as_numeric <- function(x, default = NA_real_) {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0)) return(default)
  if (isTRUE(is.character(x)) && isTRUE(trimws(x) == "")) return(default)

  result <- suppressWarnings(as.numeric(x))
  if (isTRUE(is.na(result)) && isTRUE(!is.na(x))) return(default)
  result[1]
}

safe_as_date <- function(x, default = NA) {
  if (isTRUE(is.null(x)) || isTRUE(length(x) == 0)) return(default)
  if (isTRUE(is.character(x)) && isTRUE(trimws(x) == "")) return(default)

  tryCatch({
    as.Date(x)[1]
  }, error = function(e) {
    default
  })
}

# ---- Shiny Validation Helpers ----
# FIX v50: Safe with isTRUE()
validate_selection <- function(input_value, input_name = "selection") {
  shiny::validate(
    shiny::need(
      isTRUE(!is.null(input_value)) && isTRUE(length(input_value) > 0),
      sprintf("Selecione pelo menos um %s.", input_name)
    )
  )
}

validate_data <- function(df, msg = "Sem dados disponíveis. Ajuste os filtros.") {
  shiny::validate(
    shiny::need(isTRUE(!is.null(df)) && isTRUE(is.data.frame(df)) && isTRUE(nrow(df) > 0), msg)
  )
}

validate_range <- function(range, name = "range") {
  shiny::validate(
    shiny::need(
      isTRUE(!is.null(range)) && isTRUE(length(range) == 2) && isTRUE(!any(is.na(range))),
      sprintf("Selecione um intervalo válido para %s.", name)
    )
  )
}

# ---- Database Query Safety ----
# FIX v50: Safe with isTRUE()
safe_query <- function(pool, query, params = list(), query_name = "query") {
  tryCatch({
    log_debug(sprintf("Executing %s with %d params", query_name, length(params)))

    df <- DBI::dbGetQuery(pool, query, params = params)

    if (isTRUE(is.null(df)) || isTRUE(nrow(df) == 0)) {
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