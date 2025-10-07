# R/utils/scalar_utils.R
# SINGLE SOURCE OF TRUTH FOR SCALAR SAFETY
# All modules must use these functions to avoid "Expecting a single value" errors

# ---- Core null/empty coalescing ----
`%||%` <- function(x, y) if (is.null(x) || length(x) == 0L) y else x

# ---- Generic scalar extractors with consistent defaults ----
scalar <- function(x, default = NA) {
  if (is.null(x) || length(x) == 0L) return(default)
  x[[1L]]
}

scalar_chr <- function(x, default = "—") {
  if (is.null(x) || length(x) == 0L || all(is.na(x))) return(default)
  val <- as.character(x[[1L]])
  if (is.na(val) || !nzchar(val)) default else val
}

scalar_num <- function(x, default = 0) {
  if (is.null(x) || length(x) == 0L || all(is.na(x))) return(default)
  val <- suppressWarnings(as.numeric(x[[1L]]))
  if (is.na(val)) default else val
}

scalar_int <- function(x, default = 0L) {
  if (is.null(x) || length(x) == 0L || all(is.na(x))) return(default)
  val <- suppressWarnings(as.integer(x[[1L]]))
  if (is.na(val)) default else val
}

scalar_lgl <- function(x, default = FALSE) {
  if (is.null(x) || length(x) == 0L || all(is.na(x))) return(default)
  as.logical(x[[1L]]) %||% default
}

# ---- Safe calculation helpers (prevent vector leaks) ----
safe_nrow <- function(x, default = 0) {
  scalar_int(if (is.data.frame(x)) nrow(x) else if (is.atomic(x)) length(x) else NULL, default = default)
}

safe_length <- function(x, default = 0) {
  scalar_int(length(x), default = default)
}

safe_n_distinct <- function(x, default = 0) {
  scalar_int(if (!is.null(x) && length(x) > 0L) length(unique(x)) else NULL, default = default)
}

safe_mean <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (!is.null(x) && length(x) > 0L) mean(x, na.rm = na.rm) else NULL, default = default)
}

safe_sum <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (!is.null(x) && length(x) > 0L) sum(x, na.rm = na.rm) else NULL, default = default)
}

safe_max <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (!is.null(x) && length(x) > 0L) max(x, na.rm = na.rm) else NULL, default = default)
}

safe_min <- function(x, default = 0, na.rm = TRUE) {
  scalar_num(if (!is.null(x) && length(x) > 0L) min(x, na.rm = na.rm) else NULL, default = default)
}

# ---- Safe existence/length checks ----
nz_rows <- function(df) is.data.frame(df) && nrow(df) > 0L
nz_len  <- function(x)  !is.null(x) && length(x) > 0L
has_rows <- function(x) is.data.frame(x) && nrow(x) > 0L

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

  if (!is.null(format_fn) && is.function(format_fn)) {
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
  if (!is.null(x) && length(x) > 1) {
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
  if (!is.null(x) && length(x) > 1) {
    log_vector_leak(x, context = paste0("scalar_chr: ", context))
  }
  scalar_chr(x, default = default)
}

scalar_num_logged <- function(x, default = 0, context = "") {
  if (!is.null(x) && length(x) > 1) {
    log_vector_leak(x, context = paste0("scalar_num: ", context))
  }
  scalar_num(x, default = default)
}

scalar_int_logged <- function(x, default = 0L, context = "") {
  if (!is.null(x) && length(x) > 1) {
    log_vector_leak(x, context = paste0("scalar_int: ", context))
  }
  scalar_int(x, default = default)
}