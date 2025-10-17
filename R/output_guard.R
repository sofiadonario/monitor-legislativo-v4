# R/output_guard.R
# Universal guard that logs outputId + value shape, and prevents white-screen.
with_output_guard <- function(expr, fallback = NULL, label = NULL) {
  tryCatch({
    # Who am I?
    info <- try(shiny::getCurrentOutputInfo(), silent = TRUE)
    out_id <- if (!inherits(info, "try-error") && !is.null(info)) info$outputId else NA_character_
    cat("[GUARD:ENTER]", if (is.null(label)) "" else paste0(label, " "), "outputId=", out_id, "\n", file = stderr())
    val <- force(expr)

    # Log value shape to catch scalar problems early
    shape <- try({
      if (is.null(val)) "NULL"
      else if (is.atomic(val) || is.list(val)) paste0("len=", length(val), " class=", paste(class(val), collapse="|"))
      else paste0("class=", paste(class(val), collapse="|"))
    }, silent = TRUE)
    cat("[GUARD:VALUE]", "outputId=", out_id, " ", as.character(shape), "\n", file = stderr())

    val
  }, error = function(e) {
    info <- try(shiny::getCurrentOutputInfo(), silent = TRUE)
    out_id <- if (!inherits(info, "try-error") && !is.null(info)) info$outputId else NA_character_
    cat("! OUTPUT CRASH:", conditionMessage(e), " outputId=", out_id, "\n", file = stderr())
    flush.console()
    # Non-fatal: return neutral fallback so page keeps working
    fallback
  })
}

# Minimal safe scalars/formatters (used by fallbacks)
scalar1_guard <- function(x) if (is.null(x) || length(x) == 0) NA else x[[1]]
fmt_int_guard <- function(x) ifelse(is.na(x), "–", formatC(as.integer(x), big.mark=".", format="d"))
